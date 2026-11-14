"""
Núcleo único de extracción por ventanas (bloque "Extracción de huella digital" de la
Fig. 1, `ExtraerHuella` del Algoritmo 1; etapa E0 del plan, OE2).

`AgregadorVentanas` recibe tramas en orden de captura y emite una fila por
`(MAC, ventana)` al cerrarse cada ventana. Lo usan el procesado de pcap
(`scripts/pcap_to_features.py`) y la captura (`src/capture.py`): por eso entrenamiento e
inferencia ven las mismas columnas. Una fila solo depende de tramas ya vistas.

Niveles:
- Por MAC: ventana corta de 5 s más agregados de 60 s solapados (12 ventanas cortas).
- Global de segmento: se copia a todas las filas de la ventana.

Las MACs vistas por primera vez y con una sola trama en la ventana se funden en la fila
`MAC_EFIMERAS`, de modo que una inundación con `Ether.src` aleatorio aporta una fila y no
miles. Punto de observación declarado: SPAN de un segmento que ve todo el unicast.

Un SYN se evalúa al cierre si tiene al menos `GRACIA_SYN_US` de antigüedad; los más
jóvenes se ignoran, para no llamar medio abierto a un handshake en curso.
"""

from __future__ import annotations

import math
from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from .feature_schema import COLUMNAS_IDENTIDAD, COLUMNAS_MODELO, FEATURES_LARGAS

VENTANA_CORTA_S: float = 5.0
VENTANAS_EN_LARGA: int = 12  # 12 * 5 s = 60 s
MAC_EFIMERAS: str = "__efimeras__"
MAC_BROADCAST: str = "ff:ff:ff:ff:ff:ff"
ETHERTYPE_ARP: int = 0x0806
FCS_OCTETOS: int = 4
GRACIA_SYN_US: int = 1_000_000
TTL_ARP_US: int = 5_000_000
TTL_DNS_US: int = 5_000_000
TTL_ICMP_US: int = 5_000_000
PUERTO_DNS: int = 53
ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST = 0, 8
ICMP_ERRORES = (3, 11)  # destination unreachable, time exceeded
_PROTO_IP = {1: "icmp", 6: "tcp", 17: "udp"}


@dataclass(frozen=True)
class ConfigSegmento:
    """Conocimiento declarado del segmento; sin él, sus indicadores valen NaN."""

    ip_gateway: str | None = None
    mac_gateway: str | None = None
    resolvers: dict[str, str] | None = None  # IP autorizada -> MAC que la sirve


@dataclass(slots=True)
class Trama:
    """Campos de una trama que necesita el agregador, independientes de Scapy."""

    ts_us: int
    longitud: int
    mac_src: str
    mac_dst: str
    ethertype: int | None = None  # None en IEEE 802.3 LLC (campo longitud)
    vlan: bool = False
    arp_op: int | None = None
    arp_psrc: str = ""
    arp_pdst: str = ""
    arp_hwsrc: str = ""
    ip_src: str | None = None
    ip_dst: str | None = None
    proto: str | None = None  # "tcp", "udp" o "icmp"
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0
    icmp_tipo: int = -1
    icmp_id_seq: tuple[int, int] | None = None  # echo request / reply
    # Error ICMP: datagrama citado (ip_src, ip_dst, proto, sport, dport).
    icmp_cita: tuple[str, str, str, int, int] | None = None
    dns_qr: int | None = None
    dns_id: int = 0


def trama_desde_paquete(pkt) -> Trama | None:
    """Convierte un paquete Scapy en `Trama`; None si no tiene capa de enlace."""
    from scapy.all import (
        ARP,
        DNS,
        ICMP,
        IP,
        TCP,
        UDP,
        Dot1Q,
        Dot3,
        Ether,
        IPerror,
        TCPerror,
        UDPerror,
    )

    capa = pkt.getlayer(Ether) or pkt.getlayer(Dot3)
    if capa is None:
        return None
    trama = Trama(
        ts_us=round(float(pkt.time) * 1_000_000),
        longitud=len(pkt),
        mac_src=str(capa.src).lower(),
        mac_dst=str(capa.dst).lower(),
    )
    if isinstance(capa, Ether):
        trama.ethertype = int(capa.type)
    vlan = pkt.getlayer(Dot1Q)
    if vlan is not None:
        trama.vlan = True
        trama.ethertype = int(vlan.type)
    arp = pkt.getlayer(ARP)
    if arp is not None:
        trama.arp_op = int(arp.op)
        trama.arp_psrc, trama.arp_pdst = str(arp.psrc), str(arp.pdst)
        trama.arp_hwsrc = str(arp.hwsrc).lower()
        return trama
    ip = pkt.getlayer(IP)
    if ip is None:
        return trama
    trama.ip_src, trama.ip_dst = str(ip.src), str(ip.dst)
    tcp, udp, icmp = pkt.getlayer(TCP), pkt.getlayer(UDP), pkt.getlayer(ICMP)
    if tcp is not None:
        trama.proto = "tcp"
        trama.sport, trama.dport, trama.tcp_flags = int(tcp.sport), int(tcp.dport), int(tcp.flags)
    elif udp is not None:
        trama.proto = "udp"
        trama.sport, trama.dport = int(udp.sport), int(udp.dport)
        dns = pkt.getlayer(DNS)
        if dns is not None:
            trama.dns_qr, trama.dns_id = int(dns.qr), int(dns.id)
    elif icmp is not None:
        trama.proto = "icmp"
        trama.icmp_tipo = int(icmp.type)
        if trama.icmp_tipo in (ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST):
            trama.icmp_id_seq = (int(icmp.id or 0), int(icmp.seq or 0))
        citado = pkt.getlayer(IPerror)
        if trama.icmp_tipo in ICMP_ERRORES and citado is not None:
            capa4 = pkt.getlayer(TCPerror) or pkt.getlayer(UDPerror)
            trama.icmp_cita = (
                str(citado.src), str(citado.dst), _PROTO_IP.get(int(citado.proto), str(citado.proto)),
                int(capa4.sport) if capa4 is not None else 0, int(capa4.dport) if capa4 is not None else 0,
            )
    return trama


def _entropia(conteos: Iterable[int]) -> float:
    """Entropía de Shannon en base 2 de una distribución dada por conteos."""
    valores = [c for c in conteos if c > 0]
    total = sum(valores)
    return -sum(c / total * math.log2(c / total) for c in valores) if total else 0.0


def _media_std(valores: list[float]) -> tuple[float, float]:
    """Media y desviación muestral; NaN cuando no hay datos suficientes."""
    if not valores:
        return math.nan, math.nan
    media = sum(valores) / len(valores)
    if len(valores) < 2:
        return media, math.nan
    return media, math.sqrt(sum((v - media) ** 2 for v in valores) / (len(valores) - 1))


@dataclass
class _Acumulador:
    """Estadísticos de una MAC (o de la fila de efímeras) en una ventana."""

    c: Counter = field(default_factory=Counter)
    longitudes: list[int] = field(default_factory=list)
    iats_ms: list[float] = field(default_factory=list)
    ethertypes: Counter = field(default_factory=Counter)
    puertos: Counter = field(default_factory=Counter)
    macs_destino: set = field(default_factory=set)
    ips_origen: set = field(default_factory=set)
    ips_destino: set = field(default_factory=set)
    conexiones: set = field(default_factory=set)

    def fundir(self, otro: _Acumulador) -> None:
        """Suma `otro` a este acumulador (fila de MACs efímeras)."""
        self.c.update(otro.c)
        self.longitudes.extend(otro.longitudes)
        self.iats_ms.extend(otro.iats_ms)
        self.ethertypes.update(otro.ethertypes)
        self.puertos.update(otro.puertos)
        self.macs_destino |= otro.macs_destino
        self.ips_origen |= otro.ips_origen
        self.ips_destino |= otro.ips_destino
        self.conexiones |= otro.conexiones


@dataclass(slots=True)
class _Syn:
    mac: str
    ts_us: int
    ip_dst: str
    con_synack: bool = False
    completo: bool = False


@dataclass(slots=True)
class _ConsultaDns:
    ts_us: int
    primer_respondedor: str | None = None


class AgregadorVentanas:
    """Agregador incremental de tramas en filas por `(MAC, ventana)` (OE2)."""

    def __init__(
        self,
        config: ConfigSegmento | None = None,
        ventana_s: float = VENTANA_CORTA_S,
        ventanas_en_larga: int = VENTANAS_EN_LARGA,
    ) -> None:
        self.config = config or ConfigSegmento()
        self.ventana_us = round(ventana_s * 1_000_000)
        self.ventanas_en_larga = ventanas_en_larga
        self.t0_us: int | None = None
        self._idx: int | None = None
        self._acc: dict[str, _Acumulador] = {}
        self._ultimo_ts: dict[str, int] = {}
        self._macs_conocidas: set[str] = set()
        self._macs_nuevas: set[str] = set()
        self._syns: dict[tuple, _Syn] = {}
        self._arp_pendientes: dict[tuple[str, str], int] = {}
        self._vinculos: dict[str, str] = {}
        self._dns: dict[tuple, _ConsultaDns] = {}
        self._echo_pendientes: dict[tuple, int] = {}
        self._datagramas: dict[tuple, int] = {}
        self._historial: dict[str, deque] = {}

    def agregar(self, trama: Trama) -> list[dict]:
        """Procesa una trama y devuelve las filas de las ventanas que cierre."""
        if self.t0_us is None:
            self.t0_us = trama.ts_us
            self._idx = 0
        idx = (trama.ts_us - self.t0_us) // self.ventana_us
        filas: list[dict] = []
        if idx > self._idx:
            filas = self._cerrar_ventana()
            self._idx = idx
        self._acumular(trama)
        return filas

    def cerrar(self) -> list[dict]:
        """Cierra la ventana en curso (fin de captura)."""
        return self._cerrar_ventana() if self._acc else []

    def _acumular(self, t: Trama) -> None:
        acc = self._acc.setdefault(t.mac_src, _Acumulador())
        if t.mac_src not in self._macs_conocidas:
            self._macs_conocidas.add(t.mac_src)
            self._macs_nuevas.add(t.mac_src)
        previo = self._ultimo_ts.get(t.mac_src)
        if previo is not None:
            acc.iats_ms.append(max(t.ts_us - previo, 0) / 1000.0)
        self._ultimo_ts[t.mac_src] = t.ts_us

        c = acc.c
        c["n_tramas"] += 1
        acc.longitudes.append(t.longitud)
        acc.ethertypes[t.ethertype if t.ethertype is not None else -1] += 1
        acc.macs_destino.add(t.mac_dst)
        if t.mac_dst == MAC_BROADCAST:
            c["broadcast"] += 1
        elif int(t.mac_dst[:2], 16) & 1:
            c["multicast"] += 1
        else:
            c["unicast"] += 1
        c["menor_64"] += t.longitud + FCS_OCTETOS < 64
        c["vlan"] += t.vlan
        c["llc"] += t.ethertype is None

        if t.arp_op is not None:
            self._acumular_arp(t, acc)
        if t.ip_src is not None:
            acc.ips_origen.add(t.ip_src)
            acc.ips_destino.add(t.ip_dst)
            self._datagramas[(t.ip_src, t.ip_dst, t.proto, t.sport, t.dport)] = t.ts_us
        if t.proto in ("tcp", "udp"):
            acc.puertos[t.dport] += 1
            acc.conexiones.add((t.ip_dst, t.dport))
        if t.proto == "tcp":
            self._acumular_tcp(t, acc)
        elif t.proto == "icmp":
            c["n_icmp_echo"] += t.icmp_tipo == ICMP_ECHO_REQUEST
            self._acumular_icmp(t, acc)
        elif t.dns_qr is not None and PUERTO_DNS in (t.sport, t.dport):
            self._acumular_dns(t, acc)

    def _acumular_arp(self, t: Trama, acc: _Acumulador) -> None:
        c = acc.c
        c["arp_ether_distinto_hwsrc"] += t.arp_hwsrc != t.mac_src
        gw = self.config.ip_gateway
        if gw is not None and t.arp_psrc == gw and t.arp_hwsrc != self.config.mac_gateway:
            c["arp_gateway_reclamado"] += 1
        vinculo = self._vinculos.get(t.arp_psrc)
        if t.arp_psrc != "0.0.0.0":
            if vinculo is not None and vinculo != t.arp_hwsrc:
                c["arp_cambios_vinculo"] += 1
            self._vinculos[t.arp_psrc] = t.arp_hwsrc
        if t.arp_psrc == t.arp_pdst:
            c["arp_gratuitos"] += 1
        elif t.arp_op == 1:
            c["arp_requests"] += 1
            self._arp_pendientes[(t.arp_psrc, t.arp_pdst)] = t.ts_us
        elif t.arp_op == 2:
            c["arp_replies"] += 1
            pendiente = self._arp_pendientes.get((t.arp_pdst, t.arp_psrc))
            if pendiente is None or t.ts_us - pendiente > TTL_ARP_US:
                c["arp_replies_no_solicitadas"] += 1
                c["respuestas_no_solicitadas"] += 1

    def _acumular_icmp(self, t: Trama, acc: _Acumulador) -> None:
        """Echo reply sin request, o error que cita un datagrama que su destinatario no envió."""
        if t.icmp_tipo == ICMP_ECHO_REQUEST and t.icmp_id_seq is not None:
            self._echo_pendientes[(t.ip_src, t.ip_dst, t.icmp_id_seq)] = t.ts_us
        elif t.icmp_tipo == ICMP_ECHO_REPLY:
            pendiente = self._echo_pendientes.get((t.ip_dst, t.ip_src, t.icmp_id_seq))
            if pendiente is None or t.ts_us - pendiente > TTL_ICMP_US:
                acc.c["respuestas_no_solicitadas"] += 1
        elif t.icmp_tipo in ICMP_ERRORES:
            cita = t.icmp_cita
            enviado = self._datagramas.get(cita) if cita is not None else None
            if cita is None or cita[0] != t.ip_dst or enviado is None or t.ts_us - enviado > TTL_ICMP_US:
                acc.c["respuestas_no_solicitadas"] += 1

    def _acumular_tcp(self, t: Trama, acc: _Acumulador) -> None:
        syn, ack, rst = t.tcp_flags & 0x02, t.tcp_flags & 0x10, t.tcp_flags & 0x04
        clave = (t.ip_src, t.sport, t.ip_dst, t.dport)
        inversa = (t.ip_dst, t.dport, t.ip_src, t.sport)
        if syn and not ack:
            acc.c["n_syn"] += 1
            self._syns.setdefault(clave, _Syn(t.mac_src, t.ts_us, t.ip_dst))
        elif syn and ack:
            if inversa in self._syns:
                self._syns[inversa].con_synack = True
        elif ack and not rst and clave in self._syns:
            self._syns[clave].completo = True  # ACK final del cliente
        if rst:
            acc.c["n_rst"] += 1

    def _acumular_dns(self, t: Trama, acc: _Acumulador) -> None:
        c = acc.c
        if t.dns_qr == 0:
            c["dns_consultas"] += 1
            self._dns[(t.ip_src, t.sport, t.dns_id)] = _ConsultaDns(t.ts_us)
            return
        c["dns_respuestas"] += 1
        resolvers = self.config.resolvers
        if resolvers is not None and resolvers.get(t.ip_src) != t.mac_src:
            c["dns_resolver_no_autorizado"] += 1
        consulta = self._dns.get((t.ip_dst, t.dport, t.dns_id))
        if consulta is None or t.ts_us - consulta.ts_us > TTL_DNS_US:
            c["dns_respuestas_sin_consulta"] += 1
            c["respuestas_no_solicitadas"] += 1
        elif consulta.primer_respondedor is None:
            consulta.primer_respondedor = t.mac_src
        else:
            # La respuesta falsa suele ganar la carrera: se señala también al primero.
            c["dns_multiples_respuestas_txid"] += 1
            primero = consulta.primer_respondedor
            if primero != t.mac_src and primero in self._acc:
                self._acc[primero].c["dns_multiples_respuestas_txid"] += 1

    def _evaluar_syns(self) -> tuple[Counter, Counter, Counter]:
        """Clasifica los SYN evaluables al cierre y descarta el estado de la ventana."""
        fin_us = self.t0_us + (self._idx + 1) * self.ventana_us
        evaluables: Counter = Counter()
        sin_synack: Counter = Counter()
        medio_abiertos: Counter = Counter()
        for syn in self._syns.values():
            if fin_us - syn.ts_us < GRACIA_SYN_US:
                continue
            evaluables[syn.mac] += 1
            sin_synack[syn.ip_dst] += not syn.con_synack
            if not syn.completo:
                medio_abiertos[syn.ip_dst] += 1
                self._acc[syn.mac].c["syn_medio_abiertos"] += 1
        self._syns.clear()
        return evaluables, sin_synack, medio_abiertos

    def _podar_estado(self) -> None:
        """Retira consultas y peticiones caducadas para acotar la memoria."""
        limite = self.t0_us + self._idx * self.ventana_us
        self._arp_pendientes = {
            k: ts for k, ts in self._arp_pendientes.items() if limite - ts <= TTL_ARP_US
        }
        self._dns = {k: v for k, v in self._dns.items() if limite - v.ts_us <= TTL_DNS_US}
        self._echo_pendientes = {
            k: ts for k, ts in self._echo_pendientes.items() if limite - ts <= TTL_ICMP_US
        }
        self._datagramas = {k: ts for k, ts in self._datagramas.items() if limite - ts <= TTL_ICMP_US}

    def _cerrar_ventana(self) -> list[dict]:
        evaluables, sin_synack, medio_abiertos = self._evaluar_syns()
        activas = len(self._acc)
        una_trama = sum(a.c["n_tramas"] == 1 for a in self._acc.values())
        macs_nuevas = len(self._macs_nuevas)

        efimeras = _Acumulador()
        eval_efimeras = 0
        filas_acc: dict[str, _Acumulador] = {}
        evaluables_fila: dict[str, int] = {}
        for mac, acc in self._acc.items():
            if mac in self._macs_nuevas and acc.c["n_tramas"] == 1:
                efimeras.fundir(acc)
                eval_efimeras += evaluables[mac]
            else:
                filas_acc[mac] = acc
                evaluables_fila[mac] = evaluables[mac]
        if efimeras.c["n_tramas"]:
            filas_acc[MAC_EFIMERAS] = efimeras
            evaluables_fila[MAC_EFIMERAS] = eval_efimeras

        globales = {
            "macs_nuevas_por_s": macs_nuevas / (self.ventana_us / 1_000_000),
            "macs_activas": activas,
            "ratio_macs_una_trama": una_trama / activas if activas else math.nan,
            "syn_sin_synack_max_destino": max(sin_synack.values(), default=0),
            "syn_medio_abiertos_max_destino": max(medio_abiertos.values(), default=0),
        }
        filas = [
            self._fila(mac, acc, evaluables_fila[mac], globales) for mac, acc in filas_acc.items()
        ]
        self._acc = {}
        self._macs_nuevas = set()
        self._podar_estado()
        return filas

    def _largas(self, mac: str, acc: _Acumulador) -> dict[str, float]:
        """Actualiza el historial de la MAC y agrega los últimos 60 s solapados."""
        historial = self._historial.setdefault(mac, deque())
        historial.append((self._idx, acc.c, acc.puertos.keys(), acc.ips_destino))
        while historial[0][0] <= self._idx - self.ventanas_en_larga:
            historial.popleft()
        puertos: set = set()
        ips: set = set()
        for _, _, p, i in historial:
            puertos |= set(p)
            ips |= i
        suma = lambda nombre: sum(h[1][nombre] for h in historial)  # noqa: E731
        return {
            "n_tramas_60s": suma("n_tramas"),
            "arp_replies_no_solicitadas_60s": suma("arp_replies_no_solicitadas"),
            "arp_cambios_vinculo_60s": suma("arp_cambios_vinculo"),
            "syn_medio_abiertos_60s": suma("syn_medio_abiertos"),
            "dns_respuestas_sin_consulta_60s": suma("dns_respuestas_sin_consulta"),
            "respuestas_no_solicitadas_60s": suma("respuestas_no_solicitadas"),
            "puertos_destino_distintos_60s": len(puertos),
            "ips_destino_distintas_60s": len(ips),
        }

    def _fila(self, mac: str, acc: _Acumulador, evaluables: int, globales: dict) -> dict:
        c = acc.c
        n = c["n_tramas"]
        media_l, std_l = _media_std([float(v) for v in acc.longitudes])
        media_iat, std_iat = _media_std(acc.iats_ms)
        fila: dict = {
            "mac": mac,
            "idx_ventana": self._idx,
            "t0_us": self.t0_us,
            "n_tramas": n,
            "bytes_totales": sum(acc.longitudes),
            "longitud_trama_media": media_l,
            "longitud_trama_std": std_l,
            "iat_media_ms": media_iat,
            "iat_std_ms": std_iat,
            "tasa_unicast": c["unicast"] / n,
            "tasa_multicast": c["multicast"] / n,
            "tasa_broadcast": c["broadcast"] / n,
            "macs_destino_distintas": len(acc.macs_destino),
            "pct_menor_64": 100.0 * c["menor_64"] / n,
            "tasa_vlan": c["vlan"] / n,
            "tasa_llc": c["llc"] / n,
            "entropia_ethertype": _entropia(acc.ethertypes.values()),
            "tasa_syn": c["n_syn"] / n,
            "tasa_respuestas_no_solicitadas": c["respuestas_no_solicitadas"] / n,
            "ratio_syn_medio_abiertos": (
                c["syn_medio_abiertos"] / evaluables if evaluables else math.nan
            ),
            "ips_origen_distintas": len(acc.ips_origen),
            "ips_destino_distintas": len(acc.ips_destino),
            "puertos_destino_distintos": len(acc.puertos),
            "entropia_puertos_destino": _entropia(acc.puertos.values()),
            "conexiones_distintas": len(acc.conexiones),
            "arp_gateway_reclamado": (
                c["arp_gateway_reclamado"] if self.config.ip_gateway is not None else math.nan
            ),
            "dns_resolver_no_autorizado": (
                c["dns_resolver_no_autorizado"] if self.config.resolvers is not None else math.nan
            ),
            **self._largas(mac, acc),
            **globales,
        }
        for columna in COLUMNAS_MODELO:
            if columna not in fila:
                fila[columna] = c[columna]
        return fila


def extraer_ventanas(tramas: Iterable[Trama], config: ConfigSegmento | None = None) -> list[dict]:
    """Agrega una secuencia de tramas ya ordenadas y devuelve todas sus filas."""
    agregador = AgregadorVentanas(config)
    filas: list[dict] = []
    for trama in tramas:
        filas.extend(agregador.agregar(trama))
    filas.extend(agregador.cerrar())
    return filas


def leer_pcap(ruta) -> Iterable[Trama]:
    """Itera las tramas de un pcap sin cargarlo en memoria (no requiere root)."""
    from scapy.all import PcapReader

    with PcapReader(str(ruta)) as lector:
        for pkt in lector:
            trama = trama_desde_paquete(pkt)
            if trama is not None:
                yield trama


__all__ = [
    "AgregadorVentanas", "COLUMNAS_IDENTIDAD", "ConfigSegmento", "FEATURES_LARGAS", "MAC_EFIMERAS",
    "Trama", "VENTANA_CORTA_S", "extraer_ventanas", "leer_pcap", "trama_desde_paquete",
]
