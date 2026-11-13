#!/usr/bin/env python3
"""
Generador del timeline de laboratorio (etapa E1 del plan, OE1 y OE2).

Sintetiza una captura continua por sesión: mismo reloj, topología y fondo benigno, con
ataques en instantes Poisson. Escribe solo archivos locales (pcap, manifiestos y
topología); no toca ninguna interfaz ni requiere root. El objetivo es entrenar un IDS
defensivo, así que se generan bytes en disco, nunca tráfico emitido.

Salida para `sesion_NNN`:
    .pcap          captura ordenada por tiempo, todas las tramas >= 60 octetos
    .tramas.csv    manifiesto por trama de ataque
    .episodios.csv manifiesto por intervalo
    .config.json   gateway y resolvers declarados al IDS

Todos los parámetros son constantes fijadas antes de ver resultados del modelo; cualquier
cambio posterior debe documentarse (riesgo "sesgo del autor" del plan).
"""
from __future__ import annotations

import csv
import json
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    LLC,
    STP,
    TCP,
    UDP,
    Dot1Q,
    Dot3,
    Ether,
    Raw,
)

T0_US = 1_000_000_000_000
DURACION_S = 900.0
ESPACIO_ENTRE_ATAQUES_S = 100.0  # media del proceso de Poisson de inicio de episodios
MIN_DISPOSITIVOS, MAX_DISPOSITIVOS = 22, 30
N_HOSTS_ATACANTES = 2
LONGITUD_MINIMA = 60

OUIS = ["3c:52:82", "00:1b:21", "f4:8e:38", "b8:27:eb", "00:50:56", "a4:83:e7", "00:0c:29", "dc:a6:32"]
MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
RED = "10.0.0."
IP_GATEWAY, IP_RESOLVER, IP_ARCHIVOS, IP_WEB = RED + "1", RED + "2", RED + "3", RED + "4"
IPS_EXTERNAS = ["93.184.216.34", "151.101.1.69", "142.250.72.14", "104.16.133.229"]

# Perfil -> (eventos/s en periodo activo, pesos de web, archivo, ping, arp, mdns, ntp).
PERFILES: dict[str, tuple[float, tuple[float, ...]]] = {
    "oficina": (0.35, (0.55, 0.15, 0.03, 0.12, 0.10, 0.05)),
    "iot": (0.08, (0.15, 0.00, 0.05, 0.20, 0.30, 0.30)),
    "impresora": (0.03, (0.00, 0.30, 0.10, 0.30, 0.30, 0.00)),
    "voip": (0.12, (0.40, 0.00, 0.10, 0.20, 0.10, 0.20)),
    "administracion": (0.25, (0.40, 0.20, 0.20, 0.15, 0.00, 0.05)),
    "host_atacante": (0.10, (0.60, 0.05, 0.05, 0.15, 0.10, 0.05)),
}
EVENTOS = ("web", "archivo", "ping", "arp", "mdns", "ntp")

# Atributos de una trama de ataque: atacante, episodio, tipo, variante, capa.
Marca = tuple[str, int, str, str, str]


@dataclass
class Dispositivo:
    mac: str
    ip: str
    perfil: str
    vlan: int | None = None
    ttl: int = 64


@dataclass
class Sesion:
    """Estado de una captura sintética: reloj común, topología y tramas emitidas."""

    semilla: int
    rng: np.random.Generator = field(init=False)
    gateway: Dispositivo = field(init=False)
    resolver: Dispositivo = field(init=False)
    archivos: Dispositivo = field(init=False)
    web: Dispositivo = field(init=False)
    dispositivos: list[Dispositivo] = field(default_factory=list)
    tramas: list[tuple[int, bytes, Marca | None]] = field(default_factory=list)
    episodios: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.rng = np.random.default_rng(self.semilla)
        self.gateway = Dispositivo(self.mac_aleatoria(), IP_GATEWAY, "infraestructura")
        self.resolver = Dispositivo(self.mac_aleatoria(), IP_RESOLVER, "infraestructura")
        self.archivos = Dispositivo(self.mac_aleatoria(), IP_ARCHIVOS, "infraestructura")
        self.web = Dispositivo(self.mac_aleatoria(), IP_WEB, "infraestructura")
        n = int(self.rng.integers(MIN_DISPOSITIVOS, MAX_DISPOSITIVOS + 1))
        perfiles = list(self.rng.choice(
            ["oficina", "iot", "impresora", "voip"], size=n - 1 - N_HOSTS_ATACANTES,
            p=[0.55, 0.25, 0.08, 0.12],
        )) + ["administracion"] + ["host_atacante"] * N_HOSTS_ATACANTES
        for i, perfil in enumerate(perfiles):
            self.dispositivos.append(Dispositivo(
                self.mac_aleatoria(), f"{RED}{20 + i}", str(perfil),
                vlan=100 if i % 9 == 4 else None,
                ttl=int(self.rng.choice([64, 128])),
            ))

    @property
    def atacantes(self) -> list[Dispositivo]:
        return [d for d in self.dispositivos if d.perfil == "host_atacante"]

    @property
    def victimas(self) -> list[Dispositivo]:
        return [d for d in self.dispositivos if d.perfil != "host_atacante"]

    def elegir(self, opciones: list):
        return opciones[int(self.rng.integers(len(opciones)))]

    def mac_aleatoria(self) -> str:
        cola = ":".join(f"{int(x):02x}" for x in self.rng.integers(0, 256, 3))
        return f"{self.elegir(OUIS)}:{cola}"

    def puerto(self) -> int:
        return int(self.rng.integers(32768, 61000))

    def emitir(self, t: float, pkt, marca: Marca | None = None) -> None:
        """Registra la trama rellenada a 60 octetos en el instante `t` (s de sesión)."""
        pkt.time = 0  # el instante real viaja aparte; bytes() no lo usa
        crudo = bytes(pkt)
        crudo += b"\x00" * max(0, LONGITUD_MINIMA - len(crudo))
        self.tramas.append((T0_US + round(t * 1_000_000), crudo, marca))

    def eth(self, src: Dispositivo, mac_dst: str):
        """Cabecera Ethernet, con 802.1Q si el dispositivo está en VLAN."""
        if src.vlan is None:
            return Ether(src=src.mac, dst=mac_dst)
        return Ether(src=src.mac, dst=mac_dst) / Dot1Q(vlan=src.vlan)

    def tras_salto(self, ip: str, srv: Dispositivo | None) -> Dispositivo:
        return srv if srv is not None else self.gateway


def _flujo_tcp(s: Sesion, t: float, cli: Dispositivo, srv: Dispositivo, ip_srv: str, dport: int,
               n_datos: int, separacion: float | None = None) -> float:
    """Conexión completa y coherente: handshake, datos con seq/ack y cierre FIN."""
    rng = s.rng
    sport = s.puerto()
    isn_c, isn_s = int(rng.integers(1, 2**31)), int(rng.integers(1, 2**31))
    rtt = float(rng.uniform(0.0004, 0.03))
    separacion = separacion if separacion is not None else float(rng.uniform(0.001, 0.05))

    def segmento(desde_cliente: bool, flags: str, seq: int, ack: int, carga: int = 0):
        origen, destino = (cli, srv) if desde_cliente else (srv, cli)
        ip_o, ip_d = (cli.ip, ip_srv) if desde_cliente else (ip_srv, cli.ip)
        p_o, p_d = (sport, dport) if desde_cliente else (dport, sport)
        pkt = s.eth(origen, destino.mac) / IP(src=ip_o, dst=ip_d, ttl=origen.ttl) / TCP(
            sport=p_o, dport=p_d, flags=flags, seq=seq % 2**32, ack=ack % 2**32,
            window=int(29200 if origen.ttl == 64 else 64240),
        )
        return pkt / Raw(b"x" * carga) if carga else pkt

    s.emitir(t, segmento(True, "S", isn_c, 0))
    t += rtt / 2
    s.emitir(t, segmento(False, "SA", isn_s, isn_c + 1))
    t += rtt / 2
    seq_c, seq_s = isn_c + 1, isn_s + 1
    s.emitir(t, segmento(True, "A", seq_c, seq_s))
    # Petición corta y respuesta en segmentos, como HTTP/SMB.
    t += float(rng.uniform(0.0005, 0.01))
    peticion = int(rng.integers(80, 600))
    s.emitir(t, segmento(True, "PA", seq_c, seq_s, peticion))
    seq_c += peticion
    for _ in range(n_datos):
        t += float(rng.exponential(separacion)) + 0.00002
        carga = int(rng.choice([1460, 1460, 1460, int(rng.integers(100, 1460))]))
        s.emitir(t, segmento(False, "A", seq_s, seq_c, carga))
        seq_s += carga
        t += 0.00002 + float(rng.exponential(0.0005))
        s.emitir(t, segmento(True, "A", seq_c, seq_s))
    t += float(rng.uniform(0.001, 0.2))
    s.emitir(t, segmento(True, "FA", seq_c, seq_s))
    t += rtt / 2
    s.emitir(t, segmento(False, "FA", seq_s, seq_c + 1))
    t += rtt / 2
    s.emitir(t, segmento(True, "A", seq_c + 1, seq_s + 1))
    return t


def _dns_consulta(s: Sesion, t: float, cli: Dispositivo, nombre: str) -> tuple[int, int]:
    sport, txid = s.puerto(), int(s.rng.integers(1, 65535))
    s.emitir(t, s.eth(cli, s.resolver.mac) / IP(src=cli.ip, dst=IP_RESOLVER, ttl=cli.ttl) / UDP(
        sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=nombre)))
    return sport, txid


def _dns_respuesta(s: Sesion, t: float, cli: Dispositivo, sport: int, txid: int, nombre: str,
                   rdata: str, mac_origen: str | None = None, marca: Marca | None = None) -> None:
    """Respuesta DNS; con `mac_origen` procede de un equipo que no es el resolver."""
    pkt = Ether(src=mac_origen or s.resolver.mac, dst=cli.mac) / IP(
        src=IP_RESOLVER, dst=cli.ip) / UDP(sport=53, dport=sport) / DNS(
        id=txid, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=nombre),
        an=DNSRR(rrname=nombre, rdata=rdata, ttl=300))
    s.emitir(t, pkt, marca)


def _resolver_y_conectar(s: Sesion, t: float, d: Dispositivo) -> None:
    nombre = f"srv{int(s.rng.integers(1, 40))}.ejemplo.lab"
    externa = bool(s.rng.random() < 0.7)
    ip = s.elegir(IPS_EXTERNAS) if externa else IP_WEB
    sport, txid = _dns_consulta(s, t, d, nombre)
    t += float(s.rng.uniform(0.002, 0.04))
    _dns_respuesta(s, t, d, sport, txid, nombre, ip)
    t += float(s.rng.uniform(0.001, 0.02))
    n = 1 + int(s.rng.geometric(0.15))
    r = float(s.rng.random())
    if r < 0.04:  # puerto cerrado: SYN respondido con RST
        srv = s.gateway if externa else s.web
        sp = s.puerto()
        s.emitir(t, s.eth(d, srv.mac) / IP(src=d.ip, dst=ip, ttl=d.ttl) / TCP(sport=sp, dport=8443, flags="S"))
        s.emitir(t + 0.003, Ether(src=srv.mac, dst=d.mac) / IP(src=ip, dst=d.ip) / TCP(
            sport=8443, dport=sp, flags="RA", ack=1))
    elif r < 0.07:  # destino caído: SYN con retransmisiones sin respuesta
        sp = s.puerto()
        for reintento in range(3):
            s.emitir(t + reintento + 0.001 * reintento,
                     s.eth(d, s.gateway.mac) / IP(src=d.ip, dst=ip, ttl=d.ttl) / TCP(sport=sp, dport=443, flags="S"))
    else:
        _flujo_tcp(s, t, d, s.gateway if externa else s.web, ip, 443, n)


def _arp_resolver(s: Sesion, t: float, d: Dispositivo, objetivo: Dispositivo) -> None:
    s.emitir(t, s.eth(d, MAC_BROADCAST) / ARP(op=1, hwsrc=d.mac, psrc=d.ip, pdst=objetivo.ip))
    s.emitir(t + float(s.rng.uniform(0.0002, 0.003)), s.eth(objetivo, d.mac) / ARP(
        op=2, hwsrc=objetivo.mac, psrc=objetivo.ip, hwdst=d.mac, pdst=d.ip))


def _evento(s: Sesion, t: float, d: Dispositivo, tipo: str) -> None:
    rng = s.rng
    if tipo == "web":
        _resolver_y_conectar(s, t, d)
    elif tipo == "archivo":
        _flujo_tcp(s, t, d, s.archivos, IP_ARCHIVOS, 445, 3 + int(rng.geometric(0.05)))
    elif tipo == "ping":
        ident = int(rng.integers(1, 65535))
        for i in range(int(rng.integers(1, 5))):
            s.emitir(t + i, s.eth(d, s.gateway.mac) / IP(src=d.ip, dst=IP_GATEWAY, ttl=d.ttl) / ICMP(
                type=8, id=ident, seq=i))
            s.emitir(t + i + 0.001, Ether(src=s.gateway.mac, dst=d.mac) / IP(src=IP_GATEWAY, dst=d.ip) / ICMP(
                type=0, id=ident, seq=i))
    elif tipo == "arp":
        _arp_resolver(s, t, d, s.elegir(s.victimas + [s.gateway, s.web]))
    elif tipo == "mdns":
        s.emitir(t, s.eth(d, "01:00:5e:00:00:fb") / IP(src=d.ip, dst="224.0.0.251", ttl=255) / UDP(
            sport=5353, dport=5353) / DNS(id=0, qd=DNSQR(qname="_ipp._tcp.local", qtype="PTR")))
    elif tipo == "ntp":
        sport = s.puerto()
        s.emitir(t, s.eth(d, s.gateway.mac) / IP(src=d.ip, dst=IP_GATEWAY, ttl=d.ttl) / UDP(
            sport=sport, dport=123) / Raw(b"\x23" + b"\x00" * 47))
        s.emitir(t + 0.002, Ether(src=s.gateway.mac, dst=d.mac) / IP(src=IP_GATEWAY, dst=d.ip) / UDP(
            sport=123, dport=sport) / Raw(b"\x24" + b"\x00" * 47))


def _fondo_dispositivo(s: Sesion, d: Dispositivo) -> None:
    """Proceso temporal propio: Poisson modulado por periodos activos e inactivos."""
    rng = s.rng
    tasa, pesos = PERFILES[d.perfil]
    pesos_n = np.array(pesos) / sum(pesos)
    tasa *= float(rng.uniform(0.6, 1.4))
    t, activo = float(rng.uniform(0, 30)), True
    while t < DURACION_S:
        fin = t + float(rng.exponential(150.0 if activo else 60.0))
        if activo:
            cursor = t + float(rng.exponential(1 / tasa))
            while cursor < min(fin, DURACION_S):
                _evento(s, cursor, d, str(rng.choice(EVENTOS, p=pesos_n)))
                cursor += float(rng.exponential(1 / tasa))
        t, activo = fin, not activo


def _control_de_red(s: Sesion) -> None:
    """STP/LLC, LLDP, DHCP, ARP gratuito y sondeos del gateway."""
    rng = s.rng
    mac_switch = s.mac_aleatoria()
    for k in range(int(DURACION_S / 2)):
        s.emitir(0.05 + 2.0 * k, Dot3(src=mac_switch, dst="01:80:c2:00:00:00") / LLC(
            dsap=0x42, ssap=0x42, ctrl=3) / STP())
    for k in range(int(DURACION_S / 30)):
        s.emitir(1.0 + 30.0 * k, Ether(src=mac_switch, dst="01:80:c2:00:00:0e", type=0x88cc) / Raw(b"\x02\x07\x04" + b"\x00" * 40))
    for d in s.dispositivos:
        if rng.random() < 0.5:  # arranque: DHCP y ARP gratuito
            t = float(rng.uniform(0, DURACION_S))
            xid = int(rng.integers(1, 2**31))
            for i, (origen, tipo) in enumerate((("c", "discover"), ("s", "offer"), ("c", "request"), ("s", "ack"))):
                if origen == "c":
                    pkt = Ether(src=d.mac, dst=MAC_BROADCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(
                        sport=68, dport=67) / BOOTP(xid=xid) / DHCP(options=[("message-type", tipo), "end"])
                else:
                    pkt = Ether(src=s.gateway.mac, dst=d.mac) / IP(src=IP_GATEWAY, dst=d.ip) / UDP(
                        sport=67, dport=68) / BOOTP(op=2, xid=xid, yiaddr=d.ip) / DHCP(options=[("message-type", tipo), "end"])
                s.emitir(t + 0.01 * i, pkt)
            s.emitir(t + 0.1, Ether(src=d.mac, dst=MAC_BROADCAST) / ARP(
                op=1, hwsrc=d.mac, psrc=d.ip, pdst=d.ip))
    t = float(rng.exponential(45.0))
    while t < DURACION_S:
        _arp_resolver(s, t, s.gateway, s.elegir(s.dispositivos))
        t += float(rng.exponential(45.0))
    # Reemplazo de equipo: otra MAC reclama legítimamente una IP antes vista.
    ip_compartida = f"{RED}200"
    t = float(rng.uniform(60, DURACION_S / 2))
    for mac in (s.mac_aleatoria(), s.mac_aleatoria()):
        s.emitir(t, Ether(src=mac, dst=MAC_BROADCAST) / ARP(op=1, hwsrc=mac, psrc=ip_compartida, pdst=ip_compartida))
        t += float(rng.uniform(60, 300))


def _rafagas_legitimas(s: Sesion) -> None:
    """Copias de seguridad y escaneo administrativo: se parecen a ataques sin serlo."""
    rng = s.rng
    for _ in range(int(rng.integers(1, 4))):
        d = s.elegir(s.victimas)
        _flujo_tcp(s, float(rng.uniform(0, DURACION_S)), d, s.archivos, IP_ARCHIVOS, 445,
                   int(rng.integers(300, 1500)), separacion=0.001)
    admin = next(d for d in s.dispositivos if d.perfil == "administracion")
    for _ in range(int(rng.integers(1, 3))):
        t = float(rng.uniform(0, DURACION_S - 60))
        for objetivo in s.victimas[:15]:
            for puerto in (22, 80, 443, 445, 3389):
                sp = s.puerto()
                s.emitir(t, s.eth(admin, objetivo.mac) / IP(src=admin.ip, dst=objetivo.ip, ttl=admin.ttl) / TCP(
                    sport=sp, dport=puerto, flags="S"))
                s.emitir(t + 0.0008, s.eth(objetivo, admin.mac) / IP(src=objetivo.ip, dst=admin.ip) / TCP(
                    sport=puerto, dport=sp, flags="RA", ack=1))
                t += float(rng.exponential(0.05))


# ---------------------------------------------------------------- Ataques (en pcap)
def _origen_ataque(s: Sesion) -> tuple[Dispositivo, str]:
    """Host atacante reutilizado (65 %) o clon de una víctima que sigue activa (35 %)."""
    host = s.elegir(s.atacantes)
    if s.rng.random() < 0.35:
        clon = s.elegir(s.victimas)
        return Dispositivo(clon.mac, host.ip, "clon"), "clon"
    return host, "propia"


def _ataque_mac_flooding(s, t, ep, atacante, _modo) -> tuple[str, float]:
    rng = s.rng
    pps, dur = float(rng.uniform(100, 1500)), float(rng.uniform(4, 25))
    marca = (atacante.mac, ep, "mac_flooding", "ether_aleatorio", "enlace")
    n = int(pps * dur)
    fin = t
    for i in range(n):
        fin = t + i / pps + float(rng.uniform(0, 0.5 / pps))
        src = s.mac_aleatoria()
        s.emitir(fin, Ether(src=src, dst=s.mac_aleatoria()) / IP(src=atacante.ip, dst=IP_WEB) / UDP(
            sport=s.puerto(), dport=int(rng.integers(1, 65535))), (marca[0], ep, *marca[2:]))
    return marca[3], fin


def _ataque_arp(s, t, ep, atacante, _modo) -> tuple[str, float]:
    rng = s.rng
    lento = bool(rng.random() < 0.6)
    variante = "unicast_lento" if lento else "rafaga"
    victima = s.elegir(s.victimas)
    marca = (atacante.mac, ep, "arp_spoofing", variante, "enlace")
    if lento:
        fin = t + float(rng.uniform(60, 200))
        cursor = t
        while cursor < fin:
            s.emitir(cursor, Ether(src=atacante.mac, dst=victima.mac) / ARP(
                op=2, hwsrc=atacante.mac, psrc=IP_GATEWAY, hwdst=victima.mac, pdst=victima.ip), marca)
            s.emitir(cursor + 0.001, Ether(src=atacante.mac, dst=s.gateway.mac) / ARP(
                op=2, hwsrc=atacante.mac, psrc=victima.ip, hwdst=s.gateway.mac, pdst=IP_GATEWAY), marca)
            cursor += float(np.clip(rng.normal(2.0, 0.4), 0.5, 4.0))
        return variante, fin
    pps, dur = float(rng.uniform(20, 200)), float(rng.uniform(4, 20))
    for i in range(int(pps * dur)):
        s.emitir(t + i / pps, Ether(src=atacante.mac, dst=MAC_BROADCAST) / ARP(
            op=2, hwsrc=atacante.mac, psrc=IP_GATEWAY, pdst=f"{RED}255"), marca)
    return variante, t + dur


def _ataque_dns(s, t, ep, atacante, _modo) -> tuple[str, float]:
    """Respuesta falsa a la MAC de la víctima, compitiendo con la real."""
    rng = s.rng
    clona_resolver = bool(rng.random() < 0.3)
    variante = "clona_resolver" if clona_resolver else "mac_propia"
    mac = s.resolver.mac if clona_resolver else atacante.mac
    marca = (atacante.ip, ep, "dns_spoofing", variante, "aplicacion")
    victima = s.elegir(s.victimas)
    fin = t + float(rng.uniform(15, 60))
    tasa = float(rng.uniform(0.4, 2.0))
    cursor = t
    while cursor < fin:
        nombre = f"banco{int(rng.integers(1, 6))}.ejemplo.lab"
        sport, txid = _dns_consulta(s, cursor, victima, nombre)
        falsa = cursor + float(rng.uniform(0.0003, 0.002))
        real = cursor + float(rng.uniform(0.004, 0.04))
        _dns_respuesta(s, falsa, victima, sport, txid, nombre, atacante.ip, mac, marca)
        _dns_respuesta(s, real, victima, sport, txid, nombre, s.elegir(IPS_EXTERNAS))
        cursor += float(rng.exponential(1 / tasa))
    return variante, fin


def _ataque_syn(s, t, ep, atacante, _modo) -> tuple[str, float]:
    """SYN flood con MAC fija o rotatoria; el servidor responde hasta llenar su backlog."""
    rng = s.rng
    rotatoria = bool(rng.random() < 0.4)
    variante = "mac_rotatoria" if rotatoria else "mac_fija"
    pps, dur = float(rng.uniform(50, 1200)), float(rng.uniform(4, 30))
    objetivo = s.elegir([s.web, s.archivos])
    backlog = int(rng.integers(64, 256))
    for i in range(int(pps * dur)):
        ti = t + i / pps + float(rng.uniform(0, 0.5 / pps))
        mac = s.mac_aleatoria() if rotatoria else atacante.mac
        ip_falsa = f"172.{int(rng.integers(16, 32))}.{int(rng.integers(0, 256))}.{int(rng.integers(1, 255))}"
        sp = s.puerto()
        marca = (atacante.mac, ep, "syn_flood", variante, "transporte")
        s.emitir(ti, Ether(src=mac, dst=objetivo.mac) / IP(src=ip_falsa, dst=objetivo.ip) / TCP(
            sport=sp, dport=443, flags="S", seq=int(rng.integers(1, 2**31))), marca)
        if i < backlog:
            s.emitir(ti + 0.0003, Ether(src=objetivo.mac, dst=s.gateway.mac) / IP(src=objetivo.ip, dst=ip_falsa) / TCP(
                sport=443, dport=sp, flags="SA", seq=int(rng.integers(1, 2**31)), ack=1))
    return variante, t + dur


def _ataque_scan(s, t, ep, atacante, _modo) -> tuple[str, float]:
    rng = s.rng
    lento = bool(rng.random() < 0.4)
    variante = "lento" if lento else "rapido"
    pps = float(rng.uniform(0.3, 1.5)) if lento else float(rng.uniform(20, 300))
    n = int(rng.integers(60, 300)) if lento else int(rng.integers(200, 2000))
    objetivo = s.elegir(s.victimas + [s.web, s.archivos])
    marca = (atacante.mac, ep, "port_scan", variante, "transporte")
    puertos = rng.permutation(np.arange(1, 10000))[:n]
    cursor = t
    for puerto in puertos:
        sp = s.puerto()
        s.emitir(cursor, Ether(src=atacante.mac, dst=objetivo.mac) / IP(src=atacante.ip, dst=objetivo.ip) / TCP(
            sport=sp, dport=int(puerto), flags="S"), marca)
        s.emitir(cursor + 0.0005, Ether(src=objetivo.mac, dst=atacante.mac) / IP(src=objetivo.ip, dst=atacante.ip) / TCP(
            sport=int(puerto), dport=sp, flags="RA", ack=1))
        cursor += float(rng.exponential(1 / pps))
    return variante, cursor


def _ataque_icmp(s, t, ep, atacante, _modo) -> tuple[str, float]:
    """Vector de red: inundación de echo request, con respuestas hasta saturar."""
    rng = s.rng
    pps, dur = float(rng.uniform(50, 1000)), float(rng.uniform(4, 25))
    objetivo = s.elegir(s.victimas + [s.web])
    marca = (atacante.mac, ep, "icmp_flood", "echo", "red")
    for i in range(int(pps * dur)):
        ti = t + i / pps + float(rng.uniform(0, 0.5 / pps))
        s.emitir(ti, Ether(src=atacante.mac, dst=objetivo.mac) / IP(src=atacante.ip, dst=objetivo.ip) / ICMP(
            type=8, id=int(rng.integers(1, 65535)), seq=i % 65536) / Raw(b"x" * int(rng.integers(32, 1000))), marca)
        if rng.random() < 0.5:
            s.emitir(ti + 0.0004, Ether(src=objetivo.mac, dst=atacante.mac) / IP(src=objetivo.ip, dst=atacante.ip) / ICMP(
                type=0, seq=i % 65536))
    return "echo", t + dur


ATAQUES: dict[str, tuple[Callable, str]] = {
    "mac_flooding": (_ataque_mac_flooding, "enlace"),
    "arp_spoofing": (_ataque_arp, "enlace"),
    "icmp_flood": (_ataque_icmp, "red"),
    "syn_flood": (_ataque_syn, "transporte"),
    "port_scan": (_ataque_scan, "transporte"),
    "dns_spoofing": (_ataque_dns, "aplicacion"),
}


def _programar_ataques(s: Sesion, duracion: float) -> None:
    """Inicios Poisson; los tipos se reparten por rondas barajadas para cubrirlos todos."""
    rng = s.rng
    t, ep = float(rng.exponential(ESPACIO_ENTRE_ATAQUES_S)), 0
    cola: list[str] = []
    while t < duracion:
        if not cola:
            cola = [str(x) for x in rng.permutation(list(ATAQUES))]
        tipo = cola.pop()
        generador, capa = ATAQUES[tipo]
        atacante, modo = _origen_ataque(s)
        variante, fin = generador(s, t, ep, atacante, modo)
        s.episodios.append({
            "episodio": ep, "tipo": tipo, "variante": variante, "capa": capa,
            "atacante": atacante.mac, "origen": modo, "t_inicio_s": round(t, 6), "t_fin_s": round(fin, 6),
        })
        ep += 1
        t += float(rng.exponential(ESPACIO_ENTRE_ATAQUES_S))


def generar_sesion(semilla: int) -> Sesion:
    """Construye el timeline completo de una sesión, ordenado por tiempo."""
    s = Sesion(semilla)
    for d in s.dispositivos:
        _fondo_dispositivo(s, d)
    _control_de_red(s)
    _rafagas_legitimas(s)
    _programar_ataques(s, DURACION_S)
    s.tramas.sort(key=lambda x: x[0])
    return s


def escribir_pcap(ruta: Path, tramas: list[tuple[int, bytes, Marca | None]]) -> None:
    """Escribe un pcap clásico (Ethernet, microsegundos) directamente a disco."""
    with open(ruta, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts_us, crudo, _ in tramas:
            f.write(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000, len(crudo), len(crudo)))
            f.write(crudo)


def escribir_sesion(s: Sesion, ruta_pcap: Path) -> None:
    """Persiste pcap, manifiestos y topología de la sesión."""
    ruta_pcap.parent.mkdir(parents=True, exist_ok=True)
    escribir_pcap(ruta_pcap, s.tramas)
    capas = {e["episodio"]: e for e in s.episodios}
    with open(ruta_pcap.with_suffix(".tramas.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["n_trama", "ts_us", "mac_src", "atacante", "episodio", "tipo", "variante", "capa"])
        for n, (ts_us, crudo, marca) in enumerate(s.tramas):
            if marca is None:
                continue
            mac_src = ":".join(f"{b:02x}" for b in crudo[6:12])
            _, ep, tipo, variante, capa = marca
            w.writerow([n, ts_us, mac_src, capas[ep]["atacante"], ep, tipo, variante, capa])
    campos = ["episodio", "tipo", "variante", "capa", "atacante", "origen", "t_inicio_s", "t_fin_s"]
    with open(ruta_pcap.with_suffix(".episodios.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(s.episodios)
    ruta_pcap.with_suffix(".config.json").write_text(json.dumps({
        "ip_gateway": IP_GATEWAY,
        "mac_gateway": s.gateway.mac,
        "resolvers": {IP_RESOLVER: s.resolver.mac},
    }, indent=2))
