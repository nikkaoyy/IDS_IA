#!/usr/bin/env python3
"""
Generador del timeline de laboratorio (etapa E1 del plan, OE1 y OE2).

Sintetiza una captura continua por sesión: mismo reloj, topología y fondo benigno, con
ataques en instantes Poisson. Escribe solo archivos locales (pcap, manifiestos y
topología); no toca ninguna interfaz ni requiere root. El objetivo es entrenar un IDS
defensivo, así que se generan bytes en disco, nunca tráfico emitido.

Salida para `sesion_NNN`:
    .pcap          captura ordenada por tiempo, todas las tramas >= 60 octetos
    .tramas.csv    manifiesto por trama de ataque (incluye `variante` e `intensidad`)
    .episodios.csv manifiesto por intervalo (incluye `variante` e `intensidad`)
    .config.json   gateway y resolvers declarados al IDS

Solapamiento medible (E1, bloque 3)
-----------------------------------
El generador anterior era separable con una regla de un umbral (reports/baseline_reglas.json
del 2026-10-31): todos los ataques eran ráfagas muy por encima del benigno y ninguna ráfaga
benigna se les parecía. Ahora cada episodio sortea, de forma independiente, una
**intensidad** (`PESOS_INTENSIDAD`) y una **variante** (técnica), y el benigno incluye
picos legítimos y comportamientos de red reales que activan las mismas características.

Intensidad por episodio: rafaga 25 %, media 30 %, suave 45 %. Rangos (`RANGOS_ATAQUE`;
tasa en tramas o eventos de ataque por segundo, duración en s; antes = generador anterior):

| ataque        | rafaga               | media              | suave               | antes                       |
|---------------|----------------------|--------------------|---------------------|-----------------------------|
| mac_flooding  | 100-1500 /s, 4-25    | 10-60 /s, 20-90    | 1-6 /s, 60-300      | 100-1500 /s, 4-25           |
| arp_spoofing  | 20-200 /s, 4-20      | 1-4 /s, 20-90      | 0.25-0.8 /s, 120-400| 20-200 /s 4-20 o ~1 /s 60-200|
| dns_spoofing  | 50-400 /s, 4-15      | 0.5-2 /s, 15-60    | 0.3-0.7 /s, 120-400 | 0.4-2 /s, 15-60             |
| syn_flood     | 50-1200 /s, 4-30     | 8-40 /s, 20-90     | 0.4-2.5 /s, 120-400 | 50-1200 /s, 4-30            |
| port_scan     | 20-300 /s, 200-2000 p| 0.3-1.5 /s, 60-300 p| 0.3-0.6 /s, 40-120 p| 20-300 o 0.3-1.5 /s         |
| icmp_flood    | 50-1000 /s, 4-25     | 5-30 /s, 20-90     | 0.5-2 /s, 60-300    | 50-1000 /s, 4-25            |

(port_scan: tasa en sondas/s y número de puertos `p` en lugar de duración.)

Variantes (`VARIANTES`, sorteadas por episodio con los pesos indicados):
- mac_flooding: `ether_aleatorio` (una trama por MAC falsa, como macof) o `rafaga_por_mac`
  (2-4 tramas por MAC falsa, evade el conteo de MACs de una sola trama). Solo en suave,
  50/50: con `rafaga_por_mac` cada MAC falsa es una fila, y en ráfaga o media un episodio
  daría miles. Mezcla de UDP, TCP SYN y ARP en las tramas falsas.
- arp_spoofing: método `respuesta` (is-at no solicitado, 30 %), `carrera` (contesta antes
  que el dueño a una petición real, 20 %), `peticion` (envenena con who-has falsificado,
  25 %) o `gratuito` (GARP, 25 %); objetivo `gateway` (35 %), servidor (35 %) o víctima
  (30 %). La variante es `<metodo>_<gateway|host>`. En ráfaga, `carrera` pasa a `respuesta`.
- dns_spoofing: `carrera_propia`/`carrera_clona` (compite con la respuesta real),
  `mitm_propia`/`mitm_clona` (víctima ya envenenada: solo responde el atacante; `clona`
  usa la MAC del resolver) y `kaminsky` (respuestas con txid aleatorio al resolver, solo
  en ráfaga y media).
- syn_flood: `spoof_mac_fija` (40 %), `spoof_mac_rotatoria` (25 %) o `ip_propia` (35 %).
- port_scan: `syn` (40 %), `connect` (25 %), `udp` (20 %) o `fin_xmas_null` (15 %); la
  suave recorre puertos comunes (`TOP_PUERTOS`) en orden aleatorio.
- icmp_flood: `echo` (45 %), `echo_reply` (25 %) o `unreachable` (30 %, tipo 3 código 3).

Benigno que se parece a los ataques suaves (`_rafagas_legitimas`, `_control_de_red`):
- copia de seguridad (300-1500 segmentos), actualización de software (5-30 flujos
  externos en 2-20 s), escaneo administrativo en barrido (existía) y auditoría de un
  equipo (30-300 puertos, 0.3-50 sondas/s, estilo connect);
- monitorización ICMP del NMS (60 % de sesiones, un eco por equipo cada 30-120 s) y
  ping continuo de diagnóstico (0-3 por sesión, 0.5-2 s de intervalo, 60-600 s);
- gateway en alta disponibilidad (40 % de sesiones): GARP de refresco y una conmutación
  en la que el router de respaldo reclama la IP del gateway con su MAC física;
- sondas ARP unicast de vecindad (NUD) y barridos ARP del gateway cada ~20 s;
- clientes con DNS externo (8.8.8.8, 1.1.1.1) o el reenviador del gateway, y
  retransmisiones DNS con dos respuestas por txid (3 % de consultas);
- servicios de dominio con puertos dinámicos RPC, Delivery Optimization (TCP 7680 a
  pares de la LAN, cerrado o filtrado), QUIC bloqueado con ICMP inalcanzable;
- IoT con servicio en la nube abandonado (30 % de los IoT): SYN a 8883/443 cada 10-60 s,
  con dos retransmisiones y sin respuesta;
- servidor web expuesto (50 % de sesiones): clientes de Internet y escaneo de fondo
  desde Internet (SYN medio abiertos) a través del gateway;
- rotación de MACs (0-0.03 equipos nuevos/s): DHCP, ARP gratuito y algo de tráfico
  durante 30-300 s con IPs de un grupo pequeño (`GRUPO_IPS_ROTACION`), de modo que una
  IP ya vista cambia de MAC sin ataque (BYOD con MAC privada y lease corto); y reinicio
  de punto de acceso (30 % de sesiones).

Todos los parámetros son constantes declaradas; los cambios de este bloque se hicieron
con el baseline de reglas a la vista y quedan documentados en docs/INFORME_E1.md (riesgo
"sesgo del autor" del plan).
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
DNS_EXTERNOS = ["8.8.8.8", "1.1.1.1"]
PUERTOS_DOMINIO = [88, 389, 135, 445, 636, 3268]
TOP_PUERTOS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 514, 548, 587,
    631, 636, 993, 995, 1025, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 3000, 3268, 3306, 3389,
    5000, 5060, 5222, 5432, 5900, 5985, 6379, 7680, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
    9090, 9100, 9200, 10000, 27017,
]

# Perfil -> (eventos/s en periodo activo, pesos de web, archivo, ping, arp, mdns, ntp, dominio).
PERFILES: dict[str, tuple[float, tuple[float, ...]]] = {
    "oficina": (0.35, (0.45, 0.12, 0.03, 0.12, 0.08, 0.05, 0.15)),
    "iot": (0.08, (0.15, 0.00, 0.05, 0.20, 0.30, 0.30, 0.00)),
    "impresora": (0.03, (0.00, 0.30, 0.10, 0.30, 0.30, 0.00, 0.00)),
    "voip": (0.12, (0.40, 0.00, 0.10, 0.20, 0.10, 0.20, 0.00)),
    "administracion": (0.25, (0.35, 0.20, 0.15, 0.10, 0.00, 0.05, 0.15)),
    "host_atacante": (0.10, (0.55, 0.05, 0.05, 0.15, 0.10, 0.05, 0.05)),
}
EVENTOS = ("web", "archivo", "ping", "arp", "mdns", "ntp", "dominio")

# DNS que usa cada perfil: (resolver local, DNS externo, reenviador del gateway).
PESOS_DNS: dict[str, tuple[float, float, float]] = {
    "iot": (0.4, 0.3, 0.3),
    "voip": (0.6, 0.2, 0.2),
}
PESOS_DNS_DEFECTO = (0.8, 0.15, 0.05)

INTENSIDADES = ("rafaga", "media", "suave")
PESOS_INTENSIDAD = (0.25, 0.30, 0.45)

# (tasa mín, máx) y (duración mín, máx) en s; para port_scan, (puertos mín, máx).
RANGOS_ATAQUE: dict[str, dict[str, tuple[tuple[float, float], tuple[float, float]]]] = {
    "mac_flooding": {"rafaga": ((100, 1500), (4, 25)), "media": ((10, 60), (20, 90)),
                     "suave": ((1, 6), (60, 300))},
    "arp_spoofing": {"rafaga": ((20, 200), (4, 20)), "media": ((1, 4), (20, 90)),
                     "suave": ((0.25, 0.8), (120, 400))},
    "dns_spoofing": {"rafaga": ((50, 400), (4, 15)), "media": ((0.5, 2), (15, 60)),
                     "suave": ((0.3, 0.7), (120, 400))},
    "syn_flood": {"rafaga": ((50, 1200), (4, 30)), "media": ((8, 40), (20, 90)),
                  "suave": ((0.4, 2.5), (120, 400))},
    "port_scan": {"rafaga": ((20, 300), (200, 2000)), "media": ((0.3, 1.5), (60, 300)),
                  "suave": ((0.3, 0.6), (40, 120))},
    "icmp_flood": {"rafaga": ((50, 1000), (4, 25)), "media": ((5, 30), (20, 90)),
                   "suave": ((0.5, 2), (60, 300))},
}

# Variantes por ataque e intensidad: (nombres, pesos).
VARIANTES: dict[str, dict[str, tuple[tuple[str, ...], tuple[float, ...]]]] = {
    "mac_flooding": {
        "rafaga": (("ether_aleatorio",), (1.0,)),
        "media": (("ether_aleatorio",), (1.0,)),
        "suave": (("ether_aleatorio", "rafaga_por_mac"), (0.5, 0.5)),
    },
    "arp_spoofing": {"*": (("respuesta", "carrera", "peticion", "gratuito"), (0.30, 0.20, 0.25, 0.25))},
    "dns_spoofing": {
        "rafaga": (("kaminsky", "carrera_propia", "carrera_clona"), (0.5, 0.3, 0.2)),
        "media": (("kaminsky", "carrera_propia", "carrera_clona", "mitm_propia", "mitm_clona"),
                  (0.15, 0.25, 0.15, 0.25, 0.20)),
        "suave": (("carrera_propia", "carrera_clona", "mitm_propia", "mitm_clona"),
                  (0.30, 0.15, 0.30, 0.25)),
    },
    "syn_flood": {"*": (("spoof_mac_fija", "spoof_mac_rotatoria", "ip_propia"), (0.40, 0.25, 0.35))},
    "port_scan": {"*": (("syn", "connect", "udp", "fin_xmas_null"), (0.40, 0.25, 0.20, 0.15))},
    "icmp_flood": {"*": (("echo", "echo_reply", "unreachable"), (0.45, 0.25, 0.30))},
}
PESOS_OBJETIVO_ARP = (0.35, 0.35, 0.30)  # gateway, servidor, víctima

# Configuración de red sorteada por sesión.
P_GATEWAY_HA = 0.4
P_SERVIDOR_EXPUESTO = 0.5
P_NMS = 0.6
P_REINICIO_AP = 0.3
P_DELIVERY_OPTIMIZATION = 0.4
TASA_ROTACION_MACS = (0.0, 0.03)  # MACs nuevas por segundo
GRUPO_IPS_ROTACION = [f"10.0.0.{i}" for i in range(100, 116)]
P_RETRANSMISION_DNS = 0.03
P_NUBE_MUERTA_IOT = 0.3

# Atributos de una trama de ataque: atacante, episodio, tipo, variante, capa.
Marca = tuple[str, int, str, str, str]


@dataclass
class Dispositivo:
    mac: str
    ip: str
    perfil: str
    vlan: int | None = None
    ttl: int = 64
    dns: str = IP_RESOLVER
    delivery_optimization: bool = False


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
    red: dict = field(default_factory=dict)

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
        for d in self.dispositivos:
            pesos = PESOS_DNS.get(d.perfil, PESOS_DNS_DEFECTO)
            opcion = int(self.rng.choice(3, p=pesos))
            d.dns = [IP_RESOLVER, self.elegir(DNS_EXTERNOS), IP_GATEWAY][opcion]
            d.delivery_optimization = d.perfil == "oficina" and bool(
                self.rng.random() < P_DELIVERY_OPTIMIZATION)
        self.red = {
            "gateway_ha": bool(self.rng.random() < P_GATEWAY_HA),
            "servidor_expuesto": bool(self.rng.random() < P_SERVIDOR_EXPUESTO),
            "nms": bool(self.rng.random() < P_NMS),
            "reinicio_ap": bool(self.rng.random() < P_REINICIO_AP),
            "tasa_rotacion_macs": float(self.rng.uniform(*TASA_ROTACION_MACS)),
        }

    @property
    def atacantes(self) -> list[Dispositivo]:
        return [d for d in self.dispositivos if d.perfil == "host_atacante"]

    @property
    def victimas(self) -> list[Dispositivo]:
        return [d for d in self.dispositivos if d.perfil != "host_atacante"]

    def elegir(self, opciones: list):
        return opciones[int(self.rng.integers(len(opciones)))]

    def sortear(self, nombres: tuple[str, ...], pesos: tuple[float, ...]) -> str:
        return str(nombres[int(self.rng.choice(len(nombres), p=np.array(pesos) / sum(pesos)))])

    def mac_aleatoria(self) -> str:
        cola = ":".join(f"{int(x):02x}" for x in self.rng.integers(0, 256, 3))
        return f"{self.elegir(OUIS)}:{cola}"

    def ip_externa(self) -> str:
        a = int(self.rng.choice([23, 31, 45, 62, 81, 103, 141, 177, 185, 201]))
        return f"{a}.{int(self.rng.integers(0, 256))}.{int(self.rng.integers(0, 256))}.{int(self.rng.integers(1, 255))}"

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


def _instantes(s: Sesion, t: float, tasa: float, duracion: float, regular: bool = False) -> list[float]:
    """Instantes de un proceso a `tasa` eventos/s en [t, t + duracion), sin pasar del fin.

    Regular (con fluctuación) para herramientas de inundación; Poisson para las lentas.
    Siempre devuelve al menos `t`, que está dentro de la sesión.
    """
    fin = min(t + duracion, DURACION_S)
    if regular:
        n = max(1, int(tasa * (fin - t)))
        return [t] + [t + i / tasa + float(s.rng.uniform(0, 0.5 / tasa)) for i in range(1, n)]
    instantes, cursor = [t], t + float(s.rng.exponential(1 / tasa))
    while cursor < fin:
        instantes.append(cursor)
        cursor += float(s.rng.exponential(1 / tasa))
    return instantes


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


def _servidor_dns(s: Sesion, ip_dns: str) -> Dispositivo:
    """Equipo que entrega las tramas del DNS `ip_dns`: el resolver o el gateway."""
    return s.resolver if ip_dns == IP_RESOLVER else s.gateway


def _dns_consulta(s: Sesion, t: float, cli: Dispositivo, nombre: str, ip_dns: str = IP_RESOLVER,
                  sport: int | None = None, txid: int | None = None,
                  mac_dst: str | None = None) -> tuple[int, int]:
    sport = sport if sport is not None else s.puerto()
    txid = txid if txid is not None else int(s.rng.integers(1, 65535))
    s.emitir(t, s.eth(cli, mac_dst or _servidor_dns(s, ip_dns).mac) / IP(src=cli.ip, dst=ip_dns, ttl=cli.ttl) / UDP(
        sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=nombre)))
    return sport, txid


def _dns_respuesta(s: Sesion, t: float, cli: Dispositivo, sport: int, txid: int, nombre: str,
                   rdata: str, mac_origen: str | None = None, marca: Marca | None = None,
                   ip_dns: str = IP_RESOLVER) -> None:
    """Respuesta DNS; con `mac_origen` procede de un equipo que no es el servidor."""
    pkt = Ether(src=mac_origen or _servidor_dns(s, ip_dns).mac, dst=cli.mac) / IP(
        src=ip_dns, dst=cli.ip) / UDP(sport=53, dport=sport) / DNS(
        id=txid, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=nombre),
        an=DNSRR(rrname=nombre, rdata=rdata, ttl=300))
    s.emitir(t, pkt, marca)


def _resolver_y_conectar(s: Sesion, t: float, d: Dispositivo) -> None:
    rng = s.rng
    nombre = f"srv{int(rng.integers(1, 40))}.ejemplo.lab"
    externa = bool(rng.random() < 0.7)
    ip = s.elegir(IPS_EXTERNAS) if externa else IP_WEB
    sport, txid = _dns_consulta(s, t, d, nombre, d.dns)
    if rng.random() < P_RETRANSMISION_DNS:
        # Respuesta lenta: el cliente reenvía el mismo txid y llegan dos respuestas.
        _dns_consulta(s, t + 1.0, d, nombre, d.dns, sport, txid)
        t += 1.0 + float(rng.uniform(0.01, 0.08))
        _dns_respuesta(s, t, d, sport, txid, nombre, ip, ip_dns=d.dns)
        t += float(rng.uniform(0.001, 0.03))
    else:
        t += float(rng.uniform(0.002, 0.04))
    _dns_respuesta(s, t, d, sport, txid, nombre, ip, ip_dns=d.dns)
    t += float(rng.uniform(0.001, 0.02))
    n = 1 + int(rng.geometric(0.15))
    r = float(rng.random())
    dport = int(rng.choice([443, 80, 8080], p=[0.8, 0.15, 0.05]))
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
    elif r < 0.12 and externa:  # QUIC bloqueado: el gateway devuelve inalcanzable
        sp = s.puerto()
        s.emitir(t, s.eth(d, s.gateway.mac) / IP(src=d.ip, dst=ip, ttl=d.ttl) / UDP(sport=sp, dport=443) / Raw(b"q" * 1200))
        s.emitir(t + 0.002, Ether(src=s.gateway.mac, dst=d.mac) / IP(src=IP_GATEWAY, dst=d.ip) / ICMP(
            type=3, code=13) / IP(src=d.ip, dst=ip) / UDP(sport=sp, dport=443))
        _flujo_tcp(s, t + 0.01, d, s.gateway, ip, 443, n)
    else:
        _flujo_tcp(s, t, d, s.gateway if externa else s.web, ip, dport, n)


def _arp_resolver(s: Sesion, t: float, d: Dispositivo, objetivo: Dispositivo, unicast: bool = False) -> None:
    s.emitir(t, s.eth(d, objetivo.mac if unicast else MAC_BROADCAST) / ARP(
        op=1, hwsrc=d.mac, psrc=d.ip, pdst=objetivo.ip))
    s.emitir(t + float(s.rng.uniform(0.0002, 0.003)), s.eth(objetivo, d.mac) / ARP(
        op=2, hwsrc=objetivo.mac, psrc=objetivo.ip, hwdst=d.mac, pdst=d.ip))


def _dominio(s: Sesion, t: float, d: Dispositivo) -> None:
    """Servicios de dominio (Kerberos, LDAP, RPC con puertos dinámicos) contra el servidor."""
    rng = s.rng
    for _ in range(int(rng.integers(1, 4))):
        dinamico = rng.random() < 0.35
        dport = int(rng.integers(49152, 65535)) if dinamico else int(s.elegir(PUERTOS_DOMINIO))
        t = _flujo_tcp(s, t, d, s.archivos, IP_ARCHIVOS, dport, int(rng.integers(1, 4))) + float(
            rng.exponential(0.2))


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
    elif tipo == "dominio":
        _dominio(s, t, d)


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


def _garp(s: Sesion, t: float, mac: str, ip: str, repeticiones: int) -> None:
    """Anuncio ARP gratuito (keepalived/VRRP): petición con psrc == pdst, en difusión."""
    for k in range(repeticiones):
        s.emitir(t + 0.001 * k, Ether(src=mac, dst=MAC_BROADCAST) / ARP(op=1, hwsrc=mac, psrc=ip, pdst=ip))


def _gateway_ha(s: Sesion) -> None:
    """Alta disponibilidad: refresco GARP y una conmutación al router de respaldo.

    keepalived sin `use_vmac` anuncia la IP virtual con la MAC física del nuevo maestro, así
    que durante la conmutación la IP del gateway aparece reclamada por otra MAC sin ataque.
    """
    rng = s.rng
    mac_respaldo = s.mac_aleatoria()
    inicio = float(rng.uniform(60, DURACION_S * 0.6))
    fin = inicio + float(rng.uniform(60, 300))
    t = float(rng.uniform(0, 60))
    while t < DURACION_S:
        maestro = mac_respaldo if inicio <= t < fin else s.gateway.mac
        _garp(s, t, maestro, IP_GATEWAY, int(rng.integers(1, 6)))
        t += float(rng.uniform(30, 120))
    _garp(s, inicio, mac_respaldo, IP_GATEWAY, 5)
    _garp(s, min(fin, DURACION_S - 1), s.gateway.mac, IP_GATEWAY, 5)
    # Durante la conmutación el respaldo contesta las peticiones por la IP del gateway.
    respaldo = Dispositivo(mac_respaldo, IP_GATEWAY, "infraestructura")
    for ti in _instantes(s, inicio, 0.1, fin - inicio)[1:]:
        _arp_resolver(s, ti, s.elegir(s.dispositivos), respaldo)


def _control_de_red(s: Sesion) -> None:
    """STP/LLC, LLDP, DHCP, ARP gratuito, sondas de vecindad y barridos del gateway."""
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
            _dhcp(s, t, d.mac, d.ip)
            s.emitir(t + 0.1, Ether(src=d.mac, dst=MAC_BROADCAST) / ARP(op=1, hwsrc=d.mac, psrc=d.ip, pdst=d.ip))
        # Sondas de alcanzabilidad (NUD): petición ARP unicast al gateway y su respuesta.
        periodo = float(rng.uniform(30, 120))
        for ti in _instantes(s, float(rng.uniform(0, periodo)), 1 / periodo, DURACION_S):
            _arp_resolver(s, ti, d, s.gateway, unicast=True)
    t = float(rng.exponential(20.0))
    while t < DURACION_S:
        _arp_resolver(s, t, s.gateway, s.elegir(s.dispositivos))
        t += float(rng.exponential(20.0))
    # Reemplazo de equipo: otra MAC reclama legítimamente una IP antes vista.
    ip_compartida = f"{RED}200"
    t = float(rng.uniform(60, DURACION_S / 2))
    for mac in (s.mac_aleatoria(), s.mac_aleatoria()):
        s.emitir(t, Ether(src=mac, dst=MAC_BROADCAST) / ARP(op=1, hwsrc=mac, psrc=ip_compartida, pdst=ip_compartida))
        t += float(rng.uniform(60, 300))
    if s.red["gateway_ha"]:
        _gateway_ha(s)


def _dhcp(s: Sesion, t: float, mac: str, ip: str, pasos: int = 4) -> None:
    """Intercambio DHCP (discover, offer, request, ack) de `pasos` mensajes."""
    xid = int(s.rng.integers(1, 2**31))
    secuencia = (("c", "discover"), ("s", "offer"), ("c", "request"), ("s", "ack"))[:pasos]
    for i, (origen, tipo) in enumerate(secuencia):
        if origen == "c":
            pkt = Ether(src=mac, dst=MAC_BROADCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(
                sport=68, dport=67) / BOOTP(xid=xid) / DHCP(options=[("message-type", tipo), "end"])
        else:
            pkt = Ether(src=s.gateway.mac, dst=mac) / IP(src=IP_GATEWAY, dst=ip) / UDP(
                sport=67, dport=68) / BOOTP(op=2, xid=xid, yiaddr=ip) / DHCP(options=[("message-type", tipo), "end"])
        s.emitir(t + 0.01 * i, pkt)


def _sondeo_connect(s: Sesion, t: float, origen: Dispositivo, objetivo: Dispositivo, puerto: int,
                    abiertos: set[int], marca: Marca | None = None) -> None:
    """Sonda estilo connect: handshake completo y RST si está abierto; RST del destino si no."""
    sp = s.puerto()
    s.emitir(t, s.eth(origen, objetivo.mac) / IP(src=origen.ip, dst=objetivo.ip, ttl=origen.ttl) / TCP(
        sport=sp, dport=puerto, flags="S", seq=1000), marca)
    if puerto in abiertos:
        s.emitir(t + 0.0005, s.eth(objetivo, origen.mac) / IP(src=objetivo.ip, dst=origen.ip) / TCP(
            sport=puerto, dport=sp, flags="SA", seq=5000, ack=1001))
        s.emitir(t + 0.0008, s.eth(origen, objetivo.mac) / IP(src=origen.ip, dst=objetivo.ip, ttl=origen.ttl) / TCP(
            sport=sp, dport=puerto, flags="A", seq=1001, ack=5001), marca)
        s.emitir(t + 0.0011, s.eth(origen, objetivo.mac) / IP(src=origen.ip, dst=objetivo.ip, ttl=origen.ttl) / TCP(
            sport=sp, dport=puerto, flags="RA", seq=1001, ack=5001), marca)
    else:
        s.emitir(t + 0.0005, s.eth(objetivo, origen.mac) / IP(src=objetivo.ip, dst=origen.ip) / TCP(
            sport=puerto, dport=sp, flags="RA", ack=1001))


def _puertos_abiertos(s: Sesion, objetivo: Dispositivo) -> set[int]:
    if objetivo is s.web:
        return {22, 80, 443}
    if objetivo is s.archivos:
        return {88, 135, 139, 389, 445}
    return {int(p) for p in s.rng.choice([22, 80, 443, 445, 3389, 8080, 9100], size=int(s.rng.integers(0, 3)), replace=False)}


def _eco(s: Sesion, t: float, origen: Dispositivo, objetivo: Dispositivo, ident: int, seq: int,
         carga: int = 56, marca: Marca | None = None, responde: bool = True) -> None:
    s.emitir(t, s.eth(origen, objetivo.mac) / IP(src=origen.ip, dst=objetivo.ip, ttl=origen.ttl) / ICMP(
        type=8, id=ident, seq=seq % 65536) / Raw(b"x" * carga), marca)
    if responde:
        s.emitir(t + float(s.rng.uniform(0.0002, 0.002)), s.eth(objetivo, origen.mac) / IP(
            src=objetivo.ip, dst=origen.ip) / ICMP(type=0, id=ident, seq=seq % 65536) / Raw(b"x" * carga))


def _rafagas_legitimas(s: Sesion) -> None:
    """Picos legítimos que se parecen a ataques sin serlo (ver docstring del módulo)."""
    rng = s.rng
    admin = next(d for d in s.dispositivos if d.perfil == "administracion")
    # Copias de seguridad y actualizaciones de software.
    for _ in range(int(rng.integers(1, 4))):
        d = s.elegir(s.victimas)
        _flujo_tcp(s, float(rng.uniform(0, DURACION_S)), d, s.archivos, IP_ARCHIVOS, 445,
                   int(rng.integers(300, 1500)), separacion=0.001)
    for _ in range(int(rng.integers(0, 3))):
        d, t = s.elegir(s.victimas), float(rng.uniform(0, DURACION_S - 30))
        fin = t + float(rng.uniform(2, 20))
        for _ in range(int(rng.integers(5, 31))):
            _flujo_tcp(s, float(rng.uniform(t, fin)), d, s.gateway, s.elegir(IPS_EXTERNAS + [s.ip_externa()]), 443,
                       int(rng.integers(20, 200)), separacion=0.002)
    # Escaneo administrativo en barrido (inventario).
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
    # Auditoría de un equipo: muchos puertos de un solo destino, rápida o pausada.
    for _ in range(int(rng.integers(0, 3))):
        objetivo = s.elegir([s.web, s.archivos] + s.victimas)
        if objetivo is admin:
            continue
        tasa = float(rng.uniform(2, 50)) if rng.random() < 0.5 else float(rng.uniform(0.3, 2))
        puertos = list(rng.permutation(TOP_PUERTOS))[: int(rng.integers(30, 300))]
        abiertos = _puertos_abiertos(s, objetivo)
        for ti, puerto in zip(_instantes(s, float(rng.uniform(0, DURACION_S - 60)), tasa, 1e9), puertos):
            _sondeo_connect(s, ti, admin, objetivo, int(puerto), abiertos)
    # Monitorización ICMP del NMS y pings continuos de diagnóstico.
    if s.red["nms"]:
        periodo = float(rng.uniform(30, 120))
        t = float(rng.uniform(0, periodo))
        while t < DURACION_S:
            ti = t
            for objetivo in s.dispositivos + [s.web, s.archivos, s.resolver]:
                if objetivo is not admin:
                    _eco(s, ti, admin, objetivo, int(rng.integers(1, 65535)), 0, 32)
                    ti += float(rng.uniform(0.02, 0.2))
            t += periodo
    for _ in range(int(rng.integers(0, 4))):
        d = s.elegir(s.victimas)
        objetivo = s.elegir([s.gateway, s.web, s.archivos, s.resolver])
        ident = int(rng.integers(1, 65535))
        for seq, ti in enumerate(_instantes(s, float(rng.uniform(0, DURACION_S - 60)), 1 / float(rng.uniform(0.5, 2)),
                                            float(rng.uniform(60, 600)), regular=True)):
            _eco(s, ti, d, objetivo, ident, seq)
    # Delivery Optimization: TCP 7680 a pares de la LAN, casi siempre cerrado o filtrado.
    for d in s.dispositivos:
        if not d.delivery_optimization:
            continue
        for ti in _instantes(s, float(rng.uniform(0, 120)), 1 / 120, DURACION_S):
            par, sp = s.elegir(s.victimas), s.puerto()
            if par is d:
                continue
            if rng.random() < 0.7:
                s.emitir(ti, s.eth(d, par.mac) / IP(src=d.ip, dst=par.ip, ttl=d.ttl) / TCP(sport=sp, dport=7680, flags="S"))
                s.emitir(ti + 0.0006, s.eth(par, d.mac) / IP(src=par.ip, dst=d.ip) / TCP(
                    sport=7680, dport=sp, flags="RA", ack=1))
            else:
                for k, espera in enumerate((0, 1, 3)):
                    s.emitir(ti + espera + 0.001 * k, s.eth(d, par.mac) / IP(src=d.ip, dst=par.ip, ttl=d.ttl) / TCP(
                        sport=sp, dport=7680, flags="S"))
    # IoT cuya nube ya no existe: reintenta TCP sin respuesta indefinidamente.
    for d in s.dispositivos:
        if d.perfil != "iot" or rng.random() >= P_NUBE_MUERTA_IOT:
            continue
        ip, dport = s.ip_externa(), int(rng.choice([8883, 443]))
        for ti in _instantes(s, float(rng.uniform(0, 60)), 1 / float(rng.uniform(10, 60)), DURACION_S):
            sp = s.puerto()
            for k, espera in enumerate((0, 1, 3)):
                s.emitir(ti + espera + 0.001 * k, s.eth(d, s.gateway.mac) / IP(src=d.ip, dst=ip, ttl=d.ttl) / TCP(
                    sport=sp, dport=dport, flags="S"))
    # Servidor web expuesto: clientes de Internet y escaneo de fondo vía gateway.
    if s.red["servidor_expuesto"]:
        for ti in _instantes(s, float(rng.uniform(0, 10)), float(rng.uniform(0.1, 1.0)), DURACION_S):
            cliente = Dispositivo(s.gateway.mac, s.ip_externa(), "externo", ttl=int(rng.choice([48, 52, 116])))
            _flujo_tcp(s, ti, cliente, s.web, IP_WEB, 443, 1 + int(rng.geometric(0.2)))
        for ti in _instantes(s, float(rng.uniform(0, 30)), float(rng.uniform(0.02, 0.3)), DURACION_S):
            puerto, sp, ip = int(s.elegir(TOP_PUERTOS)), s.puerto(), s.ip_externa()
            s.emitir(ti, Ether(src=s.gateway.mac, dst=s.web.mac) / IP(src=ip, dst=IP_WEB, ttl=50) / TCP(
                sport=sp, dport=puerto, flags="S"))
            flags = "SA" if puerto in (80, 443) else "RA"
            s.emitir(ti + 0.0004, Ether(src=s.web.mac, dst=s.gateway.mac) / IP(src=IP_WEB, dst=ip) / TCP(
                sport=puerto, dport=sp, flags=flags, ack=1))
    # Rotación de MACs: equipos nuevos que piden DHCP; reinicio de un punto de acceso.
    tasa = s.red["tasa_rotacion_macs"]
    if tasa > 0:
        for ti in _instantes(s, float(rng.exponential(1 / tasa)), tasa, DURACION_S)[1:]:
            _equipo_rotado(s, ti)
    if s.red["reinicio_ap"]:
        t = float(rng.uniform(0, DURACION_S - 30))
        for _ in range(int(rng.integers(8, 41))):
            _dhcp(s, t + float(rng.uniform(0, 20)), s.mac_aleatoria(), f"{RED}{int(rng.integers(100, 250))}",
                  pasos=int(rng.choice([1, 4])))


def _equipo_rotado(s: Sesion, t: float) -> None:
    """Equipo con MAC nueva: DHCP; a veces se queda, anuncia su IP y genera tráfico."""
    rng = s.rng
    mac = s.mac_aleatoria()
    if rng.random() < 0.4:  # solo sondea (una o dos tramas) y se va
        _dhcp(s, t, mac, s.elegir(GRUPO_IPS_ROTACION), pasos=int(rng.choice([1, 2])))
        return
    d = Dispositivo(mac, s.elegir(GRUPO_IPS_ROTACION), str(s.elegir(["oficina", "iot"])),
                    ttl=int(rng.choice([64, 128])))
    _dhcp(s, t, d.mac, d.ip)
    s.emitir(t + 0.1, Ether(src=d.mac, dst=MAC_BROADCAST) / ARP(op=1, hwsrc=d.mac, psrc=d.ip, pdst=d.ip))
    tasa_eventos, pesos = PERFILES[d.perfil]
    for ti in _instantes(s, t + 0.5, tasa_eventos, float(rng.uniform(30, 300)))[1:]:
        _evento(s, ti, d, str(rng.choice(EVENTOS, p=np.array(pesos) / sum(pesos))))


# ---------------------------------------------------------------- Ataques (en pcap)
def _origen_ataque(s: Sesion) -> tuple[Dispositivo, str]:
    """Host atacante reutilizado (65 %) o clon de una víctima que sigue activa (35 %)."""
    host = s.elegir(s.atacantes)
    if s.rng.random() < 0.35:
        clon = s.elegir(s.victimas)
        return Dispositivo(clon.mac, host.ip, "clon"), "clon"
    return host, "propia"


def _rango(s: Sesion, tipo: str, intensidad: str) -> tuple[float, float]:
    """Tasa y duración (o puertos) sorteadas dentro de `RANGOS_ATAQUE`."""
    (t0, t1), (d0, d1) = RANGOS_ATAQUE[tipo][intensidad]
    return float(s.rng.uniform(t0, t1)), float(s.rng.uniform(d0, d1))


def _variante(s: Sesion, tipo: str, intensidad: str) -> str:
    tabla = VARIANTES[tipo]
    return s.sortear(*tabla.get(intensidad, tabla.get("*")))


def _trama_falsa(s: Sesion, mac: str, atacante: Dispositivo):
    """Trama de inundación: UDP, TCP SYN estilo macof o ARP, con destino aleatorio."""
    r = float(s.rng.random())
    eth = Ether(src=mac, dst=s.mac_aleatoria())
    if r < 0.5:
        return eth / IP(src=atacante.ip, dst=IP_WEB) / UDP(sport=s.puerto(), dport=int(s.rng.integers(1, 65535)))
    if r < 0.8:
        ip = lambda: ".".join(str(int(x)) for x in s.rng.integers(1, 255, 4))  # noqa: E731
        return eth / IP(src=ip(), dst=ip()) / TCP(sport=s.puerto(), dport=int(s.rng.integers(1, 65535)), flags="S")
    return Ether(src=mac, dst=MAC_BROADCAST) / ARP(op=1, hwsrc=mac, psrc=f"{RED}{int(s.rng.integers(2, 254))}",
                                                   pdst=f"{RED}{int(s.rng.integers(2, 254))}")


def _ataque_mac_flooding(s, t, ep, atacante, _modo, intensidad) -> tuple[str, float]:
    rng = s.rng
    variante = _variante(s, "mac_flooding", intensidad)
    pps, dur = _rango(s, "mac_flooding", intensidad)
    marca = (atacante.mac, ep, "mac_flooding", variante, "enlace")
    instantes = _instantes(s, t, pps, dur, regular=intensidad != "suave")
    i = 0
    while i < len(instantes):
        mac = s.mac_aleatoria()
        k = 1 if variante == "ether_aleatorio" else int(rng.integers(2, 5))
        for ti in instantes[i:i + k]:
            s.emitir(ti, _trama_falsa(s, mac, atacante), marca)
        i += k
    return variante, instantes[-1]


def _objetivo_arp(s: Sesion, victima: Dispositivo) -> tuple[Dispositivo, str]:
    opcion = int(s.rng.choice(3, p=PESOS_OBJETIVO_ARP))
    if opcion == 0:
        return s.gateway, "gateway"
    if opcion == 1:
        return s.elegir([s.archivos, s.web]), "host"
    return s.elegir([v for v in s.victimas if v is not victima]), "host"


def _ataque_arp(s, t, ep, atacante, _modo, intensidad) -> tuple[str, float]:
    """Envenenamiento ARP: el atacante se hace pasar por el `dueno` de una IP ante la víctima."""
    rng = s.rng
    metodo = _variante(s, "arp_spoofing", intensidad)
    if intensidad == "rafaga" and metodo == "carrera":
        metodo = "respuesta"
    victima = s.elegir(s.victimas)
    dueno, clase = _objetivo_arp(s, victima)
    variante = f"{metodo}_{clase}"
    marca = (atacante.mac, ep, "arp_spoofing", variante, "enlace")
    tasa, dur = _rango(s, "arp_spoofing", intensidad)
    rafaga = intensidad == "rafaga"
    bidireccional = clase == "host" and rng.random() < 0.5
    instantes = _instantes(s, t, tasa, dur, regular=rafaga)
    for n, ti in enumerate(instantes):
        # En MITM entre dos equipos se alterna: a la víctima por el dueño y al dueño por la víctima.
        enganado, suplantado = (dueno, victima) if bidireccional and n % 2 else (victima, dueno)
        if metodo == "respuesta":
            dst = MAC_BROADCAST if rafaga else enganado.mac
            s.emitir(ti, Ether(src=atacante.mac, dst=dst) / ARP(
                op=2, hwsrc=atacante.mac, psrc=suplantado.ip, hwdst=enganado.mac, pdst=enganado.ip), marca)
        elif metodo == "peticion":
            dst = MAC_BROADCAST if rafaga else enganado.mac
            s.emitir(ti, Ether(src=atacante.mac, dst=dst) / ARP(
                op=1, hwsrc=atacante.mac, psrc=suplantado.ip, pdst=enganado.ip), marca)
        elif metodo == "gratuito":
            s.emitir(ti, Ether(src=atacante.mac, dst=MAC_BROADCAST) / ARP(
                op=int(rng.choice([1, 2])), hwsrc=atacante.mac, psrc=dueno.ip, hwdst=MAC_BROADCAST,
                pdst=dueno.ip), marca)
        else:  # carrera: alguien pregunta por el dueño y el atacante contesta primero
            pide = s.elegir([v for v in s.victimas if v is not dueno])
            s.emitir(ti, s.eth(pide, MAC_BROADCAST) / ARP(op=1, hwsrc=pide.mac, psrc=pide.ip, pdst=dueno.ip))
            s.emitir(ti + float(rng.uniform(0.0002, 0.001)), Ether(src=atacante.mac, dst=pide.mac) / ARP(
                op=2, hwsrc=atacante.mac, psrc=dueno.ip, hwdst=pide.mac, pdst=pide.ip), marca)
            s.emitir(ti + float(rng.uniform(0.0015, 0.005)), s.eth(dueno, pide.mac) / ARP(
                op=2, hwsrc=dueno.mac, psrc=dueno.ip, hwdst=pide.mac, pdst=pide.ip))
    return variante, instantes[-1]


def _ataque_dns(s, t, ep, atacante, _modo, intensidad) -> tuple[str, float]:
    """Respuestas DNS falsas: en carrera, tras envenenar (MITM) o por fuerza bruta de txid."""
    rng = s.rng
    variante = _variante(s, "dns_spoofing", intensidad)
    marca = (atacante.mac, ep, "dns_spoofing", variante, "aplicacion")
    tasa, dur = _rango(s, "dns_spoofing", intensidad)
    if variante == "kaminsky":
        autoritativo = s.ip_externa()
        instantes = _instantes(s, t, tasa, dur, regular=True)
        for ti in instantes:
            nombre = f"x{int(rng.integers(0, 10**6))}.banco1.ejemplo.lab"
            s.emitir(ti, Ether(src=atacante.mac, dst=s.resolver.mac) / IP(src=autoritativo, dst=IP_RESOLVER) / UDP(
                sport=53, dport=int(rng.integers(1024, 65535))) / DNS(
                id=int(rng.integers(0, 65536)), qr=1, aa=1, qd=DNSQR(qname=nombre),
                an=DNSRR(rrname=nombre, rdata=atacante.ip, ttl=86400)), marca)
        return variante, instantes[-1]
    if intensidad == "rafaga":  # carrera a ráfaga: limitada por las consultas de la víctima
        tasa = float(rng.uniform(3, 10))
    mac = s.resolver.mac if variante.endswith("clona") else atacante.mac
    victima = s.elegir(s.victimas)
    instantes = _instantes(s, t, tasa, dur)
    for ti in instantes:
        nombre = f"banco{int(rng.integers(1, 6))}.ejemplo.lab"
        if variante.startswith("carrera"):
            sport, txid = _dns_consulta(s, ti, victima, nombre)
            _dns_respuesta(s, ti + float(rng.uniform(0.0003, 0.002)), victima, sport, txid, nombre,
                           atacante.ip, mac, marca)
            _dns_respuesta(s, ti + float(rng.uniform(0.004, 0.04)), victima, sport, txid, nombre,
                           s.elegir(IPS_EXTERNAS))
        else:  # mitm: la consulta ya llega al atacante (víctima envenenada); nadie compite
            sport, txid = _dns_consulta(s, ti, victima, nombre, mac_dst=atacante.mac)
            _dns_respuesta(s, ti + float(rng.uniform(0.0005, 0.003)), victima, sport, txid, nombre,
                           atacante.ip, mac, marca)
    return variante, instantes[-1]


def _ataque_syn(s, t, ep, atacante, _modo, intensidad) -> tuple[str, float]:
    """SYN flood con IP falsa (MAC fija o rotatoria) o desde la IP propia, de ráfaga a goteo."""
    rng = s.rng
    variante = _variante(s, "syn_flood", intensidad)
    pps, dur = _rango(s, "syn_flood", intensidad)
    objetivo = s.elegir([s.web, s.archivos])
    dport = 443 if objetivo is s.web else 445
    backlog = int(rng.integers(64, 256))
    marca = (atacante.mac, ep, "syn_flood", variante, "transporte")
    instantes = _instantes(s, t, pps, dur, regular=intensidad != "suave")
    for i, ti in enumerate(instantes):
        mac = s.mac_aleatoria() if variante == "spoof_mac_rotatoria" else atacante.mac
        if variante == "ip_propia":
            ip_origen, mac_respuesta = atacante.ip, atacante.mac
        else:
            ip_origen = f"172.{int(rng.integers(16, 32))}.{int(rng.integers(0, 256))}.{int(rng.integers(1, 255))}"
            mac_respuesta = s.gateway.mac
        sp = s.puerto()
        s.emitir(ti, Ether(src=mac, dst=objetivo.mac) / IP(src=ip_origen, dst=objetivo.ip) / TCP(
            sport=sp, dport=dport, flags="S", seq=int(rng.integers(1, 2**31))), marca)
        if i < backlog or intensidad != "rafaga":
            s.emitir(ti + 0.0003, Ether(src=objetivo.mac, dst=mac_respuesta) / IP(src=objetivo.ip, dst=ip_origen) / TCP(
                sport=dport, dport=sp, flags="SA", seq=int(rng.integers(1, 2**31)), ack=1))
    return variante, instantes[-1]


def _ataque_scan(s, t, ep, atacante, _modo, intensidad) -> tuple[str, float]:
    """Escaneo de puertos SYN, connect, UDP o FIN/Xmas/Null contra un destino."""
    rng = s.rng
    variante = _variante(s, "port_scan", intensidad)
    pps, n = _rango(s, "port_scan", intensidad)
    objetivo = s.elegir(s.victimas + [s.web, s.archivos])
    abiertos = _puertos_abiertos(s, objetivo)
    marca = (atacante.mac, ep, "port_scan", variante, "transporte")
    if intensidad == "suave":
        puertos = [int(p) for p in rng.permutation(TOP_PUERTOS)][: int(n)]
    else:
        puertos = [int(p) for p in rng.permutation(np.arange(1, 10000))[: int(n)]]
    instantes = _instantes(s, t, pps, 1e9)[: len(puertos)]
    eth_a = lambda: Ether(src=atacante.mac, dst=objetivo.mac) / IP(src=atacante.ip, dst=objetivo.ip)  # noqa: E731
    eth_o = lambda: Ether(src=objetivo.mac, dst=atacante.mac) / IP(src=objetivo.ip, dst=atacante.ip)  # noqa: E731
    for ti, puerto in zip(instantes, puertos):
        sp = s.puerto()
        if variante == "connect":
            _sondeo_connect(s, ti, Dispositivo(atacante.mac, atacante.ip, "atacante"), objetivo, puerto, abiertos, marca)
        elif variante == "syn":
            s.emitir(ti, eth_a() / TCP(sport=sp, dport=puerto, flags="S"), marca)
            if puerto in abiertos:
                s.emitir(ti + 0.0005, eth_o() / TCP(sport=puerto, dport=sp, flags="SA", ack=1))
                s.emitir(ti + 0.0008, eth_a() / TCP(sport=sp, dport=puerto, flags="R", seq=1), marca)
            else:
                s.emitir(ti + 0.0005, eth_o() / TCP(sport=puerto, dport=sp, flags="RA", ack=1))
        elif variante == "udp":
            s.emitir(ti, eth_a() / UDP(sport=sp, dport=puerto), marca)
            if puerto not in abiertos and rng.random() < 0.5:  # inalcanzables limitados por tasa
                s.emitir(ti + 0.0005, eth_o() / ICMP(type=3, code=3) / IP(src=atacante.ip, dst=objetivo.ip) / UDP(
                    sport=sp, dport=puerto))
        else:
            flags = str(s.elegir(["F", "FPU", ""]))
            s.emitir(ti, eth_a() / TCP(sport=sp, dport=puerto, flags=flags), marca)
            if puerto not in abiertos:
                s.emitir(ti + 0.0005, eth_o() / TCP(sport=puerto, dport=sp, flags="RA", ack=1))
    return variante, instantes[-1]


def _ataque_icmp(s, t, ep, atacante, _modo, intensidad) -> tuple[str, float]:
    """Vector de red: eco, respuestas de eco no solicitadas o inalcanzables (BlackNurse)."""
    rng = s.rng
    variante = _variante(s, "icmp_flood", intensidad)
    pps, dur = _rango(s, "icmp_flood", intensidad)
    objetivo = s.elegir(s.victimas + [s.web])
    marca = (atacante.mac, ep, "icmp_flood", variante, "red")
    ident = int(rng.integers(1, 65535))
    instantes = _instantes(s, t, pps, dur, regular=True)
    for i, ti in enumerate(instantes):
        carga = int(rng.integers(32, 1000)) if intensidad == "rafaga" else int(rng.choice([56, 56, 32]))
        base = Ether(src=atacante.mac, dst=objetivo.mac) / IP(src=atacante.ip, dst=objetivo.ip)
        if variante == "echo":
            _eco(s, ti, atacante, objetivo, ident, i, carga, marca, responde=bool(rng.random() < 0.5))
        elif variante == "echo_reply":
            s.emitir(ti, base / ICMP(type=0, id=ident, seq=i % 65536) / Raw(b"x" * carga), marca)
        else:
            s.emitir(ti, base / ICMP(type=3, code=3) / IP(src=objetivo.ip, dst=s.ip_externa()) / UDP(
                sport=s.puerto(), dport=int(rng.integers(1, 65535))), marca)
    return variante, instantes[-1]


ATAQUES: dict[str, tuple[Callable, str]] = {
    "mac_flooding": (_ataque_mac_flooding, "enlace"),
    "arp_spoofing": (_ataque_arp, "enlace"),
    "icmp_flood": (_ataque_icmp, "red"),
    "syn_flood": (_ataque_syn, "transporte"),
    "port_scan": (_ataque_scan, "transporte"),
    "dns_spoofing": (_ataque_dns, "aplicacion"),
}


def _programar_ataques(s: Sesion, duracion: float) -> None:
    """Inicios Poisson; tipos por rondas barajadas; intensidad y variante por episodio."""
    rng = s.rng
    t, ep = float(rng.exponential(ESPACIO_ENTRE_ATAQUES_S)), 0
    cola: list[str] = []
    while t < duracion:
        if not cola:
            cola = [str(x) for x in rng.permutation(list(ATAQUES))]
        tipo = cola.pop()
        generador, capa = ATAQUES[tipo]
        atacante, modo = _origen_ataque(s)
        intensidad = s.sortear(INTENSIDADES, PESOS_INTENSIDAD)
        variante, fin = generador(s, t, ep, atacante, modo, intensidad)
        s.episodios.append({
            "episodio": ep, "tipo": tipo, "variante": variante, "intensidad": intensidad, "capa": capa,
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


CAMPOS_TRAMAS = ["n_trama", "ts_us", "mac_src", "atacante", "episodio", "tipo", "variante", "intensidad", "capa"]
CAMPOS_EPISODIOS = ["episodio", "tipo", "variante", "intensidad", "capa", "atacante", "origen",
                    "t_inicio_s", "t_fin_s"]


def escribir_sesion(s: Sesion, ruta_pcap: Path) -> None:
    """Persiste pcap, manifiestos y topología de la sesión."""
    ruta_pcap.parent.mkdir(parents=True, exist_ok=True)
    escribir_pcap(ruta_pcap, s.tramas)
    episodios = {e["episodio"]: e for e in s.episodios}
    with open(ruta_pcap.with_suffix(".tramas.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(CAMPOS_TRAMAS)
        for n, (ts_us, crudo, marca) in enumerate(s.tramas):
            if marca is None:
                continue
            mac_src = ":".join(f"{b:02x}" for b in crudo[6:12])
            _, ep, tipo, variante, capa = marca
            e = episodios[ep]
            w.writerow([n, ts_us, mac_src, e["atacante"], ep, tipo, variante, e["intensidad"], capa])
    with open(ruta_pcap.with_suffix(".episodios.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CAMPOS_EPISODIOS)
        w.writeheader()
        w.writerows(s.episodios)
    ruta_pcap.with_suffix(".config.json").write_text(json.dumps({
        "ip_gateway": IP_GATEWAY,
        "mac_gateway": s.gateway.mac,
        "resolvers": {IP_RESOLVER: s.resolver.mac},
    }, indent=2))
