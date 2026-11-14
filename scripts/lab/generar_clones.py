#!/usr/bin/env python3
"""
Generador propio de sesiones con clones de MAC (PEDIDO-E3A-1, bloque 3; etapa E3, OE3).

No toca `generar_trafico.py` (congelado). Sintetiza con Scapy, a pcap y sin root, sesiones
de un segmento con equipos legítimos de pila distinta y episodios de clonación:

- **ingenuo**: el atacante copia la MAC de la víctima; todo lo demás es suyo (IP, pila,
  ritmo y tamaños de trama).
- **ritmo**: copia la MAC y la IP, e imita el ritmo de conexiones y la distribución de
  longitudes de la víctima; la pila sigue siendo la suya.

La víctima sigue emitiendo durante el episodio (víctima apagada y clon de pila completa son
la parte B). Determinista: semilla `SEMILLA_BASE_CLONES + índice`.

El propósito es medir un detector **defensivo** de suplantación de identidad; los pcap
quedan en archivos locales y no se inyecta nada en ninguna interfaz.

Uso:
    python scripts/lab/generar_clones.py --sesiones 10 --dir-pcap data/pcap_clones
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

import numpy as np

_RAIZ = Path(__file__).resolve().parents[2]
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

logger = logging.getLogger("ids.lab.clones")

SEMILLA_BASE_CLONES: int = 77_000
DURACION_S: float = 900.0
N_EQUIPOS: int = 12
EPISODIOS_POR_NIVEL: int = 2
NIVELES: tuple[str, ...] = ("ingenuo", "ritmo")
INICIO_MIN_EPISODIO_S: float = 300.0  # deja construir el perfil antes del primer clon
DURACION_EPISODIO_S: tuple[float, float] = (60.0, 180.0)
MAC_GATEWAY: str = "02:00:00:00:00:01"
IP_GATEWAY: str = "10.20.0.1"
IP_RESOLVER: str = "10.20.0.2"

# Pilas de referencia (valores habituales de cada familia de sistema; aproximados).
PILAS: dict[str, dict] = {
    "linux": {"ttl": 64, "window": 64240, "opciones": [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (0, 0)),
                                                       ("NOP", None), ("WScale", 7)], "ipid": "por_flujo", "mdns": False},
    "windows": {"ttl": 128, "window": 64240, "opciones": [("MSS", 1460), ("NOP", None), ("WScale", 8), ("NOP", None),
                                                          ("NOP", None), ("SAckOK", b"")], "ipid": "global", "mdns": False},
    "macos": {"ttl": 64, "window": 65535, "opciones": [("MSS", 1460), ("NOP", None), ("WScale", 6), ("NOP", None),
                                                       ("NOP", None), ("Timestamp", (0, 0)), ("SAckOK", b"")],
              "ipid": "aleatorio", "mdns": True},
    "android": {"ttl": 64, "window": 65535, "opciones": [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (0, 0)),
                                                         ("NOP", None), ("WScale", 9)], "ipid": "cero", "mdns": True},
    "iot": {"ttl": 255, "window": 5840, "opciones": [("MSS", 536)], "ipid": "global", "mdns": True},
}


@dataclass
class Equipo:
    """Equipo emisor: identidad de enlace y red, pila y comportamiento."""

    mac: str
    ip: str
    pila: str
    conexiones_por_min: float
    longitud_media: float
    _ipid: int = 0
    _flujos: dict = field(default_factory=dict)

    def siguiente_ipid(self, rng: np.random.Generator, flujo: tuple) -> int:
        modo = PILAS[self.pila]["ipid"]
        if modo == "global":
            self._ipid = (self._ipid + 1) % 65536
            return self._ipid
        if modo == "aleatorio":
            return int(rng.integers(0, 65536))
        if modo == "cero":
            return 0
        base = self._flujos.setdefault(flujo, int(rng.integers(0, 65536)))
        self._flujos[flujo] = (base + 1) % 65536
        return self._flujos[flujo]


def _mac(rng: np.random.Generator) -> str:
    return "02:" + ":".join(f"{int(b):02x}" for b in rng.integers(0, 256, 5))


def _equipo(rng: np.random.Generator, n: int, pila: str | None = None) -> Equipo:
    return Equipo(mac=_mac(rng), ip=f"10.20.0.{20 + n}", pila=pila or str(rng.choice(list(PILAS))),
                  conexiones_por_min=float(rng.lognormal(np.log(4.0), 0.6)),
                  longitud_media=float(rng.lognormal(np.log(300.0), 0.7)), _ipid=int(rng.integers(0, 65536)))


def _conexion(paquetes: list, rng, t: float, e: Equipo, ip_src: str, mac_src: str, longitud_media: float) -> None:
    """SYN con la pila del emisor y unos segmentos de datos; el gateway responde SYN-ACK."""
    from scapy.all import IP, TCP, Ether, Raw

    pila = PILAS[e.pila]
    sport, dport = int(rng.integers(32768, 61000)), int(rng.choice([443, 80, 8443, 22]))
    flujo = (ip_src, sport, dport)
    df = "DF" if e.pila != "iot" else 0
    isn = int(rng.integers(0, 2**32))
    syn = Ether(src=mac_src, dst=MAC_GATEWAY) / IP(src=ip_src, dst="93.184.216.34", ttl=pila["ttl"],
                                                   id=e.siguiente_ipid(rng, flujo), flags=df) / TCP(
        sport=sport, dport=dport, flags="S", seq=isn, window=pila["window"], options=pila["opciones"])
    syn.time = t
    paquetes.append(syn)
    sa = Ether(src=MAC_GATEWAY, dst=mac_src) / IP(src="93.184.216.34", dst=ip_src, ttl=58, id=0, flags="DF") / TCP(
        sport=dport, dport=sport, flags="SA", seq=int(rng.integers(0, 2**32)), ack=isn + 1, window=65160,
        options=[("MSS", 1460)])
    sa.time = t + 0.012
    paquetes.append(sa)
    seq = isn + 1
    for i in range(int(rng.integers(2, 7))):
        n = int(np.clip(rng.lognormal(np.log(longitud_media), 0.4), 0, 1400))
        seg = Ether(src=mac_src, dst=MAC_GATEWAY) / IP(src=ip_src, dst="93.184.216.34", ttl=pila["ttl"],
                                                       id=e.siguiente_ipid(rng, flujo), flags=df) / TCP(
            sport=sport, dport=dport, flags="PA", seq=seq, ack=1, window=502) / Raw(b"x" * n)
        seg.time = t + 0.02 + 0.03 * i
        paquetes.append(seg)
        seq = (seq + n) % 2**32


def _dns(paquetes: list, rng, t: float, e: Equipo, ip_src: str, mac_src: str) -> None:
    from scapy.all import DNS, DNSQR, IP, UDP, Ether

    q = Ether(src=mac_src, dst=MAC_GATEWAY) / IP(src=ip_src, dst=IP_RESOLVER, ttl=PILAS[e.pila]["ttl"],
                                                 id=e.siguiente_ipid(rng, ("dns",))) / UDP(
        sport=int(rng.integers(32768, 61000)), dport=53) / DNS(id=int(rng.integers(0, 65536)), qd=DNSQR(qname="ejemplo.lab"))
    q.time = t
    paquetes.append(q)


def _mdns(paquetes: list, rng, t: float, e: Equipo, ip_src: str, mac_src: str) -> None:
    from scapy.all import IP, UDP, Ether, Raw

    m = Ether(src=mac_src, dst="01:00:5e:00:00:fb") / IP(src=ip_src, dst="224.0.0.251", ttl=255, id=0) / UDP(
        sport=5353, dport=5353) / Raw(b"m" * 40)
    m.time = t
    paquetes.append(m)


def _emitir(paquetes: list, rng, e: Equipo, desde: float, hasta: float, *, ip_src: str | None = None,
            mac_src: str | None = None, conexiones_por_min: float | None = None,
            longitud_media: float | None = None) -> None:
    """Tráfico de `e` en [desde, hasta): conexiones Poisson, DNS antes de algunas y mDNS periódico."""
    ip_src, mac_src = ip_src or e.ip, mac_src or e.mac
    tasa = (conexiones_por_min or e.conexiones_por_min) / 60.0
    longitud = longitud_media or e.longitud_media
    t = desde + float(rng.exponential(1 / tasa))
    while t < hasta:
        if rng.random() < 0.4:
            _dns(paquetes, rng, t - 0.05, e, ip_src, mac_src)
        _conexion(paquetes, rng, t, e, ip_src, mac_src, longitud)
        t += float(rng.exponential(1 / tasa))
    if PILAS[e.pila]["mdns"]:
        t = desde + float(rng.uniform(0, 30))
        while t < hasta:
            _mdns(paquetes, rng, t, e, ip_src, mac_src)
            t += float(rng.uniform(20, 40))


def generar_sesion(semilla: int) -> tuple[list, dict]:
    """Paquetes de la sesión y su manifiesto (equipos y episodios de clonación)."""
    rng = np.random.default_rng(semilla)
    equipos = [_equipo(rng, n) for n in range(N_EQUIPOS)]
    paquetes: list = []
    for e in equipos:
        _emitir(paquetes, rng, e, 0.0, DURACION_S)
    episodios = []
    huecos = np.linspace(INICIO_MIN_EPISODIO_S, DURACION_S - DURACION_EPISODIO_S[1], EPISODIOS_POR_NIVEL * len(NIVELES))
    victimas = rng.choice(len(equipos), size=len(huecos), replace=False)
    niveles = [n for n in NIVELES for _ in range(EPISODIOS_POR_NIVEL)]
    rng.shuffle(niveles)
    for k, (inicio, iv, nivel) in enumerate(zip(huecos, victimas, niveles)):
        victima = equipos[int(iv)]
        inicio = float(inicio + rng.uniform(0, 20))
        fin = inicio + float(rng.uniform(*DURACION_EPISODIO_S))
        pila_clon = str(rng.choice([p for p in PILAS if p != victima.pila]))
        atacante = _equipo(rng, 100 + k, pila=pila_clon)
        if nivel == "ingenuo":
            # Su propio ritmo (más alto que el de un equipo final) y sus propios tamaños e IP.
            _emitir(paquetes, rng, atacante, inicio, fin, mac_src=victima.mac,
                    conexiones_por_min=float(rng.uniform(15, 40)))
        else:
            _emitir(paquetes, rng, atacante, inicio, fin, mac_src=victima.mac, ip_src=victima.ip,
                    conexiones_por_min=victima.conexiones_por_min, longitud_media=victima.longitud_media)
        episodios.append({"episodio": k, "nivel": nivel, "mac_victima": victima.mac, "pila_victima": victima.pila,
                          "pila_clon": pila_clon, "inicio_s": inicio, "fin_s": fin,
                          "ip_clon": atacante.ip if nivel == "ingenuo" else victima.ip})
    paquetes.sort(key=lambda p: float(p.time))
    manifiesto = {"semilla": semilla, "duracion_s": DURACION_S,
                  "equipos": [{k: v for k, v in asdict(e).items() if not k.startswith("_")} for e in equipos],
                  "episodios": episodios}
    return paquetes, manifiesto


def escribir_sesion(paquetes: list, manifiesto: dict, ruta_pcap: Path) -> None:
    """pcap + `<nombre>.clones.json` con equipos y episodios."""
    from scapy.all import wrpcap

    ruta_pcap.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(ruta_pcap), paquetes)
    ruta_pcap.with_suffix(".clones.json").write_text(json.dumps(manifiesto, indent=2, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(description="Sesiones sintéticas con clones de MAC (ingenuo y de ritmo).")
    p.add_argument("--sesiones", type=int, default=10)
    p.add_argument("--inicio", type=int, default=0)
    p.add_argument("--dir-pcap", type=Path, default=_RAIZ / "data" / "pcap_clones")
    args = p.parse_args(argv)
    for i in range(args.inicio, args.inicio + args.sesiones):
        paquetes, manifiesto = generar_sesion(SEMILLA_BASE_CLONES + i)
        ruta = args.dir_pcap / f"clones_{i:03d}.pcap"
        escribir_sesion(paquetes, manifiesto, ruta)
        logger.info("%s: %d tramas, %d episodios", ruta.name, len(paquetes), len(manifiesto["episodios"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
