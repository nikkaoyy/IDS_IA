#!/usr/bin/env python3
"""
Generador de tráfico del laboratorio virtual (Fase 1 — §3.1 opción A).

Sintetiza, con Scapy, los **patrones de tráfico representativos** de cada escenario
(benigno y ataques por capa) y los escribe directamente a archivos .pcap. No inyecta
tráfico en ninguna interfaz real: todo queda confinado a archivos locales, es
reproducible con semilla fija y no requiere privilegios de root. El objetivo es
construir un conjunto de datos etiquetado para ENTRENAR un IDS defensivo, no atacar
sistemas; por eso se generan las *huellas* de los patrones, no herramientas de ataque.

Los .pcap producidos se consumen después con `scripts/pcap_to_features.py`, que los
agrega en ventanas temporales por dispositivo y extrae el contrato de características
de `src/feature_schema.py`.

Escenarios y capa del modelo TCP/IP que caracterizan (OE1):
    benigno        -> tráfico legítimo mixto (TCP/DNS/ARP/ICMP), ninguna
    arp_spoofing   -> enlace (2): respuestas ARP falsas asociando la IP del gateway a otra MAC
    mac_flooding   -> enlace (2): inundación de MACs de origen aleatorias (desborde de tabla CAM)
    syn_flood      -> transporte (4): ráfaga de SYN sin completar el handshake
    port_scan      -> transporte (4): SYN a muchos puertos destino desde un mismo origen
    dns_spoofing   -> aplicación (7): respuestas DNS forjadas

Uso:
    python scripts/lab/generar_trafico.py --escenario benigno --salida data/benigno.pcap
    python scripts/lab/generar_trafico.py --escenario syn_flood --salida data/syn.pcap --n 2000
"""
from __future__ import annotations

import argparse
import logging

logger = logging.getLogger("ids.lab.trafico")

# MAC/OUI de dispositivos "legítimos" del laboratorio (OUIs de administración local,
# bit localmente administrado activado: 02:..). Cada dispositivo tiene su propio ritmo.
DISPOSITIVOS_LEGITIMOS = {
    "02:00:00:00:00:0a": "10.0.0.10",
    "02:00:00:00:00:0b": "10.0.0.11",
    "02:00:00:00:00:0c": "10.0.0.12",
    "02:00:00:00:00:0d": "10.0.0.13",
}
MAC_GATEWAY = "02:00:00:00:00:01"
IP_GATEWAY = "10.0.0.1"
MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
MAC_ATACANTE = "02:ff:ff:ff:ff:ff"
IP_ATACANTE = "10.0.0.66"

T0 = 1_000_000.0  # timestamp base (s), determinista


def _rng(seed: int):
    import numpy as np

    return np.random.default_rng(seed)


# Separación temporal entre episodios de ataque (s). Cada episodio es una ráfaga que
# cae en su propia ventana temporal, de modo que un ataque produzca MUCHAS ventanas
# (muestras) y no una sola. Así las clases quedan balanceadas para el entrenamiento
# y la validación cruzada por grupos (Fase 3).
ESPACIADO_EPISODIO_S = 6.0


def _mac_atacante_aleatoria(rng) -> str:
    """MAC de atacante variada por episodio (bit localmente administrado, OUI aleatorio).

    Es deliberado que el OUI del atacante varíe y se solape con el rango de los
    dispositivos legítimos: así el modelo NO puede clasificar por "la MAC del malo" y
    se ve forzado a aprender la huella conductual del ataque (IAT, tasa SYN, entropía de
    puertos). Un atacante real también puede suplantar OUIs — esto lo refleja y evita la
    fuga trivial por identificador que invalidaría la evaluación (ver §3.2/§3.3).
    """
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(int(x) for x in rng.integers(0, 256, 5))


def _por_episodios(fn_burst, episodios: int, seed: int):
    """Ejecuta `fn_burst(rng, t_base, mac_atacante)` en `episodios` ventanas separadas.

    `fn_burst` devuelve la lista de paquetes de una ráfaga, tomando como referencia
    temporal `t_base` y la MAC de atacante del episodio. Cada episodio arranca
    `ESPACIADO_EPISODIO_S` después del anterior y usa una MAC/OUI distinta.
    """
    rng = _rng(seed)
    paquetes = []
    for e in range(episodios):
        t_base = T0 + e * ESPACIADO_EPISODIO_S
        mac_atacante = _mac_atacante_aleatoria(rng)
        paquetes.extend(fn_burst(rng, t_base, mac_atacante))
    return paquetes


def gen_benigno(n: int, seed: int):
    """Tráfico legítimo mixto: handshakes TCP completos, DNS, ARP e ICMP periódicos.

    Cada dispositivo mantiene un ritmo propio (IAT) para que su huella temporal 802.3
    sea distinguible — base del fingerprinting pasivo.
    """
    from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, TCP, UDP

    rng = _rng(seed)
    macs = list(DISPOSITIVOS_LEGITIMOS)
    paquetes = []
    t = T0
    for _ in range(n):
        mac = macs[rng.integers(0, len(macs))]
        ip = DISPOSITIVOS_LEGITIMOS[mac]
        ritmo = 0.05 + 0.2 * (macs.index(mac) + 1)  # IAT característico por dispositivo
        t += float(rng.exponential(ritmo))
        clase = rng.random()
        if clase < 0.55:  # TCP: handshake (SYN, SYN-ACK, ACK) a puerto de servicio
            dport = int(rng.choice([80, 443, 22, 53]))
            for flags in ("S", "SA", "A"):
                pkt = Ether(src=mac, dst=MAC_GATEWAY) / IP(src=ip, dst=IP_GATEWAY) / TCP(
                    sport=int(rng.integers(1024, 65535)), dport=dport, flags=flags
                )
                pkt.time = t
                paquetes.append(pkt)
        elif clase < 0.8:  # DNS: consulta legítima
            pkt = Ether(src=mac, dst=MAC_GATEWAY) / IP(src=ip, dst=IP_GATEWAY) / UDP(
                sport=int(rng.integers(1024, 65535)), dport=53
            ) / DNS(rd=1, qd=DNSQR(qname="servicio.lab.local"))
            pkt.time = t
            paquetes.append(pkt)
        elif clase < 0.92:  # ICMP echo (ping)
            pkt = Ether(src=mac, dst=MAC_GATEWAY) / IP(src=ip, dst=IP_GATEWAY) / ICMP()
            pkt.time = t
            paquetes.append(pkt)
        else:  # ARP: resolución normal (broadcast)
            pkt = Ether(src=mac, dst=MAC_BROADCAST) / ARP(psrc=ip, pdst=IP_GATEWAY)
            pkt.time = t
            paquetes.append(pkt)
    return paquetes


def gen_arp_spoofing(n: int, seed: int):
    """Capa 2: respuestas ARP no solicitadas asociando la IP del gateway a la MAC del atacante.

    Huella: alta tasa ARP, tramas ARP tipo 'is-at' repetidas desde una sola MAC.
    `n` = número de episodios (ventanas); cada episodio es una ráfaga de ~30-60 tramas.
    """
    from scapy.all import ARP, Ether

    def burst(rng, t_base, mac_atacante):
        pk = []
        t = t_base
        for _ in range(int(rng.integers(30, 60))):
            t += float(rng.exponential(0.02))  # ráfaga: IAT muy bajo
            pkt = Ether(src=mac_atacante, dst=MAC_BROADCAST) / ARP(
                op=2, psrc=IP_GATEWAY, hwsrc=mac_atacante, pdst="10.0.0.255"
            )
            pkt.time = t
            pk.append(pkt)
        return pk

    return _por_episodios(burst, n, seed)


def gen_mac_flooding(n: int, seed: int):
    """Capa 2: inundación con MACs de origen aleatorias (patrón de desborde de tabla CAM).

    Huella: cardinalidad de OUIs/MAC explosiva, tramas broadcast de orígenes efímeros.
    Para que la inundación quede en UNA ventana (y no genere una por MAC), todas las
    MACs aleatorias del episodio se atribuyen a un mismo "origen lógico" vía la MAC del
    atacante en Ethernet, variando el OUI anunciado en el ARP interno.
    """
    from scapy.all import ARP, Ether

    def burst(rng, t_base, mac_atacante):
        pk = []
        t = t_base
        for _ in range(int(rng.integers(80, 150))):
            t += float(rng.exponential(0.005))
            mac_aleatoria = "02:%02x:%02x:%02x:%02x:%02x" % tuple(int(x) for x in rng.integers(0, 256, 5))
            # Ethernet.src = MAC del atacante (agrupa el episodio); el flood se ve en
            # el hwsrc del ARP, que varía en cada trama (desborde de CAM anunciado).
            pkt = Ether(src=mac_atacante, dst=MAC_BROADCAST) / ARP(
                op=1, hwsrc=mac_aleatoria, psrc="10.0.0.%d" % rng.integers(2, 254), pdst=IP_GATEWAY
            )
            pkt.time = t
            pk.append(pkt)
        return pk

    return _por_episodios(burst, n, seed)


def gen_syn_flood(n: int, seed: int):
    """Capa 4: ráfaga de SYN a un puerto, sin completar el handshake (sin ACK).

    Huella: tasa_syn ~1.0, IAT mínimo, un solo puerto destino (baja entropía de puertos).
    """
    from scapy.all import Ether, IP, TCP

    def burst(rng, t_base, mac_atacante):
        pk = []
        t = t_base
        for _ in range(int(rng.integers(100, 200))):
            t += float(rng.exponential(0.003))
            src_ip = "10.0.0.%d" % rng.integers(2, 254)  # orígenes variados
            pkt = Ether(src=mac_atacante, dst=MAC_GATEWAY) / IP(src=src_ip, dst=IP_GATEWAY) / TCP(
                sport=int(rng.integers(1024, 65535)), dport=80, flags="S"
            )
            pkt.time = t
            pk.append(pkt)
        return pk

    return _por_episodios(burst, n, seed)


def gen_port_scan(n: int, seed: int):
    """Capa 4: SYN a muchos puertos destino desde un mismo origen.

    Huella: alta entropía de puertos destino, tasa_syn alta, una sola MAC de origen.
    """
    from scapy.all import Ether, IP, TCP

    def burst(rng, t_base, mac_atacante):
        pk = []
        t = t_base
        puerto = int(rng.integers(1, 1000))
        for _ in range(int(rng.integers(60, 120))):
            t += float(rng.exponential(0.01))
            puerto = (puerto + int(rng.integers(1, 7))) % 65535 + 1
            pkt = Ether(src=mac_atacante, dst=MAC_GATEWAY) / IP(src=IP_ATACANTE, dst=IP_GATEWAY) / TCP(
                sport=int(rng.integers(1024, 65535)), dport=puerto, flags="S"
            )
            pkt.time = t
            pk.append(pkt)
        return pk

    return _por_episodios(burst, n, seed)


def gen_dns_spoofing(n: int, seed: int):
    """Capa 7: respuestas DNS forjadas (resolución apuntada a la IP del atacante).

    Huella: tráfico UDP/53 de respuestas no solicitadas desde la MAC del atacante.
    """
    from scapy.all import DNS, DNSRR, Ether, IP, UDP

    def burst(rng, t_base, mac_atacante):
        pk = []
        t = t_base
        for _ in range(int(rng.integers(40, 80))):
            t += float(rng.exponential(0.03))
            pkt = Ether(src=mac_atacante, dst=MAC_GATEWAY) / IP(
                src=IP_GATEWAY, dst="10.0.0.%d" % rng.integers(2, 254)
            ) / UDP(sport=53, dport=int(rng.integers(1024, 65535))) / DNS(
                qr=1, an=DNSRR(rrname="servicio.lab.local", rdata=IP_ATACANTE)
            )
            pkt.time = t
            pk.append(pkt)
        return pk

    return _por_episodios(burst, n, seed)


ESCENARIOS = {
    "benigno": (gen_benigno, 0, "ninguna"),
    "arp_spoofing": (gen_arp_spoofing, 1, "enlace"),
    "mac_flooding": (gen_mac_flooding, 1, "enlace"),
    "syn_flood": (gen_syn_flood, 1, "transporte"),
    "port_scan": (gen_port_scan, 1, "transporte"),
    "dns_spoofing": (gen_dns_spoofing, 1, "aplicacion"),
}


def generar(escenario: str, n: int, seed: int):
    """Devuelve (paquetes, etiqueta, capa) para un escenario dado."""
    if escenario not in ESCENARIOS:
        raise ValueError(f"Escenario desconocido: {escenario}. Opciones: {sorted(ESCENARIOS)}")
    fn, etiqueta, capa = ESCENARIOS[escenario]
    return fn(n, seed), etiqueta, capa


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(description="Genera .pcap sintético por escenario (lab virtual).")
    p.add_argument("--escenario", required=True, choices=sorted(ESCENARIOS))
    p.add_argument("--n", type=int, default=1000, help="Número de eventos a generar.")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--salida", required=True, help="Ruta del .pcap de salida.")
    args = p.parse_args(argv)

    from pathlib import Path

    from scapy.all import wrpcap

    paquetes, etiqueta, capa = generar(args.escenario, args.n, args.seed)
    Path(args.salida).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(args.salida, paquetes)
    logger.info(
        "Escenario '%s': %d tramas -> %s (etiqueta=%d, capa=%s)",
        args.escenario,
        len(paquetes),
        args.salida,
        etiqueta,
        capa,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
