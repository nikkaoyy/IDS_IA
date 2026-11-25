#!/usr/bin/env python3
"""
Verificador del pcap de demostración (entrega, bloque 3; Fig. 1 «Captura» → «Huella IEEE 802.3»).

Lee `data/pcap/demo/sesion_demo.pcap` con Scapy e imprime, con su valor real, los campos que
muestra Wireshark y que usa el proyecto: MAC origen/destino, OUI, ethertype, VLAN 802.1Q y LLC
(802.3 con longitud) y STP si los hay, IP origen/destino, IP-ID, TTL, protocolo, puertos, ventana y
opciones TCP, ARP (op, hwsrc/psrc) y DNS (txid, qname). Termina con
`N tramas, M flujos, tipos: ...`.

Si junto al pcap están `.tramas.csv` y `.clones.json`, imprime además las tramas del episodio de
ataque y las pilas que se ven bajo la MAC clonada.

Sale con código 1 si el pcap no trae ARP, TCP con opciones o al menos un cambio de IP-ID entre
dos tramas IPv4 consecutivas del mismo emisor (par MAC de origen, IP de origen; la IP sola no
basta porque los dos generadores usan la misma IP externa 93.184.216.34).

Uso:
    python scripts/verificar_demo_pcap.py [--pcap data/pcap/demo/sesion_demo.pcap] [--ejemplos 3]
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import ARP, DNS, IP, LLC, STP, TCP, UDP, Dot1Q, Dot3, Ether, PcapReader

_RAIZ = Path(__file__).resolve().parent.parent
PCAP_DEMO: Path = _RAIZ / "data" / "pcap" / "demo" / "sesion_demo.pcap"
ETHERTYPES: dict[int, str] = {0x0800: "IPv4", 0x0806: "ARP", 0x8100: "802.1Q", 0x86DD: "IPv6",
                              0x88CC: "LLDP"}
T0_S: float = 1_000_000.0  # reloj sintético del generador: 1e12 µs + segundo de sesión


def _nombre_tipo(tipo: int) -> str:
    if tipo <= 1500:
        return f"longitud {tipo} (802.3/LLC)"
    return f"0x{tipo:04x} ({ETHERTYPES.get(tipo, '?')})"


def _enlace(pkt):
    """Cabecera de enlace: Ethernet II (`Ether`) o IEEE 802.3 con longitud (`Dot3`, así la
    disecciona Scapy cuando el campo vale ≤ 1500)."""
    return pkt[Ether] if Ether in pkt else pkt[Dot3] if Dot3 in pkt else None


def _ethertype(pkt) -> str:
    """Ethertype de la trama; con 802.1Q, el exterior y el interior; `802.3/LLC` si es longitud."""
    if Dot3 in pkt and Ether not in pkt:
        return _nombre_tipo(pkt[Dot3].len)
    if Dot1Q in pkt:
        return f"{_nombre_tipo(pkt[Ether].type)} -> {_nombre_tipo(pkt[Dot1Q].type)}"
    return _nombre_tipo(pkt[Ether].type)


def _tipo(pkt) -> str:
    if ARP in pkt:
        return "ARP"
    if LLC in pkt:
        return "LLC/STP" if STP in pkt else "LLC"
    if DNS in pkt:
        return "DNS"
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if IP in pkt:
        return {1: "ICMP"}.get(pkt[IP].proto, f"IP/{pkt[IP].proto}")
    if Ether in pkt and pkt[Ether].type == 0x88CC:
        return "LLDP"
    return "otro"


def describir(n: int, pkt) -> str:
    """Una línea con los campos de Wireshark que usa el proyecto, con su valor real."""
    e = _enlace(pkt)
    partes = [f"#{n} t={float(pkt.time):.6f}", f"mac {e.src} -> {e.dst}", f"oui {e.src[:8]}",
              f"ethertype {_ethertype(pkt)}"]
    if Dot1Q in pkt:
        partes.append(f"vlan {pkt[Dot1Q].vlan}")
    if LLC in pkt:
        partes.append(f"llc dsap=0x{pkt[LLC].dsap:02x} ssap=0x{pkt[LLC].ssap:02x}")
    if STP in pkt:
        partes.append(f"stp raiz={pkt[STP].rootmac} puente={pkt[STP].bridgemac}")
    if ARP in pkt:
        a = pkt[ARP]
        partes.append(f"arp op={a.op} ({'who-has' if a.op == 1 else 'is-at'}) hwsrc={a.hwsrc} psrc={a.psrc} "
                      f"hwdst={a.hwdst} pdst={a.pdst}")
    if IP in pkt:
        ip = pkt[IP]
        partes.append(f"ip {ip.src} -> {ip.dst} id={ip.id} ttl={ip.ttl} proto={ip.proto} flags={ip.flags}")
    if TCP in pkt:
        t = pkt[TCP]
        partes.append(f"tcp {t.sport} -> {t.dport} flags={t.flags} window={t.window} opciones={t.options}")
    elif UDP in pkt:
        partes.append(f"udp {pkt[UDP].sport} -> {pkt[UDP].dport}")
    if DNS in pkt:
        d = pkt[DNS]
        qname = d.qd.qname.decode(errors="replace") if d.qd is not None else "-"
        partes.append(f"dns txid=0x{d.id:04x} qr={d.qr} qname={qname}")
    return " | ".join(partes)


def _manifiestos(ruta: Path) -> tuple[set[int], dict | None]:
    """Índices (base 0) de tramas de ataque de `.tramas.csv` y el episodio de `.clones.json`."""
    import csv
    import json

    ataque: set[int] = set()
    ruta_tramas = ruta.with_suffix(".tramas.csv")
    if ruta_tramas.exists():
        with open(ruta_tramas, newline="") as f:
            ataque = {int(fila["n_trama"]) for fila in csv.DictReader(f)}
    ruta_clones = ruta.with_suffix(".clones.json")
    clon = None
    if ruta_clones.exists():
        episodios = json.loads(ruta_clones.read_text()).get("episodios", [])
        clon = episodios[0] if episodios else None
    return ataque, clon


def verificar(ruta: Path, ejemplos: int = 3) -> int:
    """Recorre el pcap, imprime ejemplos y estadísticos por campo; 0 si cumple, 1 si no."""
    if not ruta.exists():
        print(f"ERROR: no existe {ruta}")
        return 1
    tipos: Counter = Counter()
    vistos: Counter = Counter()
    flujos: set = set()
    ethertypes: Counter = Counter()
    ttls: Counter = Counter()
    ventanas: Counter = Counter()
    firmas_opciones: Counter = Counter()
    vlans: Counter = Counter()
    arp_ops: Counter = Counter()
    macs: set = set()
    ultimo_ipid: dict[tuple[str, str], int] = {}
    ipids_por_origen: dict[tuple[str, str], set] = defaultdict(set)
    ataque, clon = _manifiestos(ruta)
    tramas_ataque: list[str] = []
    pilas_mac_clonada: dict[str, Counter] = {"antes": Counter(), "durante": Counter()}
    cambios_ipid = 0
    ejemplo_cambio = None
    tcp_con_opciones = 0
    n = 0
    print(f"== Ejemplos por tipo de trama ({ejemplos} de cada uno) ==")
    with PcapReader(str(ruta)) as lector:
        for n, pkt in enumerate(lector, start=1):
            enlace = _enlace(pkt)
            if enlace is None:
                continue
            tipo = _tipo(pkt)
            tipos[tipo] += 1
            macs.add(enlace.src)
            ethertypes[_ethertype(pkt)] += 1
            es_opciones = TCP in pkt and bool(pkt[TCP].options)
            # Ejemplos: por tipo, más los de TCP con opciones (señal del canal de identidad).
            clave = "TCP+opciones" if es_opciones else tipo
            if vistos[clave] < ejemplos:
                vistos[clave] += 1
                print(f"[{clave}] {describir(n, pkt)}")
            if Dot1Q in pkt:
                vlans[pkt[Dot1Q].vlan] += 1
            if ARP in pkt:
                arp_ops[pkt[ARP].op] += 1
            if IP in pkt:
                ip = pkt[IP]
                ttls[ip.ttl] += 1
                emisor = (enlace.src, ip.src)
                ipids_por_origen[emisor].add(ip.id)
                previo = ultimo_ipid.get(emisor)
                if previo is not None and previo != ip.id:
                    cambios_ipid += 1
                    if ejemplo_cambio is None:
                        ejemplo_cambio = (n, *emisor, previo, ip.id)
                ultimo_ipid[emisor] = ip.id
                capa4 = TCP if TCP in pkt else UDP if UDP in pkt else None
                if capa4 is not None:
                    flujos.add((ip.src, ip.dst, ip.proto, pkt[capa4].sport, pkt[capa4].dport))
            if n - 1 in ataque and len(tramas_ataque) < ejemplos:
                tramas_ataque.append(describir(n, pkt))
            if clon and enlace.src == clon["mac_victima"] and TCP in pkt and pkt[TCP].flags == "S":
                t = float(pkt.time) - T0_S
                fase = "durante" if clon["inicio_s"] <= t <= clon["fin_s"] else "antes" if t < clon["inicio_s"] else ""
                if fase:
                    firma = ",".join(str(o[0]) for o in pkt[TCP].options)
                    pilas_mac_clonada[fase][f"ip={pkt[IP].src} ttl={pkt[IP].ttl} window={pkt[TCP].window} "
                                            f"opciones={firma}"] += 1
            if TCP in pkt:
                ventanas[pkt[TCP].window] += 1
                if es_opciones:
                    tcp_con_opciones += 1
                    firmas_opciones[",".join(str(o[0]) for o in pkt[TCP].options)] += 1

    print("\n== Campos agregados ==")
    print(f"MACs de origen distintas: {len(macs)}  |  OUIs: {sorted({m[:8] for m in macs})}")
    print(f"ethertypes: {dict(ethertypes.most_common())}")
    print(f"VLAN 802.1Q: {dict(vlans) or 'ninguna'}")
    print(f"ARP por op (1=who-has, 2=is-at): {dict(arp_ops)}")
    print(f"TTL: {dict(ttls.most_common())}")
    print(f"ventana TCP (top 8): {dict(ventanas.most_common(8))}")
    print(f"TCP con opciones: {tcp_con_opciones}  |  firmas: {dict(firmas_opciones.most_common())}")
    constantes = sum(1 for v in ipids_por_origen.values() if len(v) == 1)
    print(f"IP-ID: {cambios_ipid} cambios entre tramas consecutivas del mismo emisor (MAC, IP); "
          f"{constantes} de {len(ipids_por_origen)} emisores IPv4 con IP-ID constante")
    if ejemplo_cambio:
        print("  primer cambio: trama #{} emisor {} / {} id {} -> {}".format(*ejemplo_cambio))
    if ataque:
        print(f"\n== Episodio de ataque del catálogo ({len(ataque)} tramas en .tramas.csv); primeras ==")
        for linea in tramas_ataque:
            print(linea)
    if clon:
        print(f"\n== Clon de MAC ({clon['nivel']}, víctima {clon['mac_victima']}, pila {clon['pila_victima']} "
              f"-> clon {clon['pila_clon']}, {clon['inicio_s']:.1f}-{clon['fin_s']:.1f} s): SYN bajo esa MAC ==")
        for fase in ("antes", "durante"):
            print(f"  {fase} {'del' if fase == 'antes' else 'el'} episodio: {dict(pilas_mac_clonada[fase])}")

    fallos = []
    if not tipos["ARP"]:
        fallos.append("no hay tramas ARP")
    if not tcp_con_opciones:
        fallos.append("no hay TCP con opciones")
    if not cambios_ipid:
        fallos.append("no hay ningún cambio de IP-ID")
    resumen = ", ".join(f"{k} {v}" for k, v in tipos.most_common())
    print(f"\n{n} tramas, {len(flujos)} flujos, tipos: {resumen}")
    if fallos:
        print("FALLO: " + "; ".join(fallos))
        return 1
    print("OK: el pcap trae ARP, TCP con opciones y cambios de IP-ID")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Verifica e imprime los campos del pcap de demostración.")
    p.add_argument("--pcap", type=Path, default=PCAP_DEMO)
    p.add_argument("--ejemplos", type=int, default=3, help="Tramas de ejemplo por tipo.")
    args = p.parse_args(argv)
    return verificar(args.pcap, args.ejemplos)


if __name__ == "__main__":
    sys.exit(main())
