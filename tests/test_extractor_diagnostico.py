"""Pruebas del diagnóstico del extractor (PEDIDO-EXTRACTOR-1, iteración 0)."""
from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Dot1Q, Ether

from scripts import extractor_diagnostico as dx
from tests.test_evaluacion import _dataset


def test_clasifica_tramas_por_protocolo():
    e = Ether(src="00:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
    assert dx.clasificar(bytes(e / ARP(op=2)))[0] == "arp/op2"
    assert dx.clasificar(bytes(e / Dot1Q(vlan=5) / ARP(op=1)))[0] == "arp/op1"
    clase, ttl, hl, win = dx.clasificar(bytes(e / IP(ttl=77) / TCP(flags="S", window=1234)))
    assert (clase, ttl, hl, win) == ("tcp/S", 77, 20, 1234)
    assert dx.clasificar(bytes(e / IP() / TCP(flags=0)))[0] == "tcp/nulo"
    assert dx.clasificar(bytes(e / IP() / TCP(flags="FPU")))[0] == "tcp/FPU"
    assert dx.clasificar(bytes(e / IP() / ICMP(type=3)))[0] == "icmp/3"
    assert dx.clasificar(bytes(e / IP() / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="a.b"))))[0] \
        == "udp/dns-consulta"
    assert dx.clasificar(bytes(e / IP() / UDP(sport=53, dport=40000) / DNS(qr=1)))[0] == "udp/dns-respuesta"
    assert dx.clasificar(b"\x00" * 10)[0] == "corta"


def test_la_separacion_pone_primero_la_caracteristica_con_senal():
    sep = dx.separacion(_dataset(n_sesiones=2, senal=True))
    for d in sep.values():
        assert d["caracteristicas"][0]["caracteristica"] == "n_syn"
        assert d["caracteristicas"][0]["auc"] == 1.0


def test_todos_los_top_tienen_juicio():
    """Cada característica del top del dataset real tiene juicio escrito (no «sin_juicio»)."""
    import json
    from pathlib import Path
    ruta = Path(__file__).resolve().parent.parent / "reports" / "extractor_diagnostico.json"
    top = json.loads(ruta.read_text())["top_por_ataque"]
    assert len(top) == 6
    assert all(f["depende_de_herramienta"] in {"sí", "no", "mixta"} and f["motivo"]
               for filas in top.values() for f in filas)
