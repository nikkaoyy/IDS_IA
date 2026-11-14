"""Pruebas de los generadores propios de E3 (PEDIDO-E3B-1): misma semilla, mismo pcap."""
from __future__ import annotations

import hashlib

from scapy.all import rdpcap

from scripts.lab import generar_clones as gc
from scripts.lab import generar_variacion as gv


def _sha(ruta) -> str:
    return hashlib.sha256(ruta.read_bytes()).hexdigest()


def test_variacion_misma_semilla_mismo_pcap_byte_a_byte(tmp_path):
    a, b = tmp_path / "a" / "v.pcap", tmp_path / "b" / "v.pcap"
    gc.escribir_sesion(*gv.generar_sesion(gv.SEMILLA_BASE_VARIACION + 3), a)
    gc.escribir_sesion(*gv.generar_sesion(gv.SEMILLA_BASE_VARIACION + 3), b)
    assert _sha(a) == _sha(b)
    assert a.with_suffix(".clones.json").read_bytes() == b.with_suffix(".clones.json").read_bytes()
    otra = tmp_path / "c" / "v.pcap"
    gc.escribir_sesion(*gv.generar_sesion(gv.SEMILLA_BASE_VARIACION + 4), otra)
    assert _sha(otra) != _sha(a)


def test_clones_misma_semilla_mismo_pcap_byte_a_byte(tmp_path):
    a, b = tmp_path / "a" / "c.pcap", tmp_path / "b" / "c.pcap"
    gc.escribir_sesion(*gc.generar_sesion(gc.SEMILLA_BASE_CLONES + 1), a)
    gc.escribir_sesion(*gc.generar_sesion(gc.SEMILLA_BASE_CLONES + 1), b)
    assert _sha(a) == _sha(b)


def test_cada_variacion_aparece_en_el_pcap(tmp_path):
    ruta = tmp_path / "v.pcap"
    paquetes, man = gv.generar_sesion(gv.SEMILLA_BASE_VARIACION)
    gc.escribir_sesion(paquetes, man, ruta)
    tipos = [e["variacion"] for e in man["equipos"]]
    assert sorted(set(tipos)) == sorted(set(gv.TIPOS) | {"control"}) and tipos.count("control") == gv.CONTROLES
    pkts = rdpcap(str(ruta))
    por_mac: dict[str, set] = {}
    for p in pkts:
        if p.haslayer("IP"):
            por_mac.setdefault(p.src, set()).add(p["IP"].ttl)
    for e in man["equipos"]:
        ttls = por_mac[e["mac"]]
        if e["variacion"] == "actualizacion":
            assert set(e["detalle"]["ttl"]) <= ttls
        if e["variacion"] == "vpn":
            assert e["detalle"]["ttl"][1] in ttls
        if e["variacion"] == "descubrimiento":
            assert gv.TTL_SSDP in ttls
        if e["variacion"] == "dos_pilas" and gc.PILAS[e["detalle"]["segunda_pila"]]["ttl"] != gc.PILAS[e["pila"]]["ttl"]:
            assert gc.PILAS[e["detalle"]["segunda_pila"]]["ttl"] in ttls
