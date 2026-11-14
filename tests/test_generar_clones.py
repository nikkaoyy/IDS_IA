"""Pruebas de los generadores propios de E3 (PEDIDO-E3B-1): misma semilla, mismo pcap."""
from __future__ import annotations

import hashlib

from scapy.all import rdpcap

from scripts.lab import generar_clones as gc
from scripts.lab import generar_suplantacion as gs
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


def test_suplantacion_misma_semilla_mismo_pcap_byte_a_byte(tmp_path):
    a, b = tmp_path / "a" / "s.pcap", tmp_path / "b" / "s.pcap"
    gc.escribir_sesion(*gs.generar_sesion(gs.SEMILLA_BASE_SUPLANTACION + 2), a)
    gc.escribir_sesion(*gs.generar_sesion(gs.SEMILLA_BASE_SUPLANTACION + 2), b)
    assert _sha(a) == _sha(b)


def test_cada_nivel_de_suplantacion_hace_lo_que_dice():
    paquetes, man = gs.generar_sesion(gs.SEMILLA_BASE_SUPLANTACION)
    assert sorted(e["nivel"] for e in man["episodios"]) == sorted(n for n in gs.NIVELES for _ in range(2))
    for e in man["episodios"]:
        en_ep = [p for p in paquetes if p.haslayer("IP") and e["inicio_s"] <= float(p.time) < e["fin_s"]]
        if e["nivel"] == "pila_completa":
            assert e["mac_clon"] == e["mac_victima"] and e["pila_clon"] == e["pila_victima"]
            ttl = gc.PILAS[e["pila_victima"]]["ttl"]
            assert all(p["IP"].ttl in (ttl, 255) for p in en_ep if p.src == e["mac_victima"])
        else:
            macs = {p.src for p in en_ep if p["IP"].src == e["ip_victima"]}
            assert e["mac_clon"] in macs
            if e["nivel"] == "victima_apagada":
                callada = [p for p in paquetes if p.src == e["mac_victima"]
                           and e["calla_desde_s"] <= float(p.time) < e["vuelve_s"]]
                assert not callada and e["mac_victima"] not in macs
            else:
                assert e["mac_victima"] in macs
