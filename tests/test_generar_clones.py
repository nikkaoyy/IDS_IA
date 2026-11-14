"""Pruebas de los generadores propios de E3 (PEDIDO-E3B-1): misma semilla, mismo pcap."""
from __future__ import annotations

import hashlib

from scapy.all import rdpcap

from scripts.lab import generar_clones as gc
from scripts.lab import generar_contaminacion as gco
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


def test_contaminacion_misma_semilla_mismo_pcap_byte_a_byte(tmp_path):
    a, b = tmp_path / "a" / "c.pcap", tmp_path / "b" / "c.pcap"
    gc.escribir_sesion(*gco.generar_sesion(gco.SEMILLA_BASE_CONTAMINACION + 5), a)
    gc.escribir_sesion(*gco.generar_sesion(gco.SEMILLA_BASE_CONTAMINACION + 5), b)
    assert _sha(a) == _sha(b)


def test_cada_condicion_de_contaminacion_pone_sus_rafagas():
    paquetes, man = gco.generar_sesion(gco.SEMILLA_BASE_CONTAMINACION)
    principales = [e for e in man["episodios"] if not e["nivel"].startswith("rafaga_")]
    assert sorted(e["nivel"] for e in principales) == sorted(c for c in gco.CONDICIONES for _ in range(gco.POR_CONDICION))
    for e in principales:
        fraccion, desde = gco.CONDICIONES[e["nivel"]]
        n = int(round(fraccion * (gco.FIN_APRENDIZAJE_S - desde) / gco.VENTANA_S))
        assert len(e["ventanas_contaminadas"]) == n
        assert all(desde <= w * gco.VENTANA_S < gco.FIN_APRENDIZAJE_S for w in e["ventanas_contaminadas"])
        ttl_clon = gc.PILAS[e["pila_clon"]]["ttl"]
        for w in e["ventanas_contaminadas"]:
            en_w = [p for p in paquetes if p.src == e["mac_victima"] and p.haslayer("TCP") and p["TCP"].flags == "S"
                    and w * gco.VENTANA_S <= float(p.time) < (w + 1) * gco.VENTANA_S]
            assert any(p["IP"].ttl == ttl_clon and p["TCP"].window == gc.PILAS[e["pila_clon"]]["window"] for p in en_w)
