"""Pruebas del generador de clones y del evaluador de identidad (PEDIDO-E3A-1, bloque 3)."""
from __future__ import annotations

import math

from scripts import evaluar_identidad as ei
from scripts.lab import generar_clones as gc


def test_generador_determinista_y_clon_con_la_mac_de_la_victima():
    a, man_a = gc.generar_sesion(gc.SEMILLA_BASE_CLONES + 5)
    b, man_b = gc.generar_sesion(gc.SEMILLA_BASE_CLONES + 5)
    assert man_a == man_b and len(a) == len(b)
    e = man_a["episodios"][0]
    assert e["pila_victima"] != e["pila_clon"] and e["inicio_s"] >= gc.INICIO_MIN_EPISODIO_S
    # En el episodio hay tramas con la MAC de la víctima y el TTL de la pila del clon.
    ttl_clon = gc.PILAS[e["pila_clon"]]["ttl"]
    del_clon = [p for p in a if e["inicio_s"] <= float(p.time) <= e["fin_s"] and p.src == e["mac_victima"]
                and p.haslayer("IP") and p["IP"].ttl == ttl_clon and p["IP"].dst != "224.0.0.251"]
    assert del_clon
    assert sorted(x["nivel"] for x in man_a["episodios"]) == ["ingenuo", "ingenuo", "ritmo", "ritmo"]


def test_evaluar_sesion_cuenta_deteccion_latencia_y_falsas_alarmas():
    def fila(idx, alarma=False, estado="confiable"):
        return {"idx": idx, "estado_previo": estado, "estado": estado, "puntaje": 0.0, "alarma": alarma}
    seguimiento = {
        "v": [fila(i) for i in range(60, 70)] + [fila(70), fila(72, alarma=True)] + [fila(90, alarma=True)],
        "x": [fila(i, estado="no_confiable") for i in range(5)],
    }
    manifiesto = {"episodios": [{"episodio": 0, "nivel": "ingenuo", "mac_victima": "v", "pila_victima": "linux",
                                 "pila_clon": "windows", "inicio_s": 350.0, "fin_s": 400.0, "ip_clon": "x"}]}
    r = ei.evaluar_sesion("s", seguimiento, manifiesto)
    ep = r["episodios"][0]
    assert ep["detectado"] and ep["acusable"] and ep["latencia_s"] == (72 + 1) * 5 - 350.0
    disp = {d["mac"]: d for d in r["dispositivos"]}
    assert disp["v"]["falsas_alarmas"] == 1  # la ventana 90 queda fuera del episodio
    assert not disp["x"]["llego_a_confiable"]


def test_episodio_sobre_victima_no_confiable_no_es_acusable():
    seguimiento = {"v": [{"idx": 70, "estado_previo": "no_confiable", "estado": "no_confiable", "puntaje": math.nan,
                          "alarma": False}, {"idx": 71, "estado_previo": "no_confiable", "estado": "no_confiable",
                                             "puntaje": math.nan, "alarma": False}]}
    manifiesto = {"episodios": [{"episodio": 0, "nivel": "ritmo", "mac_victima": "v", "pila_victima": "iot",
                                 "pila_clon": "linux", "inicio_s": 352.0, "fin_s": 400.0, "ip_clon": "y"}]}
    ep = ei.evaluar_sesion("s", seguimiento, manifiesto)["episodios"][0]
    assert not ep["acusable"] and not ep["detectado"]
