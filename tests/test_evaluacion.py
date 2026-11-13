"""Pruebas de la evaluación por episodio y por dispositivo (etapa E2, bloque 1)."""
from __future__ import annotations

import math

import numpy as np
import pandas as pd
import pytest

from src import evaluacion as ev
from src.data import HoldoutError, nombre_sesion
from src.feature_schema import COLUMNAS_MODELO, ETIQUETA

DISPOSITIVOS, VENTANAS, EPISODIOS, DURACION_EP = 6, 40, 3, 4


def _dataset(n_sesiones: int = 8, senal: bool = True, semilla: int = 0) -> pd.DataFrame:
    """Sesiones sintéticas: dispositivos benignos y episodios con una ventana bajo K al inicio."""
    rng = np.random.default_rng(semilla)
    filas = []
    tipos = ["arp_spoofing", "syn_flood", "icmp_flood"]
    for s in range(n_sesiones):
        for d in range(DISPOSITIVOS):
            for w in range(VENTANAS):
                filas.append({"sesion": nombre_sesion(s), "mac": f"m{d}", "idx_ventana": w, ETIQUETA: 0,
                              "n_tramas_ataque": 0, "episodio": -1, "tipo_ataque": "normal", "atacante": "",
                              "intensidad": "", "variante": ""})
        for e in range(EPISODIOS):
            inicio = 5 + 10 * e
            tipo = tipos[(s + e) % len(tipos)]
            for w in range(inicio, inicio + DURACION_EP + 1):
                ambigua = w == inicio
                filas.append({"sesion": nombre_sesion(s), "mac": f"a{e}", "idx_ventana": w,
                              ETIQUETA: int(not ambigua), "n_tramas_ataque": 1 if ambigua else 5, "episodio": e,
                              "tipo_ataque": "normal" if ambigua else tipo, "atacante": f"a{e}",
                              "intensidad": "suave" if e % 2 else "rafaga", "variante": "v"})
    df = pd.DataFrame(filas)
    ruido = pd.DataFrame(rng.normal(size=(len(df), len(COLUMNAS_MODELO))), columns=COLUMNAS_MODELO)
    if senal:
        ruido["n_syn"] = df[ETIQUETA] * 50.0
    return pd.concat([df, ruido], axis=1)


def test_el_reparto_nunca_mezcla_sesiones():
    df = _dataset()
    for semilla in (1, 2, 3):
        for tr, te in ev.repartos_por_sesion(df, 4, semilla):
            assert not set(df["sesion"].iloc[tr]) & set(df["sesion"].iloc[te])


def test_el_reparto_rechaza_el_holdout():
    df = _dataset().assign(sesion=lambda d: d["sesion"].replace({nombre_sesion(0): nombre_sesion(20)}))
    with pytest.raises(HoldoutError):
        ev.repartos_por_sesion(df, 4, 1)


def test_episodios_detectados_y_tiempo_hasta_la_deteccion():
    df = _dataset(n_sesiones=1)
    alarma = (df[ETIQUETA] == 1) & (df["idx_ventana"] % 10 == 7)  # segunda ventana etiquetada de cada episodio
    tabla = ev.tabla_episodios(df, alarma.to_numpy())
    assert len(tabla) == EPISODIOS and tabla["detectado"].all()
    # Inicio en la ventana ambigua (5), alarma al cierre de la ventana 7: 3 ventanas = 15 s.
    assert tabla["t_deteccion_s"].tolist() == [15.0] * EPISODIOS


def test_las_ventanas_ambiguas_no_son_falsas_alarmas():
    df = _dataset(n_sesiones=1)
    alarma = ev.filas_ambiguas(df).to_numpy()
    assert ev.falsas_alarmas_por_dispositivo_dia(df, alarma) == 0.0
    assert not ev.tabla_episodios(df, alarma)["detectado"].any()


def test_el_umbral_respeta_el_objetivo_de_falsas_alarmas():
    df = _dataset(senal=False)
    prob = np.random.default_rng(3).random(len(df))
    for objetivo in (10.0, 100.0, 1000.0):
        umbral = ev.umbral_para_objetivo(df, prob, objetivo)
        assert ev.falsas_alarmas_por_dispositivo_dia(df, prob > umbral) <= objetivo + 1e-9


def test_alarmas_al_azar_dan_recall_de_azar():
    df = _dataset(n_sesiones=40, senal=False)
    p = 0.2
    alarma = np.random.default_rng(5).random(len(df)) < p
    recall = ev.tabla_episodios(df, alarma)["detectado"].mean()
    assert recall == pytest.approx(1 - (1 - p) ** DURACION_EP, abs=0.08)


def test_senal_perfecta_da_recall_uno():
    df = _dataset(senal=True)
    pred = ev.predecir_fuera_de_fold(df, "random_forest", 1, n_folds=4, n_folds_internos=2,
                                     objetivo_por_dispositivo_dia=1.0)
    resumen = ev.resumir(df, [pred], n_replicas=200)
    assert resumen["episodios"]["recall"]["valor"] == 1.0
    assert resumen["atacantes"]["recall"]["valor"] == 1.0
    assert resumen["dispositivos"]["falsas_alarmas_por_dispositivo_dia"]["valor"] == 0.0
    assert len(pred.folds) == 4 and all(f["sesiones_test"] for f in pred.folds)


def test_sin_senal_el_recall_por_episodio_cae_al_azar():
    """Con ruido puro, el recall por episodio no supera lo que darían alarmas al azar."""
    df = _dataset(n_sesiones=8, senal=False)
    # Objetivo laxo (~30 % de ventanas benignas con alarma) para que haya alarmas que comparar.
    dias_por_ventana = ev.VENTANA_CORTA_S / ev.SEGUNDOS_POR_DIA
    pred = ev.predecir_fuera_de_fold(df, "random_forest", 1, n_folds=4, n_folds_internos=2,
                                     objetivo_por_dispositivo_dia=0.3 / dias_por_ventana)
    tasa = pred.alarma[ev.benignas_limpias(df).to_numpy()].mean()
    azar = 1 - (1 - tasa) ** DURACION_EP
    recall = ev.tabla_episodios(df, pred.alarma)["detectado"].mean()
    assert recall <= azar + 0.25


def test_el_ic_con_8_sesiones_tiene_ancho():
    rng = np.random.default_rng(0)
    num, den = rng.integers(0, 10, 8), rng.integers(20, 40, 8)
    ic = ev.ic_razon_por_sesion(num, den, n_replicas=1000)
    assert ic["ic95"][0] < ic["valor"] < ic["ic95"][1]
    assert ic["ic95"][1] - ic["ic95"][0] > 0


def test_ic_de_episodios_y_mediana():
    ic = ev.ic_media_por_unidad(np.array([1, 0, 1, 1, 0, 1, 1, 0.5]))
    assert ic["n"] == 8 and ic["ic95"][1] > ic["ic95"][0]
    med = ev.ic_mediana_por_unidad([np.array([5.0]), np.array([10.0, 15.0]), np.array([])])
    assert med["n"] == 2 and med["valor"] == 10.0
    assert math.isnan(ev.ic_media_por_unidad(np.array([]))["valor"])
