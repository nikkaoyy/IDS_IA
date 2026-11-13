"""Pruebas unitarias del simulador de evasión (src/attack_simulator.py)."""

import numpy as np
import pandas as pd
import pytest

from src.attack_simulator import FEATURES_FALSIFICABLES, evaluar_bajo_ataque, simular_evasion
from src.feature_schema import COLUMNAS_MODELO


@pytest.fixture
def huellas():
    maliciosas = pd.DataFrame(1.0, index=range(10, 30), columns=COLUMNAS_MODELO)
    legitimas = pd.DataFrame(0.0, index=range(5), columns=COLUMNAS_MODELO)
    return maliciosas, legitimas


def test_evasion_conserva_syn_e_indice(huellas):
    maliciosas, legitimas = huellas
    falsas = simular_evasion(maliciosas, legitimas, nivel="black_box")
    assert falsas.index.equals(maliciosas.index)
    assert (falsas["tasa_syn"] == 1.0).all()
    assert (falsas["longitud_trama_media"] == 0.0).all()


def test_mac_clonada_solo_cambia_identidad(huellas):
    maliciosas, legitimas = huellas
    falsas = simular_evasion(maliciosas, legitimas, nivel="mac_clonada")
    cambiadas = FEATURES_FALSIFICABLES["mac_clonada"]
    assert (falsas[cambiadas] == 0.0).all().all()
    assert falsas.drop(columns=cambiadas).equals(maliciosas.drop(columns=cambiadas))


def test_white_box_elige_el_candidato_de_menor_puntaje(huellas):
    maliciosas, _ = huellas
    legitimas = pd.DataFrame(
        {c: np.arange(50.0) for c in COLUMNAS_MODELO},
    )
    falsas = simular_evasion(
        maliciosas, legitimas, nivel="white_box",
        puntuar=lambda X: X["longitud_trama_media"].to_numpy(),
    )
    azar = simular_evasion(maliciosas, legitimas, nivel="black_box")
    assert falsas["longitud_trama_media"].mean() < azar["longitud_trama_media"].mean()


def test_white_box_sin_puntuar_y_nivel_invalido_fallan(huellas):
    maliciosas, legitimas = huellas
    with pytest.raises(ValueError):
        simular_evasion(maliciosas, legitimas, nivel="white_box")
    with pytest.raises(ValueError):
        simular_evasion(maliciosas, legitimas, nivel="otro")


def test_evaluar_bajo_ataque_calcula_evasion():
    X = pd.DataFrame({"v": [1, 1, 1, 0]})
    X_falso = pd.DataFrame({"v": [1, 0, 0, 0]})
    r = evaluar_bajo_ataque(lambda d: d["v"].to_numpy(), X, X_falso)
    assert r["recall_limpio"] == 0.75
    assert r["recall_bajo_ataque"] == 0.25
    assert r["tasa_evasion_exitosa"] == pytest.approx(2 / 3)
