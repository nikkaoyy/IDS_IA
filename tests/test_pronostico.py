"""Pruebas del pronóstico de anomalías (E6, OE3): tendencia, forecast y backtesting."""
from __future__ import annotations

import numpy as np
import pytest

from src.pronostico import PronosticadorAnomalias, RegistroTemporalAlertas


def test_registro_produce_la_serie_en_orden():
    r = RegistroTemporalAlertas()
    for k in range(5):
        r.registrar(ts_s=float(k), n_alertas=k, score_medio=0.5)
    assert list(r.serie()) == [0.0, 1.0, 2.0, 3.0, 4.0] and len(r) == 5


def test_holt_pronostica_una_tendencia_creciente():
    serie = np.arange(0, 20, dtype=float)  # 0,1,2,...,19
    p = PronosticadorAnomalias(metodo="holt").entrenar(serie)
    pred = p.pronosticar(3)
    assert p.tendencia == "creciente" and pred[0] > 18 and pred[2] > pred[0]


def test_serie_plana_es_estable():
    p = PronosticadorAnomalias(metodo="holt").entrenar(np.full(15, 4.0))
    assert p.tendencia == "estable" and abs(p.pronosticar(1)[0] - 4.0) < 1e-6


def test_pronostico_no_negativo():
    p = PronosticadorAnomalias(metodo="holt").entrenar(np.array([5.0, 4, 3, 2, 1, 0]))
    assert np.all(p.pronosticar(10) >= 0.0)  # una tasa de alertas no puede ser negativa


def test_aviso_temprano_ante_tendencia_creciente():
    p = PronosticadorAnomalias(metodo="holt").entrenar(np.arange(0, 10, dtype=float))
    aviso = p.aviso_temprano(umbral=100.0, pasos=5)  # umbral alto: el aviso viene de la tendencia
    assert aviso["aviso"] and aviso["tendencia"] == "creciente"


def test_backtesting_da_mae_bajo_en_serie_lineal():
    serie = np.arange(0, 30, dtype=float)
    r = PronosticadorAnomalias(metodo="holt").backtesting(serie, train_ratio=0.8)
    assert r["n_test"] == 6 and r["mae"] < 1.0  # Holt sigue bien una recta


def test_serie_corta_falla_explicito():
    with pytest.raises(ValueError, match="2 puntos"):
        PronosticadorAnomalias().entrenar(np.array([3.0]))


def test_holt_winters_statsmodels_si_esta():
    serie = np.arange(0, 20, dtype=float)
    p = PronosticadorAnomalias(metodo="holt_winters").entrenar(serie)
    assert len(p.pronosticar(3)) == 3 and np.all(p.pronosticar(3) >= 0.0)
