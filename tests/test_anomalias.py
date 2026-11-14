"""Pruebas del detector de anomalías entrenado solo con benigno (PEDIDO-ANOMALIAS-1, bloque 1)."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src import anomalias as an
from src import evaluacion as ev
from src.data import nombre_sesion
from src.feature_schema import ETIQUETA

COLUMNAS = an.CONJUNTOS["sin_capa2"][:6]
VENTANAS = 60


def _dataset(n_sesiones: int = 6, anomalia: float = 0.0, semilla: int = 0) -> pd.DataFrame:
    """Dos dispositivos benignos separables (centros 0 y 3, ruido 1) y, si `anomalia`, un atacante.

    El atacante emite 5 ventanas etiquetadas con todas las características en `anomalia`.
    """
    rng = np.random.default_rng(semilla)
    filas, valores = [], []
    for s in range(n_sesiones):
        for d, centro in enumerate((0.0, 3.0)):
            for w in range(VENTANAS):
                filas.append({"sesion": nombre_sesion(s), "mac": f"m{d}", "idx_ventana": w, ETIQUETA: 0,
                              "n_tramas_ataque": 0, "episodio": -1, "tipo_ataque": "normal", "atacante": "",
                              "intensidad": "", "variante": ""})
                valores.append(centro + rng.normal(0, 1.0, len(COLUMNAS)))
        if anomalia:
            for w in range(20, 25):
                filas.append({"sesion": nombre_sesion(s), "mac": "a0", "idx_ventana": w, ETIQUETA: 1,
                              "n_tramas_ataque": 5, "episodio": 0, "tipo_ataque": "icmp_flood", "atacante": "a0",
                              "intensidad": "rafaga", "variante": "v"})
                valores.append(np.full(len(COLUMNAS), anomalia))
    return pd.concat([pd.DataFrame(filas), pd.DataFrame(valores, columns=COLUMNAS)], axis=1)


@pytest.mark.parametrize("modelo", an.MODELOS)
def test_dos_dispositivos_separables_no_dan_falsas_alarmas(modelo):
    df = _dataset()
    pred = an.predecir_fuera_de_fold(df, modelo, 42, n_folds=3, n_folds_internos=2,
                                     objetivo_por_dispositivo_dia=1.0, columnas=COLUMNAS)
    # 6 sesiones × 2 dispositivos × 5 min: el objetivo permite 0 alarmas por fold; el umbral es el
    # máximo benigno interno y solo lo superan colas del ruido. FA≈0: ≤ 1 % de las ventanas.
    assert pred.alarma.sum() <= 0.01 * len(df)


# IF sobre PCA no ve una anomalía que solo se sale del rango por el primer componente: el IF
# satura fuera del rango de entrenamiento y en los demás componentes el punto cae en el centro
# benigno (puntaje 0,46 frente a un máximo benigno de 0,62). Declarado antes de medir.
_PCA_SATURA = pytest.mark.xfail(strict=True, reason="IF sobre PCA satura fuera del rango del primer componente")


@pytest.mark.parametrize("modelo", ["isolation_forest", "lof", pytest.param("isolation_forest_pca", marks=_PCA_SATURA)])
def test_una_anomalia_evidente_da_alarma(modelo):
    df = _dataset(anomalia=40.0)
    pred = an.predecir_fuera_de_fold(df, modelo, 42, n_folds=3, n_folds_internos=2,
                                     objetivo_por_dispositivo_dia=1.0, columnas=COLUMNAS)
    episodios = ev.tabla_episodios(df, pred.alarma)
    assert episodios["detectado"].all()
    assert pred.alarma[(df[ETIQUETA] == 0).to_numpy()].sum() <= 0.01 * len(df)


def test_el_ajuste_rechaza_la_etiqueta():
    df = _dataset(anomalia=40.0)
    with pytest.raises(an.EtiquetaEnAjusteError):
        an.ajustar_detector("isolation_forest", df[COLUMNAS + [ETIQUETA]], 42)
    # Aunque solo traiga ceros: la etiqueta no llega al modelo, las filas las elige filas_de_ajuste.
    benignas = df[df[ETIQUETA] == 0]
    with pytest.raises(an.EtiquetaEnAjusteError):
        an.ajustar_detector("isolation_forest", benignas[COLUMNAS + [ETIQUETA]], 42)


def test_filas_de_ajuste_excluye_maliciosas_y_ambiguas():
    df = _dataset(anomalia=40.0)
    df.loc[df.index[0], "n_tramas_ataque"] = 1  # ambigua: etiqueta 0 con trama de ataque
    mascara = an.filas_de_ajuste(df)
    assert not mascara[(df[ETIQUETA] == 1).to_numpy()].any()
    assert not mascara[0]


@pytest.mark.parametrize("modelo", an.MODELOS)
def test_el_malicioso_no_toca_ni_el_ajuste_ni_el_umbral(modelo):
    """Cambiar por completo las filas maliciosas no altera umbrales ni puntajes benignos."""
    df = _dataset(anomalia=40.0)
    otro = df.copy()
    maliciosas = (df[ETIQUETA] == 1).to_numpy()
    otro.loc[maliciosas, COLUMNAS] = np.random.default_rng(7).normal(0, 1e3, (maliciosas.sum(), len(COLUMNAS)))
    kw = dict(n_folds=3, n_folds_internos=2, objetivo_por_dispositivo_dia=1.0, columnas=COLUMNAS)
    a = an.predecir_fuera_de_fold(df, modelo, 42, **kw)
    b = an.predecir_fuera_de_fold(otro, modelo, 42, **kw)
    assert [f["umbral"] for f in a.folds] == [f["umbral"] for f in b.folds]
    assert [f["filas_ajuste"] for f in a.folds] == [f["filas_ajuste"] for f in b.folds]
    np.testing.assert_array_equal(a.prob[~maliciosas], b.prob[~maliciosas])


def test_el_puntaje_crece_con_la_anomalia():
    df = _dataset()
    det = an.ajustar_detector("isolation_forest", df.loc[df["mac"] == "m0", COLUMNAS], 42)
    cerca = pd.DataFrame(np.zeros((1, len(COLUMNAS))), columns=COLUMNAS)
    lejos = pd.DataFrame(np.full((1, len(COLUMNAS)), 30.0), columns=COLUMNAS)
    assert det.puntuar(lejos)[0] > det.puntuar(cerca)[0]


def test_modelo_desconocido():
    df = _dataset()
    with pytest.raises(KeyError):
        an.ajustar_detector("autoencoder", df[COLUMNAS], 42)
