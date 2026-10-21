"""Pruebas unitarias para el contrato de características (src/feature_schema.py)."""

import pytest
import pandas as pd
from src.feature_schema import (
    COLUMNAS_MODELO,
    ETIQUETA,
    FEATURES_HUELLA_802_3,
    FEATURES_FLUJO,
    validar_esquema,
    mapear_huella_a_vector_modelo,
)


def test_columnas_modelo_definidas():
    assert len(COLUMNAS_MODELO) == 6
    for f in FEATURES_HUELLA_802_3:
        assert f in COLUMNAS_MODELO
    for f in FEATURES_FLUJO:
        assert f in COLUMNAS_MODELO


def test_validar_esquema_exitoso(dataset_pequeno):
    assert validar_esquema(dataset_pequeno, incluir_etiqueta=True) is True


def test_validar_esquema_columna_faltante(dataset_pequeno):
    invalido = dataset_pequeno.drop(columns=["tasa_syn"])
    with pytest.raises(ValueError, match="Columnas faltantes"):
        validar_esquema(invalido)


def test_mapear_huella_a_vector_modelo(vector_huella_cruda):
    vector = mapear_huella_a_vector_modelo(vector_huella_cruda)
    assert set(vector.keys()) == set(COLUMNAS_MODELO)
    assert vector["longitud_trama"] == 1514.0
    assert vector["tiempo_entre_tramas_ms"] == 12.5
    assert isinstance(vector["oui_frecuente"], int)
