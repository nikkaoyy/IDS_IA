"""Pruebas unitarias para el contrato de características (src/feature_schema.py)."""

import pytest
from src.feature_schema import (
    COLUMNAS_MODELO,
    ETIQUETA,
    FEATURES_CAPA2,
    FEATURES_GLOBALES,
    validar_esquema,
)


def test_columnas_modelo_definidas():
    assert len(COLUMNAS_MODELO) == len(set(COLUMNAS_MODELO))
    for f in FEATURES_CAPA2 + FEATURES_GLOBALES:
        assert f in COLUMNAS_MODELO
    assert "oui_frecuente" not in COLUMNAS_MODELO
    assert "oui_encoded" not in COLUMNAS_MODELO


def test_validar_esquema_exitoso(dataset_pequeno):
    assert validar_esquema(dataset_pequeno, incluir_etiqueta=True) is True


def test_validar_esquema_columna_faltante(dataset_pequeno):
    invalido = dataset_pequeno.drop(columns=["tasa_syn"])
    with pytest.raises(ValueError, match="Columnas faltantes"):
        validar_esquema(invalido)
