"""Pruebas unitarias para el módulo de datos (src/data.py)."""

from pathlib import Path
import pandas as pd
import pytest
from src.data import RUTA_DATASET_LAB, generar_dataset_sintetico, cargar_dataset
from src.feature_schema import COLUMNAS_MODELO, ETIQUETA


def test_generar_dataset_sintetico_dimensiones():
    df = generar_dataset_sintetico(n=250, seed=123)
    assert len(df) == 250
    assert set(df.columns) == set(COLUMNAS_MODELO + [ETIQUETA])


def test_generar_dataset_sintetico_reproducibilidad():
    df1 = generar_dataset_sintetico(n=100, seed=999)
    df2 = generar_dataset_sintetico(n=100, seed=999)
    assert df1.equals(df2)


def test_generar_dataset_sintetico_tiene_dos_clases():
    df = generar_dataset_sintetico(n=500, seed=42)
    clases = df[ETIQUETA].unique()
    assert 0 in clases
    assert 1 in clases


def test_cargar_dataset_inexistente_retorna_sintetico():
    ruta_falsa = Path("/tmp/no_existe_archivo_dataset.csv")
    df = cargar_dataset(ruta=ruta_falsa, n_sintetico=50)
    assert len(df) == 50
    assert set(df.columns) == set(COLUMNAS_MODELO + [ETIQUETA])


@pytest.mark.skipif(
    not RUTA_DATASET_LAB.exists(),
    reason="data/dataset_lab.csv no generado todavía (Fase 1 pendiente)",
)
def test_cargar_dataset_por_defecto_usa_el_dataset_del_laboratorio():
    """Sin ruta explícita debe preferir el dataset propio y conservar sus metadatos."""
    df = cargar_dataset()
    assert set(COLUMNAS_MODELO + [ETIQUETA]).issubset(df.columns)
    assert df[ETIQUETA].nunique() == 2
    assert len(df) == len(pd.read_csv(RUTA_DATASET_LAB))


@pytest.mark.skipif(
    not RUTA_DATASET_LAB.exists(),
    reason="data/dataset_lab.csv no generado todavía (Fase 1 pendiente)",
)
def test_forzar_sintetico_no_carga_el_dataset_del_laboratorio():
    df = cargar_dataset(forzar_sintetico=True, n_sintetico=40)
    assert len(df) == 40
    assert "tipo_ataque" not in df.columns
