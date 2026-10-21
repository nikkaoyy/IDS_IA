"""Pruebas unitarias para el módulo de datos (src/data.py)."""

from pathlib import Path
from src.data import generar_dataset_sintetico, cargar_dataset
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
