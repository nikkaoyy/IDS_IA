"""El holdout de E2 lo protege el código, no la memoria (etapa E1, bloque 2)."""
from __future__ import annotations

import pandas as pd
import pytest

from scripts.lab import generar_dataset_lab as gdl
from src.data import (
    RUTA_DATASET_LAB,
    SEMILLA_BASE_LAB,
    SESIONES_RESERVADAS,
    HoldoutError,
    cargar_dataset,
    generar_dataset_sintetico,
    indice_sesion,
    nombre_sesion,
)
from src.preprocess import dividir

RESERVADA = nombre_sesion(SESIONES_RESERVADAS.start)


def _con_sesiones(nombres: list[str]) -> pd.DataFrame:
    df = generar_dataset_sintetico(n=80, seed=1)
    return df.assign(sesion=[nombres[i % len(nombres)] for i in range(len(df))])


def test_el_desarrollo_por_defecto_no_toca_el_holdout():
    assert not set(range(gdl.SESIONES)) & set(SESIONES_RESERVADAS)
    assert gdl.indices_a_generar(0, gdl.SESIONES) == list(range(gdl.SESIONES))


def test_generar_una_sesion_reservada_exige_el_flag():
    with pytest.raises(HoldoutError):
        gdl.indices_a_generar(0, SESIONES_RESERVADAS.start + 1)
    with pytest.raises(HoldoutError):
        gdl.indices_a_generar(SESIONES_RESERVADAS.stop - 1, 1)
    assert gdl.indices_a_generar(SESIONES_RESERVADAS.start, 2, romper_holdout=True) == [
        SESIONES_RESERVADAS.start, SESIONES_RESERVADAS.start + 1,
    ]


def test_el_orquestador_se_niega_antes_de_generar(tmp_path):
    salida, pcaps = tmp_path / "d.csv", tmp_path / "pcap"
    codigo = gdl.main(["--sesiones", str(SESIONES_RESERVADAS.start + 1),
                       "--salida", str(salida), "--dir-pcap", str(pcaps)])
    assert codigo == 2
    assert not salida.exists() and not pcaps.exists()


def test_el_entrenamiento_rechaza_sesiones_reservadas(tmp_path):
    df = _con_sesiones(["sesion_000", "sesion_001", "sesion_002", "sesion_003", RESERVADA])
    with pytest.raises(HoldoutError):
        dividir(df)
    ruta = tmp_path / "d.csv"
    df.to_csv(ruta, index=False)
    with pytest.raises(HoldoutError):
        cargar_dataset(ruta)
    assert len(cargar_dataset(ruta, permitir_holdout=True)) == len(df)


def test_sesiones_de_desarrollo_siguen_permitidas():
    df = _con_sesiones([nombre_sesion(i) for i in range(8)])
    x_train, x_test, _, _ = dividir(df)
    assert len(x_train) + len(x_test) == len(df)


@pytest.mark.skipif(not RUTA_DATASET_LAB.exists(), reason="data/dataset_lab.csv no generado todavía")
def test_el_dataset_en_disco_no_contiene_el_holdout():
    sesiones = pd.read_csv(RUTA_DATASET_LAB, usecols=["sesion"])["sesion"].unique()
    indices = {indice_sesion(s) for s in sesiones}
    assert not indices & set(SESIONES_RESERVADAS), "el dataset de desarrollo usó semillas del holdout"
    assert SEMILLA_BASE_LAB + SESIONES_RESERVADAS.start not in {SEMILLA_BASE_LAB + i for i in indices}
