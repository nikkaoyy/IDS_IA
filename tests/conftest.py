"""Fixtures compartidas para la suite de pruebas del IDS."""

import pytest
import pandas as pd
from src.data import generar_dataset_sintetico


@pytest.fixture
def dataset_pequeno() -> pd.DataFrame:
    """Fixture de dataset sintético pequeño para tests rápidos."""
    return generar_dataset_sintetico(n=100, seed=42)


@pytest.fixture(scope="session")
def sesion_corta(tmp_path_factory):
    """Sesión de laboratorio de 3 min con ataques densos, ya escrita a pcap."""
    from scripts.lab import generar_trafico as g

    previos = g.DURACION_S, g.ESPACIO_ENTRE_ATAQUES_S
    g.DURACION_S, g.ESPACIO_ENTRE_ATAQUES_S = 180.0, 12.0
    try:
        sesion = g.generar_sesion(7)
    finally:
        g.DURACION_S, g.ESPACIO_ENTRE_ATAQUES_S = previos
    ruta = tmp_path_factory.mktemp("lab") / "sesion.pcap"
    g.escribir_sesion(sesion, ruta)
    return sesion, ruta
