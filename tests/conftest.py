"""Fixtures compartidas para la suite de pruebas del IDS."""

import pytest
import pandas as pd
from src.data import generar_dataset_sintetico
from src.feature_schema import COLUMNAS_MODELO, ETIQUETA


@pytest.fixture
def dataset_pequeno() -> pd.DataFrame:
    """Fixture de dataset sintético pequeño para tests rápidos."""
    return generar_dataset_sintetico(n=100, seed=42)


@pytest.fixture
def vector_huella_cruda() -> dict:
    """Representa una huella extraída directamente de Scapy por src/fingerprint.py."""
    return {
        "mac_origen": "00:1A:2B:3C:4D:5E",
        "oui": "001A2B",
        "longitud_trama": 1514,
        "ethertype": 0x0800,
        "tiempo_entre_tramas_ms": 12.5,
    }
