"""
Módulo de carga de datos (Fase 2 de la metodología).

Intenta cargar el conjunto de datos real (captura propia etiquetada o dataset procesado).
Si no está disponible, genera un conjunto sintético con la estructura definida en
`src/feature_schema.py` para permitir validar el pipeline de extremo a extremo.
"""

from __future__ import annotations
import logging
from pathlib import Path
import numpy as np
import pandas as pd

from .feature_schema import COLUMNAS, COLUMNAS_MODELO, ETIQUETA, validar_esquema

logger = logging.getLogger("ids_pipeline.data")

RANDOM_STATE = 42
RUTA_DATASET_DEFECTO = Path("data/cicids2017_procesado.csv")


def generar_dataset_sintetico(n: int = 5000, seed: int = RANDOM_STATE) -> pd.DataFrame:
    """Genera un dataset sintético alineado con el contrato de características.

    Nota: En el dataset sintético se agrega ruido para evitar relaciones deterministas triviales.
    """
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({
        "longitud_trama": rng.integers(60, 1518, n),
        "tiempo_entre_tramas_ms": rng.exponential(5, n),
        "num_conexiones_por_min": rng.poisson(20, n),
        "tasa_syn": rng.uniform(0, 1, n),
        "entropia_puertos_destino": rng.uniform(0, 5, n),
        "oui_frecuente": rng.integers(0, 50, n),
    })

    # Regla probabilística con ruido
    prob_base = (
        0.4 * (df["tasa_syn"] > 0.7).astype(float)
        + 0.35 * (df["num_conexiones_por_min"] > 35).astype(float)
        + 0.35 * (df["entropia_puertos_destino"] > 3.5).astype(float)
        + 0.1 * (df["longitud_trama"] < 100).astype(float)
    )
    ruido = rng.normal(0, 0.15, n)
    prob_final = np.clip(prob_base + ruido, 0, 1)
    df[ETIQUETA] = (prob_final > 0.6).astype(int)

    validar_esquema(df, incluir_etiqueta=True)
    return df


def cargar_dataset(
    ruta: str | Path = RUTA_DATASET_DEFECTO,
    n_sintetico: int = 5000,
    forzar_sintetico: bool = False,
) -> pd.DataFrame:
    """Carga el dataset de entrenamiento o recurre al generador sintético.

    Emite advertencia explícita en caso de usar datos sintéticos (evitando caídas silenciosas).
    """
    ruta_p = Path(ruta)
    if forzar_sintetico or not ruta_p.exists():
        logger.warning(
            "Archivo %s no encontrado (o forzar_sintetico=True). "
            "Generando dataset sintético de respaldo (n=%d, seed=%d). "
            "ADVERTENCIA: Los resultados no corresponden a tráfico real.",
            ruta_p,
            n_sintetico,
            RANDOM_STATE,
        )
        return generar_dataset_sintetico(n=n_sintetico)

    df = pd.read_csv(ruta_p)
    validar_esquema(df, incluir_etiqueta=True)
    return df
