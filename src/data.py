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

from .feature_schema import COLUMNAS_MODELO, ETIQUETA, validar_esquema

logger = logging.getLogger("ids_pipeline.data")

RANDOM_STATE = 42
DIR_DATOS = Path(__file__).resolve().parent.parent / "data"

# Identidad de las sesiones del laboratorio (etapa E1): `sesion_NNN` se genera con la
# semilla `SEMILLA_BASE_LAB + NNN`. Vive aquí para que generación, ficha y entrenamiento
# compartan la misma correspondencia nombre <-> semilla.
SEMILLA_BASE_LAB = RANDOM_STATE * 1000
PREFIJO_SESION = "sesion_"


def nombre_sesion(indice: int) -> str:
    """Nombre canónico de la sesión `indice` (p. ej. `sesion_007`)."""
    return f"{PREFIJO_SESION}{indice:03d}"


def indice_sesion(nombre: str) -> int | None:
    """Índice de una sesión por su nombre; None si no sigue el patrón `sesion_NNN`."""
    sufijo = str(nombre).removeprefix(PREFIJO_SESION)
    return int(sufijo) if sufijo != str(nombre) and sufijo.isdigit() else None


# Holdout final de la etapa E2: sesiones de semilla nunca usada, abiertas una sola vez.
# Ni la generación del dataset de desarrollo ni el entrenamiento pueden tocarlas sin una
# decisión explícita (`--romper-holdout` / `permitir_holdout=True`).
SESIONES_RESERVADAS: range = range(20, 30)


class HoldoutError(ValueError):
    """Se intentó usar una sesión reservada para el holdout de E2."""


def sesiones_reservadas_en(df: pd.DataFrame) -> list[str]:
    """Sesiones de `df` que pertenecen al holdout (vacío si no hay columna `sesion`)."""
    if "sesion" not in df.columns:
        return []
    return sorted(
        s for s in df["sesion"].astype(str).unique()
        if (i := indice_sesion(s)) is not None and i in SESIONES_RESERVADAS
    )


def verificar_holdout(df: pd.DataFrame, permitir: bool = False) -> None:
    """Falla si `df` contiene sesiones reservadas y no se permitió explícitamente.

    Raises:
        HoldoutError: Si aparece alguna sesión de `SESIONES_RESERVADAS`.
    """
    reservadas = sesiones_reservadas_en(df)
    if reservadas and not permitir:
        raise HoldoutError(
            f"El dataset contiene sesiones del holdout de E2 {reservadas}; "
            "no pueden usarse para desarrollo ni entrenamiento."
        )

# Datasets aceptados, en orden de preferencia. El primero es el dataset propio
# generado en el laboratorio virtual (Fase 1); el segundo, un CICIDS ya procesado.
RUTA_DATASET_LAB = DIR_DATOS / "dataset_lab.csv"
RUTA_DATASET_DEFECTO = DIR_DATOS / "cicids2017_procesado.csv"
RUTAS_DATASET_PREFERIDAS: list[Path] = [RUTA_DATASET_LAB, RUTA_DATASET_DEFECTO]


def ruta_dataset_disponible() -> Path | None:
    """Devuelve el primer dataset del proyecto que exista, en orden de preferencia."""
    for ruta in RUTAS_DATASET_PREFERIDAS:
        if ruta.exists():
            return ruta
    return None


def generar_dataset_sintetico(n: int = 5000, seed: int = RANDOM_STATE) -> pd.DataFrame:
    """Genera un dataset sintético alineado con el contrato de características.

    Nota: En el dataset sintético se agrega ruido para evitar relaciones deterministas triviales.
    """
    rng = np.random.default_rng(seed)
    df = pd.DataFrame(rng.poisson(3.0, (n, len(COLUMNAS_MODELO))).astype(float), columns=COLUMNAS_MODELO)
    df["n_tramas"] = rng.poisson(20, n) + 1.0
    df["longitud_trama_media"] = rng.uniform(60, 1518, n)
    df["iat_media_ms"] = rng.exponential(5, n)
    df["tasa_syn"] = rng.uniform(0, 1, n)
    df["entropia_puertos_destino"] = rng.uniform(0, 5, n)

    # Regla probabilística con ruido
    prob_base = (
        0.4 * (df["tasa_syn"] > 0.7).astype(float)
        + 0.35 * (df["n_tramas"] > 25).astype(float)
        + 0.35 * (df["entropia_puertos_destino"] > 3.5).astype(float)
        + 0.1 * (df["longitud_trama_media"] < 100).astype(float)
    )
    ruido = rng.normal(0, 0.15, n)
    prob_final = np.clip(prob_base + ruido, 0, 1)
    df[ETIQUETA] = (prob_final > 0.6).astype(int)

    validar_esquema(df, incluir_etiqueta=True)
    return df


def cargar_dataset(
    ruta: str | Path | None = None,
    n_sintetico: int = 5000,
    forzar_sintetico: bool = False,
    permitir_holdout: bool = False,
) -> pd.DataFrame:
    """Carga el dataset de entrenamiento o recurre al generador sintético.

    Con `ruta=None` se busca, en orden de preferencia, `data/dataset_lab.csv`
    (dataset propio del laboratorio virtual, Fase 1) y `data/cicids2017_procesado.csv`.
    Si se indica una ruta explícita que no existe, se cae al generador sintético:
    pedir un archivo concreto y recibir otro sin avisar sería peor que el respaldo.

    Emite advertencia explícita en caso de usar datos sintéticos (evitando caídas silenciosas).

    Raises:
        HoldoutError: Si el dataset trae sesiones reservadas y `permitir_holdout` es False.
    """
    if forzar_sintetico:
        ruta_p: Path | None = None
    elif ruta is not None:
        ruta_p = Path(ruta)
        if not ruta_p.exists():
            logger.warning("El dataset solicitado %s no existe.", ruta_p)
            ruta_p = None
    else:
        ruta_p = ruta_dataset_disponible()

    if ruta_p is None or not ruta_p.exists():
        logger.warning(
            "Ningún dataset del proyecto disponible (se buscaron %s). "
            "Generando dataset sintético de respaldo (n=%d, seed=%d). "
            "ADVERTENCIA: Los resultados no corresponden a tráfico real.",
            [str(r) for r in RUTAS_DATASET_PREFERIDAS],
            n_sintetico,
            RANDOM_STATE,
        )
        return generar_dataset_sintetico(n=n_sintetico)

    df = pd.read_csv(ruta_p)
    validar_esquema(df, incluir_etiqueta=True)
    verificar_holdout(df, permitir=permitir_holdout)
    logger.info(
        "Dataset cargado desde %s: %d filas × %d columnas (%.1f %% maliciosas).",
        ruta_p,
        len(df),
        df.shape[1],
        100 * df[ETIQUETA].mean(),
    )
    return df
