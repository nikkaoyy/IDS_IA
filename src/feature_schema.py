"""
Contrato unificado de características (Feature Schema) para el IDS IEEE 802.3.

Resuelve el desacople técnico documentado en CONTEXT_UPGRADE.md (§3.1):
Define de forma única y centralizada las columnas esperadas por:
- El módulo de captura y extracción de huella (src/capture.py, src/fingerprint.py)
- El módulo de generación y carga de datos (src/data.py)
- El módulo de preprocesamiento (src/preprocess.py)
- Los modelos y el pipeline de inferencia (src/models.py, src/pipeline.py)
"""

from __future__ import annotations
from typing import Final
import pandas as pd

# Nombre de la columna objetivo (1: malicioso, 0: legítimo)
ETIQUETA: Final[str] = "etiqueta"

# ==============================================================================
# 1. CARACTERÍSTICAS DE CAPA 2 (HUELLA DIGITAL IEEE 802.3 / ETHERNET)
# ==============================================================================
FEATURES_HUELLA_802_3: Final[list[str]] = [
    "longitud_trama",              # Longitud en bytes de la trama Ethernet/802.3
    "tiempo_entre_tramas_ms",      # Delta de tiempo (IAT) entre tramas del mismo origen
    "oui_frecuente",               # Identificador codificado del fabricante (primeros 3 octetos MAC)
]

# Características enriquecidas de capa 2 para agregación por ventana temporal (Fase 1+)
FEATURES_HUELLA_VENTANA: Final[list[str]] = [
    "longitud_trama_media",
    "longitud_trama_std",
    "iat_media_ms",
    "iat_std_ms",
    "tasa_broadcast",
    "tasa_arp",
    "entropia_ethertype",
    "oui_encoded",
]

# ==============================================================================
# 2. CARACTERÍSTICAS DE CAPA 3-4 (FLUJO Y TRANSPORTE)
# ==============================================================================
FEATURES_FLUJO: Final[list[str]] = [
    "num_conexiones_por_min",       # Frecuencia de flujos / tasa de conexión
    "tasa_syn",                     # Proporción de paquetes con bandera SYN activa
    "entropia_puertos_destino",     # Medida de dispersión de puertos (indicador de escaneo)
]

# ==============================================================================
# 3. CONTRATO CANÓNICO DEL MODELO
# ==============================================================================
# Este es el conjunto exacto de columnas que los clasificadores (RF y XGBoost)
# esperan recibir ordenadas durante el entrenamiento y la inferencia.
COLUMNAS_MODELO: Final[list[str]] = [
    "longitud_trama",
    "tiempo_entre_tramas_ms",
    "num_conexiones_por_min",
    "tasa_syn",
    "entropia_puertos_destino",
    "oui_frecuente",
]

# Alias para compatibilidad con código existente que use `COLUMNAS`
COLUMNAS: Final[list[str]] = COLUMNAS_MODELO


def validar_esquema(df: pd.DataFrame, incluir_etiqueta: bool = True) -> bool:
    """Valida que un DataFrame cumpla estrictamente con el contrato de características.

    Args:
        df: DataFrame a validar.
        incluir_etiqueta: Si True, exige que la columna ETIQUETA esté presente.

    Returns:
        True si el esquema es válido.

    Raises:
        ValueError: Si faltan columnas requeridas o si hay tipos incompatibles.
    """
    columnas_esperadas = set(COLUMNAS_MODELO)
    if incluir_etiqueta:
        columnas_esperadas.add(ETIQUETA)

    faltantes = columnas_esperadas - set(df.columns)
    if faltantes:
        raise ValueError(
            f"El DataFrame no cumple el contrato de características. Columnas faltantes: {sorted(faltantes)}"
        )
    return True


def mapear_huella_a_vector_modelo(huella_dict: dict, defaults_flujo: dict | None = None) -> dict:
    """Mapea un diccionario de huella (producido por el extractor IEEE 802.3)

    al formato esperado por el modelo, integrando estimaciones de capa 3-4 si no están
    disponibles en la captura pura de enlace.
    """
    valores_flujo = defaults_flujo or {
        "num_conexiones_por_min": 1,
        "tasa_syn": 0.0,
        "entropia_puertos_destino": 0.0,
    }

    # Si el OUI viene en string o no está codificado, aplicar codificación
    oui_val = huella_dict.get("oui_frecuente")
    if oui_val is None:
        raw_oui = str(huella_dict.get("oui", "000000")).replace(":", "").replace("-", "")[:6]
        try:
            oui_val = int(raw_oui, 16) % 50
        except ValueError:
            oui_val = 0

    return {
        "longitud_trama": float(huella_dict.get("longitud_trama", 64)),
        "tiempo_entre_tramas_ms": float(huella_dict.get("tiempo_entre_tramas_ms", 0.0)),
        "num_conexiones_por_min": float(huella_dict.get("num_conexiones_por_min", valores_flujo["num_conexiones_por_min"])),
        "tasa_syn": float(huella_dict.get("tasa_syn", valores_flujo["tasa_syn"])),
        "entropia_puertos_destino": float(huella_dict.get("entropia_puertos_destino", valores_flujo["entropia_puertos_destino"])),
        "oui_frecuente": int(oui_val),
    }
