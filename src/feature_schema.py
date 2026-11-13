"""
Contrato único de características (Feature Schema) del IDS IEEE 802.3.

Define las columnas por ventana que producen `src/ventanas.py` (bloque "Extracción de
huella digital" de la Fig. 1) y consumen el preprocesado y los modelos (OE2). No hay
vectores por trama ni valores por defecto de flujo: una ventana trae todas sus columnas
o se rechaza (etapa E0 de docs/PLAN_IMPLEMENTACION.md).

Los campos sin datos (IAT y desviaciones con menos de dos muestras, o indicadores que
requieren una `ConfigSegmento` no declarada) valen NaN: "sin dato" no equivale a cero.
`oui_frecuente` y `oui_encoded` salieron del modelo: `OUI % 50` colisiona y no es ordinal.
"""

from __future__ import annotations

from typing import Final

import pandas as pd

# Nombre de la columna objetivo (1: malicioso, 0: legítimo)
ETIQUETA: Final[str] = "etiqueta"

# Se incrementa cuando cambia el contrato; lo valida `inferir_ventana`.
VERSION_ESQUEMA: Final[str] = "2.0"

FEATURES_CAPA2: Final[list[str]] = [
    "n_tramas",
    "bytes_totales",
    "longitud_trama_media",
    "longitud_trama_std",
    "iat_media_ms",
    "iat_std_ms",
    "tasa_unicast",
    "tasa_multicast",
    "tasa_broadcast",
    "macs_destino_distintas",
    "pct_menor_64",            # longitud en el medio (captura + FCS de 4 octetos) < 64
    "tasa_vlan",
    "tasa_llc",
    "entropia_ethertype",
]

FEATURES_ARP: Final[list[str]] = [
    "arp_requests",
    "arp_replies",
    "arp_replies_no_solicitadas",
    "arp_gratuitos",
    "arp_cambios_vinculo",     # IP ya vista con otra MAC
    "arp_ether_distinto_hwsrc",
    "arp_gateway_reclamado",   # NaN sin gateway declarado
]

FEATURES_TCP: Final[list[str]] = [
    "n_syn",
    "tasa_syn",
    "syn_medio_abiertos",
    "ratio_syn_medio_abiertos",  # NaN sin SYN evaluables en la ventana
    "n_rst",
    "ips_origen_distintas",
    "ips_destino_distintas",
    "puertos_destino_distintos",
    "entropia_puertos_destino",
    "conexiones_distintas",
    "n_icmp_echo",
]

FEATURES_DNS: Final[list[str]] = [
    "dns_consultas",
    "dns_respuestas",
    "dns_respuestas_sin_consulta",
    "dns_multiples_respuestas_txid",
    "dns_resolver_no_autorizado",  # NaN sin resolvers declarados
]

# Ventana larga solapada (bajo y lento): 12 ventanas cortas = 60 s.
FEATURES_LARGAS: Final[list[str]] = [
    "n_tramas_60s",
    "arp_replies_no_solicitadas_60s",
    "arp_cambios_vinculo_60s",
    "syn_medio_abiertos_60s",
    "dns_respuestas_sin_consulta_60s",
    "puertos_destino_distintos_60s",
    "ips_destino_distintas_60s",
]

# Nivel de segmento: mismo valor en todas las filas de una ventana.
FEATURES_GLOBALES: Final[list[str]] = [
    "macs_nuevas_por_s",
    "macs_activas",
    "ratio_macs_una_trama",
    "syn_sin_synack_max_destino",
    "syn_medio_abiertos_max_destino",
]

# Orden canónico para entrenamiento e inferencia.
COLUMNAS_MODELO: Final[list[str]] = (
    FEATURES_CAPA2 + FEATURES_ARP + FEATURES_TCP + FEATURES_DNS + FEATURES_LARGAS + FEATURES_GLOBALES
)

# Alias para compatibilidad con código existente que use `COLUMNAS`
COLUMNAS: Final[list[str]] = COLUMNAS_MODELO

# Identificación de la fila: nunca entra al modelo.
COLUMNAS_IDENTIDAD: Final[list[str]] = ["mac", "idx_ventana", "t0_us"]

# Verdad terreno y trazabilidad, solo para evaluación. `variante` e `intensidad` (E1,
# aditivas) permiten medir recall por técnica e intensidad; valen "" en filas benignas.
COLUMNAS_TRAZA: Final[list[str]] = [
    "sesion", "tipo_ataque", "capa", "atacante", "episodio", "n_tramas_ataque", "grupo",
    "variante", "intensidad",
]


def validar_esquema(df: pd.DataFrame, incluir_etiqueta: bool = True) -> bool:
    """Valida que un DataFrame cumpla estrictamente con el contrato de características.

    Args:
        df: DataFrame a validar.
        incluir_etiqueta: Si True, exige que la columna ETIQUETA esté presente.

    Returns:
        True si el esquema es válido.

    Raises:
        ValueError: Si faltan columnas requeridas.
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
