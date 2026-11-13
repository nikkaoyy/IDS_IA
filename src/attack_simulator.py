"""
Módulo de simulación de ataque (bloque "Simulador de ataque de suplantación"
de la Fig. 1 y función `PerturbarHuella(h)` del Algoritmo 1).

Modela evasión (OE3, CONTEXT_UPGRADE.md §3.3): un atacante parte de tráfico
malicioso e intenta parecer un dispositivo legítimo. La etiqueta sigue siendo 1,
de modo que la caída de recall mide la capacidad de defensa del clasificador.

Solo se alteran características que el atacante controla sin dejar de atacar.
`tasa_syn` nunca cambia: un SYN flood sin SYN ya no sería el mismo ataque.
"""

from __future__ import annotations
from collections.abc import Callable
import numpy as np
import pandas as pd

from .data import RANDOM_STATE

# Adaptación mínima al esquema 2.0; se reemplaza por evasión a nivel de pcap en E4.
# Clonar una MAC ya vista evita aparecer como nueva o de una sola trama.
_IDENTIDAD: list[str] = ["macs_nuevas_por_s", "ratio_macs_una_trama"]
_FORMA: list[str] = ["longitud_trama_media", "longitud_trama_std", "iat_media_ms", "iat_std_ms"]

# Nivel de conocimiento del atacante -> características que falsifica.
FEATURES_FALSIFICABLES: dict[str, list[str]] = {
    "mac_clonada": _IDENTIDAD,
    "black_box": _IDENTIDAD + _FORMA,
    "white_box": _IDENTIDAD + _FORMA + ["conexiones_distintas"],
}
NIVELES_EVASION: list[str] = list(FEATURES_FALSIFICABLES)
CANDIDATOS_WHITE_BOX = 25


def _imitar_donantes(
    X_malicioso: pd.DataFrame,
    X_legitimo: pd.DataFrame,
    columnas: list[str],
    rng: np.random.Generator,
) -> pd.DataFrame:
    """Copia `columnas` de una huella legítima elegida al azar para cada muestra."""
    X_falso = X_malicioso.copy()
    donantes = rng.integers(0, len(X_legitimo), len(X_falso))
    X_falso[columnas] = X_legitimo[columnas].to_numpy()[donantes]
    return X_falso


def simular_evasion(
    X_malicioso: pd.DataFrame,
    X_legitimo: pd.DataFrame,
    nivel: str = "black_box",
    puntuar: Callable[[pd.DataFrame], np.ndarray] | None = None,
    seed: int = RANDOM_STATE + 1,
) -> pd.DataFrame:
    """Perturba huellas maliciosas para imitar dispositivos legítimos (Algoritmo 1).

    Args:
        X_malicioso: Huellas maliciosas sin escalar.
        X_legitimo: Huellas legítimas que el atacante observó.
        nivel: "mac_clonada" (solo identidad), "black_box" (identidad, longitud y ritmo) o
            "white_box" (además conexiones, con consulta al modelo).
        puntuar: Probabilidad de malicioso por fila; obligatoria en "white_box",
            donde se elige por muestra el candidato con menor puntaje.
        seed: Semilla reproducible.

    Returns:
        DataFrame con el mismo índice y columnas que `X_malicioso`.

    Raises:
        ValueError: Si el nivel no existe o falta `puntuar` en "white_box".
    """
    if nivel not in FEATURES_FALSIFICABLES:
        raise ValueError(f"Nivel de evasión desconocido: {nivel}")
    rng = np.random.default_rng(seed)
    columnas = FEATURES_FALSIFICABLES[nivel]
    if nivel != "white_box":
        return _imitar_donantes(X_malicioso, X_legitimo, columnas, rng)
    if puntuar is None:
        raise ValueError("El nivel white_box requiere `puntuar`.")

    mejor = _imitar_donantes(X_malicioso, X_legitimo, columnas, rng)
    mejor_puntaje = np.asarray(puntuar(mejor))
    for _ in range(CANDIDATOS_WHITE_BOX - 1):
        candidato = _imitar_donantes(X_malicioso, X_legitimo, columnas, rng)
        puntaje = np.asarray(puntuar(candidato))
        mejora = puntaje < mejor_puntaje
        mejor.loc[mejora, columnas] = candidato.loc[mejora, columnas]
        mejor_puntaje = np.minimum(puntaje, mejor_puntaje)
    return mejor


def evaluar_bajo_ataque(
    predecir: Callable[[pd.DataFrame], np.ndarray],
    X_malicioso: pd.DataFrame,
    X_perturbado: pd.DataFrame,
) -> dict[str, float]:
    """Compara el recall limpio contra el recall bajo evasión (OE3).

    Returns:
        `recall_limpio`, `recall_bajo_ataque` y `tasa_evasion_exitosa`, esta última
        calculada sobre las muestras que el modelo sí detectaba sin perturbar.
    """
    limpio = np.asarray(predecir(X_malicioso)) == 1
    atacado = np.asarray(predecir(X_perturbado)) == 1
    detectadas = int(limpio.sum())
    return {
        "recall_limpio": float(limpio.mean()),
        "recall_bajo_ataque": float(atacado.mean()),
        "tasa_evasion_exitosa": float((limpio & ~atacado).sum() / detectadas) if detectadas else 0.0,
    }
