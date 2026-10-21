"""
Módulo de simulación de ataque (bloque "Simulador de ataque de suplantación"
de la Fig. 1 y función `PerturbarHuella(h)` del Algoritmo 1).

Emula un ataque de suplantación de huella digital IEEE 802.3: falsifica el
fabricante (OUI/MAC) y altera la longitud y el patrón de tramas de tráfico
legítimo, para evaluar si el clasificador sigue detectando el tráfico
como anómalo (capacidad de defensa, objetivo específico 3).
"""

from __future__ import annotations
import numpy as np
import pandas as pd

from .data import RANDOM_STATE


def simular_ataque_spoofing(X_legitimo: pd.DataFrame, seed: int = RANDOM_STATE + 1) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    X_ataque = X_legitimo.copy()
    X_ataque["oui_frecuente"] = rng.integers(0, 50, len(X_ataque))
    X_ataque["longitud_trama"] = X_ataque["longitud_trama"] * rng.uniform(0.9, 1.1, len(X_ataque))
    X_ataque["tasa_syn"] = np.clip(
        X_ataque["tasa_syn"] + rng.uniform(0.3, 0.6, len(X_ataque)), 0, 1
    )
    return X_ataque
