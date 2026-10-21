"""
Módulo de preprocesamiento (bloque "Preprocesamiento y escalado" de la Fig. 1
y función `Preprocesar(h)` del Algoritmo 1).
"""

from __future__ import annotations
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from .data import RANDOM_STATE
from .feature_schema import ETIQUETA


def dividir(df: pd.DataFrame, test_size: float = 0.25):
    """Divide el dataset en conjuntos de entrenamiento y prueba estratificados."""
    X = df.drop(columns=[ETIQUETA])
    y = df[ETIQUETA]
    return train_test_split(
        X, y, test_size=test_size, random_state=RANDOM_STATE, stratify=y
    )


def ajustar_escalador(X_train: pd.DataFrame) -> StandardScaler:
    """Ajusta un escalador estándar sobre las características de entrenamiento."""
    scaler = StandardScaler()
    scaler.fit(X_train)
    return scaler


def preprocesar(X: pd.DataFrame, scaler: StandardScaler):
    """Aplica el escalado ya ajustado. Es la función `Preprocesar` del

    Algoritmo 1, usada tanto en entrenamiento como en inferencia en vivo.
    """
    return scaler.transform(X)
