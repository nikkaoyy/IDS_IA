"""
Módulo de preprocesamiento (bloque "Preprocesamiento y escalado" de la Fig. 1
y función `Preprocesar(h)` del Algoritmo 1).
"""

from __future__ import annotations
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

from .data import RANDOM_STATE
from .feature_schema import COLUMNAS_MODELO, ETIQUETA


def grupos_por_dispositivo(df: pd.DataFrame) -> pd.Series | None:
    """Devuelve el dispositivo (MAC) de cada ventana, o None si no hay columna `grupo`.

    `grupo` vale `mac#ventana` y es único por fila, así que no sirve como grupo: la
    unidad independiente es el dispositivo, cuyas ventanas están muy correlacionadas.
    """
    if "grupo" not in df.columns:
        return None
    return df["grupo"].astype(str).str.rsplit("#", n=1).str[0]


def grupos_de_division(df: pd.DataFrame) -> pd.Series | None:
    """Unidad independiente del reparto: la sesión si existe; si no, el dispositivo.

    Dentro de una sesión comparten reloj, fondo y atacantes, así que partirla filtraría.
    """
    if "sesion" in df.columns:
        return df["sesion"].astype(str)
    return grupos_por_dispositivo(df)


def dividir(df: pd.DataFrame, test_size: float = 0.25):
    """Divide el dataset en entrenamiento y prueba estratificados, sin fuga (Fase 2).

    Con columna `sesion` ninguna sesión aparece en ambos conjuntos; con solo `grupo`,
    ningún dispositivo; sin ninguna se divide por fila. X se recorta al contrato canónico
    (`COLUMNAS_MODELO`): la traza y la identidad son metadatos de evaluación
    y no deben entrar al escalador ni al modelo.
    """
    X = df[COLUMNAS_MODELO]
    y = df[ETIQUETA]
    grupos = grupos_de_division(df)
    if grupos is None:
        return train_test_split(
            X, y, test_size=test_size, random_state=RANDOM_STATE, stratify=y
        )
    divisor = StratifiedGroupKFold(
        n_splits=round(1 / test_size), shuffle=True, random_state=RANDOM_STATE
    )
    idx_train, idx_test = next(divisor.split(X, y, grupos))
    return X.iloc[idx_train], X.iloc[idx_test], y.iloc[idx_train], y.iloc[idx_test]


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
