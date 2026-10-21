"""
Módulo de clasificación (bloque "Clasificación (Random Forest / XGBoost)"
de la Fig. 1). Entrena, evalúa y persiste ambos modelos para su comparación
(objetivo específico 2 y Fase 3 de la metodología).
"""

from __future__ import annotations
from pathlib import Path
from datetime import datetime
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score,
)
from xgboost import XGBClassifier

from .data import RANDOM_STATE

MODELOS_DIR = Path(__file__).resolve().parent.parent / "models"


def entrenar_random_forest(X_train, y_train) -> RandomForestClassifier:
    modelo = RandomForestClassifier(
        n_estimators=200, max_depth=None, random_state=RANDOM_STATE, n_jobs=-1, class_weight="balanced"
    )
    modelo.fit(X_train, y_train)
    return modelo


def entrenar_xgboost(X_train, y_train) -> XGBClassifier:
    # Estimación de desbalance para scale_pos_weight
    n_neg = (y_train == 0).sum()
    n_pos = (y_train == 1).sum()
    scale_pos = float(n_neg / n_pos) if n_pos > 0 else 1.0

    modelo = XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        eval_metric="logloss", scale_pos_weight=scale_pos,
        random_state=RANDOM_STATE, n_jobs=-1,
    )
    modelo.fit(X_train, y_train)
    return modelo


def evaluar(modelo, X_test, y_test, nombre: str) -> dict:
    y_pred = modelo.predict(X_test)
    # labels=[0, 1] asegura que la matriz de confusión siempre devuelva 4 elementos (tn, fp, fn, tp)
    # incluso si y_test contiene solo una clase (e.g. en evaluación de ataque con y todo = 1).
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    metricas = {
        "modelo": nombre,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall": recall_score(y_test, y_pred, zero_division=0),
        "f1_score": f1_score(y_test, y_pred, zero_division=0),
        "tasa_falsos_positivos": fpr,
    }

    # ROC-AUC (solo si hay más de una clase en el conjunto de prueba)
    if len(set(y_test)) > 1 and hasattr(modelo, "predict_proba"):
        try:
            y_prob = modelo.predict_proba(X_test)[:, 1]
            metricas["roc_auc"] = roc_auc_score(y_test, y_prob)
        except Exception:
            metricas["roc_auc"] = None
    else:
        metricas["roc_auc"] = None

    return metricas


def guardar_modelo(modelo, nombre: str) -> Path:
    MODELOS_DIR.mkdir(parents=True, exist_ok=True)
    ruta = MODELOS_DIR / f"{nombre}.joblib"
    joblib.dump(modelo, ruta)
    return ruta


def guardar_artefacto_completo(modelo, scaler, columnas: list[str], nombre: str, metadata: dict | None = None) -> Path:
    """Guarda modelo + scaler + columnas + metadata como un único artefacto autocontenido."""
    MODELOS_DIR.mkdir(parents=True, exist_ok=True)
    ruta = MODELOS_DIR / f"{nombre}_artefacto.joblib"
    artefacto = {
        "modelo": modelo,
        "scaler": scaler,
        "columnas": columnas,
        "metadata": metadata or {},
        "timestamp": datetime.now().isoformat(),
        "version": "0.1.0",
    }
    joblib.dump(artefacto, ruta)
    return ruta


def cargar_modelo(nombre: str):
    ruta = MODELOS_DIR / f"{nombre}.joblib"
    return joblib.load(ruta)
