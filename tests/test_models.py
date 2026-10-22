"""Pruebas unitarias para el módulo de modelos (src/models.py)."""

from src.models import (
    entrenar_random_forest,
    evaluar,
    guardar_artefacto_completo,
    MODELOS_DIR,
)
from src.preprocess import dividir, ajustar_escalador, preprocesar
from src.feature_schema import COLUMNAS_MODELO
import pandas as pd
import numpy as np


def test_entrenamiento_y_evaluacion_rf(dataset_pequeno):
    X_train, X_test, y_train, y_test = dividir(dataset_pequeno)
    scaler = ajustar_escalador(X_train)
    X_train_esc = preprocesar(X_train, scaler)
    X_test_esc = preprocesar(X_test, scaler)

    rf = entrenar_random_forest(X_train_esc, y_train)
    metricas = evaluar(rf, X_test_esc, y_test, "Random Forest Test")

    assert metricas["modelo"] == "Random Forest Test"
    assert 0.0 <= metricas["accuracy"] <= 1.0
    assert 0.0 <= metricas["tasa_falsos_positivos"] <= 1.0


def test_evaluar_con_una_sola_clase():
    """Verifica que labels=[0, 1] previene el error ravel() cuando y_test solo tiene 1 clase."""
    from unittest.mock import MagicMock
    modelo = MagicMock()
    modelo.predict.return_value = np.array([1, 1, 1])

    y_solo_unos = pd.Series([1, 1, 1])
    X_mock = np.zeros((3, len(COLUMNAS_MODELO)))

    metricas = evaluar(modelo, X_mock, y_solo_unos, "Mono-clase")
    assert metricas["recall"] == 1.0
    assert metricas["tasa_falsos_positivos"] == 0.0


def test_guardar_artefacto_completo():
    """El artefacto debe guardar y recargar modelo + scaler + columnas (round-trip real).

    Se usan estimadores reales (no mocks): joblib serializa vía pickle y un MagicMock
    no es serializable, además de que así se valida que el artefacto es funcional.
    """
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler

    X = np.random.default_rng(0).random((20, len(COLUMNAS_MODELO)))
    y = np.array([0, 1] * 10)
    scaler = StandardScaler().fit(X)
    modelo = RandomForestClassifier(n_estimators=5, random_state=0).fit(scaler.transform(X), y)

    ruta = guardar_artefacto_completo(modelo, scaler, COLUMNAS_MODELO, "test_model")
    try:
        assert ruta.exists()
        assert ruta.name.endswith(".joblib")
        artefacto = joblib.load(ruta)
        assert artefacto["columnas"] == COLUMNAS_MODELO
        assert hasattr(artefacto["modelo"], "predict")
        assert hasattr(artefacto["scaler"], "transform")
    finally:
        ruta.unlink()  # Limpieza
