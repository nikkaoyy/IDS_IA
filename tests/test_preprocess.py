"""Pruebas unitarias para el módulo de preprocesamiento (src/preprocess.py)."""

from src.preprocess import dividir, ajustar_escalador, preprocesar
from src.feature_schema import ETIQUETA


def test_dividir_proporciones(dataset_pequeno):
    X_train, X_test, y_train, y_test = dividir(dataset_pequeno, test_size=0.20)
    assert len(X_train) == 80
    assert len(X_test) == 20
    assert ETIQUETA not in X_train.columns
    assert len(y_train) == 80
    assert len(y_test) == 20


def test_escalador_ajuste_y_transformacion(dataset_pequeno):
    X_train, X_test, _, _ = dividir(dataset_pequeno)
    scaler = ajustar_escalador(X_train)
    X_proc = preprocesar(X_test, scaler)
    assert X_proc.shape == X_test.shape
