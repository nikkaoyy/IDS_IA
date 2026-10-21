"""Pruebas de integración para el pipeline del IDS (src/pipeline.py)."""

from src.pipeline import inferir
from src.preprocess import dividir, ajustar_escalador
from src.models import entrenar_random_forest
from src.feature_schema import COLUMNAS_MODELO


def test_inferir_desde_huella_cruda_incompleta(dataset_pequeno, vector_huella_cruda):
    """Prueba que inferir() puede procesar una huella que no tenga columnas de capa 3-4

    gracias al adaptador de contrato de características.
    """
    X_train, _, y_train, _ = dividir(dataset_pequeno)
    scaler = ajustar_escalador(X_train)
    X_train_esc = scaler.transform(X_train)

    rf = entrenar_random_forest(X_train_esc, y_train)

    prediccion = inferir(
        huella=vector_huella_cruda,
        modelo=rf,
        scaler=scaler,
        columnas=COLUMNAS_MODELO,
    )

    assert prediccion in (0, 1)
