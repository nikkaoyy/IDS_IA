"""Pruebas de integración para el pipeline del IDS (src/pipeline.py)."""

import pytest

from src.pipeline import inferir_ventana
from src.preprocess import dividir, ajustar_escalador
from src.models import entrenar_random_forest
from src.feature_schema import COLUMNAS_MODELO, VERSION_ESQUEMA


def _artefacto(dataset):
    X_train, _, y_train, _ = dividir(dataset)
    scaler = ajustar_escalador(X_train)
    rf = entrenar_random_forest(scaler.transform(X_train), y_train)
    return {
        "modelo": rf, "scaler": scaler, "columnas": COLUMNAS_MODELO,
        "version_esquema": VERSION_ESQUEMA,
    }


def test_inferir_ventana_acepta_nan_del_contrato(dataset_pequeno):
    ventana = dataset_pequeno.iloc[0][COLUMNAS_MODELO].to_dict()
    ventana["iat_std_ms"] = float("nan")
    assert inferir_ventana(ventana, _artefacto(dataset_pequeno)) in (0, 1)


def test_inferir_ventana_rechaza_ventana_incompleta(dataset_pequeno):
    ventana = dataset_pequeno.iloc[0][COLUMNAS_MODELO].to_dict()
    del ventana["tasa_syn"]
    with pytest.raises(ValueError, match="incompleta"):
        inferir_ventana(ventana, _artefacto(dataset_pequeno))


def test_inferir_ventana_rechaza_artefacto_de_otro_esquema(dataset_pequeno):
    artefacto = _artefacto(dataset_pequeno) | {"version_esquema": "0"}
    with pytest.raises(ValueError, match="Esquema"):
        inferir_ventana(dataset_pequeno.iloc[0][COLUMNAS_MODELO].to_dict(), artefacto)
    sin_columnas = _artefacto(dataset_pequeno) | {"columnas": COLUMNAS_MODELO[:-1]}
    with pytest.raises(ValueError, match="columnas"):
        inferir_ventana(dataset_pequeno.iloc[0][COLUMNAS_MODELO].to_dict(), sin_columnas)


def test_importar_pipeline_no_configura_logging():
    import subprocess
    import sys

    codigo = "import logging, src.pipeline; print(len(logging.getLogger().handlers))"
    salida = subprocess.run([sys.executable, "-c", codigo], capture_output=True, text=True, check=True)
    assert salida.stdout.strip() == "0"


def test_experimento_reporta_evasion_y_guarda_artefacto(tmp_path, monkeypatch):
    """El experimento mide evasión sobre maliciosas y persiste el artefacto de inferencia."""
    import joblib
    import src.models
    import src.pipeline
    from src.data import generar_dataset_sintetico

    monkeypatch.setattr(src.models, "MODELOS_DIR", tmp_path)
    monkeypatch.setattr(src.pipeline, "cargar_dataset", lambda: generar_dataset_sintetico(n=400))

    salida = src.pipeline.ejecutar_experimento_completo()

    assert len(salida["evasion"]) == 6
    assert salida["evasion"]["recall_bajo_ataque"].between(0, 1).all()
    artefacto = joblib.load(tmp_path / "xgboost_artefacto.joblib")
    assert artefacto["columnas"] == COLUMNAS_MODELO
    assert artefacto["scaler"] is not None
