"""Pruebas unitarias para el módulo de preprocesamiento (src/preprocess.py)."""

from src.preprocess import ajustar_escalador, dividir, grupos_por_dispositivo, preprocesar
from src.feature_schema import COLUMNAS_MODELO, ETIQUETA


def test_dividir_proporciones(dataset_pequeno):
    X_train, X_test, y_train, y_test = dividir(dataset_pequeno, test_size=0.20)
    assert len(X_train) == 80
    assert len(X_test) == 20
    assert ETIQUETA not in X_train.columns
    assert len(y_train) == 80
    assert len(y_test) == 20


def test_dividir_ignora_metadatos_de_evaluacion(dataset_pequeno):
    """El dataset propio trae tipo_ataque, capa y grupo: no deben entrar al modelo."""
    grupos = [f"mac{i}#0" for i in range(len(dataset_pequeno))]
    df = dataset_pequeno.assign(tipo_ataque="benigno", capa="ninguna", grupo=grupos)
    X_train, _, _, _ = dividir(df, test_size=0.20)
    assert list(X_train.columns) == COLUMNAS_MODELO


def test_dividir_no_comparte_dispositivos_entre_train_y_test(dataset_pequeno):
    """Las ventanas de una MAC deben quedar todas del mismo lado (sin fuga)."""
    grupos = [f"mac{i % 12}#{i}" for i in range(len(dataset_pequeno))]
    df = dataset_pequeno.assign(grupo=grupos)
    X_train, X_test, _, _ = dividir(df)
    macs = grupos_por_dispositivo(df)
    assert not set(macs.loc[X_train.index]) & set(macs.loc[X_test.index])
    assert len(X_test) > 0


def test_escalador_ajuste_y_transformacion(dataset_pequeno):
    X_train, X_test, _, _ = dividir(dataset_pequeno)
    scaler = ajustar_escalador(X_train)
    X_proc = preprocesar(X_test, scaler)
    assert X_proc.shape == X_test.shape


def test_dividir_no_comparte_sesiones_entre_train_y_test(dataset_pequeno):
    sesiones = [f"s{i % 8}" for i in range(len(dataset_pequeno))]
    df = dataset_pequeno.assign(sesion=sesiones, grupo=[f"m#{i}" for i in range(len(sesiones))])
    X_train, X_test, _, _ = dividir(df)
    assert not set(df.loc[X_train.index, "sesion"]) & set(df.loc[X_test.index, "sesion"])
