"""
Orquestador del pipeline (Algoritmo 1 del documento del proyecto).

Implementa el flujo de inferencia por trama:
    h <- ExtraerHuella(t)
    [si modo ataque: h <- PerturbarHuella(h)]
    x <- Preprocesar(h)
    y <- M.predict(x)
    si y == malicioso: RegistrarAlerta(h, y); AplicarMitigacion(h)
    devolver y

A nivel de módulo también expone `ejecutar_experimento_completo`, que corre
las Fases 2-4 de la metodología de punta a punta (datos -> entrenamiento ->
evaluación -> simulación de ataque) para validar el pipeline sin necesitar
todavía la captura en vivo.
"""

from __future__ import annotations
import logging
import pandas as pd

from .data import cargar_dataset
from .preprocess import dividir, ajustar_escalador, preprocesar
from .models import entrenar_random_forest, entrenar_xgboost, evaluar, guardar_modelo
from .attack_simulator import simular_ataque_spoofing
from .feature_schema import COLUMNAS_MODELO, mapear_huella_a_vector_modelo

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ids_pipeline")


def registrar_alerta(huella: dict, etiqueta: int) -> None:
    logger.warning("ALERTA: tráfico malicioso detectado. Huella: %s", huella)


def aplicar_mitigacion(huella: dict) -> None:
    mac = huella.get("mac_origen", "desconocida")
    logger.info("MITIGACIÓN: dispositivo %s marcado para cuarentena/bloqueo temporal.", mac)


def inferir(huella: dict, modelo, scaler, columnas: list[str] | None = None) -> int:
    """Aplica el Algoritmo 1 a una única huella digital ya extraída.

    Adapta la huella mediante el contrato de características si provino directamente
    del extractor IEEE 802.3.
    """
    cols = columnas or COLUMNAS_MODELO
    if any(col not in huella for col in cols):
        huella_vector = mapear_huella_a_vector_modelo(huella)
    else:
        huella_vector = huella

    x = pd.DataFrame([huella_vector])[cols]
    x_proc = preprocesar(x, scaler)
    y = int(modelo.predict(x_proc)[0])
    if y == 1:
        registrar_alerta(huella, y)
        aplicar_mitigacion(huella)
    return y


def ejecutar_experimento_completo() -> dict:
    """Fases 2 a 4 de la metodología: datos, modelado, evaluación y
    simulación de ataque. Devuelve un resumen para inspección/registro."""
    logger.info("Fase 2 — Cargando conjunto de datos...")
    df = cargar_dataset()
    logger.info("Dataset: %s filas, %s columnas", *df.shape)

    X_train, X_test, y_train, y_test = dividir(df)
    scaler = ajustar_escalador(X_train)
    X_train_esc = preprocesar(X_train, scaler)
    X_test_esc = preprocesar(X_test, scaler)

    logger.info("Fase 3 — Entrenando Random Forest y XGBoost...")
    modelo_rf = entrenar_random_forest(X_train_esc, y_train)
    modelo_xgb = entrenar_xgboost(X_train_esc, y_train)

    logger.info("Fase 4 — Evaluando modelos...")
    resultados = pd.DataFrame([
        evaluar(modelo_rf, X_test_esc, y_test, "Random Forest"),
        evaluar(modelo_xgb, X_test_esc, y_test, "XGBoost"),
    ])

    logger.info("Fase 4 — Simulando ataque de suplantación de huella digital...")
    idx_legitimo = y_test[y_test == 0].index
    X_legitimo_test = X_test.loc[idx_legitimo]
    X_ataque = simular_ataque_spoofing(X_legitimo_test)
    X_ataque_esc = preprocesar(X_ataque, scaler)
    y_ataque_esperado = pd.Series(1, index=X_ataque.index)

    deteccion = pd.DataFrame([
        evaluar(modelo_rf, X_ataque_esc, y_ataque_esperado, "Random Forest (bajo ataque)"),
        evaluar(modelo_xgb, X_ataque_esc, y_ataque_esperado, "XGBoost (bajo ataque)"),
    ])

    ruta_rf = guardar_modelo(modelo_rf, "random_forest")
    ruta_xgb = guardar_modelo(modelo_xgb, "xgboost")
    logger.info("Modelos guardados en %s y %s", ruta_rf, ruta_xgb)

    return {
        "resultados": resultados,
        "deteccion_bajo_ataque": deteccion,
        "modelo_rf": modelo_rf,
        "modelo_xgb": modelo_xgb,
        "scaler": scaler,
        "columnas": list(X_train.columns),
    }


if __name__ == "__main__":
    salida = ejecutar_experimento_completo()
    print("\n=== Comparación Random Forest vs. XGBoost ===")
    print(salida["resultados"].set_index("modelo").round(4))
    print("\n=== Tasa de detección bajo ataque simulado (recall) ===")
    print(
        salida["deteccion_bajo_ataque"]
        .set_index("modelo")[["recall"]]
        .rename(columns={"recall": "tasa_deteccion_ataque"})
        .round(4)
    )
