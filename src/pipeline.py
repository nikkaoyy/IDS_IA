"""
Orquestador del pipeline (Algoritmo 1 del documento del proyecto).

Implementa el flujo de inferencia, aplicado a cada ventana cerrada de `src/ventanas.py`:
    h <- ExtraerHuella(ventana)
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
import numpy as np
import pandas as pd

from .data import cargar_dataset, ruta_dataset_disponible
from .preprocess import dividir, ajustar_escalador, preprocesar
from .models import (
    entrenar_random_forest,
    entrenar_xgboost,
    evaluar,
    guardar_artefacto_completo,
    guardar_modelo,
    validar_artefacto,
)
from .attack_simulator import NIVELES_EVASION, evaluar_bajo_ataque, simular_evasion
from .feature_schema import COLUMNAS_MODELO

logger = logging.getLogger("ids_pipeline")


def registrar_alerta(huella: dict, etiqueta: int) -> None:
    logger.warning("ALERTA: tráfico malicioso detectado. Huella: %s", huella)


def aplicar_mitigacion(huella: dict) -> None:
    mac = huella.get("mac", "desconocida")
    logger.info("MITIGACIÓN: dispositivo %s marcado para cuarentena/bloqueo temporal.", mac)


def inferir_ventana(ventana: dict, artefacto: dict) -> int:
    """Aplica el Algoritmo 1 a una fila cerrada de `AgregadorVentanas` (OE2).

    No completa datos: una ventana incompleta es un error, no un vector con ceros. Los
    NaN del contrato sí son válidos.

    Raises:
        ValueError: Si el artefacto no es válido o faltan columnas en la ventana.
    """
    validar_artefacto(artefacto)
    columnas = artefacto["columnas"]
    faltantes = [c for c in columnas if c not in ventana]
    if faltantes:
        raise ValueError(f"Ventana incompleta, faltan: {faltantes}")
    x = pd.DataFrame([{c: ventana[c] for c in columnas}], columns=columnas, dtype=float)
    y = int(artefacto["modelo"].predict(preprocesar(x, artefacto["scaler"]))[0])
    if y == 1:
        registrar_alerta(ventana, y)
        aplicar_mitigacion(ventana)
    return y


def desglose_por_tipo(
    tipo_ataque: pd.Series,
    y_real: pd.Series,
    predicciones: dict[str, np.ndarray],
) -> pd.DataFrame:
    """Tasa de acierto por tipo de ataque sobre el conjunto de prueba.

    Para el tráfico benigno la tasa es especificidad (cuánto se respeta lo legítimo);
    para cada ataque es el recall (cuánto de ese ataque se detecta). Muestra el punto
    débil real de un IDS, que la exactitud global esconde.
    """
    tabla = pd.DataFrame({"tipo_ataque": tipo_ataque.to_numpy(), "real": y_real.to_numpy()})
    for nombre, pred in predicciones.items():
        tabla[nombre] = pred
    filas = []
    for tipo, grupo in tabla.groupby("tipo_ataque", sort=False):
        fila: dict[str, object] = {"tipo_ataque": tipo, "muestras": len(grupo)}
        for nombre in predicciones:
            fila[nombre] = float((grupo[nombre] == grupo["real"]).mean())
        filas.append(fila)
    return pd.DataFrame(filas)


def ejecutar_experimento_completo() -> dict:
    """Fases 2 a 4 de la metodología: datos, modelado, evaluación y
    simulación de ataque. Devuelve un resumen para inspección/registro."""
    logger.info("Fase 2 — Cargando conjunto de datos...")
    df = cargar_dataset()
    origen = ruta_dataset_disponible()
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

    logger.info("Fase 4 — Simulando evasión de la huella digital...")
    X_malicioso = X_test[y_test == 1]
    X_legitimo = X_test[y_test == 0]
    filas_evasion = []
    for nombre, modelo in (("Random Forest", modelo_rf), ("XGBoost", modelo_xgb)):
        def predecir(X: pd.DataFrame, m=modelo) -> np.ndarray:
            return m.predict(preprocesar(X, scaler))

        def puntuar(X: pd.DataFrame, m=modelo) -> np.ndarray:
            return m.predict_proba(preprocesar(X, scaler))[:, 1]

        for nivel in NIVELES_EVASION:
            X_falso = simular_evasion(X_malicioso, X_legitimo, nivel=nivel, puntuar=puntuar)
            filas_evasion.append({
                "modelo": nombre,
                "nivel": nivel,
                **evaluar_bajo_ataque(predecir, X_malicioso, X_falso),
            })
    evasion = pd.DataFrame(filas_evasion)

    columnas = list(X_train.columns)
    metadata = {"origen_datos": str(origen) if origen is not None else "sintético (respaldo)"}
    ruta_rf = guardar_modelo(modelo_rf, "random_forest")
    ruta_xgb = guardar_modelo(modelo_xgb, "xgboost")
    guardar_artefacto_completo(modelo_rf, scaler, columnas, "random_forest", metadata)
    guardar_artefacto_completo(modelo_xgb, scaler, columnas, "xgboost", metadata)
    logger.info("Modelos guardados en %s y %s", ruta_rf, ruta_xgb)

    desglose = None
    if "tipo_ataque" in df.columns:
        desglose = desglose_por_tipo(
            df.loc[y_test.index, "tipo_ataque"],
            y_test,
            {
                "Random Forest": modelo_rf.predict(X_test_esc),
                "XGBoost": modelo_xgb.predict(X_test_esc),
            },
        )

    return {
        "origen_datos": metadata["origen_datos"],
        "filas": int(len(df)),
        "resultados": resultados,
        "detalle_por_ataque": desglose,
        "evasion": evasion,
        "modelo_rf": modelo_rf,
        "modelo_xgb": modelo_xgb,
        "scaler": scaler,
        "columnas": columnas,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    salida = ejecutar_experimento_completo()
    print(f"\nOrigen de datos: {salida['origen_datos']} ({salida['filas']} filas)")
    print("\n=== Comparación Random Forest vs. XGBoost ===")
    print(salida["resultados"].set_index("modelo").round(4).to_string())
    print("\n=== Evasión de la huella digital (muestras maliciosas de test) ===")
    print(salida["evasion"].set_index(["modelo", "nivel"]).round(4).to_string())
    if salida["detalle_por_ataque"] is not None:
        print("\n=== Acierto por tipo de tráfico (test) ===")
        print(salida["detalle_por_ataque"].set_index("tipo_ataque").round(4).to_string())
