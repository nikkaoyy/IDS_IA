#!/usr/bin/env python3
"""
Baseline de reglas (etapa E1.5): stump y árbol de profundidad 2, por ataque.

Es referencia, no puerta de calidad: si una regla de un umbral detecta un ataque, ese
ataque sigue siendo trivial en este laboratorio. Reparte por sesión. La salida se guarda
en `reports/baseline_reglas.json`.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import pandas as pd  # noqa: E402
from sklearn.tree import DecisionTreeClassifier, export_text  # noqa: E402

from src.data import RANDOM_STATE, RUTA_DATASET_LAB  # noqa: E402
from src.feature_schema import COLUMNAS_MODELO, ETIQUETA  # noqa: E402
from src.preprocess import dividir  # noqa: E402


def calcular_baseline(df: pd.DataFrame) -> list[dict]:
    """Recall por ataque y FPR de cada regla, entrenada solo contra ese ataque."""
    X_train, X_test, y_train, y_test = dividir(df)
    tipos_tr, tipos_te = df.loc[X_train.index, "tipo_ataque"], df.loc[X_test.index, "tipo_ataque"]
    resultados: list[dict] = []
    for tipo in sorted(t for t in df["tipo_ataque"].unique() if t != "normal"):
        filas_tr = (y_train == 0) | (tipos_tr == tipo)
        filas_te = (y_test == 0) | (tipos_te == tipo)
        for profundidad in (1, 2):
            arbol = DecisionTreeClassifier(
                max_depth=profundidad, class_weight="balanced", random_state=RANDOM_STATE
            ).fit(X_train[filas_tr], y_train[filas_tr])
            pred = arbol.predict(X_test[filas_te])
            real = y_test[filas_te].to_numpy()
            resultados.append({
                "ataque": tipo,
                "profundidad": profundidad,
                "recall": float(pred[real == 1].mean()) if (real == 1).any() else None,
                "fpr": float(pred[real == 0].mean()),
                "muestras_ataque_test": int((real == 1).sum()),
                "regla": export_text(arbol, feature_names=COLUMNAS_MODELO).split("\n")[0].strip("|- "),
            })
    return resultados


def main() -> int:
    df = pd.read_csv(RUTA_DATASET_LAB)
    resultados = calcular_baseline(df)
    salida = _RAIZ / "reports" / "baseline_reglas.json"
    salida.parent.mkdir(exist_ok=True)
    salida.write_text(json.dumps(resultados, indent=2, ensure_ascii=False))
    print(pd.DataFrame(resultados).round(4).to_string(index=False))
    print(f"\nPositivos totales: {int(df[ETIQUETA].sum())}. Reporte: {salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
