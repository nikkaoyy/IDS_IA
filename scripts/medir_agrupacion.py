#!/usr/bin/env python3
"""
Medición para el addendum del §4.3 del informe de Fase 1 (etapa E1, bloque 5).

El §4.3 radicado afirma que la validación agrupada por `grupo` evita la fuga. En el código
`grupo` vale `mac#ventana` y es único por fila (`src/preprocess.py`, docstring de
`grupos_por_dispositivo`), así que agrupar por él equivale a no agrupar. Este script mide
la diferencia real entre cuatro repartos, con los modelos de `src/models.py`:

- `sin_agrupar`: StratifiedKFold por fila.
- `grupo`: StratifiedGroupKFold por `grupo` (lo que describía el informe).
- `dispositivo`: StratifiedGroupKFold por MAC.
- `sesion`: StratifiedGroupKFold por sesión (lo que hace hoy `dividir`).

Escribe `reports/agrupacion_4_3.json`.

Uso:
    python scripts/medir_agrupacion.py [data/dataset_lab.csv]
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import balanced_accuracy_score, confusion_matrix, f1_score  # noqa: E402
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold  # noqa: E402

from src.data import RANDOM_STATE, RUTA_DATASET_LAB, verificar_holdout  # noqa: E402
from src.feature_schema import COLUMNAS_MODELO, ETIQUETA  # noqa: E402
from src.models import entrenar_random_forest, entrenar_xgboost  # noqa: E402
from src.preprocess import grupos_por_dispositivo  # noqa: E402

N_FOLDS = 4
# Equivalentes actuales de las variables que cita el §4.3: `tiempo_entre_tramas_ms` es hoy
# el IAT por MAC; `oui_frecuente` salió del contrato en la versión 2.0 del esquema.
VARIABLES_4_3 = ["iat_media_ms", "iat_std_ms"]
MODELOS = {"random_forest": entrenar_random_forest, "xgboost": entrenar_xgboost}


def repartos(df: pd.DataFrame) -> dict[str, list[tuple[np.ndarray, np.ndarray]]]:
    """Índices de los cuatro esquemas de validación, todos estratificados por etiqueta."""
    X, y = df[COLUMNAS_MODELO], df[ETIQUETA]  # noqa: N806
    por_fila = StratifiedKFold(N_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    por_grupo = StratifiedGroupKFold(N_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    return {
        "sin_agrupar": list(por_fila.split(X, y)),
        "grupo": list(por_grupo.split(X, y, df["grupo"])),
        "dispositivo": list(por_grupo.split(X, y, grupos_por_dispositivo(df))),
        "sesion": list(por_grupo.split(X, y, df["sesion"])),
    }


def _metricas(y: np.ndarray, pred: np.ndarray) -> dict[str, float]:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "exactitud": float((tp + tn) / len(y)),
        "exactitud_balanceada": float(balanced_accuracy_score(y, pred)),
        "recall": float(tp / (tp + fn)) if tp + fn else float("nan"),
        "fpr": float(fp / (fp + tn)) if fp + tn else float("nan"),
        "f1": float(f1_score(y, pred, zero_division=0)),
    }


def medir(df: pd.DataFrame) -> dict:
    """Métricas medias (y desviación) por esquema y modelo, más importancias del RF."""
    verificar_holdout(df)
    X, y = df[COLUMNAS_MODELO], df[ETIQUETA].to_numpy()  # noqa: N806
    salida: dict = {
        "filas": int(len(df)),
        "grupos_unicos": int(df["grupo"].nunique()),
        "dispositivos": int(grupos_por_dispositivo(df).nunique()),
        "sesiones": int(df["sesion"].nunique()),
        "n_folds": N_FOLDS,
        "esquemas": {},
    }
    for esquema, folds in repartos(df).items():
        resultado: dict = {}
        for nombre, entrenar in MODELOS.items():
            por_fold, importancias = [], []
            for idx_tr, idx_te in folds:
                modelo = entrenar(X.iloc[idx_tr], y[idx_tr])
                por_fold.append(_metricas(y[idx_te], modelo.predict(X.iloc[idx_te])))
                if nombre == "random_forest":
                    importancias.append(modelo.feature_importances_)
            tabla = pd.DataFrame(por_fold)
            resultado[nombre] = {
                "media": tabla.mean().round(4).to_dict(),
                "desviacion": tabla.std(ddof=1).round(4).to_dict(),
            }
            if importancias:
                imp = pd.Series(np.mean(importancias, axis=0), index=COLUMNAS_MODELO).sort_values(ascending=False)
                rango = {c: int(i) + 1 for i, c in enumerate(imp.index)}
                resultado[nombre]["importancia"] = {
                    c: {"valor": round(float(imp[c]), 4), "puesto": rango[c]} for c in VARIABLES_4_3
                }
                resultado[nombre]["top5"] = {c: round(float(v), 4) for c, v in imp.head(5).items()}
        salida["esquemas"][esquema] = resultado
    return salida


def main() -> int:
    ruta = Path(sys.argv[1]) if len(sys.argv) > 1 else RUTA_DATASET_LAB
    inicio = time.time()
    resultado = medir(pd.read_csv(ruta, low_memory=False))
    try:
        resultado["dataset"] = str(ruta.resolve().relative_to(_RAIZ))
    except ValueError:
        resultado["dataset"] = str(ruta)
    resultado["segundos"] = round(time.time() - inicio, 1)
    destino = _RAIZ / "reports" / "agrupacion_4_3.json"
    destino.write_text(json.dumps(resultado, indent=2, ensure_ascii=False) + "\n")
    for esquema, r in resultado["esquemas"].items():
        for modelo, v in r.items():
            m = v["media"]
            print(f"{esquema:12s} {modelo:14s} exact {m['exactitud']:.4f}  EB {m['exactitud_balanceada']:.4f}  "
                  f"recall {m['recall']:.4f}  FPR {m['fpr']:.4f}  F1 {m['f1']:.4f}")
    print(f"Reporte: {destino} ({resultado['segundos']} s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
