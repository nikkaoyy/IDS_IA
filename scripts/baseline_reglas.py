#!/usr/bin/env python3
"""
Baseline de reglas (etapa E1): stump y árbol de profundidad 2, por ataque.

Desde el bloque 3 de E1 es también la **puerta de separabilidad**: si una regla de uno o
dos umbrales separa un ataque, el dataset no sirve para medir un clasificador. Cada
regla se entrena solo contra un ataque (benigno + ese ataque) y se evalúa en sesiones no
vistas, en los `N_FOLDS` repartos por sesión de `StratifiedGroupKFold` (el fold 0 es el
reparto de `src.preprocess.dividir`, el único que usaba la versión anterior).

Métrica de la puerta: exactitud balanceada = (recall + 1 - FPR) / 2. La exactitud simple
no sirve con ~95 % de ventanas benignas: un clasificador constante ya pasaría de 0,9.
Un ataque cumple si la exactitud balanceada máxima entre stump y profundidad 2, y entre
todos los folds, es <= `UMBRAL_PUERTA`: con pocas sesiones de prueba un solo reparto
puede pasar por suerte. La salida se guarda en `reports/baseline_reglas.json`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import pandas as pd  # noqa: E402
from sklearn.model_selection import StratifiedGroupKFold  # noqa: E402
from sklearn.tree import DecisionTreeClassifier, export_text  # noqa: E402

from src.data import RANDOM_STATE, RUTA_DATASET_LAB, verificar_holdout  # noqa: E402
from src.feature_schema import COLUMNAS_MODELO, ETIQUETA  # noqa: E402
from src.preprocess import grupos_de_division  # noqa: E402

UMBRAL_PUERTA = 0.85
PROFUNDIDADES = (1, 2)
N_FOLDS = 4  # mismo reparto que `dividir(test_size=0.25)`


def exactitud_balanceada(recall: float | None, fpr: float) -> float | None:
    """(recall + 1 - FPR) / 2; None si no hay positivos en prueba."""
    return None if recall is None else (recall + 1.0 - fpr) / 2.0


def _repartos(df: pd.DataFrame, n_folds: int) -> list[tuple]:
    """Repartos por sesión (o dispositivo) estratificados; el primero es el de `dividir`."""
    grupos = grupos_de_division(df)
    divisor = StratifiedGroupKFold(n_splits=n_folds, shuffle=True, random_state=RANDOM_STATE)
    return list(divisor.split(df[COLUMNAS_MODELO], df[ETIQUETA], grupos))


def calcular_baseline(df: pd.DataFrame, n_folds: int = N_FOLDS) -> list[dict]:
    """Recall, FPR y exactitud balanceada de cada regla, por ataque, profundidad y fold.

    Raises:
        HoldoutError: Si `df` contiene sesiones reservadas para el holdout de E2.
    """
    verificar_holdout(df)
    X, y = df[COLUMNAS_MODELO], df[ETIQUETA]  # noqa: N806
    tipos = df["tipo_ataque"]
    resultados: list[dict] = []
    for fold, (idx_tr, idx_te) in enumerate(_repartos(df, n_folds)):
        y_tr, y_te = y.iloc[idx_tr].to_numpy(), y.iloc[idx_te].to_numpy()
        t_tr, t_te = tipos.iloc[idx_tr].to_numpy(), tipos.iloc[idx_te].to_numpy()
        for tipo in sorted(t for t in tipos.unique() if t != "normal"):
            filas_tr = (y_tr == 0) | (t_tr == tipo)
            filas_te = (y_te == 0) | (t_te == tipo)
            real = y_te[filas_te]
            for profundidad in PROFUNDIDADES:
                arbol = DecisionTreeClassifier(
                    max_depth=profundidad, class_weight="balanced", random_state=RANDOM_STATE
                ).fit(X.iloc[idx_tr][filas_tr], y_tr[filas_tr])
                pred = arbol.predict(X.iloc[idx_te][filas_te])
                recall = float(pred[real == 1].mean()) if (real == 1).any() else None
                fpr = float(pred[real == 0].mean())
                resultados.append({
                    "ataque": tipo,
                    "profundidad": profundidad,
                    "fold": fold,
                    "recall": recall,
                    "fpr": fpr,
                    "exactitud_balanceada": exactitud_balanceada(recall, fpr),
                    "muestras_ataque_test": int((real == 1).sum()),
                    "regla": export_text(arbol, feature_names=COLUMNAS_MODELO).split("\n")[0].strip("|- "),
                })
    return resultados


def resumen_puerta(resultados: list[dict], umbral: float = UMBRAL_PUERTA) -> dict[str, dict]:
    """Por ataque: exactitud balanceada máxima (profundidad y fold) y si cumple la puerta."""
    resumen: dict[str, dict] = {}
    for r in resultados:
        if r["exactitud_balanceada"] is None:
            continue
        actual = resumen.setdefault(r["ataque"], {"exactitud_balanceada_max": -1.0, "por_fold": {}})
        fold = actual["por_fold"]
        fold[r["fold"]] = max(fold.get(r["fold"], -1.0), r["exactitud_balanceada"])
        if r["exactitud_balanceada"] > actual["exactitud_balanceada_max"]:
            actual.update(exactitud_balanceada_max=r["exactitud_balanceada"], profundidad=r["profundidad"],
                          fold=r["fold"], recall=r["recall"], fpr=r["fpr"], regla=r["regla"])
    for valores in resumen.values():
        valores["exactitud_balanceada_fold0"] = valores["por_fold"].get(0)
        valores["exactitud_balanceada_media"] = sum(valores["por_fold"].values()) / len(valores["por_fold"])
        valores["cumple"] = valores["exactitud_balanceada_max"] <= umbral
    return resumen


def muestra_para_puerta(df: pd.DataFrame, fraccion_benigno: float = 0.25,
                       semilla: int = RANDOM_STATE) -> pd.DataFrame:
    """Todas las ventanas de ataque y una fracción de las benignas de cada sesión.

    La exactitud balanceada no depende de la proporción de clases, así que submuestrear el
    benigno de forma uniforme por sesión conserva el veredicto y abarata la prueba.
    """
    benigno = df[df[ETIQUETA] == 0]
    if "sesion" in df.columns:
        benigno = benigno.groupby("sesion", group_keys=False).sample(frac=fraccion_benigno, random_state=semilla)
    else:
        benigno = benigno.sample(frac=fraccion_benigno, random_state=semilla)
    return pd.concat([df[df[ETIQUETA] == 1], benigno]).sort_index()


def _relativa(ruta: Path) -> str:
    """Ruta relativa a la raíz del repositorio si cae dentro; si no, tal cual."""
    try:
        return str(ruta.resolve().relative_to(_RAIZ))
    except ValueError:
        return str(ruta)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Baseline de reglas y puerta de separabilidad.")
    p.add_argument("csv", nargs="?", type=Path, default=RUTA_DATASET_LAB)
    p.add_argument("--salida", type=Path, default=_RAIZ / "reports" / "baseline_reglas.json")
    args = p.parse_args(argv)
    df = pd.read_csv(args.csv, low_memory=False)
    resultados = calcular_baseline(df)
    resumen = resumen_puerta(resultados)
    salida = args.salida
    salida.parent.mkdir(parents=True, exist_ok=True)
    salida.write_text(json.dumps(
        {"umbral_puerta": UMBRAL_PUERTA, "metrica": "exactitud_balanceada",
         "dataset": _relativa(args.csv), "n_folds": N_FOLDS, "puerta": resumen, "reglas": resultados},
        indent=2, ensure_ascii=False) + "\n")
    tabla = pd.DataFrame(resultados)
    print(tabla[tabla["fold"] == 0].drop(columns="fold").round(4).to_string(index=False))
    print(f"\nPuerta (exactitud balanceada máxima en {N_FOLDS} folds <= {UMBRAL_PUERTA}):")
    print(f"  {'ataque':14s} {'fold0':>6s} {'media':>6s} {'máx':>6s} {'recall':>6s} {'FPR':>6s}")
    for ataque, v in resumen.items():
        estado = "cumple" if v["cumple"] else "NO CUMPLE"
        print(f"  {ataque:14s} {v['exactitud_balanceada_fold0']:6.3f} {v['exactitud_balanceada_media']:6.3f} "
              f"{v['exactitud_balanceada_max']:6.3f} {v['recall']:6.3f} {v['fpr']:6.3f}  {estado}  ({v['regla']})")
    print(f"\nPositivos totales: {int(df[ETIQUETA].sum())}. Reporte: {salida}")
    return 0 if all(v["cumple"] for v in resumen.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
