#!/usr/bin/env python3
"""
Ablaciones y multiclase de E2 (OE1, OE2, OE3): ¿qué aprende el clasificador?

1. Ablación por conjunto de características: capa 2 (`FEATURES_CAPA2`), capas 3-4
   (`FEATURES_TCP` + `FEATURES_LARGAS`) y completo (`COLUMNAS_MODELO`).
2. Leave-one-attack-out (LOAO): seis entrenamientos, cada uno sin ninguna fila de los
   episodios de un tipo de ataque (ni siquiera sus ventanas ambiguas), midiendo el recall por
   episodio del tipo excluido. Si cae a cero, el modelo aprende el catálogo del generador y
   no una huella general de «ataque».
3. Multiclase por `tipo_ataque` y por `capa` (vistas por ventana y por episodio).
4. Importancia por permutación (no por impureza): por característica y por familia, medida
   como caída de PR-AUC y de recall por episodio en el umbral del fold.

Todo con el reparto agrupado por sesión y el umbral anidado de `src/evaluacion.py`, con los
mismos parámetros que `configs/e2.json` (bloque `ablaciones`: modelos y semillas).

Uso:
    python scripts/ablaciones.py --config configs/e2.json [--partes ablacion,loao,multiclase,permutacion]
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    recall_score,
)
from sklearn.utils.class_weight import compute_sample_weight  # noqa: E402
from xgboost import XGBClassifier  # noqa: E402

from scripts.evaluar import (  # noqa: E402
    cargar_dataset_estricto,
    commit_actual,
    escribir_json,
    fmt_ic,
    leer_config,
    ruta_proyecto,
)
from scripts.lab.ficha_dataset import sha256_archivo  # noqa: E402
from src import evaluacion as ev  # noqa: E402
from src.feature_schema import (  # noqa: E402
    COLUMNAS_MODELO,
    ETIQUETA,
    FEATURES_ARP,
    FEATURES_CAPA2,
    FEATURES_DNS,
    FEATURES_GLOBALES,
    FEATURES_LARGAS,
    FEATURES_TCP,
)
from src.models import N_HILOS_XGB, entrenar_random_forest  # noqa: E402
from src.preprocess import ajustar_escalador, preprocesar  # noqa: E402

logger = logging.getLogger("ablaciones")

CONJUNTOS: dict[str, list[str]] = {
    "capa2": list(FEATURES_CAPA2),
    "capas3_4": list(FEATURES_TCP) + list(FEATURES_LARGAS),
    "completo": list(COLUMNAS_MODELO),
}
FAMILIAS: dict[str, list[str]] = {
    "capa2": list(FEATURES_CAPA2), "arp": list(FEATURES_ARP), "tcp": list(FEATURES_TCP),
    "dns": list(FEATURES_DNS), "largas_60s": list(FEATURES_LARGAS), "globales": list(FEATURES_GLOBALES),
}
CLASE_BENIGNA = {"tipo_ataque": "normal", "capa": "ninguna"}
PARTES = ("ablacion", "loao", "multiclase", "permutacion")
N_REPETICIONES_PERMUTACION = 5


def _resumen_corto(r: dict) -> dict:
    """Lo que se compara entre ablaciones: las vistas que deciden y la referencia por ventana."""
    return {
        "recall_episodios": r["episodios"]["recall"],
        "recall_atacantes": r["atacantes"]["recall"],
        "recall_episodios_por_tipo": r["episodios"]["por_tipo"],
        "falsas_alarmas_por_dispositivo_dia": r["dispositivos"]["falsas_alarmas_por_dispositivo_dia"],
        "tiempo_deteccion_s_mediana": r["episodios"]["tiempo_deteccion_s_mediana"],
        "pr_auc_ventana": r["ventanas_referencia"]["pr_auc"],
    }


def _predecir(df: pd.DataFrame, modelo: str, cfg: dict, columnas: Sequence[str] = COLUMNAS_MODELO,
              excluir: pd.Series | None = None) -> list[ev.PrediccionesFueraDeFold]:
    return [
        ev.predecir_fuera_de_fold(
            df, modelo, int(s), int(cfg["n_folds"]), int(cfg["n_folds_internos"]),
            float(cfg["objetivo_falsas_alarmas_dispositivo_dia"]), columnas=columnas,
            excluir_de_entrenamiento=excluir,
        )
        for s in cfg["ablaciones"]["semillas"]
    ]


def tipo_de_episodio(df: pd.DataFrame) -> pd.Series:
    """Tipo de ataque de cada fila según su episodio (vacío si no pertenece a ninguno).

    Las ventanas ambiguas de un episodio llevan `tipo_ataque = normal`; con esto se sabe a qué
    ataque pertenecen sus tramas.
    """
    tipos = (df[df[ETIQUETA] == 1].groupby(["sesion", "episodio"])["tipo_ataque"]
             .agg(lambda s: s.mode().iat[0]).rename("_tipo_ep"))
    return df[["sesion", "episodio"]].join(tipos, on=["sesion", "episodio"])["_tipo_ep"].fillna("")


# --------------------------------------------------------------------------------------------
# 1 y 2. Ablación por características y leave-one-attack-out
# --------------------------------------------------------------------------------------------

def ablacion(df: pd.DataFrame, cfg: dict, cache: dict) -> dict:
    """Las tres ablaciones por conjunto de características, para cada modelo."""
    salida: dict = {}
    n_rep, sem_b = int(cfg["n_bootstrap"]), int(cfg["semilla_bootstrap"])
    for modelo in cfg["ablaciones"]["modelos"]:
        salida[modelo] = {}
        for nombre, columnas in CONJUNTOS.items():
            t0 = time.time()
            preds = _predecir(df, modelo, cfg, columnas)
            if nombre == "completo":
                cache[modelo] = preds
            salida[modelo][nombre] = {"n_columnas": len(columnas), "columnas": columnas,
                                      **_resumen_corto(ev.resumir(df, preds, n_rep, sem_b))}
            logger.info("ablación %s/%s: %.0f s", modelo, nombre, time.time() - t0)
    return salida


def loao(df: pd.DataFrame, cfg: dict, cache: dict) -> dict:
    """Seis entrenamientos sin un tipo de ataque; recall por episodio del tipo excluido."""
    n_rep, sem_b = int(cfg["n_bootstrap"]), int(cfg["semilla_bootstrap"])
    tipo_ep = tipo_de_episodio(df)
    tipos = sorted(df.loc[df[ETIQUETA] == 1, "tipo_ataque"].unique())
    salida: dict = {}
    for modelo in cfg["ablaciones"]["modelos"]:
        if modelo not in cache:
            cache[modelo] = _predecir(df, modelo, cfg)
        base = ev.resumir(df, cache[modelo], n_rep, sem_b)["episodios"]["por_tipo"]
        salida[modelo] = {}
        for tipo in tipos:
            t0 = time.time()
            excluir = (tipo_ep == tipo) | (df["tipo_ataque"] == tipo)
            r = ev.resumir(df, _predecir(df, modelo, cfg, excluir=excluir), n_rep, sem_b)
            otros = {t: v for t, v in r["episodios"]["por_tipo"].items() if t != tipo}
            salida[modelo][tipo] = {
                "filas_excluidas_de_entrenamiento": int(excluir.sum()),
                "recall_episodios_excluido": r["episodios"]["por_tipo"][tipo],
                "recall_episodios_excluido_con_entrenamiento": base[tipo],
                "caida": (base[tipo]["valor"] - r["episodios"]["por_tipo"][tipo]["valor"]),
                "recall_episodios_por_intensidad_excluido": {
                    k.split("/", 1)[1]: v for k, v in r["episodios"]["por_tipo_e_intensidad"].items()
                    if k.split("/", 1)[0] == tipo
                },
                "tiempo_deteccion_s_mediana_excluido": r["episodios"]["tiempo_deteccion_s_mediana_por_tipo"][tipo],
                "recall_episodios_otros_tipos": otros,
                "falsas_alarmas_por_dispositivo_dia": r["dispositivos"]["falsas_alarmas_por_dispositivo_dia"],
            }
            logger.info("LOAO %s/%s: recall %.3f (con entrenamiento %.3f), %.0f s", modelo, tipo,
                        r["episodios"]["por_tipo"][tipo]["valor"], base[tipo]["valor"], time.time() - t0)
    return salida


# --------------------------------------------------------------------------------------------
# 3. Multiclase
# --------------------------------------------------------------------------------------------

def _entrenar_multiclase(modelo: str, X: np.ndarray, y: np.ndarray, semilla: int):  # noqa: N803
    """RF tal cual (`class_weight='balanced'`); XGB con los mismos hiperparámetros que
    `entrenar_xgboost`, pero con pesos balanceados por clase en lugar de `scale_pos_weight`,
    que solo tiene sentido en binario."""
    if modelo == "random_forest":
        return entrenar_random_forest(X, y, semilla=semilla)
    m = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, eval_metric="mlogloss",
                      random_state=semilla, n_jobs=N_HILOS_XGB)
    return m.fit(X, y, sample_weight=compute_sample_weight("balanced", y))


def multiclase(df: pd.DataFrame, cfg: dict) -> dict:
    """Clasificación por tipo de ataque y por capa, por ventana y por episodio."""
    semilla = int(cfg["ablaciones"]["semillas"][0])
    repartos = ev.repartos_por_sesion(df, int(cfg["n_folds"]), semilla)
    X = df[list(COLUMNAS_MODELO)]  # noqa: N806
    etiquetadas = (df[ETIQUETA] == 1).to_numpy()
    salida: dict = {}
    for columna, benigna in CLASE_BENIGNA.items():
        clases = sorted(df[columna].astype(str).unique())
        y = df[columna].astype(str).map({c: i for i, c in enumerate(clases)}).to_numpy()
        salida[columna] = {"clases": clases}
        for modelo in cfg["ablaciones"]["modelos"]:
            t0 = time.time()
            pred = np.full(len(df), -1)
            for idx_tr, idx_te in repartos:
                esc = ajustar_escalador(X.iloc[idx_tr])
                m = _entrenar_multiclase(modelo, preprocesar(X.iloc[idx_tr], esc), y[idx_tr], semilla)
                pred[idx_te] = np.asarray(m.predict(preprocesar(X.iloc[idx_te], esc))).astype(int).ravel()
            # Por episodio: la clase no benigna más votada entre sus ventanas etiquetadas.
            ib = clases.index(benigna)
            ep = df.loc[etiquetadas, ["sesion", "episodio"]].assign(real=y[etiquetadas], pred=pred[etiquetadas])
            filas = []
            for _, g in ep.groupby(["sesion", "episodio"]):
                votos = g.loc[g["pred"] != ib, "pred"]
                filas.append({"real": int(g["real"].mode().iat[0]),
                              "pred": int(votos.mode().iat[0]) if len(votos) else ib})
            ep_t = pd.DataFrame(filas)
            por_clase = {
                clases[c]: {"episodios": int((ep_t["real"] == c).sum()),
                            "acierto": float((ep_t.loc[ep_t["real"] == c, "pred"] == c).mean()),
                            "no_detectado": float((ep_t.loc[ep_t["real"] == c, "pred"] == ib).mean())}
                for c in sorted(ep_t["real"].unique())
            }
            salida[columna][modelo] = {
                "ventana": {
                    "exactitud_balanceada": float(balanced_accuracy_score(y, pred)),
                    "f1_macro": float(f1_score(y, pred, average="macro")),
                    "recall_por_clase": dict(zip(clases, map(float, recall_score(
                        y, pred, labels=range(len(clases)), average=None, zero_division=0)))),
                    "matriz_confusion": confusion_matrix(y, pred, labels=range(len(clases))).tolist(),
                },
                "episodio": {
                    "acierto": float((ep_t["real"] == ep_t["pred"]).mean()),
                    "acierto_entre_detectados": float(
                        (ep_t.loc[ep_t["pred"] != ib, "real"] == ep_t.loc[ep_t["pred"] != ib, "pred"]).mean()),
                    "por_clase": por_clase,
                    "matriz_confusion": confusion_matrix(ep_t["real"], ep_t["pred"],
                                                         labels=range(len(clases))).tolist(),
                },
            }
            logger.info("multiclase %s/%s: %.0f s", columna, modelo, time.time() - t0)
    return salida


# --------------------------------------------------------------------------------------------
# 4. Importancia por permutación
# --------------------------------------------------------------------------------------------

def _metricas_test(df_te: pd.DataFrame, prob: np.ndarray, umbral: float) -> tuple[float, float, float]:
    alarma = prob > umbral
    return (float(average_precision_score(df_te[ETIQUETA], prob)),
            float(ev.tabla_episodios(df_te, alarma)["detectado"].mean()),
            ev.falsas_alarmas_por_dispositivo_dia(df_te, alarma))


def permutacion(df: pd.DataFrame, cfg: dict, cache: dict, n_repeticiones: int = N_REPETICIONES_PERMUTACION) -> dict:
    """Caída de PR-AUC y de recall por episodio al permutar cada característica o familia en test.

    Se reentrena cada fold de la primera semilla con todas las características y se usa el
    umbral anidado que eligió ese mismo fold en la ablación «completo».
    """
    semilla = int(cfg["ablaciones"]["semillas"][0])
    rng = np.random.default_rng(semilla)
    columnas = list(COLUMNAS_MODELO)
    unidades = {**{f"familia:{k}": v for k, v in FAMILIAS.items()}, **{c: [c] for c in columnas}}
    salida: dict = {}
    for modelo in cfg["ablaciones"]["modelos"]:
        if modelo not in cache:
            cache[modelo] = _predecir(df, modelo, cfg)
        folds = cache[modelo][0].folds
        caidas: dict[str, list[tuple[float, float, float]]] = {u: [] for u in unidades}
        base_folds = []
        t0 = time.time()
        for k, (idx_tr, idx_te) in enumerate(ev.repartos_por_sesion(df, int(cfg["n_folds"]), semilla)):
            assert sorted(df["sesion"].iloc[idx_te].astype(str).unique()) == folds[k]["sesiones_test"]
            f = ev.ajustar_modelo(modelo, df[columnas].iloc[idx_tr], df[ETIQUETA].to_numpy()[idx_tr], semilla)
            df_te = df.iloc[idx_te].reset_index(drop=True)
            X_te = df_te[columnas]  # noqa: N806
            base = _metricas_test(df_te, f(X_te), folds[k]["umbral"])
            base_folds.append(base)
            for u, cols in unidades.items():
                for _ in range(n_repeticiones):
                    Xp = X_te.copy()  # noqa: N806
                    Xp[cols] = X_te[cols].to_numpy()[rng.permutation(len(X_te))]
                    m = _metricas_test(df_te, f(Xp), folds[k]["umbral"])
                    caidas[u].append((base[0] - m[0], base[1] - m[1], m[2] - base[2]))
        logger.info("permutación %s: %.0f s", modelo, time.time() - t0)

        def agregar(vals: list[tuple[float, float, float]]) -> dict:
            a = np.array(vals)
            return {"caida_pr_auc": float(a[:, 0].mean()), "caida_pr_auc_std": float(a[:, 0].std()),
                    "caida_recall_episodios": float(a[:, 1].mean()),
                    "caida_recall_episodios_std": float(a[:, 1].std()),
                    "aumento_falsas_alarmas_dispositivo_dia": float(a[:, 2].mean())}
        b = np.array(base_folds)
        salida[modelo] = {
            "base": {"pr_auc": float(b[:, 0].mean()), "recall_episodios": float(b[:, 1].mean()),
                     "falsas_alarmas_por_dispositivo_dia": float(b[:, 2].mean())},
            "familias": dict(sorted(((u.split(":", 1)[1], agregar(v)) for u, v in caidas.items()
                                     if u.startswith("familia:")),
                                    key=lambda kv: -kv[1]["caida_recall_episodios"])),
            "caracteristicas": dict(sorted(((u, agregar(v)) for u, v in caidas.items()
                                            if not u.startswith("familia:")),
                                           key=lambda kv: -kv[1]["caida_pr_auc"])),
        }
    return {"n_repeticiones": n_repeticiones, "semilla": semilla, "familias_definicion": FAMILIAS, **salida}


# --------------------------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------------------------

def markdown(inf: dict) -> str:
    """Tablas legibles derivadas del JSON."""
    lineas = ["# Ablaciones E2 — cifras", "",
         f"Generado por `scripts/ablaciones.py` el {inf['fecha']} en el commit `{inf['commit']}`"
         f"{' (árbol con cambios)' if inf.get('arbol_con_cambios') else ''}. "
         f"Dataset sha256 `{inf['dataset']['sha256']}`. Semillas {inf['config']['ablaciones']['semillas']}, "
         f"umbral anidado para ≤ {inf['config']['objetivo_falsas_alarmas_dispositivo_dia']:g} FA/dispositivo-día.", ""]
    if "loao" in inf:
        lineas += ["## Leave-one-attack-out (recall por episodio del tipo excluido)", "",
              "| Tipo excluido | Modelo | Sin el tipo en train | Con el tipo en train | Caída | FA/disp-día |",
              "|---|---|---|---|---|---|"]
        for m, d in inf["loao"].items():
            for t, v in d.items():
                lineas.append(f"| {t} | {m} | {fmt_ic(v['recall_episodios_excluido'])} "
                         f"(n={v['recall_episodios_excluido']['n']}) | "
                         f"{fmt_ic(v['recall_episodios_excluido_con_entrenamiento'])} | {v['caida']:+.3f} | "
                         f"{fmt_ic(v['falsas_alarmas_por_dispositivo_dia'], 2)} |")
        lineas.append("")
    if "ablacion" in inf:
        lineas += ["## Ablación por conjunto de características", "",
              "| Conjunto | Modelo | n col. | Recall episodio | FA/disp-día | PR-AUC ventana |", "|---|---|---|---|---|---|"]
        for m, d in inf["ablacion"].items():
            for c, v in d.items():
                lineas.append(f"| {c} | {m} | {v['n_columnas']} | {fmt_ic(v['recall_episodios'])} | "
                         f"{fmt_ic(v['falsas_alarmas_por_dispositivo_dia'], 2)} | {fmt_ic(v['pr_auc_ventana'])} |")
        tipos = sorted(next(iter(next(iter(inf["ablacion"].values())).values()))["recall_episodios_por_tipo"])
        lineas += ["", "Recall por episodio y tipo:", "", "| Conjunto | Modelo | " + " | ".join(tipos) + " |",
              "|---|---|" + "---|" * len(tipos)]
        for m, d in inf["ablacion"].items():
            for c, v in d.items():
                lineas.append(f"| {c} | {m} | " + " | ".join(
                    f"{v['recall_episodios_por_tipo'][t]['valor']:.2f}" for t in tipos) + " |")
        lineas.append("")
    if "multiclase" in inf:
        lineas += ["## Multiclase", "", "| Etiqueta | Modelo | Exactitud bal. (ventana) | F1 macro (ventana) | "
              "Acierto por episodio | Acierto entre detectados |", "|---|---|---|---|---|---|"]
        for col, d in inf["multiclase"].items():
            for m, v in d.items():
                if m == "clases":
                    continue
                lineas.append(f"| {col} | {m} | {v['ventana']['exactitud_balanceada']:.3f} | {v['ventana']['f1_macro']:.3f} | "
                         f"{v['episodio']['acierto']:.3f} | {v['episodio']['acierto_entre_detectados']:.3f} |")
        lineas.append("")
    if "permutacion" in inf:
        p = inf["permutacion"]
        for m in inf["config"]["ablaciones"]["modelos"]:
            if m not in p:
                continue
            lineas += [f"## Importancia por permutación — {m}", "",
                  f"Base (media de folds): PR-AUC {p[m]['base']['pr_auc']:.3f}, recall por episodio "
                  f"{p[m]['base']['recall_episodios']:.3f}. {p['n_repeticiones']} repeticiones por fold.", "",
                  "| Familia | Caída recall episodio | Caída PR-AUC | Δ FA/disp-día |", "|---|---|---|---|"]
            for f, v in p[m]["familias"].items():
                lineas.append(f"| {f} | {v['caida_recall_episodios']:+.3f} ± {v['caida_recall_episodios_std']:.3f} | "
                         f"{v['caida_pr_auc']:+.3f} ± {v['caida_pr_auc_std']:.3f} | "
                         f"{v['aumento_falsas_alarmas_dispositivo_dia']:+.2f} |")
            lineas += ["", "| Característica (top 10 por caída de PR-AUC) | Caída PR-AUC | Caída recall episodio |",
                  "|---|---|---|"]
            for c, v in list(p[m]["caracteristicas"].items())[:10]:
                lineas.append(f"| {c} | {v['caida_pr_auc']:+.4f} | {v['caida_recall_episodios']:+.4f} |")
            lineas.append("")
    return "\n".join(lineas)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Ablaciones, LOAO, multiclase e importancia por permutación (E2).")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--partes", default=",".join(PARTES), help=f"Subconjunto de {PARTES}, separado por comas.")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    cfg = leer_config(args.config)
    partes = [x for x in args.partes.split(",") if x]
    if desconocidas := set(partes) - set(PARTES):
        p.error(f"partes desconocidas: {sorted(desconocidas)}")
    ruta_ds = ruta_proyecto(cfg["dataset"])
    df = cargar_dataset_estricto(ruta_ds)
    informe: dict = {
        "etapa": "E2", "fecha": datetime.now().isoformat(timespec="seconds"), **commit_actual(),
        "config_archivo": str(args.config), "config": cfg,
        "dataset": {"ruta": cfg["dataset"], "sha256": sha256_archivo(ruta_ds), "filas": int(len(df))},
        "conjuntos": CONJUNTOS,
    }
    cache: dict = {}
    n_perm = int(cfg["ablaciones"].get("repeticiones_permutacion", N_REPETICIONES_PERMUTACION))
    funciones = {"ablacion": ablacion, "loao": loao, "multiclase": lambda d, c, _: multiclase(d, c),
                 "permutacion": lambda d, c, k: permutacion(d, c, k, n_perm)}
    for parte in PARTES:
        if parte in partes:
            informe[parte] = funciones[parte](df, cfg, cache)
    destino = ruta_proyecto(cfg["ablaciones"]["salida"])
    escribir_json(informe, destino)
    destino.with_suffix(".md").write_text(markdown(json.loads(destino.read_text())))
    print(f"Escrito {destino} y {destino.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
