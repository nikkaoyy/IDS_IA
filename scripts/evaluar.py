#!/usr/bin/env python3
"""
Evaluación E2 del clasificador (OE2, OE3; Fig. 1, bloque «Clasificación»).

RF y XGBoost sobre `COLUMNAS_MODELO`, con el escalador de `src/preprocess.py` y semillas fijas.
Reparto agrupado por sesión (5 folds × 5 semillas), umbral elegido por validación anidada para
un objetivo numérico de falsas alarmas por dispositivo-día, y métricas por episodio, por
atacante y por dispositivo con IC al 95 % (bootstrap por sesiones y por episodios). La vista
por ventana se conserva como referencia.

Uso:
    python scripts/evaluar.py --config configs/e2.json

Escribe `reports/evaluacion_e2.json` (o la `salida` de la configuración) y el Markdown derivado
con el mismo nombre y extensión `.md`.
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from scripts.lab.ficha_dataset import sha256_archivo  # noqa: E402
from src import evaluacion as ev  # noqa: E402
from src.data import cargar_dataset  # noqa: E402
from src.feature_schema import COLUMNAS_MODELO, VERSION_ESQUEMA  # noqa: E402

logger = logging.getLogger("evaluar")


# --------------------------------------------------------------------------------------------
# Utilidades compartidas con ablaciones.py y evaluar_holdout.py
# --------------------------------------------------------------------------------------------

def ruta_proyecto(ruta: str | Path) -> Path:
    """Rutas relativas de la configuración se resuelven contra la raíz del repositorio."""
    p = Path(ruta)
    return p if p.is_absolute() else _RAIZ / p


def leer_config(ruta: str | Path) -> dict:
    """Lee la configuración congelada de E2."""
    return json.loads(Path(ruta).read_text())


def commit_actual() -> dict:
    """Commit de HEAD y si el árbol tiene cambios sin confirmar (para la trazabilidad del JSON)."""
    def git(*args: str) -> str | None:
        try:
            return subprocess.run(["git", *args], cwd=_RAIZ, capture_output=True, text=True,
                                  check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return None
    estado = git("status", "--porcelain")
    return {"commit": git("rev-parse", "HEAD"), "arbol_con_cambios": bool(estado) if estado is not None else None}


def cargar_dataset_estricto(ruta: str | Path, permitir_holdout: bool = False) -> pd.DataFrame:
    """Como `cargar_dataset`, pero sin caer al sintético si el archivo no existe."""
    ruta_p = ruta_proyecto(ruta)
    if not ruta_p.exists():
        raise FileNotFoundError(f"No existe el dataset {ruta_p}; genéralo antes de evaluar.")
    return cargar_dataset(ruta_p, permitir_holdout=permitir_holdout).reset_index(drop=True)


def escribir_json(datos: dict, destino: Path) -> None:
    """JSON legible; los NaN se escriben como null para que el archivo sea JSON válido."""
    def limpiar(x):
        if isinstance(x, dict):
            return {str(k): limpiar(v) for k, v in x.items()}
        if isinstance(x, (list, tuple)):
            return [limpiar(v) for v in x]
        if isinstance(x, (np.floating, float)):
            return None if not np.isfinite(x) else float(x)
        if isinstance(x, np.integer):
            return int(x)
        if isinstance(x, np.bool_):
            return bool(x)
        return x
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(json.dumps(limpiar(datos), indent=2, ensure_ascii=False) + "\n")


def fmt_ic(m: dict | None, dec: int = 3, pct: bool = False) -> str:
    """«valor [lo, hi]» de un bloque {valor, ic95}."""
    if not m or m.get("valor") is None:
        return "—"
    f = 100.0 if pct else 1.0
    v, (lo, hi) = m["valor"], m.get("ic95") or (None, None)
    if lo is None or hi is None:
        return f"{v * f:.{dec}f}"
    return f"{v * f:.{dec}f} [{lo * f:.{dec}f}, {hi * f:.{dec}f}]"


# --------------------------------------------------------------------------------------------
# Evaluación
# --------------------------------------------------------------------------------------------

def evaluar_modelo(df: pd.DataFrame, nombre: str, cfg: dict) -> dict:
    """Validación cruzada anidada por semilla y resumen con IC para un modelo."""
    objetivo = float(cfg["objetivo_falsas_alarmas_dispositivo_dia"])
    sensibilidad = [float(o) for o in cfg.get("objetivos_sensibilidad", [])]
    objetivos = [objetivo] + [o for o in sensibilidad if o != objetivo]
    predicciones: list[ev.PrediccionesFueraDeFold] = []
    corridas = []
    for semilla in cfg["semillas"]:
        t0 = time.time()
        pred = ev.predecir_fuera_de_fold(
            df, nombre, int(semilla), n_folds=int(cfg["n_folds"]),
            n_folds_internos=int(cfg["n_folds_internos"]), objetivo_por_dispositivo_dia=objetivos,
        )
        predicciones.append(pred)
        corridas.append({"semilla": int(semilla), "segundos": round(time.time() - t0, 1), "folds": pred.folds})
        logger.info("%s semilla %s: %.0f s", nombre, semilla, time.time() - t0)

    n_rep, sem_b = int(cfg["n_bootstrap"]), int(cfg["semilla_bootstrap"])
    resumen = ev.resumir(df, predicciones, n_rep, sem_b)
    resumen["umbral"] = {
        "objetivo_falsas_alarmas_dispositivo_dia": objetivo,
        "umbrales_por_fold": [f["umbral"] for c in corridas for f in c["folds"]],
    }
    resumen["sensibilidad_al_objetivo"] = {}
    for o in sensibilidad:
        alternativas = [ev.PrediccionesFueraDeFold(p.prob, p.alarmas_por_objetivo[o]) for p in predicciones]
        r = ev.resumir(df, alternativas, n_rep, sem_b)
        resumen["sensibilidad_al_objetivo"][str(o)] = {
            "recall_episodios": r["episodios"]["recall"],
            "recall_atacantes": r["atacantes"]["recall"],
            "falsas_alarmas_por_dispositivo_dia": r["dispositivos"]["falsas_alarmas_por_dispositivo_dia"],
            "fpr_ventana": r["ventanas_referencia"]["fpr"],
            "tiempo_deteccion_s_mediana": r["episodios"]["tiempo_deteccion_s_mediana"],
        }
    return {"resumen": resumen, "corridas": corridas}


def evaluar(cfg: dict, ruta_config: str | None = None) -> dict:
    """Evalúa todos los modelos de la configuración y devuelve el informe completo."""
    ruta_ds = ruta_proyecto(cfg["dataset"])
    df = cargar_dataset_estricto(ruta_ds)
    informe: dict = {
        "etapa": "E2",
        "fecha": datetime.now().isoformat(timespec="seconds"),
        **commit_actual(),
        "config_archivo": ruta_config,
        "config": cfg,
        "dataset": {"ruta": cfg["dataset"], "sha256": sha256_archivo(ruta_ds), "filas": int(len(df))},
        "version_esquema": VERSION_ESQUEMA,
        "columnas_modelo": list(COLUMNAS_MODELO),
        "definiciones": {
            "falsa_alarma": "ventana benigna limpia (n_tramas_ataque == 0) con prob > umbral",
            "ventana_ambigua": "0 < n_tramas_ataque < K, etiquetada benigna; no cuenta como FP ni como TP",
            "dispositivo_dia": "lapso observado de cada (sesión, MAC), de la primera a la última ventana, "
                               f"× {ev.VENTANA_CORTA_S:g} s, sumado y dividido por 86 400",
            "episodio_detectado": "al menos una ventana etiquetada del episodio con alarma",
            "tiempo_deteccion_s": "desde el inicio de la primera ventana con alguna trama del episodio "
                                  "hasta el cierre de la primera ventana etiquetada con alarma",
            "umbral": "k-ésima mayor probabilidad benigna limpia en las predicciones internas (OOF) del "
                      "fold externo, con k = floor(objetivo × dispositivo-días internos); alarma si prob > umbral",
            "ic95": "percentiles 2,5/97,5 del bootstrap: sesiones para razones y PR-AUC; episodios o "
                    "atacantes para recall y tiempos; promedio entre semillas dentro de cada réplica",
        },
        "modelos": {},
    }
    for nombre in cfg["modelos"]:
        informe["modelos"][nombre] = evaluar_modelo(df, nombre, cfg)
    return informe


# --------------------------------------------------------------------------------------------
# Markdown derivado
# --------------------------------------------------------------------------------------------

def markdown(informe: dict) -> str:
    """Resumen legible del JSON (no añade cifras que no estén en él)."""
    cfg = informe["config"]
    modelos = list(informe["modelos"])
    res = {m: informe["modelos"][m]["resumen"] for m in modelos}
    c = res[modelos[0]]["conteos"]
    disp = res[modelos[0]]["dispositivos"]
    lineas = [
        "# Evaluación E2 — cifras",
        "",
        f"Generado por `scripts/evaluar.py` el {informe['fecha']} en el commit `{informe['commit']}`"
        f"{' (árbol con cambios)' if informe.get('arbol_con_cambios') else ''}.",
        f"Dataset `{informe['dataset']['ruta']}` sha256 `{informe['dataset']['sha256']}`.",
        "",
        f"{cfg['n_folds']} folds agrupados por sesión × {len(cfg['semillas'])} semillas {cfg['semillas']}; "
        f"umbral por validación anidada ({cfg['n_folds_internos']} folds internos) para "
        f"**≤ {cfg['objetivo_falsas_alarmas_dispositivo_dia']:g} falsa alarma por dispositivo-día**; "
        f"IC 95 % con {cfg['n_bootstrap']} réplicas bootstrap (semilla {cfg['semilla_bootstrap']}).",
        "",
        f"Conteos: {c['sesiones']} sesiones, {c['episodios']} episodios, {c['atacantes']} atacantes, "
        f"{disp['dispositivos']} dispositivos ({disp['dispositivo_dias']:.2f} dispositivo-días), "
        f"{c['ventanas']} ventanas ({c['ventanas_maliciosas']} maliciosas, "
        f"{c['ventanas_benignas_limpias']} benignas limpias, {c['ventanas_ambiguas']} ambiguas).",
        "",
        "## Métricas que deciden (por episodio, atacante y dispositivo)",
        "",
        "| Métrica | " + " | ".join(modelos) + " |",
        "|---|" + "---|" * len(modelos),
    ]
    filas = [
        ("Recall por episodio", lambda r: fmt_ic(r["episodios"]["recall"])),
        ("Recall por atacante", lambda r: fmt_ic(r["atacantes"]["recall"])),
        ("Falsas alarmas / dispositivo-día", lambda r: fmt_ic(r["dispositivos"]["falsas_alarmas_por_dispositivo_dia"], 2)),
        ("Dispositivos con ≥1 falsa alarma", lambda r: fmt_ic(r["dispositivos"]["fraccion_con_alguna_alarma"])),
        ("Tiempo hasta la detección, mediana (s)", lambda r: fmt_ic(r["episodios"]["tiempo_deteccion_s_mediana"], 1)),
        ("Tiempo hasta la detección, p90 (s)", lambda r: fmt_ic(r["episodios"]["tiempo_deteccion_s_p90"], 1)),
    ]
    lineas += [f"| {n} | " + " | ".join(f(res[m]) for m in modelos) + " |" for n, f in filas]
    lineas += ["", "## Referencia por ventana", "", "| Métrica | " + " | ".join(modelos) + " |",
          "|---|" + "---|" * len(modelos)]
    filas = [
        ("PR-AUC", lambda r: fmt_ic(r["ventanas_referencia"]["pr_auc"])),
        ("Recall por ventana en el umbral", lambda r: fmt_ic(r["ventanas_referencia"]["recall"])),
        ("FPR por ventana en el umbral (×10⁻³)",
         lambda r: fmt_ic({"valor": r["ventanas_referencia"]["fpr"]["valor"] * 1e3,
                           "ic95": [x * 1e3 for x in r["ventanas_referencia"]["fpr"]["ic95"]]}, 3)),
    ]
    lineas += [f"| {n} | " + " | ".join(f(res[m]) for m in modelos) + " |" for n, f in filas]

    tipos = sorted(res[modelos[0]]["episodios"]["por_tipo"])
    lineas += ["", "## Recall por tipo de ataque", "",
          "| Tipo | " + " | ".join(f"{m} episodio | {m} ventana | {m} t. mediana (s)" for m in modelos) + " |",
          "|---|" + "---|---|---|" * len(modelos)]
    for t in tipos:
        celdas = []
        for m in modelos:
            e = res[m]["episodios"]
            n = e["por_tipo"][t].get("n")
            celdas += [f"{fmt_ic(e['por_tipo'][t])} (n={n})",
                       f"{res[m]['ventanas_referencia']['recall_por_tipo'].get(t, float('nan')):.3f}",
                       fmt_ic(e["tiempo_deteccion_s_mediana_por_tipo"][t], 1)]
        lineas.append(f"| {t} | " + " | ".join(celdas) + " |")

    lineas += ["", "## Recall por intensidad", "", "| Intensidad | " + " | ".join(modelos) + " |",
          "|---|" + "---|" * len(modelos)]
    for i in sorted(res[modelos[0]]["episodios"]["por_intensidad"]):
        lineas.append(f"| {i} | " + " | ".join(
            f"{fmt_ic(res[m]['episodios']['por_intensidad'][i])} (n={res[m]['episodios']['por_intensidad'][i]['n']})"
            for m in modelos) + " |")

    if res[modelos[0]].get("sensibilidad_al_objetivo"):
        lineas += ["", "## Sensibilidad al objetivo de falsas alarmas", "",
              "| Objetivo (FA/disp-día) | Modelo | Recall episodio | FA/disp-día medidas | T. mediana (s) |",
              "|---|---|---|---|---|"]
        for o in res[modelos[0]]["sensibilidad_al_objetivo"]:
            for m in modelos:
                s = res[m]["sensibilidad_al_objetivo"][o]
                lineas.append(f"| {float(o):g} | {m} | {fmt_ic(s['recall_episodios'])} | "
                         f"{fmt_ic(s['falsas_alarmas_por_dispositivo_dia'], 2)} | "
                         f"{fmt_ic(s['tiempo_deteccion_s_mediana'], 1)} |")

    lineas += ["", "## Umbrales elegidos (validación anidada)", "", "| Modelo | mín | mediana | máx |", "|---|---|---|---|"]
    for m in modelos:
        u = np.array(res[m]["umbral"]["umbrales_por_fold"], dtype=float)
        lineas.append(f"| {m} | {u.min():.4f} | {np.median(u):.4f} | {u.max():.4f} |")
    lineas += ["", "Las particiones (sesiones de test por fold y semilla) están en el JSON, en "
          "`modelos.<modelo>.corridas[].folds[].sesiones_test`.", ""]
    return "\n".join(lineas)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Evaluación E2 por episodio y por dispositivo con IC.")
    p.add_argument("--config", required=True, type=Path)
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    cfg = leer_config(args.config)
    informe = evaluar(cfg, str(args.config))
    destino = ruta_proyecto(cfg["salida"])
    escribir_json(informe, destino)
    destino.with_suffix(".md").write_text(markdown(json.loads(destino.read_text())))
    print(f"Escrito {destino} y {destino.with_suffix('.md')}")
    for m, d in informe["modelos"].items():
        r = d["resumen"]
        print(f"{m}: recall episodio {fmt_ic(r['episodios']['recall'])} · "
              f"FA/disp-día {fmt_ic(r['dispositivos']['falsas_alarmas_por_dispositivo_dia'], 2)} · "
              f"PR-AUC {fmt_ic(r['ventanas_referencia']['pr_auc'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
