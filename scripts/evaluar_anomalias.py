#!/usr/bin/env python3
"""
Evaluación del detector de anomalías entrenado solo con benigno (PEDIDO-ANOMALIAS-1).

Mismo protocolo que E2 y que el marcador del extractor: 5 folds por sesión × semillas,
umbral por validación anidada para ≤ 1 falsa alarma por dispositivo-día (calculado solo con
puntajes benignos fuera de fold), métricas por episodio, atacante y dispositivo con IC al 95 %
(`src/evaluacion.resumir`), la vista por ventana como referencia y una sonda de deriva: los
dispositivos legítimos que más alarmas acumulan.

Uso:
    python scripts/evaluar_anomalias.py --config configs/anomalias.json

Escribe `salidas.json` y `salidas.md` de la configuración.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from scripts.evaluar import (  # noqa: E402
    cargar_dataset_estricto,
    commit_actual,
    escribir_json,
    fmt_ic,
    leer_config,
    ruta_proyecto,
)
from scripts.lab.ficha_dataset import sha256_archivo  # noqa: E402
from src import anomalias as an  # noqa: E402
from src import evaluacion as ev  # noqa: E402
from src.feature_schema import VERSION_ESQUEMA  # noqa: E402
from src.ventanas import MAC_EFIMERAS  # noqa: E402

logger = logging.getLogger("evaluar_anomalias")


def sonda_deriva(df: pd.DataFrame, predicciones: list[ev.PrediccionesFueraDeFold], top: int) -> dict:
    """Dispositivos legítimos con más falsas alarmas (media entre semillas) y su tasa.

    Se agrega por MAC a través de las sesiones (el mismo equipo reaparece en cada sesión) y
    también por (sesión, MAC). `cuota` es la fracción de todas las falsas alarmas.
    """
    tablas = [ev.tabla_dispositivos(df, p.alarma) for p in predicciones]
    base = tablas[0][["sesion", "mac", "segundos", "efimeras"]].copy()
    base["alarmas"] = np.mean([t["alarmas"].to_numpy() for t in tablas], axis=0)
    total = float(base["alarmas"].sum())

    def ranking(grupo: list[str]) -> list[dict]:
        g = base.groupby(grupo).agg(alarmas=("alarmas", "sum"), segundos=("segundos", "sum"),
                                    efimeras=("efimeras", "max"), sesiones=("sesion", "nunique"))
        g["dias"] = g["segundos"] / ev.SEGUNDOS_POR_DIA
        g["alarmas_por_dia"] = g["alarmas"] / g["dias"]
        g["cuota"] = g["alarmas"] / total if total else np.nan
        g = g.sort_values(["alarmas", "alarmas_por_dia"], ascending=False).head(top).reset_index()
        return g.drop(columns=["segundos"]).to_dict(orient="records")

    con_alarma = base.groupby("mac")["alarmas"].sum()
    return {
        "falsas_alarmas_totales_media_semillas": total,
        "dispositivos_mac": int(base["mac"].nunique()),
        "macs_con_alguna_alarma": int((con_alarma > 0).sum()),
        "cuota_top": float(sum(r["cuota"] for r in ranking(["mac"]))) if total else None,
        "por_mac": ranking(["mac"]),
        "por_sesion_y_mac": ranking(["sesion", "mac"]),
        "mac_efimeras": MAC_EFIMERAS,
    }


def compacto(r: dict) -> dict:
    """Las cifras que deciden, para imprimir y comparar."""
    e = r["episodios"]
    return {
        "recall_episodios": e["recall"],
        "recall_episodios_por_tipo": {t: round(v["valor"], 3) for t, v in e["por_tipo"].items()},
        "recall_atacantes": r["atacantes"]["recall"],
        "falsas_alarmas_por_dispositivo_dia": r["dispositivos"]["falsas_alarmas_por_dispositivo_dia"],
        "pr_auc_ventana": r["ventanas_referencia"]["pr_auc"],
        "tiempo_deteccion_s_mediana": e["tiempo_deteccion_s_mediana"],
    }


def evaluar_uno(df: pd.DataFrame, modelo: str, conjunto: str, cfg: dict) -> dict:
    """Todas las semillas de un modelo sobre un conjunto de características."""
    columnas = an.CONJUNTOS[conjunto]
    predicciones, corridas = [], []
    for semilla in cfg["semillas"]:
        t0 = time.time()
        pred = an.predecir_fuera_de_fold(
            df, modelo, int(semilla), int(cfg["n_folds"]), int(cfg["n_folds_internos"]),
            float(cfg["objetivo_falsas_alarmas_dispositivo_dia"]), columnas)
        predicciones.append(pred)
        corridas.append({"semilla": int(semilla), "segundos": round(time.time() - t0, 1), "folds": pred.folds})
        logger.info("%s/%s semilla %s: %.0f s", modelo, conjunto, semilla, time.time() - t0)
    detalle = ev.resumir(df, predicciones, int(cfg["n_bootstrap"]), int(cfg["semilla_bootstrap"]))
    fa_test = [f["falsas_alarmas_dispositivo_dia_test"] for c in corridas for f in c["folds"]]
    detalle["umbral"] = {
        "objetivo_falsas_alarmas_dispositivo_dia": float(cfg["objetivo_falsas_alarmas_dispositivo_dia"]),
        "umbrales_por_fold": [f["umbral"] for c in corridas for f in c["folds"]],
        "falsas_alarmas_test_por_fold": fa_test,
        "folds_sobre_objetivo": int(sum(x > cfg["objetivo_falsas_alarmas_dispositivo_dia"] for x in fa_test)),
    }
    return {
        "modelo": modelo,
        "conjunto": conjunto,
        "columnas": columnas,
        "resumen": compacto(detalle),
        "detalle": detalle,
        "deriva": sonda_deriva(df, predicciones, int(cfg.get("top_deriva", 5))),
        "corridas": corridas,
    }


def referencias(cfg: dict) -> dict:
    """Cifras del supervisado con las que se compara (se leen, no se recalculan)."""
    salida: dict = {}
    refs = cfg.get("referencias_supervisado", {})
    if "e2_xgboost_completo" in refs and ruta_proyecto(refs["e2_xgboost_completo"]).exists():
        e2 = json.loads(ruta_proyecto(refs["e2_xgboost_completo"]).read_text())
        for m, d in e2["modelos"].items():
            r = d["resumen"]
            salida[f"supervisado_{m}_completo_con_tipo"] = {
                "fuente": refs["e2_xgboost_completo"], "version_esquema": e2.get("version_esquema"),
                "recall_episodios": r["episodios"]["recall"],
                "falsas_alarmas_por_dispositivo_dia": r["dispositivos"]["falsas_alarmas_por_dispositivo_dia"],
                "recall_episodios_por_tipo": {t: v["valor"] for t, v in r["episodios"]["por_tipo"].items()},
            }
    if "loao_sin_capa2" in refs and ruta_proyecto(refs["loao_sin_capa2"]).exists():
        lo = json.loads(ruta_proyecto(refs["loao_sin_capa2"]).read_text())["loao"]
        for m in ("random_forest", "xgboost"):
            salida[f"supervisado_{m}_sin_capa2_loao"] = {
                "fuente": refs["loao_sin_capa2"],
                "recall_episodios_tipo_excluido": lo["media_seis"][m]["recall_episodios_excluido"],
                "recall_episodios_con_tipo": lo["media_seis"][m]["recall_episodios_con_entrenamiento"],
                "por_tipo_excluido": {t: lo[m][t]["recall_episodios_excluido"]["valor"] for t in lo[m]},
            }
    return salida


def evaluar(cfg: dict, ruta_config: str | None = None) -> dict:
    """Evalúa todos los modelos y conjuntos de la configuración."""
    ruta_ds = ruta_proyecto(cfg["dataset"])
    df = cargar_dataset_estricto(ruta_ds)
    informe: dict = {
        "etapa": "PEDIDO-ANOMALIAS-1",
        "fecha": datetime.now().isoformat(timespec="seconds"),
        **commit_actual(),
        "config_archivo": ruta_config,
        "config": cfg,
        "dataset": {"ruta": cfg["dataset"], "sha256": sha256_archivo(ruta_ds), "filas": int(len(df))},
        "version_esquema": VERSION_ESQUEMA,
        "definiciones": {
            "ajuste": "solo ventanas benignas limpias de las sesiones de train; la etiqueta nunca llega al modelo",
            "puntaje": "-score_samples del detector; mayor = más anómalo",
            "umbral": "umbral_para_objetivo sobre los puntajes benignos limpios fuera de fold de los folds internos "
                      "(por sesión); alarma si puntaje > umbral",
            "resto": "las mismas definiciones de falsa alarma, dispositivo-día, episodio y tiempo que E2 "
                     "(reports/evaluacion_e2.json)",
        },
        "decisiones_previas": {
            "isolation_forest": f"{an.N_ARBOLES_IF} árboles, max_samples por defecto",
            "lof": f"n_neighbors={an.VECINOS_LOF}, novelty=True, submuestra de {an.MAX_FILAS_LOF} filas benignas",
            "isolation_forest_pca": f"PCA {an.VARIANZA_PCA:.0%} de varianza benigna + el mismo IF",
            "nan": "0 tras escalar (media benigna de train)",
            "autoencoder": "fuera: sin framework de redes en el entorno",
        },
        "referencias_supervisado": referencias(cfg),
        "resultados": {},
    }
    for conjunto in cfg["conjuntos"]:
        for modelo in cfg["modelos"]:
            informe["resultados"][f"{modelo}/{conjunto}"] = evaluar_uno(df, modelo, conjunto, cfg)
    return informe


def markdown(informe: dict) -> str:
    """Resumen legible del JSON (no añade cifras que no estén en él)."""
    cfg, res = informe["config"], informe["resultados"]
    claves = list(res)
    d0 = res[claves[0]]["detalle"]
    c, disp = d0["conteos"], d0["dispositivos"]
    lineas = [
        "# Detector de anomalías entrenado solo con benigno — cifras", "",
        f"Generado por `scripts/evaluar_anomalias.py` el {informe['fecha']} en el commit `{informe['commit']}`"
        f"{' (árbol con cambios)' if informe.get('arbol_con_cambios') else ''}. Dataset sha256 "
        f"`{informe['dataset']['sha256']}`.", "",
        f"{cfg['n_folds']} folds por sesión × {len(cfg['semillas'])} semillas {cfg['semillas']}; umbral por "
        f"validación anidada ({cfg['n_folds_internos']} folds internos, solo benigno) para **≤ "
        f"{cfg['objetivo_falsas_alarmas_dispositivo_dia']:g} falsa alarma por dispositivo-día**; IC 95 % con "
        f"{cfg['n_bootstrap']} réplicas. Conteos: {c['episodios']} episodios, {disp['dispositivos']} dispositivos "
        f"({disp['dispositivo_dias']:.2f} dispositivo-días).", "",
        "## Métricas que deciden", "",
        "| Modelo / conjunto | Recall episodio | Recall atacante | FA/disp-día | Disp. con ≥1 FA | T. mediana (s) | PR-AUC ventana | Folds sobre el objetivo |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for k in claves:
        d = res[k]["detalle"]
        lineas.append(
            f"| {k} | {fmt_ic(d['episodios']['recall'])} | {fmt_ic(d['atacantes']['recall'])} | "
            f"{fmt_ic(d['dispositivos']['falsas_alarmas_por_dispositivo_dia'], 2)} | "
            f"{fmt_ic(d['dispositivos']['fraccion_con_alguna_alarma'])} | "
            f"{fmt_ic(d['episodios']['tiempo_deteccion_s_mediana'], 1)} | {fmt_ic(d['ventanas_referencia']['pr_auc'])} | "
            f"{d['umbral']['folds_sobre_objetivo']}/{len(d['umbral']['falsas_alarmas_test_por_fold'])} |")
    tipos = sorted(d0["episodios"]["por_tipo"])
    lineas += ["", "## Recall por episodio y tipo (todos los tipos son «no vistos» para este detector)", "",
               "| Modelo / conjunto | " + " | ".join(tipos) + " |", "|---|" + "---|" * len(tipos)]
    for k in claves:
        pt = res[k]["detalle"]["episodios"]["por_tipo"]
        lineas.append(f"| {k} | " + " | ".join(fmt_ic(pt[t]) for t in tipos) + " |")
    lineas += ["", "## Recall por ventana y tipo (referencia)", "",
               "| Modelo / conjunto | " + " | ".join(tipos) + " |", "|---|" + "---|" * len(tipos)]
    for k in claves:
        pt = res[k]["detalle"]["ventanas_referencia"]["recall_por_tipo"]
        lineas.append(f"| {k} | " + " | ".join(f"{pt.get(t, float('nan')):.3f}" for t in tipos) + " |")
    lineas += ["", "## Sonda de deriva: dispositivos legítimos con más falsas alarmas (media de semillas)", ""]
    for k in claves:
        dv = res[k]["deriva"]
        lineas += [f"**{k}**: {dv['falsas_alarmas_totales_media_semillas']:.1f} falsas alarmas en total; "
                   f"{dv['macs_con_alguna_alarma']} de {dv['dispositivos_mac']} MAC con alguna; los "
                   f"{len(dv['por_mac'])} primeros concentran "
                   f"{(dv['cuota_top'] or 0) * 100:.0f} %.", "",
                   "| MAC | Sesiones | Falsas alarmas | Dispositivo-días | FA/disp-día | Cuota |", "|---|---|---|---|---|---|"]
        for r in dv["por_mac"]:
            lineas.append(f"| `{r['mac']}`{' (efímeras)' if r['efimeras'] else ''} | {r['sesiones']} | "
                          f"{r['alarmas']:.1f} | {r['dias']:.3f} | {r['alarmas_por_dia']:.1f} | {r['cuota'] * 100:.0f} % |")
        lineas.append("")
    refs = informe.get("referencias_supervisado", {})
    if refs:
        lineas += ["## Referencias del supervisado (leídas de sus informes)", "", "| Referencia | Recall episodio |", "|---|---|"]
        for k, v in refs.items():
            cifra = v.get("recall_episodios") or v.get("recall_episodios_tipo_excluido")
            lineas.append(f"| {k} | {fmt_ic(cifra)} |")
        lineas.append("")
    return "\n".join(lineas)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Evaluación del detector de anomalías entrenado solo con benigno.")
    p.add_argument("--config", required=True, type=Path)
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    cfg = leer_config(args.config)
    informe = evaluar(cfg, str(args.config))
    destino = ruta_proyecto(cfg["salidas"]["json"])
    escribir_json(informe, destino)
    md = ruta_proyecto(cfg["salidas"]["md"])
    md.write_text(markdown(json.loads(destino.read_text())))
    print(f"Escrito {destino} y {md}")
    for k, d in informe["resultados"].items():
        r = d["detalle"]
        print(f"{k}: recall episodio {fmt_ic(r['episodios']['recall'])} · "
              f"FA/disp-día {fmt_ic(r['dispositivos']['falsas_alarmas_por_dispositivo_dia'], 2)} · "
              f"PR-AUC {fmt_ic(r['ventanas_referencia']['pr_auc'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
