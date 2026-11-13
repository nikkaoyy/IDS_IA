#!/usr/bin/env python3
"""
Apertura única del holdout de E2 (sesiones 20–29; OE2, OE3).

Entrena con todas las sesiones no reservadas usando la configuración congelada
(`configs/e2.json`) y evalúa sobre las sesiones 20–29, que nada más ha tocado. El umbral se
elige igual que en la validación: probabilidades fuera de fold sobre las sesiones de
desarrollo (reparto agrupado por sesión) y el objetivo de falsas alarmas por dispositivo-día;
después se entrena con todo el desarrollo y se aplica ese umbral al holdout. Una corrida por
semilla de la configuración.

El holdout se abre una sola vez. Al cargarlo se escribe el sello `reports/.holdout_abierto`
(commit y hora); si el sello existe, el script se niega y sale con código 3 sin tocar nada.
`--romper-holdout-una-vez --motivo "..."` permite una sola reapertura, solo para un bug
demostrado, y queda registrada en el sello y en el JSON. Si el holdout sale peor que la
validación, se reporta tal cual.

Uso:
    python scripts/lab/generar_dataset_lab.py --inicio 20 --sesiones 10 --romper-holdout \\
        --salida data/holdout_e2.csv --dir-pcap data/pcap_holdout
    python scripts/evaluar_holdout.py --config configs/e2.json
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
from scripts.lab.ficha_dataset import ruta_meta, sha256_archivo  # noqa: E402
from src import evaluacion as ev  # noqa: E402
from src.data import SESIONES_RESERVADAS, indice_sesion  # noqa: E402
from src.feature_schema import COLUMNAS_MODELO, ETIQUETA  # noqa: E402

logger = logging.getLogger("evaluar_holdout")

CODIGO_SELLADO = 3


class HoldoutSelladoError(Exception):
    """El holdout ya se abrió y no se pidió (o ya se agotó) la reapertura por bug."""


def leer_sello(ruta: Path) -> dict | None:
    return json.loads(ruta.read_text()) if ruta.exists() else None


def comprobar_sello(ruta: Path, romper: bool, motivo: str | None) -> dict | None:
    """Devuelve el sello previo (si se autoriza la reapertura) o lanza `HoldoutSelladoError`."""
    sello = leer_sello(ruta)
    if sello is None:
        return None
    if not romper:
        raise HoldoutSelladoError(
            f"El holdout ya se abrió (commit {sello.get('commit')}, {sello.get('fecha')}); "
            f"ver {ruta}. Solo un bug demostrado justifica --romper-holdout-una-vez --motivo.")
    if sello.get("reaperturas"):
        raise HoldoutSelladoError(f"El holdout ya se reabrió una vez ({sello['reaperturas'][0]['fecha']}); "
                             "no hay segunda reapertura.")
    if not motivo:
        raise HoldoutSelladoError("--romper-holdout-una-vez exige --motivo con el bug demostrado.")
    return sello


def escribir_sello(ruta: Path, datos: dict) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(json.dumps(datos, indent=2, ensure_ascii=False) + "\n")


def umbral_en_desarrollo(dev: pd.DataFrame, modelo: str, semilla: int, n_folds: int,
                         objetivo: float) -> tuple[float, float]:
    """Umbral a partir de probabilidades fuera de fold sobre todo el desarrollo."""
    X, y = dev[list(COLUMNAS_MODELO)], dev[ETIQUETA].to_numpy()  # noqa: N806
    oof = np.full(len(dev), np.nan)
    for idx_tr, idx_te in ev.repartos_por_sesion(dev, n_folds, semilla):
        oof[idx_te] = ev.ajustar_modelo(modelo, X.iloc[idx_tr], y[idx_tr], semilla)(X.iloc[idx_te])
    umbral = ev.umbral_para_objetivo(dev, oof, objetivo)
    return umbral, ev.falsas_alarmas_por_dispositivo_dia(dev, oof > umbral)


def comparar_con_validacion(cfg: dict, resumen: dict, modelo: str) -> dict | None:
    """Cifras de validación (bloque 2) junto a las del holdout, si el informe existe."""
    ruta = ruta_proyecto(cfg["salida"])
    if not ruta.exists():
        return None
    val = json.loads(ruta.read_text())["modelos"].get(modelo, {}).get("resumen")
    if val is None:
        return None
    claves = {
        "recall_episodios": lambda r: r["episodios"]["recall"],
        "recall_atacantes": lambda r: r["atacantes"]["recall"],
        "falsas_alarmas_por_dispositivo_dia": lambda r: r["dispositivos"]["falsas_alarmas_por_dispositivo_dia"],
        "tiempo_deteccion_s_mediana": lambda r: r["episodios"]["tiempo_deteccion_s_mediana"],
        "pr_auc_ventana": lambda r: r["ventanas_referencia"]["pr_auc"],
    }
    return {k: {"validacion": f(val), "holdout": f(resumen)} for k, f in claves.items()}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Abre el holdout 20–29 una sola vez y lo evalúa.")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--romper-holdout-una-vez", action="store_true",
                   help="Reapertura única, solo por un bug demostrado (queda registrada).")
    p.add_argument("--motivo", help="Bug demostrado que justifica la reapertura.")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    cfg = leer_config(args.config)
    hcfg = cfg["holdout"]
    ruta_sello, destino = ruta_proyecto(hcfg["sello"]), ruta_proyecto(hcfg["salida"])

    try:
        sello_previo = comprobar_sello(ruta_sello, args.romper_holdout_una_vez, args.motivo)
    except HoldoutSelladoError as e:
        print(f"NEGADO: {e}", file=sys.stderr)
        return CODIGO_SELLADO

    ruta_dev, ruta_hold = ruta_proyecto(cfg["dataset"]), ruta_proyecto(hcfg["dataset"])
    dev = cargar_dataset_estricto(ruta_dev)  # sin holdout: verificar_holdout lo exige
    if not ruta_hold.exists():
        print(f"No existe {ruta_hold}; genéralo antes (ver la ayuda del script).", file=sys.stderr)
        return 1

    # Apertura: a partir de aquí el holdout cuenta como visto, pase lo que pase.
    git = commit_actual()
    ahora = datetime.now().isoformat(timespec="seconds")
    sha_hold = sha256_archivo(ruta_hold)
    if sello_previo is None:
        sello = {"commit": git["commit"], "arbol_con_cambios": git["arbol_con_cambios"], "fecha": ahora,
                 "dataset_holdout_sha256": sha_hold, "salida": hcfg["salida"], "reaperturas": []}
    else:
        sello = {**sello_previo, "reaperturas": [{"commit": git["commit"], "fecha": ahora, "motivo": args.motivo}]}
    escribir_sello(ruta_sello, sello)
    hold = cargar_dataset_estricto(ruta_hold, permitir_holdout=True)
    sesiones_hold = sorted(hold["sesion"].astype(str).unique())
    fuera = [s for s in sesiones_hold if indice_sesion(s) not in SESIONES_RESERVADAS]
    if fuera:
        raise SystemExit(f"El holdout trae sesiones no reservadas: {fuera}")

    objetivo = float(cfg["objetivo_falsas_alarmas_dispositivo_dia"])
    informe: dict = {
        "etapa": "E2", "bloque": 4, "fecha": ahora, **git,
        "config_archivo": str(args.config), "config": cfg,
        "dataset_desarrollo": {"ruta": cfg["dataset"], "sha256": sha256_archivo(ruta_dev), "filas": int(len(dev)),
                               "sesiones": sorted(dev["sesion"].astype(str).unique())},
        "dataset_holdout": {
            "ruta": hcfg["dataset"], "sha256": sha_hold, "filas": int(len(hold)), "sesiones": sesiones_hold,
            "por_etiqueta": {str(k): int(v) for k, v in hold[ETIQUETA].value_counts().sort_index().items()},
            "generacion": json.loads(ruta_meta(ruta_hold).read_text()) if ruta_meta(ruta_hold).exists() else None,
        },
        "sello": sello,
        "reapertura": None if sello_previo is None else {"motivo": args.motivo, "sello_anterior": sello_previo},
        "procedimiento": "por semilla: umbral = objetivo de FA/dispositivo-día sobre probabilidades fuera de fold "
                         f"({cfg['n_folds']} folds agrupados por sesión) del desarrollo; modelo final entrenado con "
                         "todo el desarrollo; alarma en el holdout si prob > umbral. IC por bootstrap sobre las "
                         "sesiones y los episodios del holdout.",
        "modelos": {},
    }
    for modelo in cfg["modelos"]:
        preds, umbrales = [], []
        for semilla in cfg["semillas"]:
            t0 = time.time()
            umbral, fa_dev = umbral_en_desarrollo(dev, modelo, int(semilla), int(cfg["n_folds"]), objetivo)
            prob = ev.ajustar_modelo(modelo, dev[list(COLUMNAS_MODELO)], dev[ETIQUETA].to_numpy(),
                                     int(semilla))(hold[list(COLUMNAS_MODELO)])
            preds.append(ev.PrediccionesFueraDeFold(prob, prob > umbral))
            umbrales.append({"semilla": int(semilla), "umbral": umbral,
                             "falsas_alarmas_dispositivo_dia_desarrollo_oof": fa_dev})
            logger.info("%s semilla %s: %.0f s", modelo, semilla, time.time() - t0)
        resumen = ev.resumir(hold, preds, int(cfg["n_bootstrap"]), int(cfg["semilla_bootstrap"]))
        informe["modelos"][modelo] = {"umbrales": umbrales, "resumen": resumen,
                                      "comparacion_con_validacion": comparar_con_validacion(cfg, resumen, modelo)}
    escribir_json(informe, destino)
    escribir_sello(ruta_sello, {**sello, "completado": datetime.now().isoformat(timespec="seconds")})

    print(f"Escrito {destino}; sello {ruta_sello} (commit {sello['commit']}, {sello['fecha']})")
    print(f"Holdout: {len(sesiones_hold)} sesiones ({sesiones_hold[0]}…{sesiones_hold[-1]}), {len(hold)} ventanas, "
          f"sha256 {sha_hold}")
    for m, d in informe["modelos"].items():
        r = d["resumen"]
        print(f"{m}: recall episodio {fmt_ic(r['episodios']['recall'])} · recall atacante "
              f"{fmt_ic(r['atacantes']['recall'])} · FA/disp-día "
              f"{fmt_ic(r['dispositivos']['falsas_alarmas_por_dispositivo_dia'], 2)} · t. mediana "
              f"{fmt_ic(r['episodios']['tiempo_deteccion_s_mediana'], 1)} s · PR-AUC "
              f"{fmt_ic(r['ventanas_referencia']['pr_auc'])}")
        for t, v in r["episodios"]["por_tipo"].items():
            print(f"    {t}: {fmt_ic(v)} (n={v['n']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
