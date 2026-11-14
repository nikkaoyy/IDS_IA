#!/usr/bin/env python3
"""
Prueba de robustez del detector (PEDIDO-E4R-1; E4, OE3; Fig. 1, bloque «Clasificación»).

Fase de testing adversarial **defensiva**: medir cuánto se le escapan los ataques al detector a
medida que bajan de intensidad, sobre el **corpus de ataques ya congelado** de E1/E2
(`data/pcap/sesion_000..019`, `data/dataset_lab.csv`). No se genera ningún ataque ni evasión
nuevos: se reutiliza lo que ya existe y se mide el defensor contra ello, para documentar sus
debilidades.

El script reutiliza `src/evaluacion.py` (no lo copia ni lo modifica): el canal supervisado sale de
`predecir_fuera_de_fold` + `resumir` al punto de operación de E2 (1 FA/disp-día). La pieza nueva es
la cuenta de episodios **invisibles por construcción**: aquellos cuyo máximo de `n_tramas_ataque`
por ventana nunca llega a `K=2`, de modo que ninguna ventana se etiqueta y el canal supervisado no
puede verlos por diseño (es un límite del etiquetado por ventana, no evasión del modelo).
`tabla_episodios` solo agrupa `etiqueta==1`, así que hoy esos episodios desaparecen del denominador
sin contarse; aquí se cuentan aparte desde el `df` crudo.

Uso:
    python scripts/evaluar_robustez.py --config configs/robustez.json
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

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
from src import evaluacion as ev  # noqa: E402
from src.data import nombre_sesion  # noqa: E402

logger = logging.getLogger("evaluar_robustez")

K_DEFECTO = 2


# --------------------------------------------------------------------------------------------
# Dataset y canal supervisado
# --------------------------------------------------------------------------------------------

def verificar_dataset(cfg: dict) -> pd.DataFrame:
    """Carga el dataset y aborta si su sha256 no coincide con el congelado.

    Raises:
        FileNotFoundError: Si no existe el dataset.
        ValueError: Si el sha256 no coincide con `cfg["sha256_esperado"]`.
    """
    ruta = ruta_proyecto(cfg["dataset"])
    df = cargar_dataset_estricto(cfg["dataset"])
    sha = sha256_archivo(ruta)
    esperado = cfg.get("sha256_esperado")
    if esperado and sha != esperado:
        raise ValueError(
            f"El dataset {ruta} tiene sha256 {sha}, no el congelado {esperado}; "
            "regenéralo con los generadores congelados antes de medir la robustez."
        )
    return df


def predicciones_supervisado(df: pd.DataFrame, cfg: dict) -> list[ev.PrediccionesFueraDeFold]:
    """Predicciones fuera de fold de XGBoost por semilla, al punto de operación de E2."""
    objetivo = float(cfg["objetivo_falsas_alarmas_dispositivo_dia"])
    predicciones = []
    for semilla in cfg["semillas"]:
        logger.info("supervisado: semilla %s", semilla)
        predicciones.append(ev.predecir_fuera_de_fold(
            df, cfg["modelo"], int(semilla), n_folds=int(cfg["n_folds"]),
            n_folds_internos=int(cfg["n_folds_internos"]), objetivo_por_dispositivo_dia=objetivo,
        ))
    return predicciones


# --------------------------------------------------------------------------------------------
# Invisibles por construcción
# --------------------------------------------------------------------------------------------

def tipos_por_episodio(dir_pcap: Path, n_sesiones: int) -> dict[tuple[str, int], str]:
    """Mapa (sesión, episodio) -> tipo de ataque leído de los `.episodios.csv`.

    Los episodios por debajo de K pierden su `tipo_ataque` en el dataset (se vuelve "normal" por la
    regla K de `pcap_to_features`), pero el sidecar conserva la verdad terreno.
    """
    mapa: dict[tuple[str, int], str] = {}
    for i in range(int(n_sesiones)):
        nombre = nombre_sesion(i)
        ruta = dir_pcap / f"{nombre}.episodios.csv"
        if not ruta.exists():
            continue
        for _, fila in pd.read_csv(ruta).iterrows():
            mapa[(nombre, int(fila["episodio"]))] = str(fila["tipo"])
    return mapa


def episodios_invisibles(df: pd.DataFrame, k: int = K_DEFECTO,
                         tipos: dict[tuple[str, int], str] | None = None) -> pd.DataFrame:
    """Un episodio es invisible si ninguna de sus ventanas alcanza `k` tramas de ataque.

    Parte de las filas que tocan un episodio (`episodio >= 0`, `n_tramas_ataque > 0`), etiquetadas o
    no. `intensidad` se conserva en el dataset aun por debajo de K; `tipo` se toma del sidecar
    (`tipos`) porque el dataset lo borra bajo K, o de la moda del `df` si no se pasa.
    """
    cols = ["sesion", "episodio", "tipo", "intensidad", "max_tramas", "ventanas_tocadas", "invisible"]
    base = df[(df["episodio"] >= 0) & (df["n_tramas_ataque"] > 0)]
    if base.empty:
        return pd.DataFrame(columns=cols)
    filas = []
    for (sesion, episodio), grupo in base.groupby(["sesion", "episodio"], sort=True):
        tipo = (tipos or {}).get((str(sesion), int(episodio))) or ev._moda(grupo["tipo_ataque"])
        max_tramas = int(grupo["n_tramas_ataque"].max())
        filas.append({
            "sesion": str(sesion), "episodio": int(episodio), "tipo": tipo,
            "intensidad": ev._moda(grupo["intensidad"]), "max_tramas": max_tramas,
            "ventanas_tocadas": int(len(grupo)), "invisible": max_tramas < k,
        })
    return pd.DataFrame(filas, columns=cols)


def _recall_con_invisibles(valor: float | None, n_etiquetables: int, n_invisibles: int) -> dict:
    """Recall sobre etiquetables (como E2) y sobre todos (invisibles como no detectados)."""
    detectados = (valor or 0.0) * n_etiquetables
    total = n_etiquetables + n_invisibles
    return {
        "recall_etiquetables": valor,
        "n_etiquetables": int(n_etiquetables),
        "n_invisibles": int(n_invisibles),
        "recall_todos": (detectados / total) if total else None,
    }


def resumen_invisibles(resumen_sup: dict, inv: pd.DataFrame) -> dict:
    """Las dos cifras de recall (etiquetable vs todos) global, por tipo y por intensidad.

    El IC mostrado en el informe es el de los etiquetables (de `ev.resumir`); la cifra sobre todos
    es aritmética sobre ese punto, sin IC propio.
    """
    episodios = resumen_sup["episodios"]
    invisibles = inv[inv["invisible"]] if len(inv) else inv
    inv_tipo = invisibles["tipo"].value_counts().to_dict() if len(invisibles) else {}
    inv_int = invisibles["intensidad"].value_counts().to_dict() if len(invisibles) else {}

    global_ = _recall_con_invisibles(
        episodios["recall"]["valor"], episodios["recall"].get("n", 0), int(len(invisibles)))
    por_tipo = {}
    for t in sorted(set(episodios["por_tipo"]) | set(inv_tipo)):
        bloque = episodios["por_tipo"].get(t, {"valor": None, "n": 0})
        por_tipo[t] = _recall_con_invisibles(bloque.get("valor"), bloque.get("n", 0), int(inv_tipo.get(t, 0)))
    por_int = {}
    for i in sorted(set(episodios["por_intensidad"]) | set(inv_int)):
        bloque = episodios["por_intensidad"].get(i, {"valor": None, "n": 0})
        por_int[i] = _recall_con_invisibles(bloque.get("valor"), bloque.get("n", 0), int(inv_int.get(i, 0)))
    return {
        "total": global_,
        "por_tipo": por_tipo,
        "por_intensidad": por_int,
        "episodios_invisibles": invisibles.to_dict("records") if len(invisibles) else [],
    }


# --------------------------------------------------------------------------------------------
# Orquestación y salida
# --------------------------------------------------------------------------------------------

def evaluar(cfg: dict, ruta_config: str | None = None) -> dict:
    """Evalúa la robustez del canal supervisado y cuenta los invisibles por construcción."""
    df = verificar_dataset(cfg)
    k = int(cfg.get("k_tramas_ataque", K_DEFECTO))
    predicciones = predicciones_supervisado(df, cfg)
    resumen_sup = ev.resumir(df, predicciones, int(cfg["n_bootstrap"]), int(cfg["semilla_bootstrap"]))
    inv = episodios_invisibles(df, k, tipos_por_episodio(ruta_proyecto(cfg["dir_pcap"]), cfg["sesiones"]))

    informe: dict = {
        "etapa": "E4R",
        "fecha": datetime.now().isoformat(timespec="seconds"),
        **commit_actual(),
        "config_archivo": ruta_config,
        "config": cfg,
        "dataset": {"ruta": cfg["dataset"], "sha256": sha256_archivo(ruta_proyecto(cfg["dataset"])),
                    "filas": int(len(df))},
        "supervisado": {"resumen": resumen_sup},
        "invisibles": resumen_invisibles(resumen_sup, inv),
    }
    informe["resumen"] = resumen_robustez(informe)
    return informe


def resumen_robustez(informe: dict) -> dict:
    """Cifras de cabecera que imprime el criterio de aceptación."""
    sup = informe["supervisado"]["resumen"]
    inv = informe["invisibles"]
    suave_tipo = {t: round(v["valor"], 3) for t, v in sup["episodios"]["por_intensidad"].items()
                  if t == "suave" and v.get("valor") is not None}
    r: dict = {
        "recall_episodio": round(sup["episodios"]["recall"]["valor"], 3),
        "recall_por_intensidad": {i: (round(v["valor"], 3) if v.get("valor") is not None else None)
                                  for i, v in sup["episodios"]["por_intensidad"].items()},
        "fa_dispositivo_dia": round(sup["dispositivos"]["falsas_alarmas_por_dispositivo_dia"]["valor"], 2),
        "invisibles_total": inv["total"]["n_invisibles"],
        "recall_suave_etiquetable": (round(inv["por_intensidad"].get("suave", {}).get("recall_etiquetables") or 0, 3)),
        "recall_suave_todos": (round(inv["por_intensidad"].get("suave", {}).get("recall_todos") or 0, 3)),
        "invisibles_por_tipo": {t: v["n_invisibles"] for t, v in inv["por_tipo"].items() if v["n_invisibles"]},
    }
    r["_suave_tipo_debug"] = suave_tipo
    if "canales" in informe:
        r["canales"] = informe["canales"].get("resumen", {})
    return r


# --------------------------------------------------------------------------------------------
# Markdown derivado
# --------------------------------------------------------------------------------------------

def markdown(informe: dict) -> str:
    """Resumen legible del JSON (no añade cifras que no estén en él)."""
    sup = informe["supervisado"]["resumen"]
    inv = informe["invisibles"]
    lineas = [
        "# Robustez del detector (E4R) — cifras", "",
        f"Generado por `scripts/evaluar_robustez.py` el {informe['fecha']} en el commit "
        f"`{informe['commit']}`{' (árbol con cambios)' if informe.get('arbol_con_cambios') else ''}.",
        f"Dataset `{informe['dataset']['ruta']}` sha256 `{informe['dataset']['sha256']}` "
        f"({informe['dataset']['filas']} ventanas).",
        "",
        "Canal supervisado: XGBoost, validación anidada al punto de operación de E2 "
        f"(≤ {informe['config']['objetivo_falsas_alarmas_dispositivo_dia']:g} FA/disp-día), "
        f"{informe['config']['n_folds']} folds × {len(informe['config']['semillas'])} semillas.",
        "",
        "## Recall por intensidad (episodios etiquetables vs todos, con invisibles)", "",
        "| Intensidad | Recall etiquetable (IC) | Etiquetables | Invisibles | Recall sobre todos |",
        "|---|---|---|---|---|",
    ]
    for i in sorted(inv["por_intensidad"]):
        b = inv["por_intensidad"][i]
        ic = sup["episodios"]["por_intensidad"].get(i)
        rt = b["recall_todos"]
        lineas.append(f"| {i} | {fmt_ic(ic)} | {b['n_etiquetables']} | {b['n_invisibles']} | "
                      f"{rt:.3f} |" if rt is not None else f"| {i} | {fmt_ic(ic)} | {b['n_etiquetables']} | "
                      f"{b['n_invisibles']} | — |")
    lineas += ["", "## Recall por tipo de ataque (etiquetable vs todos)", "",
               "| Tipo | Recall etiquetable (IC) | Etiquetables | Invisibles | Recall sobre todos |",
               "|---|---|---|---|---|"]
    for t in sorted(inv["por_tipo"]):
        b = inv["por_tipo"][t]
        ic = sup["episodios"]["por_tipo"].get(t)
        rt = b["recall_todos"]
        lineas.append(f"| {t} | {fmt_ic(ic)} | {b['n_etiquetables']} | {b['n_invisibles']} | "
                      + (f"{rt:.3f} |" if rt is not None else "— |"))
    lineas += ["", f"Invisibles por construcción (máx `n_tramas_ataque` < K={informe['config'].get('k_tramas_ataque', K_DEFECTO)} "
               f"en todas sus ventanas): **{inv['total']['n_invisibles']}** episodios.",
               "El IC mostrado es el de los episodios etiquetables (de `ev.resumir`); la columna "
               "«sobre todos» añade los invisibles como no detectados y no lleva IC propio.", ""]
    return "\n".join(lineas) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Prueba de robustez del detector (E4R).")
    p.add_argument("--config", required=True, type=Path)
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    cfg = leer_config(args.config)
    informe = evaluar(cfg, str(args.config))
    destino = ruta_proyecto(cfg["salida"])
    escribir_json(informe, destino)
    destino.with_suffix(".md").write_text(markdown(json.loads(destino.read_text())))
    print(f"Escrito {destino} y {destino.with_suffix('.md')}")
    print(json.dumps(informe["resumen"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
