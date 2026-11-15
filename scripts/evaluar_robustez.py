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
from scripts.evaluar_identidad import seguir_sesion, vigilar_sesion  # noqa: E402
from scripts.lab.ficha_dataset import sha256_archivo  # noqa: E402
from src import evaluacion as ev  # noqa: E402
from src.data import nombre_sesion  # noqa: E402
from src.ventanas import leer_pcap  # noqa: E402

logger = logging.getLogger("evaluar_robustez")

K_DEFECTO = 2

# Invariante de efecto por ataque (bloque 3): la tasa mínima que lo mantiene siendo ataque la pone
# la física del objetivo, no el detector. `suave` son las tasas reales de `RANGOS_ATAQUE` en
# `scripts/lab/generar_trafico.py` (generador congelado). `suelo` es la tasa mínima teórica con la
# que el invariante aún se cumple. `lectura` compara ambas. Tabla estática, citada, no medida.
INVARIANTES: list[dict] = [
    {"ataque": "syn_flood", "suave": "0,4–2,5 SYN/s, 120–400 s",
     "invariante": "agotar el backlog (N) antes del primer reintento SYN-ACK (RTO)",
     "suelo": "N/RTO ≈ 64/3 ≈ 21 medios-abiertos/s",
     "lectura": "`suave` queda muy por debajo del suelo de backlog: no agota la cola"},
    {"ataque": "arp_spoofing", "suave": "0,25–0,8 ARP/s, 120–400 s",
     "invariante": "refrescar antes del gc_stale de la caché (≈60 s Linux, ≈30 s Windows)",
     "suelo": "≥ 1/60 s ≈ 0,017 ARP/s",
     "lectura": "`suave` por encima del suelo: sigue envenenando la caché"},
    {"ataque": "mac_flooding", "suave": "1–6 MAC/s, 60–300 s",
     "invariante": "inserciones/s ≥ tamaño de la tabla CAM / su tiempo de envejecimiento",
     "suelo": "≈ 8192/300 ≈ 27 MAC/s",
     "lectura": "`suave` muy por debajo: no desborda la CAM (no fuerza el modo hub)"},
    {"ataque": "port_scan", "suave": "0,3–0,6 sondas/s, 40–120 puertos",
     "invariante": "puertos distintos/hora suficientes para cubrir el rango objetivo",
     "suelo": "depende del rango; top-puertos se cubre lento",
     "lectura": "`suave` conserva el efecto: recorre los puertos comunes, solo más despacio"},
    {"ataque": "dns_spoofing", "suave": "0,3–0,7 resp/s, 120–400 s",
     "invariante": "la respuesta forjada llega antes que la legítima (ventana de RTT)",
     "suelo": "1 respuesta por consulta dentro de la ventana de RTT",
     "lectura": "el efecto lo pone la carrera por consulta, no la tasa agregada"},
    {"ataque": "icmp_flood", "suave": "0,5–2 ICMP/s, 60–300 s",
     "invariante": "saturar el ancho de banda o la CPU del objetivo (BlackNurse: tipo 3/3)",
     "suelo": "depende del enlace; muy por encima de unas pocas/s",
     "lectura": "`suave` no satura: es más sonda que inundación"},
]


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
# Canales de identidad y vigilante IP->MAC, y el OR
# --------------------------------------------------------------------------------------------

def _episodios_sesion(dir_pcap: Path, nombre: str, ventana_s: float) -> dict[int, dict]:
    """Por episodio de la sesión: MACs atacantes, ventanas que toca (idx absoluto) y tipo.

    El índice de ventana es `ts_us // (ventana_s · 10⁶)`, el mismo que usan `seguir_sesion` y
    `vigilar_sesion`, así que el solape temporal se calcula sin depender de `t0`.
    """
    tramas = pd.read_csv(dir_pcap / f"{nombre}.tramas.csv")
    epis: dict[int, dict] = {}
    for ep, g in tramas.groupby("episodio"):
        idx = {int(x) for x in (g["ts_us"] // int(ventana_s * 1_000_000)).astype("int64")}
        epis[int(ep)] = {"macs": set(g["mac_src"].astype(str)), "idx": idx, "tipo": ev._moda(g["tipo"])}
    return epis


def canales_identidad_vigilante(cfg: dict) -> dict:
    """Recall de los canales de identidad y vigilante IP→MAC sobre los pcaps de ataque, y sus FA.

    Detección por solape temporal: un episodio está detectado por un canal si ese canal alarma en
    una ventana que el episodio toca (y, para identidad, en una MAC del atacante). Las FA son las
    alarmas en ventanas fuera de todo episodio, por dispositivo-día. Limitación declarada: una
    alarma benigna que caiga en una ventana de episodio se acredita como detección.
    """
    dir_pcap = ruta_proyecto(cfg["dir_pcap"])
    ventana_s = ev.VENTANA_CORTA_S
    por_episodio: dict[str, dict] = {}
    fa_identidad = fa_vigilante = 0
    dispositivo_dias = 0.0
    for i in range(int(cfg["sesiones"])):
        nombre = nombre_sesion(i)
        tramas = list(leer_pcap(dir_pcap / f"{nombre}.pcap"))
        epis = _episodios_sesion(dir_pcap, nombre, ventana_s)
        seg = seguir_sesion(tramas)
        alertas = vigilar_sesion(tramas)
        union_idx: set[int] = set().union(*[e["idx"] for e in epis.values()]) if epis else set()

        alarmas_por_mac = {mac: {f["idx"] for f in filas if f["alarma"]} for mac, filas in seg.items()}
        for mac, filas in seg.items():
            idxs = [f["idx"] for f in filas]
            dispositivo_dias += (max(idxs) - min(idxs) + 1) * ventana_s / ev.SEGUNDOS_POR_DIA
            fa_identidad += len(alarmas_por_mac[mac] - union_idx)
        fa_vigilante += sum(1 for a in alertas if a["idx"] not in union_idx)

        for ep, info in epis.items():
            det_id = any(alarmas_por_mac.get(m, set()) & info["idx"] for m in info["macs"])
            det_vig = any(a["idx"] in info["idx"] for a in alertas)
            por_episodio[f"{nombre}#{ep}"] = {"tipo": info["tipo"], "det_identidad": det_id,
                                              "det_vigilante": det_vig}
        logger.info("canales: %s (%d episodios)", nombre, len(epis))

    tipos = sorted({v["tipo"] for v in por_episodio.values()})

    def recall(canal: str, tipo: str | None = None) -> float | None:
        vals = [v[canal] for v in por_episodio.values() if tipo is None or v["tipo"] == tipo]
        return float(np.mean(vals)) if vals else None

    def por_dia(fa: int) -> float | None:
        return float(fa / dispositivo_dias) if dispositivo_dias else None

    return {
        "por_episodio": por_episodio,
        "identidad": {"recall_global": recall("det_identidad"),
                      "recall_por_tipo": {t: recall("det_identidad", t) for t in tipos},
                      "falsas_alarmas": int(fa_identidad), "fa_por_dispositivo_dia": por_dia(fa_identidad)},
        "vigilante": {"recall_global": recall("det_vigilante"),
                      "recall_por_tipo": {t: recall("det_vigilante", t) for t in tipos},
                      "falsas_alarmas": int(fa_vigilante), "fa_por_dispositivo_dia": por_dia(fa_vigilante)},
        "dispositivo_dias": round(dispositivo_dias, 3),
    }


def canal_or(tabla_sup42: pd.DataFrame, canales: dict, cfg: dict, sup: dict) -> dict:
    """OR booleano por episodio: supervisado(semilla 42) ∨ identidad ∨ vigilante, con su FA sumada.

    El canal supervisado entra con la detección por episodio de la semilla de referencia 42 (no la
    media de las 5): así el OR es un ∨ limpio sobre los mismos episodios etiquetables. El recall
    supervisado de cabecera sigue siendo la media de las 5 semillas (en `supervisado.resumen`).
    """
    por_ep = canales["por_episodio"]
    filas = []
    for _, fila in tabla_sup42.iterrows():
        c = por_ep.get(f"{fila['sesion']}#{int(fila['episodio'])}", {})
        filas.append({"tipo": str(fila["tipo"]), "sup": bool(fila["detectado"]),
                      "or": bool(fila["detectado"]) or bool(c.get("det_identidad")) or bool(c.get("det_vigilante"))})
    d = pd.DataFrame(filas)
    tipos = sorted(d["tipo"].unique())
    fa_sup = float(sup["dispositivos"]["falsas_alarmas_por_dispositivo_dia"]["valor"])
    fa_id = canales["identidad"]["fa_por_dispositivo_dia"]
    fa_vig = canales["vigilante"]["fa_por_dispositivo_dia"]
    return {
        "recall_supervisado_42": float(d["sup"].mean()),
        "recall_or": float(d["or"].mean()),
        "extra_recall_or": float(d["or"].mean() - d["sup"].mean()),
        "recall_or_por_tipo": {t: float(d[d["tipo"] == t]["or"].mean()) for t in tipos},
        "recall_supervisado_42_por_tipo": {t: float(d[d["tipo"] == t]["sup"].mean()) for t in tipos},
        "fa_por_dispositivo_dia": {
            "supervisado": round(fa_sup, 2),
            "identidad_en_estas_sesiones": round(fa_id, 2) if fa_id is not None else None,
            "identidad_referencia_e3b_con_variacion": cfg.get("fa_identidad_e3b_variacion"),
            "vigilante": round(fa_vig, 2) if fa_vig is not None else None,
            "or_total_en_estas_sesiones": round(fa_sup + (fa_id or 0) + (fa_vig or 0), 2),
        },
    }


# --------------------------------------------------------------------------------------------
# Invariantes de efecto (bloque 3)
# --------------------------------------------------------------------------------------------

def invariantes_efecto(resumen_sup: dict, inv: pd.DataFrame) -> list[dict]:
    """Cruza la tabla estática de invariantes con el recall supervisado en `suave` y los invisibles.

    Donde `suave` cae bajo el suelo de efecto **y** el recall en `suave` es 0 por etiqueta (ninguna
    ventana alcanza K), se marca «invisible por construcción»: no cuenta como evasión del modelo.
    """
    por_ti = resumen_sup["episodios"].get("por_tipo_e_intensidad", {})
    inv_suave = (inv[(inv["invisible"]) & (inv["intensidad"] == "suave")]["tipo"].value_counts().to_dict()
                 if len(inv) else {})
    salida = []
    for base in INVARIANTES:
        clave = f"{base['ataque']}/suave"
        bloque = por_ti.get(clave)
        recall = bloque["valor"] if bloque and bloque.get("valor") is not None else None
        n_suave = bloque.get("n") if bloque else 0
        n_inv_suave = int(inv_suave.get(base["ataque"], 0))
        invisible = (recall == 0 or recall is None) and n_inv_suave > 0
        salida.append({
            **base, "recall_suave": recall, "episodios_suave_etiquetables": n_suave,
            "invisibles_suave": n_inv_suave,
            "invisible_por_construccion": bool(invisible),
        })
    return salida


def _markdown_invariantes(invariantes: list[dict]) -> list[str]:
    """Tabla de invariantes con el recall supervisado medido en `suave`."""
    lineas = ["## Invariantes de efecto (el suelo lo pone la física, no el detector)", "",
              "Tasa `suave` real del generador congelado (`RANGOS_ATAQUE`) frente al suelo teórico que "
              "conserva el efecto, y el recall del supervisado medido en `suave`.", "",
              "| Ataque | `suave` (generador) | Invariante | Suelo de efecto | Recall `suave` | Invisibles `suave` |",
              "|---|---|---|---|---|---|"]
    for r in invariantes:
        rec = f"{r['recall_suave']:.3f}" if r["recall_suave"] is not None else "—"
        if r["invisible_por_construccion"]:
            rec += " (invisible por construcción)"
        lineas.append(f"| {r['ataque']} | {r['suave']} | {r['invariante']} | {r['suelo']} | {rec} "
                      f"| {r['invisibles_suave']} |")
    lineas += ["", "Donde la `suave` cae bajo el suelo de efecto y el recall es 0 por etiqueta, el "
               "ataque es «invisible por construcción» y no cuenta como evasión del modelo.", ""]
    return lineas


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

    canales = canales_identidad_vigilante(cfg)
    idx_or = list(cfg["semillas"]).index(int(cfg.get("semilla_or", cfg["semillas"][0])))
    tabla42 = ev.tabla_episodios(df, predicciones[idx_or].alarma)
    canales["or"] = canal_or(tabla42, canales, cfg, resumen_sup)

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
        "canales": canales,
        "invariantes": invariantes_efecto(resumen_sup, inv),
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
        c = informe["canales"]
        r["canales"] = {
            "recall_supervisado_42": round(c["or"]["recall_supervisado_42"], 3),
            "recall_or": round(c["or"]["recall_or"], 3),
            "extra_recall_or": round(c["or"]["extra_recall_or"], 3),
            "recall_identidad": c["identidad"]["recall_global"],
            "recall_vigilante": round(c["vigilante"]["recall_global"], 3),
            "fa_por_dispositivo_dia": c["or"]["fa_por_dispositivo_dia"],
        }
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
    if "canales" in informe:
        lineas += _markdown_canales(informe["canales"])
    if "invariantes" in informe:
        lineas += _markdown_invariantes(informe["invariantes"])
    return "\n".join(lineas) + "\n"


def _celda(por_tipo: dict, t: str) -> str:
    v = por_tipo.get(t)
    return f"{v:.3f}" if v is not None else "—"


def _markdown_canales(canales: dict) -> list[str]:
    """Recall por canal y tipo, y el OR con su costo en FA."""
    o = canales["or"]
    tipos = sorted(set(o["recall_or_por_tipo"]) | set(canales["identidad"]["recall_por_tipo"]))
    lineas = ["## Canales por separado y el OR", "",
              "Detección por episodio etiquetable; el supervisado entra en el OR con la semilla 42. "
              "Identidad y vigilante por solape temporal sobre los pcaps de ataque.", "",
              "| Tipo | Supervisado(42) | Identidad | Vigilante | OR |", "|---|---|---|---|---|"]
    for t in tipos:
        lineas.append(
            f"| {t} | {_celda(o['recall_supervisado_42_por_tipo'], t)} "
            f"| {_celda(canales['identidad']['recall_por_tipo'], t)} "
            f"| {_celda(canales['vigilante']['recall_por_tipo'], t)} | {_celda(o['recall_or_por_tipo'], t)} |")
    fa = o["fa_por_dispositivo_dia"]
    lineas += [
        f"| **global** | {o['recall_supervisado_42']:.3f} | "
        f"{(canales['identidad']['recall_global'] or 0):.3f} | {canales['vigilante']['recall_global']:.3f} | "
        f"{o['recall_or']:.3f} |", "",
        f"El OR añade **{o['extra_recall_or']:+.3f}** de recall sobre el supervisado. Costo en FA/disp-día "
        f"sobre estas sesiones: supervisado {fa['supervisado']}, vigilante {fa['vigilante']}, "
        f"identidad {fa['identidad_en_estas_sesiones']} (referencia E3B con variación benigna: "
        f"{fa['identidad_referencia_e3b_con_variacion']}); OR total {fa['or_total_en_estas_sesiones']}.", ""]
    return lineas


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
