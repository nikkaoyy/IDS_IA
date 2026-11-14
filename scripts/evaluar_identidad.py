#!/usr/bin/env python3
"""
Evaluación del perfil de pila frente a clones de MAC (PEDIDO-E3A-1, bloque 3; E3, OE3).

Para cada sesión de `scripts/lab/generar_clones.py`: las tramas se agrupan por MAC de origen
y ventana de 5 s, y cada MAC lleva su `SeguidorIdentidad` (src/identidad.py) en orden
temporal. **Split temporal por dispositivo**: el perfil se construye con las primeras
ventanas del equipo y solo juzga las posteriores; nunca ve el futuro.

Métricas por nivel de clon, con IC al 95 % por bootstrap de episodios:
- tasa de detección: episodio con al menos una alarma en una ventana de la MAC víctima entre
  el inicio y el fin del clon;
- latencia: desde el inicio del clon hasta el cierre de la primera ventana con alarma;
- episodios no acusables: la víctima seguía `no_confiable` al empezar el clon.
Y sobre los legítimos: falsas alarmas (ventanas con alarma fuera de todo episodio) por
dispositivo-día con IC por sesiones, y la proporción de dispositivos `no_confiable`.

Parte B (PEDIDO-E3B-1, `--partes b`): secciones de `config["b"]`, cada una sobre sus propias
sesiones, en `reports/identidad_e3b.json`:
- `ipid`: el mismo protocolo de la parte A con el IP-ID por equipo (descartado) y por flujo.
- `con_variacion`: sesiones benignas de `generar_variacion.py` (sin clones); falsas alarmas
  por ventanas y por eventos, siempre junto a la proporción `no_confiable` y los reperfilados.

Uso:
    python scripts/evaluar_identidad.py --config configs/identidad.json [--partes a,b]
"""
from __future__ import annotations

import argparse
import contextlib
import json
import logging
import math
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import numpy as np  # noqa: E402

from scripts.evaluar import commit_actual, escribir_json, fmt_ic, leer_config, ruta_proyecto  # noqa: E402
from scripts.lab import generar_clones as gc  # noqa: E402
from scripts.lab import generar_suplantacion as gs  # noqa: E402
from scripts.lab import generar_variacion as gv  # noqa: E402
from src import evaluacion as ev  # noqa: E402
from src import identidad as idn  # noqa: E402
from src.ventanas import leer_pcap  # noqa: E402

logger = logging.getLogger("evaluar_identidad")
US = 1_000_000


def seguir_sesion(tramas, ventana_s: float = idn.VENTANA_S, **seguidor) -> dict[str, list[dict]]:
    """Por MAC de origen, el resultado de su seguidor en cada ventana en la que emite.

    `seguidor` son parámetros de `SeguidorIdentidad` (para la ablación de defensas).
    """
    por_mac: dict[str, dict[int, list]] = {}
    for t in tramas:
        por_mac.setdefault(t.mac_src, {}).setdefault(int(t.ts_us // (ventana_s * US)), []).append(t)
    salida: dict[str, list[dict]] = {}
    for mac, ventanas in por_mac.items():
        seg = idn.SeguidorIdentidad(**seguidor)
        filas = []
        for k in sorted(ventanas):
            estado_previo = seg.estado
            r = seg.observar(ventanas[k], ts_us=int(k * ventana_s * US))
            filas.append({"idx": k, "estado_previo": estado_previo, "estado": r["estado"],
                          "puntaje": r["puntaje"], "alarma": bool(r["alarma"]),
                          "reperfilado": bool(r.get("reperfilado", False)),
                          "senal": max(r["por_senal"], key=r["por_senal"].get) if r["alarma"] else None})
        salida[mac] = filas
    return salida


def evaluar_sesion(nombre: str, seguimiento: dict[str, list[dict]], manifiesto: dict,
                   ventana_s: float = idn.VENTANA_S) -> dict:
    """Episodios (detección, latencia, acusable) y legítimos (FA, tiempo, no_confiable)."""
    en_episodio: dict[str, list[tuple[int, int]]] = {}
    episodios = []
    for e in manifiesto["episodios"]:
        a, b = int(e["inicio_s"] // ventana_s), int(e["fin_s"] // ventana_s)
        en_episodio.setdefault(e["mac_victima"], []).append((a, b))
        filas = [f for f in seguimiento.get(e["mac_victima"], []) if a <= f["idx"] <= b]
        previas = [f for f in seguimiento.get(e["mac_victima"], []) if f["idx"] < a]
        acusable = bool(previas) and previas[-1]["estado"] != idn.NO_CONFIABLE
        alarmas = [f for f in filas if f["alarma"]]
        latencia = (alarmas[0]["idx"] + 1) * ventana_s - e["inicio_s"] if alarmas else math.nan
        episodios.append({"sesion": nombre, **e, "acusable": acusable, "detectado": bool(alarmas),
                          "latencia_s": latencia, "ventanas": len(filas), "ventanas_con_alarma": len(alarmas)})
    dispositivos = []
    for mac, filas in seguimiento.items():
        dentro = [any(a <= f["idx"] <= b for a, b in en_episodio.get(mac, [])) for f in filas]
        fuera = [f for f, d in zip(filas, dentro) if not d]
        eventos = sum(1 for i, (f, d) in enumerate(zip(filas, dentro))
                      if f["alarma"] and not d and (i == 0 or not filas[i - 1]["alarma"]))
        span = (filas[-1]["idx"] - filas[0]["idx"] + 1) * ventana_s
        dispositivos.append({
            "sesion": nombre, "mac": mac, "victima": mac in en_episodio, "segundos": span,
            "ventanas": len(fuera), "falsas_alarmas": sum(f["alarma"] for f in fuera), "eventos_fa": eventos,
            "reperfilados": sum(f.get("reperfilado", False) for f in fuera),
            "fa_por_senal": dict(Counter(f.get("senal") for f in fuera if f["alarma"])),
            "llego_a_confiable": any(f["estado"] != idn.NO_CONFIABLE for f in filas),
            "ventanas_no_confiable": sum(f["estado"] == idn.NO_CONFIABLE for f in filas),
            "ventanas_total": len(filas),
        })
    return {"episodios": episodios, "dispositivos": dispositivos}


def resumir(episodios: list[dict], dispositivos: list[dict], n_rep: int, semilla: int) -> dict:
    """Tabla por nivel con IC y las cifras de los legítimos."""
    por_nivel = {}
    for nivel in sorted({e["nivel"] for e in episodios}):
        ep = [e for e in episodios if e["nivel"] == nivel]
        acus = [e for e in ep if e["acusable"]]
        por_nivel[nivel] = {
            "episodios": len(ep),
            "deteccion": ev.ic_media_por_unidad(np.array([e["detectado"] for e in ep], float), n_rep, semilla),
            "deteccion_acusables": ev.ic_media_por_unidad(np.array([e["detectado"] for e in acus], float), n_rep, semilla),
            "no_acusables": int(len(ep) - len(acus)),
            "latencia_s_mediana": ev.ic_mediana_por_unidad(
                [np.array([e["latencia_s"]]) for e in ep if e["detectado"]], n_rep, semilla),
            "latencia_s_p90": ev.ic_mediana_por_unidad(
                [np.array([e["latencia_s"]]) for e in ep if e["detectado"]], n_rep, semilla, cuantil=0.9),
            "por_par_de_pilas": _por_par(ep),
        }
    sesiones = sorted({d["sesion"] for d in dispositivos})
    legit = dispositivos
    num = np.array([[sum(d["falsas_alarmas"] for d in legit if d["sesion"] == s) for s in sesiones]])
    dias = np.array([[sum(d["segundos"] for d in legit if d["sesion"] == s) / ev.SEGUNDOS_POR_DIA for s in sesiones]])
    con_fa = np.array([[sum(d["falsas_alarmas"] > 0 for d in legit if d["sesion"] == s) for s in sesiones]])
    n_disp = np.array([[sum(1 for d in legit if d["sesion"] == s) for s in sesiones]])
    no_conf = np.array([[sum(not d["llego_a_confiable"] for d in legit if d["sesion"] == s) for s in sesiones]])
    vent_nc = np.array([[sum(d["ventanas_no_confiable"] for d in legit if d["sesion"] == s) for s in sesiones]])
    vent_t = np.array([[sum(d["ventanas_total"] for d in legit if d["sesion"] == s) for s in sesiones]])
    return {
        "por_nivel": por_nivel,
        "legitimos": {
            "falsas_alarmas_por_dispositivo_dia": ev.ic_razon_por_sesion(num, dias, n_rep, semilla),
            "falsas_alarmas_totales": int(num.sum()),
            "fraccion_dispositivos_con_falsa_alarma": ev.ic_razon_por_sesion(con_fa, n_disp, n_rep, semilla),
            "fraccion_dispositivos_nunca_confiables": ev.ic_razon_por_sesion(no_conf, n_disp, n_rep, semilla),
            "fraccion_ventanas_no_confiable": ev.ic_razon_por_sesion(vent_nc, vent_t, n_rep, semilla),
            "dispositivos": int(n_disp.sum()),
            "dispositivo_dias": float(dias.sum()),
            "peores": sorted(({k: d[k] for k in ("sesion", "mac", "falsas_alarmas", "segundos", "victima")}
                              for d in legit if d["falsas_alarmas"]), key=lambda d: -d["falsas_alarmas"])[:5],
        },
    }


def _por_par(episodios: list[dict]) -> dict:
    pares: dict[str, list[bool]] = {}
    for e in episodios:
        pares.setdefault(f"{e['pila_victima']}→{e['pila_clon']}", []).append(e["detectado"])
    return {k: {"episodios": len(v), "detectados": int(sum(v))} for k, v in sorted(pares.items())}


def evaluar(cfg: dict, ruta_config: str | None = None) -> dict:
    """Genera (si hace falta) las sesiones de clones, las sigue y resume."""
    dir_pcap = ruta_proyecto(cfg["dir_pcap"])
    episodios, dispositivos, sesiones = [], [], []
    for i in range(int(cfg["inicio"]), int(cfg["inicio"]) + int(cfg["sesiones"])):
        ruta = dir_pcap / f"clones_{i:03d}.pcap"
        if cfg.get("regenerar", True) or not ruta.exists():
            gc.escribir_sesion(*gc.generar_sesion(gc.SEMILLA_BASE_CLONES + i), ruta)
        manifiesto = json.loads(ruta.with_suffix(".clones.json").read_text())
        r = evaluar_sesion(ruta.stem, seguir_sesion(leer_pcap(ruta)), manifiesto)
        episodios += r["episodios"]
        dispositivos += r["dispositivos"]
        sesiones.append({"sesion": ruta.stem, "semilla": manifiesto["semilla"]})
        logger.info("%s: %d episodios, %d dispositivos", ruta.stem, len(r["episodios"]), len(r["dispositivos"]))
    return {
        "etapa": "PEDIDO-E3A-1",
        "fecha": datetime.now().isoformat(timespec="seconds"),
        **commit_actual(),
        "config_archivo": ruta_config,
        "config": cfg,
        "generador": {"script": "scripts/lab/generar_clones.py", "semilla_base": gc.SEMILLA_BASE_CLONES,
                      "pilas": {k: {kk: vv for kk, vv in v.items() if kk != "opciones"} for k, v in gc.PILAS.items()},
                      "sesiones": sesiones},
        "decisiones_previas": {
            "min_ventanas_perfil": idn.MIN_VENTANAS_PERFIL, "umbral_desviacion": idn.UMBRAL_DESVIACION,
            "z_firma_nueva": idn.Z_FIRMA_NUEVA, "min_apariciones_valor": idn.MIN_APARICIONES_VALOR,
            "ventanas_limpias_para_recuperar": idn.VENTANAS_LIMPIAS_PARA_RECUPERAR,
            "tope_actualizaciones_dia": idn.TOPE_ACTUALIZACIONES_DIA, "historia_max": idn.HISTORIA_MAX,
        },
        "resumen": resumir(episodios, dispositivos, int(cfg["n_bootstrap"]), int(cfg["semilla_bootstrap"])),
        "episodios": episodios,
    }


def markdown_b(informe: dict) -> str:
    """Resumen legible de la parte B (solo cifras del JSON)."""
    lineas = ["# E3B — cifras", "",
              f"Generado por `scripts/evaluar_identidad.py --partes b` el {informe['fecha']} en el commit "
              f"`{informe['commit']}`{' (árbol con cambios)' if informe.get('arbol_con_cambios') else ''}.", ""]
    if "ipid" in informe:
        ip = informe["ipid"]
        lineas += ["## Bloque 1 — IP-ID por equipo (descartado) frente a por flujo", "",
                   "| Medida | Por equipo (E3A) | Por flujo |", "|---|---|---|"]
        a, d = ip["ipid_por_equipo"], ip["ipid_por_flujo"]
        lineas.append(f"| FA/disp-día | {fmt_ic(a['legitimos']['falsas_alarmas_por_dispositivo_dia'], 2)} | "
                      f"{fmt_ic(d['legitimos']['falsas_alarmas_por_dispositivo_dia'], 2)} |")
        lineas.append(f"| Dispositivos con alguna FA | {fmt_ic(a['legitimos']['fraccion_dispositivos_con_falsa_alarma'])} | "
                      f"{fmt_ic(d['legitimos']['fraccion_dispositivos_con_falsa_alarma'])} |")
        for n in d["por_nivel"]:
            lineas.append(f"| Detección {n} | {fmt_ic(a['por_nivel'][n]['deteccion'])} | {fmt_ic(d['por_nivel'][n]['deteccion'])} |")
            lineas.append(f"| Latencia mediana {n} (s) | {fmt_ic(a['por_nivel'][n]['latencia_s_mediana'], 1)} | "
                          f"{fmt_ic(d['por_nivel'][n]['latencia_s_mediana'], 1)} |")
        r = ip["ipid_por_flujo_reperfilado_24"]
        lineas.append(f"| FA/disp-día por flujo + reperfilado 24 (registrado, lava el clon) | | "
                      f"{fmt_ic(r['legitimos']['falsas_alarmas_por_dispositivo_dia'], 2)} |")
        lineas.append("")
    if "con_variacion" in informe:
        cv = informe["con_variacion"]
        for titulo, bloque in (("defensas por defecto (sin reperfilado)", cv),
                               ("con el reperfilado registrado (24)", cv["reperfilado_24"])):
            lineas += [f"## Bloque 2 — legítimos con variación real (sin clones), {titulo}", "",
                       "| Grupo | Disp. | FA ventanas/disp-día | FA eventos/disp-día | Disp. con FA | Ventanas no_confiable "
                       "| Nunca confiables | Reperfilados | FA por señal (ventanas) |",
                       "|---|---|---|---|---|---|---|---|---|"]
            grupos = [("con variación (todas)", bloque["con_variacion"]),
                      ("sin variación (control + gateway)", bloque["sin_variacion"])]
            grupos += [(t, v) for t, v in bloque["por_variacion"].items()]
            for n, v in grupos:
                lineas.append(f"| {n} | {v['dispositivos']} | {fmt_ic(v['fa_ventanas_por_dispositivo_dia'], 1)} | "
                              f"{fmt_ic(v['fa_eventos_por_dispositivo_dia'], 1)} | {fmt_ic(v['fraccion_dispositivos_con_fa'], 2)} | "
                              f"{fmt_ic(v['fraccion_ventanas_no_confiable'], 3)} | "
                              f"{fmt_ic(v['fraccion_dispositivos_nunca_confiables'], 2)} | {v['reperfilados']} | "
                              f"{', '.join(f'{s} {c}' for s, c in list(v['fa_por_senal'].items())[:3]) or '—'} |")
            lineas.append("")
    if "niveles" in informe:
        lineas += _md_niveles(informe["niveles"])
    return "\n".join(lineas) + "\n"


def _md_niveles(nv: dict) -> list[str]:
    lineas = ["## Bloque 3 — tabla por nivel de clon", "",
              "Ingenuo y ritmo sobre las sesiones de E3A; los otros tres sobre las sesiones de "
              "`generar_suplantacion.py`. Detección = alarma de identidad sobre la MAC víctima o del "
              "vigilante sobre la IP víctima dentro del episodio.", ""]
    variantes = [("señal de contadores por grupos (corrección post hoc)", "e3a", "e3b"),
                 ("señal de contadores por cadenas (registrada)", "e3a_cadenas_registradas", "e3b_cadenas_registradas"),
                 ("sin señal de contadores", "e3a_sin_contadores_ipid", "e3b_sin_contadores_ipid")]
    if "confirmacion" in nv:
        variantes.append(("confirmación en sesiones nuevas (grupos)", None, None))
    for titulo, ka, kb in variantes:
        a, b = (nv[ka], nv[kb]) if ka else (nv["confirmacion"]["e3a"], nv["confirmacion"]["e3b"])
        lineas += [f"### {titulo}", "",
                   "| Nivel | Episodios | Detección | Por identidad | Por vigilante | Latencia mediana (s) | FA/disp-día de sus sesiones |",
                   "|---|---|---|---|---|---|---|"]
        for bloque in (a, b):
            fa = fmt_ic(bloque["legitimos"]["falsas_alarmas_por_dispositivo_dia"], 2)
            for n, v in bloque["por_nivel"].items():
                lineas.append(f"| {n} | {v['episodios']} | {fmt_ic(v['deteccion'])} | {fmt_ic(v['deteccion_identidad'])} | "
                              f"{fmt_ic(v['deteccion_vigilante'])} | {fmt_ic(v['latencia_s_mediana'], 1)} | {fa} |")
        pc = b["por_nivel"].get("pila_completa")
        if pc:
            lineas += ["", "Pila completa por familia de la víctima: " + ", ".join(
                f"{p} {x['detectados']}/{x['episodios']}" for p, x in pc["por_pila_victima"].items()) + "."]
        lineas.append("")
    return lineas


def markdown(informe: dict) -> str:
    """Resumen legible del JSON."""
    r = informe["resumen"]
    lg = r["legitimos"]
    lineas = ["# E3A — perfil de pila frente a clones de MAC: cifras", "",
              f"Generado por `scripts/evaluar_identidad.py` el {informe['fecha']} en el commit `{informe['commit']}`"
              f"{' (árbol con cambios)' if informe.get('arbol_con_cambios') else ''}. "
              f"{len(informe['generador']['sesiones'])} sesiones de `generar_clones.py` (semilla base "
              f"{informe['generador']['semilla_base']}). IC 95 % con {informe['config']['n_bootstrap']} réplicas.", "",
              "| Nivel | Episodios | Detección | Detección (acusables) | No acusables | Latencia mediana (s) | Latencia p90 (s) |",
              "|---|---|---|---|---|---|---|"]
    for n, v in r["por_nivel"].items():
        lineas.append(f"| {n} | {v['episodios']} | {fmt_ic(v['deteccion'])} | {fmt_ic(v['deteccion_acusables'])} | "
                      f"{v['no_acusables']} | {fmt_ic(v['latencia_s_mediana'], 1)} | {fmt_ic(v['latencia_s_p90'], 1)} |")
    lineas += ["", "## Legítimos", "",
               f"- Falsas alarmas por dispositivo-día: {fmt_ic(lg['falsas_alarmas_por_dispositivo_dia'], 2)} "
               f"({lg['falsas_alarmas_totales']} en {lg['dispositivo_dias']:.2f} dispositivo-días, {lg['dispositivos']} dispositivos).",
               f"- Dispositivos con alguna falsa alarma: {fmt_ic(lg['fraccion_dispositivos_con_falsa_alarma'])}.",
               f"- Dispositivos que nunca llegan a `confiable`: {fmt_ic(lg['fraccion_dispositivos_nunca_confiables'])}.",
               f"- Ventanas en `no_confiable`: {fmt_ic(lg['fraccion_ventanas_no_confiable'])}.", "",
               "## Detección por par de pilas (víctima → clon)", "", "| Nivel | Par | Detectados / episodios |", "|---|---|---|"]
    for n, v in r["por_nivel"].items():
        for par, c in v["por_par_de_pilas"].items():
            lineas.append(f"| {n} | {par} | {c['detectados']}/{c['episodios']} |")
    if lg["peores"]:
        lineas += ["", "## Dispositivos legítimos con más falsas alarmas", "", "| Sesión | MAC | FA | Segundos | ¿Víctima en otro momento? |", "|---|---|---|---|---|"]
        lineas += [f"| {d['sesion']} | `{d['mac']}` | {d['falsas_alarmas']} | {d['segundos']:.0f} | {'sí' if d['victima'] else 'no'} |"
                   for d in lg["peores"]]
    return "\n".join(lineas) + "\n"


# --------------------------------------------------------------------------------------------
# Parte B (PEDIDO-E3B-1)
# --------------------------------------------------------------------------------------------

def _sesiones_clones(cfg_sec: dict) -> list[tuple[str, list, dict]]:
    """(nombre, tramas, manifiesto) de las sesiones de clones de la parte A (mismas semillas)."""
    return _sesiones_generadas(cfg_sec, "clones", gc.generar_sesion, gc.SEMILLA_BASE_CLONES)


def _medir(sesiones: list[tuple[str, list, dict]], n_rep: int, semilla: int, **seguidor) -> dict:
    episodios, dispositivos = [], []
    for nombre, tramas, manifiesto in sesiones:
        r = evaluar_sesion(nombre, seguir_sesion(tramas, **seguidor), manifiesto)
        episodios += r["episodios"]
        dispositivos += r["dispositivos"]
    return resumir(episodios, dispositivos, n_rep, semilla)


def seccion_ipid(cfg: dict, cfg_sec: dict) -> dict:
    """Bloque 1: misma evaluación con el IP-ID por equipo (descartado) y por flujo."""
    sesiones = _sesiones_clones(cfg_sec)
    n_rep, sem = int(cfg["n_bootstrap"]), int(cfg["semilla_bootstrap"])
    salida = {}
    original = idn.IPID_MODO
    try:
        for modo in ("equipo", "flujo"):
            idn.IPID_MODO = modo
            salida[f"ipid_por_{modo}"] = _medir(sesiones, n_rep, sem)
            logger.info("ipid %s hecho", modo)
        # Bloque 3: la cifra del bloque 1 sin la señal de contadores de IP-ID.
        with _modulo(JUZGAR_CONTADORES_IPID=False):
            salida["ipid_por_flujo_sin_contadores"] = _medir(sesiones, n_rep, sem)
        # Bloque 2: el reperfilado registrado (24) sobre las mismas sesiones con clon.
        salida["ipid_por_flujo_reperfilado_24"] = _medir(sesiones, n_rep, sem, reperfilar_tras=idn.REPERFILAR_REGISTRADO)
        logger.info("ipid flujo + reperfilado hecho")
    finally:
        idn.IPID_MODO = original
    antes, despues = salida["ipid_por_equipo"], salida["ipid_por_flujo"]
    salida["comparacion"] = {
        "falsas_alarmas_por_dispositivo_dia": {"antes": antes["legitimos"]["falsas_alarmas_por_dispositivo_dia"],
                                               "despues": despues["legitimos"]["falsas_alarmas_por_dispositivo_dia"],
                                               "despues_con_reperfilado_24": salida["ipid_por_flujo_reperfilado_24"][
                                                   "legitimos"]["falsas_alarmas_por_dispositivo_dia"]},
        "deteccion": {n: {"antes": antes["por_nivel"][n]["deteccion"], "despues": despues["por_nivel"][n]["deteccion"]}
                      for n in despues["por_nivel"]},
        "presupuesto_e2_fa_dispositivo_dia": 1.0,
    }
    return salida


_LEIDAS: dict[Path, tuple[str, list, dict]] = {}


def _sesiones_generadas(cfg_sec: dict, prefijo: str, generar, semilla_base: int) -> list[tuple[str, list, dict]]:
    """(nombre, tramas, manifiesto) de las sesiones `prefijo_XXX`; genera las que falten.

    Cada pcap se lee una sola vez por corrida (varias secciones usan las mismas sesiones).
    """
    dir_pcap = ruta_proyecto(cfg_sec["dir_pcap"])
    salida = []
    for i in range(int(cfg_sec["inicio"]), int(cfg_sec["inicio"]) + int(cfg_sec["sesiones"])):
        ruta = dir_pcap / f"{prefijo}_{i:03d}.pcap"
        if ruta not in _LEIDAS:
            if cfg_sec.get("regenerar", False) or not ruta.exists():
                gc.escribir_sesion(*generar(semilla_base + i), ruta)
            _LEIDAS[ruta] = (ruta.stem, list(leer_pcap(ruta)), json.loads(ruta.with_suffix(".clones.json").read_text()))
        salida.append(_LEIDAS[ruta])
    return salida


def tabla_legitimos(dispositivos: list[dict], n_rep: int, semilla: int) -> dict:
    """FA (ventanas y eventos) siempre junto a no_confiable y reperfilados, con IC por sesiones."""
    sesiones = sorted({d["sesion"] for d in dispositivos})

    def fila(campo, peso=lambda d: 1):
        return np.array([[sum(campo(d) for d in dispositivos if d["sesion"] == s) for s in sesiones]], float)
    dias = fila(lambda d: d["segundos"] / ev.SEGUNDOS_POR_DIA)
    n = fila(lambda d: 1)
    return {
        "dispositivos": int(n.sum()),
        "dispositivo_dias": float(dias.sum()),
        "falsas_alarmas_ventanas": int(fila(lambda d: d["falsas_alarmas"]).sum()),
        "fa_ventanas_por_dispositivo_dia": ev.ic_razon_por_sesion(fila(lambda d: d["falsas_alarmas"]), dias, n_rep, semilla),
        "fa_eventos_por_dispositivo_dia": ev.ic_razon_por_sesion(fila(lambda d: d["eventos_fa"]), dias, n_rep, semilla),
        "fraccion_dispositivos_con_fa": ev.ic_razon_por_sesion(fila(lambda d: d["falsas_alarmas"] > 0), n, n_rep, semilla),
        "fraccion_ventanas_no_confiable": ev.ic_razon_por_sesion(
            fila(lambda d: d["ventanas_no_confiable"]), fila(lambda d: d["ventanas_total"]), n_rep, semilla),
        "fraccion_dispositivos_nunca_confiables": ev.ic_razon_por_sesion(
            fila(lambda d: not d["llego_a_confiable"]), n, n_rep, semilla),
        "reperfilados": int(fila(lambda d: d["reperfilados"]).sum()),
        "fa_por_senal": dict(sum((Counter(d.get("fa_por_senal", {})) for d in dispositivos), Counter()).most_common()),
    }


def _dispositivos_por_variacion(sesiones, **seguidor) -> list[dict]:
    salida = []
    for nombre, tramas, man in sesiones:
        tipo = {e["mac"]: e.get("variacion", "control") for e in man["equipos"]}
        r = evaluar_sesion(nombre, seguir_sesion(tramas, **seguidor), man)
        for d in r["dispositivos"]:
            salida.append({**d, "variacion": tipo.get(d["mac"], "gateway")})
    return salida


def seccion_con_variacion(cfg: dict, cfg_sec: dict, **seguidor) -> dict:
    """Bloque 2: legítimos con variación real de pila (sin clones): FA y no_confiable juntos."""
    sesiones = _sesiones_generadas(cfg_sec, "variacion", gv.generar_sesion, gv.SEMILLA_BASE_VARIACION)
    n_rep, sem = int(cfg["n_bootstrap"]), int(cfg["semilla_bootstrap"])
    tipos = list(gv.TIPOS) + ["control", "gateway"]

    def tablas(disp):
        return {
            "por_variacion": {t: tabla_legitimos([d for d in disp if d["variacion"] == t], n_rep, sem) for t in tipos},
            "con_variacion": tabla_legitimos([d for d in disp if d["variacion"] in gv.TIPOS], n_rep, sem),
            "sin_variacion": tabla_legitimos([d for d in disp if d["variacion"] in ("control", "gateway")], n_rep, sem),
            "peores": sorted(({k: d[k] for k in ("sesion", "mac", "variacion", "falsas_alarmas", "eventos_fa", "reperfilados")}
                              for d in disp if d["falsas_alarmas"]), key=lambda d: -d["falsas_alarmas"])[:8],
        }
    salida = {"sesiones": [s[0] for s in sesiones], **tablas(_dispositivos_por_variacion(sesiones, **seguidor))}
    salida["reperfilado_24"] = tablas(_dispositivos_por_variacion(
        sesiones, **{**seguidor, "reperfilar_tras": idn.REPERFILAR_REGISTRADO}))
    with _modulo(JUZGAR_CONTADORES_IPID=False):  # la configuración medida en el bloque 2
        salida["sin_contadores_ipid"] = tablas(_dispositivos_por_variacion(sesiones, **seguidor))
    logger.info("con_variacion hecho")
    return salida


@contextlib.contextmanager
def _modulo(**valores):
    """Cambia constantes de `src/identidad.py` mientras dura el bloque (variantes y ablación)."""
    originales = {k: getattr(idn, k) for k in valores}
    try:
        for k, v in valores.items():
            setattr(idn, k, v)
        yield
    finally:
        for k, v in originales.items():
            setattr(idn, k, v)


def vigilar_sesion(tramas, ventana_s: float = idn.VENTANA_S, **vigilante) -> list[dict]:
    """Alertas de `VigilanteIP` por ventana sobre todas las tramas de la sesión."""
    por_ventana: dict[int, list] = {}
    for t in tramas:
        por_ventana.setdefault(int(t.ts_us // (ventana_s * US)), []).append(t)
    vig = idn.VigilanteIP(**vigilante)
    return [{"idx": k, **a} for k in sorted(por_ventana)
            for a in vig.observar(por_ventana[k], int(k * ventana_s * US))]


def evaluar_sesion_niveles(nombre: str, tramas, manifiesto: dict, ventana_s: float = idn.VENTANA_S,
                           **seguidor) -> dict:
    """Detección por canal (identidad de la MAC víctima, vigilante de la IP víctima) y FA de ambos.

    Los equipos del atacante con MAC propia no son legítimos: no cuentan para las FA.
    """
    seguimiento = seguir_sesion(tramas, ventana_s, **seguidor)
    r = evaluar_sesion(nombre, seguimiento, manifiesto, ventana_s)
    alertas = vigilar_sesion(tramas, ventana_s)
    ip_de = {e["mac"]: e["ip"] for e in manifiesto["equipos"]}
    for e in r["episodios"]:
        a, b = int(e["inicio_s"] // ventana_s), int(e["fin_s"] // ventana_s)
        ip_v = e.get("ip_victima", ip_de.get(e["mac_victima"]))
        propias = sorted(x["idx"] for x in alertas if x["ip"] == ip_v and a <= x["idx"] <= b)
        lat_v = (propias[0] + 1) * ventana_s - e["inicio_s"] if propias else math.nan
        e["detectado_identidad"], e["latencia_identidad_s"] = e["detectado"], e["latencia_s"]
        e["detectado_vigilante"], e["latencia_vigilante_s"] = bool(propias), lat_v
        e["tipos_vigilante"] = sorted({x["tipo"] for x in alertas if x["ip"] == ip_v and a <= x["idx"] <= b})
        e["detectado"] = e["detectado_identidad"] or e["detectado_vigilante"]
        e["latencia_s"] = float(np.nanmin([e["latencia_identidad_s"], lat_v])) if e["detectado"] else math.nan
    clones = {e["mac_clon"] for e in manifiesto["episodios"] if e.get("mac_clon") not in (None, e["mac_victima"])}
    episodios_ip: dict[str, list[tuple[int, int]]] = {}
    for e in manifiesto["episodios"]:
        episodios_ip.setdefault(e.get("ip_victima", ip_de.get(e["mac_victima"])), []).append(
            (int(e["inicio_s"] // ventana_s), int(e["fin_s"] // ventana_s)))
    dispositivos = []
    for d in r["dispositivos"]:
        if d["mac"] in clones:
            continue
        ip = ip_de.get(d["mac"])
        fa_v = len({x["idx"] for x in alertas if ip is not None and x["ip"] == ip
                    and not any(a <= x["idx"] <= b for a, b in episodios_ip.get(ip, []))})
        dispositivos.append({**d, "fa_identidad": d["falsas_alarmas"], "fa_vigilante": fa_v,
                             "falsas_alarmas": d["falsas_alarmas"] + fa_v})
    return {"episodios": r["episodios"], "dispositivos": dispositivos,
            "alertas_vigilante_fuera": [x for x in alertas
                                        if not any(a <= x["idx"] <= b for a, b in episodios_ip.get(x["ip"], []))]}


def _medir_niveles(sesiones, n_rep: int, semilla: int, **seguidor) -> dict:
    episodios, dispositivos, fuera = [], [], []
    for nombre, tramas, man in sesiones:
        r = evaluar_sesion_niveles(nombre, tramas, man, **seguidor)
        episodios += r["episodios"]
        dispositivos += r["dispositivos"]
        fuera += [{"sesion": nombre, **x} for x in r["alertas_vigilante_fuera"]]
    res = resumir(episodios, dispositivos, n_rep, semilla)
    for nivel, fila in res["por_nivel"].items():
        ep = [e for e in episodios if e["nivel"] == nivel]
        for canal in ("identidad", "vigilante"):
            fila[f"deteccion_{canal}"] = ev.ic_media_por_unidad(
                np.array([e[f"detectado_{canal}"] for e in ep], float), n_rep, semilla)
        fila["por_pila_victima"] = {
            p: {"episodios": sum(e["pila_victima"] == p for e in ep),
                "detectados": int(sum(e["detectado"] for e in ep if e["pila_victima"] == p))}
            for p in sorted({e["pila_victima"] for e in ep})}
        fila["tipos_vigilante"] = dict(Counter(tp for e in ep for tp in e["tipos_vigilante"]))
    sesiones_n = sorted({d["sesion"] for d in dispositivos})
    dias = np.array([[sum(d["segundos"] for d in dispositivos if d["sesion"] == s) / ev.SEGUNDOS_POR_DIA
                      for s in sesiones_n]])
    for canal in ("identidad", "vigilante"):
        num = np.array([[sum(d[f"fa_{canal}"] for d in dispositivos if d["sesion"] == s) for s in sesiones_n]])
        res["legitimos"][f"fa_{canal}_por_dispositivo_dia"] = ev.ic_razon_por_sesion(num, dias, n_rep, semilla)
    res["legitimos"]["alertas_vigilante_fuera_de_episodio"] = fuera[:20]
    return res


def seccion_niveles(cfg: dict, cfg_sec: dict, **seguidor) -> dict:
    """Bloque 3: tabla por nivel (ingenuo y ritmo sobre E3A; pila completa, víctima apagada y
    suplantación de IP sobre las sesiones nuevas) con detección por canal, latencia y FA."""
    n_rep, sem = int(cfg["n_bootstrap"]), int(cfg["semilla_bootstrap"])
    e3a = _sesiones_clones(cfg_sec["e3a"])
    nuevas = _sesiones_generadas(cfg_sec["e3b"], "suplantacion", gs.generar_sesion, gs.SEMILLA_BASE_SUPLANTACION)
    salida = {"sesiones_e3a": [s[0] for s in e3a], "sesiones_e3b": [s[0] for s in nuevas],
              "e3a": _medir_niveles(e3a, n_rep, sem, **seguidor),
              "e3b": _medir_niveles(nuevas, n_rep, sem, **seguidor)}
    with _modulo(JUZGAR_CONTADORES_IPID=False):
        salida["e3a_sin_contadores_ipid"] = _medir_niveles(e3a, n_rep, sem, **seguidor)
        salida["e3b_sin_contadores_ipid"] = _medir_niveles(nuevas, n_rep, sem, **seguidor)
    with _modulo(IPID_CONTADORES_MODO="cadenas"):  # la señal tal como se registró
        salida["e3a_cadenas_registradas"] = _medir_niveles(e3a, n_rep, sem, **seguidor)
        salida["e3b_cadenas_registradas"] = _medir_niveles(nuevas, n_rep, sem, **seguidor)
    salida["tabla"] = {**salida["e3a"]["por_nivel"], **salida["e3b"]["por_nivel"]}
    if "confirmacion" in cfg_sec:  # sesiones nuevas para la corrección post hoc (grupos)
        conf = cfg_sec["confirmacion"]
        e3a_c = _sesiones_clones(conf["e3a"])
        nuevas_c = _sesiones_generadas(conf["e3b"], "suplantacion", gs.generar_sesion, gs.SEMILLA_BASE_SUPLANTACION)
        salida["confirmacion"] = {"sesiones_e3a": [s[0] for s in e3a_c], "sesiones_e3b": [s[0] for s in nuevas_c],
                                  "e3a": _medir_niveles(e3a_c, n_rep, sem, **seguidor),
                                  "e3b": _medir_niveles(nuevas_c, n_rep, sem, **seguidor)}
    logger.info("niveles hecho")
    return salida


SECCIONES_B = {"ipid": seccion_ipid, "con_variacion": seccion_con_variacion, "niveles": seccion_niveles}


def resumen_b(informe: dict) -> dict:
    """Cifras de cabecera de la parte B (las que imprime el criterio de aceptación)."""
    r: dict = {}
    if "ipid" in informe:
        c = informe["ipid"]["comparacion"]
        r["ipid"] = {"fa_antes": round(c["falsas_alarmas_por_dispositivo_dia"]["antes"]["valor"], 2),
                     "fa_despues": round(c["falsas_alarmas_por_dispositivo_dia"]["despues"]["valor"], 2),
                     "fa_despues_con_reperfilado_24": round(
                         c["falsas_alarmas_por_dispositivo_dia"]["despues_con_reperfilado_24"]["valor"], 2),
                     "deteccion_despues": {n: round(v["despues"]["valor"], 3) for n, v in c["deteccion"].items()}}
    if "con_variacion" in informe:
        cv = informe["con_variacion"]
        r["con_variacion"] = {k: {"fa_ventanas_dia": round(cv[k]["fa_ventanas_por_dispositivo_dia"]["valor"], 2),
                                  "fa_eventos_dia": round(cv[k]["fa_eventos_por_dispositivo_dia"]["valor"], 2),
                                  "no_confiable_ventanas": round(cv[k]["fraccion_ventanas_no_confiable"]["valor"], 3)}
                              for k in ("con_variacion", "sin_variacion")}
    if "niveles" in informe:
        nv = informe["niveles"]
        r["niveles"] = {n: {"deteccion": round(v["deteccion"]["valor"], 3),
                            "latencia_s": None if v["latencia_s_mediana"]["valor"] is None
                            else round(v["latencia_s_mediana"]["valor"], 1)}
                        for n, v in nv["tabla"].items()}
        r["niveles"]["fa_dia"] = {k: round(nv[k]["legitimos"]["falsas_alarmas_por_dispositivo_dia"]["valor"], 2)
                                  for k in ("e3a", "e3b")}
        if "confirmacion" in nv:
            r["niveles"]["confirmacion_pila_completa"] = round(
                nv["confirmacion"]["e3b"]["por_nivel"]["pila_completa"]["deteccion"]["valor"], 3)
    return r


def evaluar_b(cfg: dict, ruta_config: str | None = None) -> dict:
    """Corre las secciones de `cfg["b"]` en orden y arma `identidad_e3b.json`."""
    informe: dict = {"etapa": "PEDIDO-E3B-1", "fecha": datetime.now().isoformat(timespec="seconds"),
                     **commit_actual(), "config_archivo": ruta_config, "config": cfg}
    for nombre, cfg_sec in cfg["b"]["secciones"].items():
        informe[nombre] = SECCIONES_B[nombre](cfg, cfg_sec)
    informe["resumen"] = resumen_b(informe)
    return informe


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Evaluación E3: perfil de pila frente a clones de MAC.")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--partes", default="a", help="a (E3A), b (E3B) o a,b.")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    cfg = leer_config(args.config)
    partes = set(args.partes.split(","))
    if "b" in partes:
        informe_b = evaluar_b(cfg, str(args.config))
        destino_b = ruta_proyecto(cfg["b"]["salida"])
        escribir_json(informe_b, destino_b)
        destino_b.with_suffix(".md").write_text(markdown_b(json.loads(destino_b.read_text())))
        print(f"Escrito {destino_b} y {destino_b.with_suffix('.md')}")
        print(json.dumps(informe_b["resumen"], ensure_ascii=False))
    if "a" not in partes:
        return 0
    informe = evaluar(cfg, str(args.config))
    destino = ruta_proyecto(cfg["salida"])
    escribir_json(informe, destino)
    destino.with_suffix(".md").write_text(markdown(json.loads(destino.read_text())))
    print(f"Escrito {destino} y {destino.with_suffix('.md')}")
    for n, v in informe["resumen"]["por_nivel"].items():
        print(f"{n}: detección {fmt_ic(v['deteccion'])} · latencia mediana {fmt_ic(v['latencia_s_mediana'], 1)} s")
    lg = informe["resumen"]["legitimos"]
    print(f"legítimos: FA/disp-día {fmt_ic(lg['falsas_alarmas_por_dispositivo_dia'], 2)} · "
          f"nunca confiables {fmt_ic(lg['fraccion_dispositivos_nunca_confiables'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
