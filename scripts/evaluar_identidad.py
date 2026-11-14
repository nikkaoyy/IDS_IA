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

Uso:
    python scripts/evaluar_identidad.py --config configs/identidad.json [--partes a,b]
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from datetime import datetime
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import numpy as np  # noqa: E402

from scripts.evaluar import commit_actual, escribir_json, fmt_ic, leer_config, ruta_proyecto  # noqa: E402
from scripts.lab import generar_clones as gc  # noqa: E402
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
                          "puntaje": r["puntaje"], "alarma": bool(r["alarma"])})
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
        fuera = [f for f in filas if not any(a <= f["idx"] <= b for a, b in en_episodio.get(mac, []))]
        span = (filas[-1]["idx"] - filas[0]["idx"] + 1) * ventana_s
        dispositivos.append({
            "sesion": nombre, "mac": mac, "victima": mac in en_episodio, "segundos": span,
            "ventanas": len(fuera), "falsas_alarmas": sum(f["alarma"] for f in fuera),
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
        lineas.append("")
    return "\n".join(lineas) + "\n"


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
    dir_pcap = ruta_proyecto(cfg_sec["dir_pcap"])
    salida = []
    for i in range(int(cfg_sec["inicio"]), int(cfg_sec["inicio"]) + int(cfg_sec["sesiones"])):
        ruta = dir_pcap / f"clones_{i:03d}.pcap"
        if cfg_sec.get("regenerar", False) or not ruta.exists():
            gc.escribir_sesion(*gc.generar_sesion(gc.SEMILLA_BASE_CLONES + i), ruta)
        salida.append((ruta.stem, list(leer_pcap(ruta)), json.loads(ruta.with_suffix(".clones.json").read_text())))
    return salida


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
    finally:
        idn.IPID_MODO = original
    antes, despues = salida["ipid_por_equipo"], salida["ipid_por_flujo"]
    salida["comparacion"] = {
        "falsas_alarmas_por_dispositivo_dia": {"antes": antes["legitimos"]["falsas_alarmas_por_dispositivo_dia"],
                                               "despues": despues["legitimos"]["falsas_alarmas_por_dispositivo_dia"]},
        "deteccion": {n: {"antes": antes["por_nivel"][n]["deteccion"], "despues": despues["por_nivel"][n]["deteccion"]}
                      for n in despues["por_nivel"]},
        "presupuesto_e2_fa_dispositivo_dia": 1.0,
    }
    return salida


SECCIONES_B = {"ipid": seccion_ipid}


def resumen_b(informe: dict) -> dict:
    """Cifras de cabecera de la parte B (las que imprime el criterio de aceptación)."""
    r: dict = {}
    if "ipid" in informe:
        c = informe["ipid"]["comparacion"]
        r["ipid"] = {"fa_antes": round(c["falsas_alarmas_por_dispositivo_dia"]["antes"]["valor"], 2),
                     "fa_despues": round(c["falsas_alarmas_por_dispositivo_dia"]["despues"]["valor"], 2),
                     "deteccion_despues": {n: round(v["despues"]["valor"], 3) for n, v in c["deteccion"].items()}}
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
