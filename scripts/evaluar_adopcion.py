#!/usr/bin/env python3
"""
Adopción de un cambio legítimo sin adoptar un clon (PEDIDO-E5C-1, bloque 2; E5, OE3).

Mide, antes (`apariciones`, comportamiento de E3B) y después (`persistencia`, las dos reglas de
E5C), las dos cifras que deciden: la **falsa alarma con variación benigna** (las 826 FA/disp-día de
E3B) y la **detección por nivel de clon**, para comprobar que las FA bajan sin perder detección.

Reutiliza los ayudantes de `scripts/evaluar_identidad.py` (no los copia): las 20 sesiones de
variación (78000–78019), las de clones (77000–77019) y las de suplantación (79000–79019).

Uso:
    python scripts/evaluar_adopcion.py --config configs/adopcion_e5c.json
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

from scripts.evaluar import commit_actual, escribir_json, fmt_ic, leer_config, ruta_proyecto  # noqa: E402
from scripts.evaluar_identidad import (  # noqa: E402
    _dispositivos_por_variacion,
    _medir_niveles,
    _modulo,
    _sesiones_clones,
    _sesiones_generadas,
    tabla_legitimos,
)
from scripts.lab import generar_suplantacion as gs  # noqa: E402
from scripts.lab import generar_variacion as gv  # noqa: E402
from src import identidad as idn  # noqa: E402

logger = logging.getLogger("evaluar_adopcion")

MODOS = ("apariciones", "persistencia")


def _fa_variacion(cfg: dict, n_rep: int, sem: int) -> dict:
    """FA por tipo de variación (y global), con la proporción `no_confiable` al lado."""
    sesiones = _sesiones_generadas(cfg["variacion"], "variacion", gv.generar_sesion, gv.SEMILLA_BASE_VARIACION)
    disp = _dispositivos_por_variacion(sesiones)
    tipos = list(gv.TIPOS) + ["control", "gateway"]
    return {
        "con_variacion": tabla_legitimos([d for d in disp if d["variacion"] in gv.TIPOS], n_rep, sem),
        "sin_variacion": tabla_legitimos([d for d in disp if d["variacion"] in ("control", "gateway")], n_rep, sem),
        "por_variacion": {t: tabla_legitimos([d for d in disp if d["variacion"] == t], n_rep, sem) for t in tipos},
    }


def _deteccion(cfg: dict, n_rep: int, sem: int) -> dict:
    """Detección por nivel: ingenuo/ritmo (clones) y pila completa/apagada/suplantación."""
    clones = _sesiones_clones(cfg["clones"])
    supl = _sesiones_generadas(cfg["suplantacion"], "suplantacion", gs.generar_sesion, gs.SEMILLA_BASE_SUPLANTACION)
    por_nivel = {}
    por_nivel.update(_medir_niveles(clones, n_rep, sem)["por_nivel"])
    por_nivel.update(_medir_niveles(supl, n_rep, sem)["por_nivel"])
    return por_nivel


def evaluar(cfg: dict, ruta_config: str | None = None) -> dict:
    """Mide FA y detección en los dos modos y arma la comparación antes/después."""
    n_rep, sem = int(cfg["n_bootstrap"]), int(cfg["semilla_bootstrap"])
    por_modo: dict = {}
    for modo in MODOS:
        with _modulo(ADOPCION_MODO=modo):
            logger.info("modo %s: FA con variación", modo)
            fa = _fa_variacion(cfg, n_rep, sem)
            logger.info("modo %s: detección por nivel", modo)
            det = _deteccion(cfg, n_rep, sem)
        por_modo[modo] = {"fa": fa, "deteccion": det}
        logger.info("modo %s hecho", modo)
    informe: dict = {
        "etapa": "E5C",
        "fecha": datetime.now().isoformat(timespec="seconds"),
        **commit_actual(),
        "config_archivo": ruta_config,
        "config": cfg,
        "ventanas_adopcion": idn.VENTANAS_ADOPCION,
        "por_modo": por_modo,
    }
    informe["resumen"] = _resumen(informe)
    return informe


def _resumen(informe: dict) -> dict:
    """Cifras de cabecera: FA con variación y detección por nivel, antes y después."""
    a, p = informe["por_modo"]["apariciones"], informe["por_modo"]["persistencia"]

    def fa_g(m):
        return round(m["fa"]["con_variacion"]["fa_ventanas_por_dispositivo_dia"]["valor"], 1)

    def nc(m):
        return round(m["fa"]["con_variacion"]["fraccion_ventanas_no_confiable"]["valor"], 3)

    tipos = list(gv.TIPOS)
    return {
        "fa_con_variacion": {"apariciones": fa_g(a), "persistencia": fa_g(p)},
        "no_confiable_con_variacion": {"apariciones": nc(a), "persistencia": nc(p)},
        "fa_por_tipo": {
            t: {"apariciones": round(a["fa"]["por_variacion"][t]["fa_ventanas_por_dispositivo_dia"]["valor"], 1),
                "persistencia": round(p["fa"]["por_variacion"][t]["fa_ventanas_por_dispositivo_dia"]["valor"], 1)}
            for t in tipos},
        "deteccion_por_nivel": {
            n: {"apariciones": round(a["deteccion"][n]["deteccion"]["valor"], 3),
                "persistencia": round(p["deteccion"][n]["deteccion"]["valor"], 3)}
            for n in sorted(a["deteccion"])},
    }


def markdown(informe: dict) -> str:
    """Resumen legible (solo cifras del JSON)."""
    a, p = informe["por_modo"]["apariciones"], informe["por_modo"]["persistencia"]
    lineas = [
        "# Adopción sin absorber el clon (E5C) — cifras", "",
        f"Generado por `scripts/evaluar_adopcion.py` el {informe['fecha']} en el commit "
        f"`{informe['commit']}`{' (árbol con cambios)' if informe.get('arbol_con_cambios') else ''}.",
        f"`VENTANAS_ADOPCION = {informe['ventanas_adopcion']}`.", "",
        "## Falsas alarmas con variación benigna (ventanas/disp-día)", "",
        "| Grupo | apariciones (E3B) | persistencia (E5C) |", "|---|---|---|",
    ]

    def fav(m, t=None):
        tabla = m["fa"]["por_variacion"][t] if t else m["fa"]["con_variacion"]
        return fmt_ic(tabla["fa_ventanas_por_dispositivo_dia"], 1)

    lineas.append(f"| **con variación (todas)** | {fav(a)} | {fav(p)} |")
    lineas.append(f"| sin variación (control + gateway) | "
                  f"{fmt_ic(a['fa']['sin_variacion']['fa_ventanas_por_dispositivo_dia'], 1)} | "
                  f"{fmt_ic(p['fa']['sin_variacion']['fa_ventanas_por_dispositivo_dia'], 1)} |")
    for t in gv.TIPOS:
        lineas.append(f"| {t} | {fav(a, t)} | {fav(p, t)} |")
    lineas.append(f"| ventanas en `no_confiable` (con variación) | "
                  f"{fmt_ic(a['fa']['con_variacion']['fraccion_ventanas_no_confiable'], 3)} | "
                  f"{fmt_ic(p['fa']['con_variacion']['fraccion_ventanas_no_confiable'], 3)} |")
    lineas += ["", "## Detección por nivel de clon", "",
               "| Nivel | apariciones (E3B) | persistencia (E5C) |", "|---|---|---|"]
    for n in sorted(a["deteccion"]):
        lineas.append(f"| {n} | {fmt_ic(a['deteccion'][n]['deteccion'])} | {fmt_ic(p['deteccion'][n]['deteccion'])} |")
    lineas.append("")
    return "\n".join(lineas) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="E5C: adopción de cambios legítimos sin absorber clones.")
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
