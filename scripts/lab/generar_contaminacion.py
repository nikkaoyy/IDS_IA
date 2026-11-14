#!/usr/bin/env python3
"""
Generador propio de contaminación del perfil (PEDIDO-E3B-1, bloque 4; E3, OE3).

Reutiliza las primitivas de `generar_clones.py`, que no cambia. Doce equipos por sesión; ocho
víctimas, dos por condición. Cada víctima recibe un episodio principal de nivel `ritmo` (MAC e
IP de la víctima, su ritmo y tamaños, pila de otra familia) desde los 300 s, como en E3A. Antes
del episodio, según la condición, el mismo clon aparece en ráfagas de una conexión:

- `limpio`: nunca.
- `contaminado_5` / `contaminado_20`: en el 5 % / 20 % de las ventanas de 5 s entre 60 y 300 s.
- `continuo_20`: en el 20 % de las ventanas entre 0 y 300 s (el perfil nace con el clon dentro).

Cada ráfaga va al manifiesto como episodio `rafaga_<condición>` (para no contarla como falsa
alarma). Determinista con `SEMILLA_BASE_CONTAMINACION + i`.

Uso:
    python scripts/lab/generar_contaminacion.py --sesiones 20 --dir-pcap data/pcap_e3b
"""
from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import asdict
from pathlib import Path

import numpy as np

_RAIZ = Path(__file__).resolve().parents[2]
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

from scripts.lab import generar_clones as gc  # noqa: E402

logger = logging.getLogger("ids.lab.contaminacion")

SEMILLA_BASE_CONTAMINACION: int = 80_000
VENTANA_S: float = 5.0
FIN_APRENDIZAJE_S: float = 300.0
CONDICIONES: dict[str, tuple[float, float]] = {  # condición: (fracción de ventanas, desde s)
    "limpio": (0.0, 0.0),
    "contaminado_5": (0.05, 60.0),
    "contaminado_20": (0.20, 60.0),
    "continuo_20": (0.20, 0.0),
}
POR_CONDICION: int = 2


def generar_sesion(semilla: int) -> tuple[list, dict]:
    """Paquetes de la sesión y su manifiesto (episodios principales y ráfagas de contaminación)."""
    rng = np.random.default_rng(semilla)
    equipos = [gc._equipo(rng, n) for n in range(gc.N_EQUIPOS)]
    paquetes: list = []
    for e in equipos:
        gc._emitir(paquetes, rng, e, 0.0, gc.DURACION_S)
    condiciones = [c for c in CONDICIONES for _ in range(POR_CONDICION)]
    rng.shuffle(condiciones)
    huecos = np.linspace(gc.INICIO_MIN_EPISODIO_S, gc.DURACION_S - gc.DURACION_EPISODIO_S[1], len(condiciones))
    victimas = rng.choice(len(equipos), size=len(condiciones), replace=False)
    episodios = []
    for k, (inicio, iv, cond) in enumerate(zip(huecos, victimas, condiciones)):
        v = equipos[int(iv)]
        pila_clon = str(rng.choice([p for p in gc.PILAS if p != v.pila]))
        clon = gc.Equipo(mac=v.mac, ip=v.ip, pila=pila_clon, conexiones_por_min=v.conexiones_por_min,
                         longitud_media=v.longitud_media, _ipid=int(rng.integers(0, 65536)))
        fraccion, desde = CONDICIONES[cond]
        candidatas = np.arange(int(desde // VENTANA_S), int(FIN_APRENDIZAJE_S // VENTANA_S))
        elegidas = sorted(int(x) for x in rng.choice(candidatas, size=int(round(fraccion * len(candidatas))), replace=False))
        comun = {"mac_victima": v.mac, "ip_victima": v.ip, "pila_victima": v.pila, "pila_clon": pila_clon,
                 "mac_clon": v.mac, "ip_clon": v.ip, "condicion": cond}
        for w in elegidas:
            t = w * VENTANA_S + float(rng.uniform(0.2, 4.0))
            gc._conexion(paquetes, rng, t, clon, v.ip, v.mac, v.longitud_media)
            episodios.append({"episodio": len(episodios), "nivel": f"rafaga_{cond}", **comun,
                              "inicio_s": w * VENTANA_S, "fin_s": w * VENTANA_S + VENTANA_S - 1e-6})
        inicio = float(inicio + rng.uniform(0, 20))
        fin = inicio + float(rng.uniform(*gc.DURACION_EPISODIO_S))
        gc._conexion(paquetes, rng, inicio + float(rng.uniform(0, 2)), clon, v.ip, v.mac, v.longitud_media)
        gc._emitir(paquetes, rng, clon, inicio, fin)
        episodios.append({"episodio": len(episodios), "nivel": cond, **comun, "inicio_s": inicio, "fin_s": fin,
                          "ventanas_contaminadas": elegidas})
    paquetes.sort(key=lambda p: float(p.time))
    manifiesto = {"semilla": semilla, "duracion_s": gc.DURACION_S,
                  "equipos": [{k: x for k, x in asdict(e).items() if not k.startswith("_")} for e in equipos],
                  "episodios": episodios}
    return paquetes, manifiesto


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(description="Sesiones con el clon presente durante el aprendizaje del perfil.")
    p.add_argument("--sesiones", type=int, default=20)
    p.add_argument("--inicio", type=int, default=0)
    p.add_argument("--dir-pcap", type=Path, default=_RAIZ / "data" / "pcap_e3b")
    args = p.parse_args(argv)
    for i in range(args.inicio, args.inicio + args.sesiones):
        paquetes, manifiesto = generar_sesion(SEMILLA_BASE_CONTAMINACION + i)
        ruta = args.dir_pcap / f"contaminacion_{i:03d}.pcap"
        gc.escribir_sesion(paquetes, manifiesto, ruta)
        logger.info("%s: %d tramas, %d episodios", ruta.name, len(paquetes), len(manifiesto["episodios"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
