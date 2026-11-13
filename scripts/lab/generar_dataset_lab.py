#!/usr/bin/env python3
"""
Orquestador del laboratorio (etapa E1): sesiones -> pcap -> ventanas etiquetadas.

Cada sesión usa una semilla distinta y sustituye al antiguo pcap por clase. No requiere
root ni toca interfaces. Las semillas desde `SEMILLA_BASE + SESIONES` quedan sin usar
para el holdout de la etapa E2.

Uso:
    python scripts/lab/generar_dataset_lab.py [--sesiones 20] [--salida data/dataset_lab.csv]
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import pandas as pd  # noqa: E402

from scripts import pcap_to_features  # noqa: E402
from scripts.lab import generar_trafico  # noqa: E402
from src.data import RANDOM_STATE  # noqa: E402

logger = logging.getLogger("ids.lab.dataset")

SESIONES = 20
MAX_PROCESOS = 6  # cada sesión mantiene sus tramas en memoria
SEMILLA_BASE = RANDOM_STATE * 1000


def _procesar(args: tuple[int, str]) -> pd.DataFrame:
    """Genera y extrae una sesión (se ejecuta en un proceso aparte)."""
    indice, dir_pcap = args
    nombre = f"sesion_{indice:03d}"
    ruta = Path(dir_pcap) / f"{nombre}.pcap"
    sesion = generar_trafico.generar_sesion(SEMILLA_BASE + indice)
    generar_trafico.escribir_sesion(sesion, ruta)
    return pcap_to_features.procesar_sesion(ruta, nombre)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(description="Genera el dataset del laboratorio por sesiones.")
    p.add_argument("--sesiones", type=int, default=SESIONES)
    p.add_argument("--salida", default="data/dataset_lab.csv")
    p.add_argument("--dir-pcap", default="data/pcap")
    args = p.parse_args(argv)

    Path(args.dir_pcap).mkdir(parents=True, exist_ok=True)
    trabajos = [(i, args.dir_pcap) for i in range(args.sesiones)]
    with ProcessPoolExecutor(max_workers=min(os.cpu_count() or 1, MAX_PROCESOS)) as grupo:
        partes = list(grupo.map(_procesar, trabajos))
    df = pd.concat(partes, ignore_index=True)
    pcap_to_features.guardar(df, Path(args.salida))
    logger.info("Dataset: %d filas, %d columnas -> %s", len(df), df.shape[1], args.salida)
    logger.info("Clases: %s", df["etiqueta"].value_counts().to_dict())
    logger.info("Tipos: %s", df["tipo_ataque"].value_counts().to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
