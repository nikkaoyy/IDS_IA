#!/usr/bin/env python3
"""
Orquestador del laboratorio (etapa E1): sesiones -> pcap -> ventanas etiquetadas.

Cada sesión usa una semilla distinta y sustituye al antiguo pcap por clase. No requiere
root ni toca interfaces. Junto al CSV escribe `<csv>.meta.json` con el comando, las
semillas y el commit, que `ficha_dataset.py` vuelca en la ficha versionada.

Holdout de E2: los índices de `src.data.SESIONES_RESERVADAS` no se generan salvo con
`--romper-holdout`, que solo debe usarse para construir el holdout, una vez.

Uso:
    python scripts/lab/generar_dataset_lab.py [--sesiones 20] [--salida data/dataset_lab.csv]
    python scripts/lab/generar_dataset_lab.py --inicio 20 --sesiones 10 --romper-holdout \
        --salida data/holdout_e2.csv --dir-pcap data/pcap_holdout
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import pandas as pd  # noqa: E402

from scripts import pcap_to_features  # noqa: E402
from scripts.lab import generar_trafico  # noqa: E402
from src.data import SEMILLA_BASE_LAB, SESIONES_RESERVADAS, HoldoutError, nombre_sesion  # noqa: E402

logger = logging.getLogger("ids.lab.dataset")

SESIONES = 20
MAX_PROCESOS = 6  # cada sesión mantiene sus tramas en memoria
SEMILLA_BASE = SEMILLA_BASE_LAB


def indices_a_generar(inicio: int, sesiones: int, romper_holdout: bool = False) -> list[int]:
    """Índices de sesión a generar; rechaza los reservados sin permiso explícito.

    Raises:
        HoldoutError: Si algún índice está en `SESIONES_RESERVADAS` y no se pasó
            `romper_holdout`.
    """
    indices = list(range(inicio, inicio + sesiones))
    reservados = [i for i in indices if i in SESIONES_RESERVADAS]
    if reservados and not romper_holdout:
        raise HoldoutError(
            f"Los índices {reservados} pertenecen al holdout de E2 "
            f"({SESIONES_RESERVADAS.start}-{SESIONES_RESERVADAS.stop - 1}); "
            "usa --romper-holdout solo para construir el holdout."
        )
    return indices


def _procesar(args: tuple[int, str]) -> pd.DataFrame:
    """Genera y extrae una sesión (se ejecuta en un proceso aparte)."""
    indice, dir_pcap = args
    nombre = nombre_sesion(indice)
    ruta = Path(dir_pcap) / f"{nombre}.pcap"
    sesion = generar_trafico.generar_sesion(SEMILLA_BASE + indice)
    generar_trafico.escribir_sesion(sesion, ruta)
    return pcap_to_features.procesar_sesion(ruta, nombre)


def _commit() -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=_RAIZ, capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def escribir_meta(salida: Path, indices: list[int], argv: list[str]) -> Path:
    """Sidecar de la generación: comando, semillas por sesión, K y commit."""
    ruta = salida.with_name(salida.name + ".meta.json")
    ruta.write_text(json.dumps({
        "comando": "python scripts/lab/generar_dataset_lab.py " + shlex.join(argv),
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "commit": _commit(),
        "semilla_base": SEMILLA_BASE,
        "semillas": {nombre_sesion(i): SEMILLA_BASE + i for i in indices},
        "k_tramas_ataque": pcap_to_features.K_TRAMAS_ATAQUE,
        "duracion_sesion_s": generar_trafico.DURACION_S,
    }, indent=2, ensure_ascii=False) + "\n")
    return ruta


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    argv = sys.argv[1:] if argv is None else argv
    p = argparse.ArgumentParser(description="Genera el dataset del laboratorio por sesiones.")
    p.add_argument("--sesiones", type=int, default=SESIONES)
    p.add_argument("--salida", default="data/dataset_lab.csv")
    p.add_argument("--dir-pcap", default="data/pcap")
    p.add_argument("--inicio", type=int, default=0, help="Índice de la primera sesión.")
    p.add_argument("--romper-holdout", action="store_true",
                   help="Permite generar sesiones reservadas para el holdout de E2.")
    args = p.parse_args(argv)

    try:
        indices = indices_a_generar(args.inicio, args.sesiones, args.romper_holdout)
    except HoldoutError as error:
        logger.error("%s", error)
        return 2
    Path(args.dir_pcap).mkdir(parents=True, exist_ok=True)
    trabajos = [(i, args.dir_pcap) for i in indices]
    with ProcessPoolExecutor(max_workers=min(os.cpu_count() or 1, MAX_PROCESOS)) as grupo:
        partes = list(grupo.map(_procesar, trabajos))
    df = pd.concat(partes, ignore_index=True)
    pcap_to_features.guardar(df, Path(args.salida))
    escribir_meta(Path(args.salida), indices, argv)
    logger.info("Dataset: %d filas, %d columnas -> %s", len(df), df.shape[1], args.salida)
    logger.info("Clases: %s", df["etiqueta"].value_counts().to_dict())
    logger.info("Tipos: %s", df["tipo_ataque"].value_counts().to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
