#!/usr/bin/env python3
"""
Orquestador del laboratorio (Fase 1 — §3.1 opción A): genera el dataset completo.

Encadena todo el flujo reproducible de extremo a extremo:
    1. Sintetiza un .pcap por escenario (benigno + ataques por capa) con
       `scripts/lab/generar_trafico.py`.
    2. Convierte cada .pcap a ventanas de características con `scripts/pcap_to_features.py`.
    3. Ensambla y guarda el dataset etiquetado en `data/dataset_lab.parquet` (o CSV).

El dataset resultante tiene etiqueta binaria (`etiqueta`), tipo de ataque (`tipo_ataque`),
capa (`capa`) y clave de agrupación por dispositivo-ventana (`grupo`), lista para el
estudio de ablación y la validación cruzada sin fuga (Fase 3).

Uso:
    python scripts/lab/generar_dataset_lab.py                    # dataset completo por defecto
    python scripts/lab/generar_dataset_lab.py --n 3000 --salida data/dataset_lab.csv
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

logger = logging.getLogger("ids.lab.dataset")

# Conteo base por escenario. Para 'benigno' es número de eventos (se reparte entre
# dispositivos y ventanas); para los ataques es número de EPISODIOS (≈ventanas, ya que
# cada episodio cae en su propia ventana temporal). El benigno domina, como en una red
# real, pero sin dejar las clases de ataque sin muestras suficientes para CV.
CONTEOS_BASE = {
    "benigno": 4000,
    "arp_spoofing": 300,
    "mac_flooding": 300,
    "syn_flood": 300,
    "port_scan": 300,
    "dns_spoofing": 300,
}


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(description="Genera el dataset completo del laboratorio virtual.")
    p.add_argument("--escala", type=float, default=1.0, help="Factor multiplicador de los conteos base.")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--ventana", type=float, default=5.0, help="Ventana temporal en segundos.")
    p.add_argument("--salida", default="data/dataset_lab.csv")
    p.add_argument("--dir-pcap", default="data/pcap", help="Carpeta para los .pcap intermedios.")
    args = p.parse_args(argv)

    import pandas as pd
    from scapy.all import wrpcap

    from scripts.lab import generar_trafico
    from scripts import pcap_to_features

    dir_pcap = Path(args.dir_pcap)
    dir_pcap.mkdir(parents=True, exist_ok=True)

    filas: list[dict] = []
    for i, (escenario, base) in enumerate(CONTEOS_BASE.items()):
        n = max(1, int(base * args.escala))
        paquetes, etiqueta, capa = generar_trafico.generar(escenario, n, args.seed + i)
        ruta_pcap = dir_pcap / f"{escenario}.pcap"
        wrpcap(str(ruta_pcap), paquetes)
        logger.info("Escenario '%s': %d tramas -> %s", escenario, len(paquetes), ruta_pcap)

        filas.extend(
            pcap_to_features.procesar_pcap(
                ruta_pcap,
                etiqueta=etiqueta,
                tipo_ataque=escenario,
                capa=capa,
                ventana_s=args.ventana,
            )
        )

    if not filas:
        logger.error("No se generaron ventanas; abortando.")
        return 1

    df = pcap_to_features.construir_dataframe(filas)
    salida = Path(args.salida)
    salida.parent.mkdir(parents=True, exist_ok=True)
    if salida.suffix == ".parquet":
        df.to_parquet(salida, index=False)
    else:
        df.to_csv(salida, index=False)

    logger.info("Dataset del laboratorio: %d filas, %d columnas -> %s", len(df), df.shape[1], salida)
    logger.info("Clases: %s", df["etiqueta"].value_counts().to_dict())
    logger.info("Escenarios: %s", df["tipo_ataque"].value_counts().to_dict())
    logger.info("Capas: %s", df["capa"].value_counts().to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
