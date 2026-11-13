#!/usr/bin/env python3
"""
PCAP de sesión + manifiesto -> dataset etiquetado por ventanas (etapas E0 y E1, OE2).

La extracción vive en `src/ventanas.py`, compartida con la captura. Aquí solo se añade la
verdad terreno, que nunca existe en inferencia: una fila es maliciosa si tiene al menos
`K_TRAMAS_ATAQUE` tramas de ataque. Las filas con menos conservan `n_tramas_ataque` para
que la evaluación pueda excluirlas o recalcular K.

Uso (sin root; solo lee archivos):
    python scripts/pcap_to_features.py --pcap data/pcap/sesion_000.pcap --salida d.csv
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import pandas as pd

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

from src.feature_schema import (  # noqa: E402
    COLUMNAS_IDENTIDAD,
    COLUMNAS_MODELO,
    COLUMNAS_TRAZA,
    ETIQUETA,
)
from src.ventanas import (  # noqa: E402
    MAC_EFIMERAS,
    VENTANA_CORTA_S,
    ConfigSegmento,
    extraer_ventanas,
    leer_pcap,
)

logger = logging.getLogger("ids.pcap_to_features")

# Fijado antes de entrenar ningún modelo: una trama aislada no es comportamiento, dos sí
# (arpspoof refresca cada ~2 s, así que el ARP lento aporta 2-3 tramas por ventana de 5 s).
K_TRAMAS_ATAQUE = 2


def cargar_config(ruta_pcap: Path) -> ConfigSegmento:
    """Lee la topología declarada junto al pcap; sin archivo, configuración vacía."""
    ruta = ruta_pcap.with_suffix(".config.json")
    if not ruta.exists():
        return ConfigSegmento()
    return ConfigSegmento(**json.loads(ruta.read_text()))


def etiquetar_ventanas(
    df: pd.DataFrame,
    manifiesto: pd.DataFrame,
    k: int = K_TRAMAS_ATAQUE,
    ventana_s: float = VENTANA_CORTA_S,
) -> pd.DataFrame:
    """Une las filas con el manifiesto por trama (`ts_us`, `mac_src`, `atacante`, ...).

    Raises:
        ValueError: Si alguna trama de ataque no cae en ninguna fila.
    """
    salida = df.copy()
    salida[ETIQUETA] = 0
    salida["tipo_ataque"] = "normal"
    salida["capa"] = "ninguna"
    salida["atacante"] = ""
    salida["episodio"] = -1
    salida["n_tramas_ataque"] = 0
    if manifiesto.empty:
        return salida

    t0_us = int(df["t0_us"].iloc[0])
    m = manifiesto.copy()
    m["idx_ventana"] = (m["ts_us"] - t0_us) // round(ventana_s * 1_000_000)
    claves = set(zip(df["mac"], df["idx_ventana"]))
    m["mac"] = [
        mac if (mac, idx) in claves else MAC_EFIMERAS
        for mac, idx in zip(m["mac_src"], m["idx_ventana"])
    ]
    posicion = {clave: i for i, clave in enumerate(zip(df["mac"], df["idx_ventana"]))}
    for (mac, idx), grupo in m.groupby(["mac", "idx_ventana"], sort=False):
        if (mac, idx) not in posicion:
            raise ValueError(f"Tramas de ataque sin fila: {mac}, ventana {idx}")
        fila = salida.index[posicion[(mac, idx)]]
        dominante = grupo.groupby(["tipo", "capa", "atacante", "episodio"]).size().idxmax()
        salida.loc[fila, ["tipo_ataque", "capa", "atacante", "episodio"]] = list(dominante)
        salida.loc[fila, "n_tramas_ataque"] = len(grupo)
    salida[ETIQUETA] = (salida["n_tramas_ataque"] >= k).astype(int)
    # Por debajo de K la fila es benigna aunque conserve el conteo.
    baja = salida[ETIQUETA] == 0
    salida.loc[baja, ["tipo_ataque", "capa"]] = ["normal", "ninguna"]
    return salida


def procesar_sesion(ruta_pcap: str | Path, sesion: str, k: int = K_TRAMAS_ATAQUE) -> pd.DataFrame:
    """Extrae y etiqueta las ventanas de un pcap de sesión.

    Raises:
        FileNotFoundError: Si no existe el pcap.
    """
    ruta = Path(ruta_pcap)
    if not ruta.exists():
        raise FileNotFoundError(f"No existe el pcap: {ruta}")
    df = pd.DataFrame(extraer_ventanas(leer_pcap(ruta), cargar_config(ruta)))
    ruta_manifiesto = ruta.with_suffix(".tramas.csv")
    manifiesto = pd.read_csv(ruta_manifiesto) if ruta_manifiesto.exists() else pd.DataFrame()
    df = etiquetar_ventanas(df, manifiesto, k)
    df["sesion"] = sesion
    df["grupo"] = df["mac"] + "#" + df["idx_ventana"].astype(str)
    return df[COLUMNAS_MODELO + [ETIQUETA] + COLUMNAS_TRAZA + COLUMNAS_IDENTIDAD]


def guardar(df: pd.DataFrame, salida: Path) -> None:
    """Escribe el dataset en CSV o Parquet según la extensión."""
    salida.parent.mkdir(parents=True, exist_ok=True)
    if salida.suffix == ".parquet":
        df.to_parquet(salida, index=False)
    else:
        df.to_csv(salida, index=False)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(description="PCAP de sesión -> dataset de ventanas etiquetadas.")
    p.add_argument("--pcap", action="append", required=True, help="Ruta a un .pcap (repetible).")
    p.add_argument("--salida", default="data/dataset_lab.csv", help="CSV o Parquet de salida.")
    args = p.parse_args(argv)
    df = pd.concat([procesar_sesion(r, Path(r).stem) for r in args.pcap], ignore_index=True)
    guardar(df, Path(args.salida))
    logger.info("Dataset guardado en %s: %d filas", args.salida, len(df))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
