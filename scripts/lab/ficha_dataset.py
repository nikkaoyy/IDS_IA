#!/usr/bin/env python3
"""
Ficha del dataset del laboratorio (etapa E1, reproducibilidad de OE2).

El CSV no se versiona (pesa y se regenera); se versiona su ficha: tamaño, distribución por
sesión y por clase, semillas, comando de generación y `sha256`. Con la ficha, quien
regenere el dataset puede comprobar que obtuvo exactamente el mismo archivo.

Las semillas, el comando y la fecha de generación (que da nombre a la ficha) salen del
sidecar `<csv>.meta.json` que escribe `generar_dataset_lab.py`; sin él, las semillas se
deducen del nombre de cada sesión y la ficha lleva la fecha del día.

Uso:
    python scripts/lab/ficha_dataset.py data/dataset_lab.csv [--salida reports]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import pandas as pd  # noqa: E402

from src.data import SEMILLA_BASE_LAB, indice_sesion  # noqa: E402
from src.feature_schema import ETIQUETA, VERSION_ESQUEMA  # noqa: E402

COLUMNAS_REPARTO_ATAQUE = ["tipo_ataque", "capa", "variante", "intensidad"]


def sha256_archivo(ruta: Path, bloque: int = 1 << 20) -> str:
    """Huella SHA-256 del archivo, leída por bloques."""
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        while trozo := f.read(bloque):
            h.update(trozo)
    return h.hexdigest()


def ruta_meta(ruta_csv: Path) -> Path:
    """Sidecar con el comando y las semillas de la generación."""
    return ruta_csv.with_name(ruta_csv.name + ".meta.json")


def _commit_actual() -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=_RAIZ, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def _conteos(serie: pd.Series) -> dict[str, int]:
    return {str(k): int(v) for k, v in serie.value_counts().sort_index().items()}


def construir_ficha(ruta_csv: Path) -> dict:
    """Describe el CSV: forma, distribuciones, semillas, comando y huella."""
    df = pd.read_csv(ruta_csv, low_memory=False)
    meta = json.loads(ruta_meta(ruta_csv).read_text()) if ruta_meta(ruta_csv).exists() else {}
    sesiones = sorted(df["sesion"].astype(str).unique()) if "sesion" in df else []
    semillas = meta.get("semillas") or {
        s: SEMILLA_BASE_LAB + i for s in sesiones if (i := indice_sesion(s)) is not None
    }
    ataques = df[df[ETIQUETA] == 1]
    ficha: dict = {
        "archivo": str(ruta_csv),
        "sha256": sha256_archivo(ruta_csv),
        "bytes": ruta_csv.stat().st_size,
        "fecha_ficha": datetime.now().isoformat(timespec="seconds"),
        "fecha_generacion": meta.get("fecha"),
        "commit": meta.get("commit") or _commit_actual(),
        "comando": meta.get("comando", "desconocido: falta el sidecar .meta.json"),
        "version_esquema": VERSION_ESQUEMA,
        "k_tramas_ataque": meta.get("k_tramas_ataque"),
        "filas": int(len(df)),
        "n_columnas": int(df.shape[1]),
        "columnas": list(df.columns),
        "sesiones": len(sesiones),
        "semillas": semillas,
        "por_sesion": _conteos(df["sesion"]) if "sesion" in df else {},
        "por_etiqueta": _conteos(df[ETIQUETA]),
        "proporcion_maliciosas": float(df[ETIQUETA].mean()),
        "atacantes_distintos_por_sesion": (
            float(ataques.groupby("sesion")["atacante"].nunique().mean())
            if {"sesion", "atacante"} <= set(df.columns) and len(ataques) else None
        ),
    }
    for columna in COLUMNAS_REPARTO_ATAQUE:
        if columna in df:
            ficha[f"por_{columna}"] = _conteos(
                df[columna] if columna == "tipo_ataque" else ataques[columna].astype(str)
            )
    if {"tipo_ataque", "variante", "intensidad"} <= set(df.columns):
        ficha["por_tipo_variante_intensidad"] = {
            "/".join(map(str, k)): int(v)
            for k, v in ataques.groupby(["tipo_ataque", "variante", "intensidad"]).size().items()
        }
    return ficha


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Escribe la ficha versionable de un dataset CSV.")
    p.add_argument("csv", type=Path)
    p.add_argument("--salida", type=Path, default=_RAIZ / "reports")
    p.add_argument("--fecha", help="AAAA-MM-DD del nombre (por defecto, la de generación del CSV).")
    args = p.parse_args(argv)
    if not args.csv.exists():
        print(f"No existe {args.csv}", file=sys.stderr)
        return 1
    ficha = construir_ficha(args.csv)
    fecha = args.fecha or (ficha["fecha_generacion"] or date.today().isoformat())[:10]
    args.salida.mkdir(parents=True, exist_ok=True)
    destino = args.salida / f"dataset_lab_{fecha}.json"
    destino.write_text(json.dumps(ficha, indent=2, ensure_ascii=False) + "\n")
    print(f"{destino}: {ficha['filas']} filas, sha256 {ficha['sha256']}")
    print(f"Etiquetas: {ficha['por_etiqueta']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
