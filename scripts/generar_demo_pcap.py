#!/usr/bin/env python3
"""
Recorte del pcap de demostración (entrega, bloque 3; Fig. 1 «Captura» → «Huella IEEE 802.3»).

No es un generador nuevo: llama a los generadores congelados con semilla fija y **recorta** una
ventana corta de su salida, sin cambiar un solo byte de las tramas.

- Canal de ataques: `scripts/lab/generar_trafico.py` (congelado), sesión de desarrollo
  `SESION_LAB` (semilla `SEMILLA_BASE_LAB + SESION_LAB`), ventana `VENTANA_LAB_S`, que contiene
  fondo benigno y **un único episodio** del catálogo (ARP spoofing, capa de enlace).
- Canal de identidad: `scripts/lab/generar_clones.py`, sesión `SESION_CLONES` (semilla
  `SEMILLA_BASE_CLONES + SESION_CLONES`), ventana de la misma duración con **un episodio de clon
  de MAC** (nivel `ritmo`). Hace falta porque el generador congelado no fija IP-ID (Scapy deja
  id=1) ni opciones TCP: las señales de pila del canal de identidad solo existen en este
  generador. Sus tiempos se desplazan para caer en la misma ventana; su segmento es otro
  (10.20.0.0/24), así que las dos poblaciones no se mezclan.

Todo es tráfico sintético de laboratorio escrito a archivo: no toca ninguna interfaz ni requiere
root. Salida en `data/pcap/demo/`: `sesion_demo.pcap` y, con el mismo nombre, `.tramas.csv` y
`.episodios.csv` (verdad terreno del canal de ataques, la que lee `pcap_to_features.py`),
`.config.json` (gateway y resolver declarados), `.clones.json` (episodio de clon) y `.meta.json`
(procedencia, semillas, ventanas y sha256).

Uso:
    python scripts/generar_demo_pcap.py [--dir-salida data/pcap/demo]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import subprocess
import sys
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

from scripts.lab import generar_clones, generar_trafico  # noqa: E402
from src.data import SEMILLA_BASE_LAB  # noqa: E402

logger = logging.getLogger("ids.demo_pcap")

NOMBRE: str = "sesion_demo"
SESION_LAB: int = 0
VENTANA_LAB_S: tuple[float, float] = (236.0, 386.0)  # solo el episodio 0 (arp_spoofing, 276–331 s)
SESION_CLONES: int = 1
INICIO_CLONES_S: float = 234.6  # su episodio 0 (ritmo, 304,6–377,1 s) cae entero en la ventana
EPISODIO_CLON: int = 0
AVISO: str = ("tráfico sintético de laboratorio, generado por scripts/lab/generar_trafico.py "
              "con semilla fija; no es una captura de red real")


def _commit() -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=_RAIZ, capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def tramas_lab() -> tuple[list, list[dict], dict]:
    """Tramas de la ventana del generador congelado, episodios dentro de ella y su configuración."""
    s = generar_trafico.generar_sesion(SEMILLA_BASE_LAB + SESION_LAB)
    t0 = generar_trafico.T0_US + round(VENTANA_LAB_S[0] * 1_000_000)
    t1 = generar_trafico.T0_US + round(VENTANA_LAB_S[1] * 1_000_000)
    tramas = [x for x in s.tramas if t0 <= x[0] < t1]
    episodios = [e for e in s.episodios
                 if e["t_fin_s"] > VENTANA_LAB_S[0] and e["t_inicio_s"] < VENTANA_LAB_S[1]]
    dentro = [e for e in episodios
              if e["t_inicio_s"] >= VENTANA_LAB_S[0] and e["t_fin_s"] <= VENTANA_LAB_S[1]]
    if len(episodios) != 1 or len(dentro) != 1:
        raise RuntimeError(f"La ventana debe contener exactamente un episodio entero: {episodios}")
    config = {"ip_gateway": generar_trafico.IP_GATEWAY, "mac_gateway": s.gateway.mac,
              "resolvers": {generar_trafico.IP_RESOLVER: s.resolver.mac}}
    return tramas, episodios, config


def tramas_clones() -> tuple[list, dict]:
    """Tramas de la ventana del generador de clones, desplazadas a la ventana del laboratorio."""
    paquetes, manifiesto = generar_clones.generar_sesion(generar_clones.SEMILLA_BASE_CLONES + SESION_CLONES)
    duracion = VENTANA_LAB_S[1] - VENTANA_LAB_S[0]
    desfase = VENTANA_LAB_S[0] - INICIO_CLONES_S
    fin = INICIO_CLONES_S + duracion
    ep = manifiesto["episodios"][EPISODIO_CLON]
    otros = [e for e in manifiesto["episodios"] if e is not ep and e["fin_s"] > INICIO_CLONES_S
             and e["inicio_s"] < fin]
    if not (INICIO_CLONES_S <= ep["inicio_s"] and ep["fin_s"] <= fin) or otros:
        raise RuntimeError("La ventana de clones debe contener entero solo el episodio elegido.")
    tramas = []
    for p in paquetes:
        t = float(p.time)
        if INICIO_CLONES_S <= t < fin:
            tramas.append((generar_trafico.T0_US + round((t + desfase) * 1_000_000), bytes(p), None))
    episodio = {**ep, "inicio_s": round(ep["inicio_s"] + desfase, 6), "fin_s": round(ep["fin_s"] + desfase, 6),
                "inicio_original_s": ep["inicio_s"], "fin_original_s": ep["fin_s"]}
    return tramas, {"semilla": manifiesto["semilla"], "desfase_s": round(desfase, 6),
                    "equipos": manifiesto["equipos"], "episodios": [episodio]}


def escribir(dir_salida: Path) -> Path:
    """Genera, recorta, fusiona por tiempo y escribe el pcap con sus manifiestos."""
    dir_salida.mkdir(parents=True, exist_ok=True)
    lab, episodios, config = tramas_lab()
    clones, man_clones = tramas_clones()
    # Orden estable por instante; a igual instante, primero el laboratorio.
    fusion = sorted([(ts, 0, i, b, m) for i, (ts, b, m) in enumerate(lab)]
                    + [(ts, 1, i, b, m) for i, (ts, b, m) in enumerate(clones)])
    tramas = [(ts, b, m) for ts, _, _, b, m in fusion]
    ruta = dir_salida / f"{NOMBRE}.pcap"
    generar_trafico.escribir_pcap(ruta, tramas)

    por_ep = {e["episodio"]: e for e in episodios}
    with open(ruta.with_suffix(".tramas.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(generar_trafico.CAMPOS_TRAMAS)
        for n, (ts_us, crudo, marca) in enumerate(tramas):
            if marca is None:
                continue
            _, ep, tipo, variante, capa = marca
            e = por_ep[ep]
            mac_src = ":".join(f"{b:02x}" for b in crudo[6:12])
            w.writerow([n, ts_us, mac_src, e["atacante"], ep, tipo, variante, e["intensidad"], capa])
    with open(ruta.with_suffix(".episodios.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=generar_trafico.CAMPOS_EPISODIOS)
        w.writeheader()
        w.writerows(episodios)
    ruta.with_suffix(".config.json").write_text(json.dumps(config, indent=2) + "\n")
    ruta.with_suffix(".clones.json").write_text(json.dumps(man_clones, indent=2, ensure_ascii=False) + "\n")

    sha = hashlib.sha256(ruta.read_bytes()).hexdigest()
    meta = {
        "aviso": AVISO,
        "archivo": f"data/pcap/demo/{ruta.name}",
        "sha256": sha,
        "bytes": ruta.stat().st_size,
        "tramas": len(tramas),
        "tramas_ataque_catalogo": sum(1 for _, _, m in tramas if m is not None),
        "commit_partida": _commit(),  # HEAD al generar (antes del commit que versiona este script)
        "comando": "python scripts/generar_demo_pcap.py",
        "canal_ataques": {
            "generador": "scripts/lab/generar_trafico.py (congelado)",
            "sesion": SESION_LAB, "semilla": SEMILLA_BASE_LAB + SESION_LAB,
            "ventana_s": list(VENTANA_LAB_S), "tramas": len(lab), "episodios": episodios,
        },
        "canal_identidad": {
            "generador": "scripts/lab/generar_clones.py",
            "sesion": SESION_CLONES, "semilla": generar_clones.SEMILLA_BASE_CLONES + SESION_CLONES,
            "ventana_original_s": [INICIO_CLONES_S, INICIO_CLONES_S + VENTANA_LAB_S[1] - VENTANA_LAB_S[0]],
            "desfase_s": man_clones["desfase_s"], "tramas": len(clones),
            "episodio": man_clones["episodios"][0],
            "nota": "el clon no está en .tramas.csv: es verdad terreno del canal de identidad, no del modelo de ataques",
        },
        "tiempo": "ts = 1e12 µs + segundo de la sesión original (reloj sintético del generador)",
    }
    ruta.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
    logger.info("%s: %d tramas (%d lab + %d clones), %.2f MB, sha256 %s", ruta, len(tramas), len(lab),
                len(clones), meta["bytes"] / 1e6, sha)
    return ruta


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(description="Recorta el pcap de demostración de los generadores congelados.")
    p.add_argument("--dir-salida", type=Path, default=_RAIZ / "data" / "pcap" / "demo")
    args = p.parse_args(argv)
    escribir(args.dir_salida)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
