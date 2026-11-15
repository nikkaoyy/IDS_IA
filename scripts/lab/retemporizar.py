#!/usr/bin/env python3
"""
Re-temporizador de episodios del corpus congelado (PEDIDO-E4C-1, bloque 2; E4, OE3).

NO es un generador: no fabrica ni una sola trama. Lee una sesión **ya existente** del
laboratorio (`data/pcap/sesion_XXX.pcap` y su `.tramas.csv`/`.episodios.csv`, producidos por el
generador congelado de E1) y **solo cambia `pkt.time`** de las tramas de un episodio ya
etiquetado, para llevar un ataque lento (ARP o DNS) al régimen donde el detector por ventana ya
no puede verlo. Los bytes de cada trama, su número y su etiqueta quedan idénticos.

Invariantes que el código verifica (y falla si se rompen):
  (i)   el multiconjunto de bytes de trama es idéntico antes y después;
  (ii)  el número de tramas es igual;
  (iii) los timestamps de salida son no decrecientes;
  (iv)  el orden relativo de las tramas movidas, y el de las no movidas, se conserva (no se
        reordena un flujo contra sí mismo).

Rechaza por diseño: tipos distintos de `arp_spoofing`/`dns_spoofing`, pcaps fuera de `data/pcap/`
y escrituras fuera de `data/pcap/`. Semilla fija ⇒ mismo pcap byte a byte.

Uso:
    python scripts/lab/retemporizar.py --pcap data/pcap/sesion_002.pcap \
        --episodio 7 --tipo arp_spoofing --paso-s 30 --jitter 0.1 --semilla 81000
"""
from __future__ import annotations

import argparse
import logging
import struct
import sys
from pathlib import Path

import numpy as np
import pandas as pd

_RAIZ = Path(__file__).resolve().parents[2]
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

logger = logging.getLogger("ids.lab.retemporizar")

TIPOS_PERMITIDOS: tuple[str, ...] = ("arp_spoofing", "dns_spoofing")
DIR_PERMITIDO = _RAIZ / "data" / "pcap"
_MAGIC_LE = 0xA1B2C3D4


def leer_pcap_crudo(ruta: Path) -> list[tuple[int, bytes]]:
    """Lee un pcap clásico (Ethernet, microsegundos) como `[(ts_us, bytes)]`, en orden de archivo."""
    datos = ruta.read_bytes()
    (magic,) = struct.unpack_from("<I", datos, 0)
    if magic != _MAGIC_LE:
        raise ValueError(f"{ruta} no es un pcap clásico little-endian (magic {magic:#x}).")
    frames, off = [], 24
    while off < len(datos):
        sec, usec, caplen, _orig = struct.unpack_from("<IIII", datos, off)
        off += 16
        frames.append((sec * 1_000_000 + usec, datos[off:off + caplen]))
        off += caplen
    return frames


def escribir_pcap_crudo(ruta: Path, frames: list[tuple[int, bytes]]) -> None:
    """Escribe un pcap clásico idéntico en formato al del generador congelado."""
    with open(ruta, "wb") as f:
        f.write(struct.pack("<IHHiIII", _MAGIC_LE, 2, 4, 0, 0, 65535, 1))
        for ts_us, crudo in frames:
            f.write(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000, len(crudo), len(crudo)))
            f.write(crudo)


def _nuevos_tiempos(indices: list[int], t0_us: int, paso_s: float, jitter: float, semilla: int) -> dict[int, int]:
    """Horario nuevo para las tramas `indices` (en su orden original): `paso_s` entre tramas.

    El jitter (fracción de `paso_s`) desplaza cada trama sin romper la monotonía estricta.
    """
    rng = np.random.default_rng(semilla)
    paso_us = int(round(paso_s * 1_000_000))
    nuevos, t = {}, t0_us
    for j, i in enumerate(indices):
        base = t0_us + j * paso_us
        desfase = int(rng.uniform(0, jitter) * paso_us) if jitter else 0
        ts = max(base + desfase, t + 1)
        nuevos[i], t = ts, ts
    return nuevos


def retemporizar(pcap: Path, episodio: int, tipo: str, paso_s: float, jitter: float, semilla: int,
                 salida: Path | None = None) -> Path:
    """Reescribe el pcap y sus sidecars moviendo en el tiempo las tramas del episodio.

    Raises:
        ValueError: Si el tipo no está permitido, el pcap no está en `data/pcap/`, el episodio no
            tiene tramas de ataque, o algún invariante se rompe.
    """
    pcap = pcap.resolve()
    if tipo not in TIPOS_PERMITIDOS:
        raise ValueError(f"Tipo no permitido en E4C: {tipo!r}; solo {TIPOS_PERMITIDOS}.")
    if pcap.parent != DIR_PERMITIDO.resolve():
        raise ValueError(f"El pcap debe estar en {DIR_PERMITIDO}, no en {pcap.parent}.")
    tramas = pd.read_csv(pcap.with_suffix(".tramas.csv"))
    sel = tramas[(tramas["episodio"] == episodio) & (tramas["tipo"] == tipo)]
    if sel.empty:
        raise ValueError(f"El episodio {episodio} de tipo {tipo} no tiene tramas de ataque en {pcap.name}.")

    frames = leer_pcap_crudo(pcap)
    bytes_antes = sorted(raw for _, raw in frames)
    indices = [int(i) for i in sorted(sel["n_trama"])]
    t0_us = frames[indices[0]][0]
    nuevos_ts = _nuevos_tiempos(indices, t0_us, paso_s, jitter, semilla)

    # Re-ordenar por tiempo, estable en el índice original (no reordena un flujo contra sí mismo).
    items = sorted(((nuevos_ts.get(i, ts), i, raw) for i, (ts, raw) in enumerate(frames)), key=lambda x: (x[0], x[1]))
    nueva_pos = {orig: p for p, (_, orig, _) in enumerate(items)}
    frames_out = [(ts, raw) for ts, _, raw in items]

    # Invariantes (i)-(iv): se verifican antes de escribir nada.
    if sorted(raw for _, raw in frames_out) != bytes_antes:
        raise ValueError("Invariante (i) roto: el multiconjunto de bytes cambió.")
    if len(frames_out) != len(frames):
        raise ValueError("Invariante (ii) roto: cambió el número de tramas.")
    if any(b[0] < a[0] for a, b in zip(frames_out, frames_out[1:])):
        raise ValueError("Invariante (iii) roto: timestamps decrecientes.")
    movidas = [nueva_pos[i] for i in indices]
    quietas = [nueva_pos[i] for i in range(len(frames)) if i not in nuevos_ts]
    if movidas != sorted(movidas) or quietas != sorted(quietas):
        raise ValueError("Invariante (iv) roto: se reordenó un flujo contra sí mismo.")

    salida = salida or pcap.with_name(f"{pcap.stem}_ret{int(paso_s)}.pcap")
    if salida.resolve().parent != DIR_PERMITIDO.resolve():
        raise ValueError(f"La salida debe escribirse en {DIR_PERMITIDO}.")
    escribir_pcap_crudo(salida, frames_out)

    # Sidecars coherentes: ts_us y n_trama nuevos (pcap_to_features etiqueta por ts_us + mac_src).
    man = tramas.copy()
    man["ts_us"] = [nuevos_ts.get(int(nt), int(ts)) for nt, ts in zip(tramas["n_trama"], tramas["ts_us"])]
    man["n_trama"] = [nueva_pos[int(nt)] for nt in tramas["n_trama"]]
    man.sort_values("n_trama").to_csv(salida.with_suffix(".tramas.csv"), index=False)

    epis = pd.read_csv(pcap.with_suffix(".episodios.csv"))
    nuevos_ep = sorted(nuevos_ts.values())
    mask = (epis["episodio"] == episodio) & (epis["tipo"] == tipo)
    epis.loc[mask, "t_inicio_s"] = nuevos_ep[0] / 1_000_000
    epis.loc[mask, "t_fin_s"] = nuevos_ep[-1] / 1_000_000
    epis.to_csv(salida.with_suffix(".episodios.csv"), index=False)
    cfg = pcap.with_suffix(".config.json")
    if cfg.exists():
        salida.with_suffix(".config.json").write_text(cfg.read_text())

    logger.info("%s: episodio %d (%s) movido a paso %.0fs, %d tramas, horizonte %.0f-%.0f s",
                salida.name, episodio, tipo, paso_s, len(indices), nuevos_ep[0] / 1e6, nuevos_ep[-1] / 1e6)
    return salida


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(description="Re-temporiza un episodio ARP/DNS del corpus del laboratorio.")
    p.add_argument("--pcap", type=Path, required=True)
    p.add_argument("--episodio", type=int, required=True)
    p.add_argument("--tipo", required=True, choices=TIPOS_PERMITIDOS)
    p.add_argument("--paso-s", type=float, required=True)
    p.add_argument("--jitter", type=float, default=0.0, help="Fracción de paso-s de desfase aleatorio.")
    p.add_argument("--semilla", type=int, default=81_000)
    p.add_argument("--salida", type=Path, default=None)
    args = p.parse_args(argv)
    retemporizar(args.pcap, args.episodio, args.tipo, args.paso_s, args.jitter, args.semilla, args.salida)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
