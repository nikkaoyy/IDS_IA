#!/usr/bin/env python3
"""
Generador propio de benigno con variación legítima de pila (PEDIDO-E3B-1, bloque 2; E3, OE3).

En `generar_clones.py`, TTL, ventana del SYN y opciones son constantes por equipo, así que
un perfil de pila nunca ve una variación legítima. Este generador reutiliza sus primitivas
(mismas pilas, mismo tráfico) y asigna a cada equipo una de estas variaciones:

- `actualizacion`: a mitad de sesión (400–600 s) cambia una sola vez el TTL y la ventana
  del SYN a los de otra familia con TTL y ventana distintos, y se queda con ellos.
- `vpn`: durante 120–300 s (empieza entre 300 y 500 s) tuneliza: TTL − 1 y ventana − 2920
  (dos MSS de 1460).
- `dos_pilas`: el mismo equipo (MAC e IP) emite toda la sesión con su pila y, en el 30 % de
  la tasa, con una segunda pila de otra familia (contenedor o segunda interfaz).
- `descubrimiento`: además de su tráfico, mDNS cada 5–15 s y SSDP cada 30–60 s, los dos con
  IP-ID 0; el SSDP sale con TTL 4 (multicast de descubrimiento).
- `deriva_lenta`: la ventana del SYN se mueve 64 cada 50 s (10 ventanas) durante toda la
  sesión: sube, o baja si la ventana base no deja margen hasta 65535.
- `control`: sin variación.

Doce equipos por sesión: dos de cada variación y dos de control, en orden aleatorio. No hay
clones: todo lo que alarme es falsa alarma. Determinista con `SEMILLA_BASE_VARIACION + i`.

Uso:
    python scripts/lab/generar_variacion.py --sesiones 20 --dir-pcap data/pcap_variacion
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

logger = logging.getLogger("ids.lab.variacion")

SEMILLA_BASE_VARIACION: int = 78_000
TIPOS: tuple[str, ...] = ("actualizacion", "vpn", "dos_pilas", "descubrimiento", "deriva_lenta")
POR_TIPO: int = 2
CONTROLES: int = 2
FRACCION_SEGUNDA_PILA: float = 0.3
PASO_DERIVA_S: float = 50.0
PASO_DERIVA_VENTANA: int = 64
TTL_SSDP: int = 4


def _con(pila: dict, **cambios) -> dict:
    return {**pila, **cambios}


def _descubrimiento(paquetes: list, rng, e: gc.Equipo, hasta: float) -> None:
    """mDNS (TTL 255) cada 5–15 s y SSDP (TTL 4) cada 30–60 s, ambos con IP-ID 0."""
    from scapy.all import IP, UDP, Ether, Raw

    t = float(rng.uniform(0, 10))
    while t < hasta:
        gc._mdns(paquetes, rng, t, e, e.ip, e.mac)
        t += float(rng.uniform(5, 15))
    t = float(rng.uniform(0, 30))
    while t < hasta:
        p = Ether(src=e.mac, dst="01:00:5e:7f:ff:fa") / IP(src=e.ip, dst="239.255.255.250", ttl=TTL_SSDP, id=0) / UDP(
            sport=int(rng.integers(32768, 61000)), dport=1900) / Raw(b"M-SEARCH * HTTP/1.1\r\n")
        p.time = t
        paquetes.append(p)
        t += float(rng.uniform(30, 60))


def emitir_con_variacion(paquetes: list, rng, e: gc.Equipo, tipo: str, n: int) -> dict:
    """Tráfico de `e` durante la sesión con la variación `tipo`; devuelve su descripción."""
    base = gc.PILAS[e.pila]
    fin = gc.DURACION_S
    if tipo == "actualizacion":
        t_u = float(rng.uniform(400, 600))
        otras = [f for f, p in gc.PILAS.items() if p["ttl"] != base["ttl"] and p["window"] != base["window"]]
        nueva = gc.PILAS[str(rng.choice(otras))]
        despues = _con(base, ttl=nueva["ttl"], window=nueva["window"])
        gc._emitir(paquetes, rng, e, 0.0, t_u)
        gc._emitir(paquetes, rng, e, t_u, fin, pila=despues)
        return {"inicio_s": t_u, "fin_s": fin, "ttl": [base["ttl"], despues["ttl"]],
                "window": [base["window"], despues["window"]]}
    if tipo == "vpn":
        a = float(rng.uniform(300, 500))
        b = min(fin, a + float(rng.uniform(120, 300)))
        tunel = _con(base, ttl=base["ttl"] - 1, window=base["window"] - 2920)
        gc._emitir(paquetes, rng, e, 0.0, a)
        gc._emitir(paquetes, rng, e, a, b, pila=tunel)
        gc._emitir(paquetes, rng, e, b, fin)
        return {"inicio_s": a, "fin_s": b, "ttl": [base["ttl"], tunel["ttl"]], "window": [base["window"], tunel["window"]]}
    if tipo == "dos_pilas":
        segunda = str(rng.choice([f for f in gc.PILAS if f != e.pila]))
        gc._emitir(paquetes, rng, e, 0.0, fin)
        hermano = gc.Equipo(mac=e.mac, ip=e.ip, pila=segunda, conexiones_por_min=e.conexiones_por_min * FRACCION_SEGUNDA_PILA,
                            longitud_media=e.longitud_media, _ipid=int(rng.integers(0, 65536)))
        gc._emitir(paquetes, rng, hermano, 0.0, fin)
        return {"segunda_pila": segunda, "fraccion": FRACCION_SEGUNDA_PILA}
    if tipo == "descubrimiento":
        gc._emitir(paquetes, rng, e, 0.0, fin)
        _descubrimiento(paquetes, rng, e, fin)
        return {"ttl_ssdp": TTL_SSDP}
    if tipo == "deriva_lenta":
        pasos = int(np.ceil(fin / PASO_DERIVA_S))
        signo = 1 if base["window"] + PASO_DERIVA_VENTANA * pasos <= 65535 else -1
        k, t = 0, 0.0
        while t < fin:
            gc._emitir(paquetes, rng, e, t, min(fin, t + PASO_DERIVA_S),
                       pila=_con(base, window=base["window"] + signo * PASO_DERIVA_VENTANA * k))
            k, t = k + 1, t + PASO_DERIVA_S
        return {"paso_s": PASO_DERIVA_S, "paso_ventana": signo * PASO_DERIVA_VENTANA, "pasos": k}
    gc._emitir(paquetes, rng, e, 0.0, fin)
    return {}


def generar_sesion(semilla: int) -> tuple[list, dict]:
    """Paquetes de una sesión benigna con variación y su manifiesto."""
    rng = np.random.default_rng(semilla)
    equipos = [gc._equipo(rng, n) for n in range(len(TIPOS) * POR_TIPO + CONTROLES)]
    tipos = [t for t in TIPOS for _ in range(POR_TIPO)] + ["control"] * CONTROLES
    rng.shuffle(tipos)
    paquetes: list = []
    descripcion = []
    for n, (e, tipo) in enumerate(zip(equipos, tipos)):
        detalle = emitir_con_variacion(paquetes, rng, e, tipo, n)
        descripcion.append({**{k: v for k, v in asdict(e).items() if not k.startswith("_")},
                            "variacion": tipo, "detalle": detalle})
    paquetes.sort(key=lambda p: float(p.time))
    return paquetes, {"semilla": semilla, "duracion_s": gc.DURACION_S, "equipos": descripcion, "episodios": []}


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(description="Sesiones benignas con variación legítima de pila.")
    p.add_argument("--sesiones", type=int, default=20)
    p.add_argument("--inicio", type=int, default=0)
    p.add_argument("--dir-pcap", type=Path, default=_RAIZ / "data" / "pcap_variacion")
    args = p.parse_args(argv)
    for i in range(args.inicio, args.inicio + args.sesiones):
        paquetes, manifiesto = generar_sesion(SEMILLA_BASE_VARIACION + i)
        ruta = args.dir_pcap / f"variacion_{i:03d}.pcap"
        gc.escribir_sesion(paquetes, manifiesto, ruta)
        logger.info("%s: %d tramas", ruta.name, len(paquetes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
