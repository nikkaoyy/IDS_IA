#!/usr/bin/env python3
"""
Generador propio del tercer nivel de clon y de la suplantación de IP (PEDIDO-E3B-1, bloque 3; E3, OE3).

Reutiliza las primitivas de `generar_clones.py` (mismas pilas, mismo tráfico; ese generador no
cambia). Doce equipos por sesión y seis episodios, dos de cada nivel, con víctimas distintas:

- `pila_completa`: misma MAC, misma IP, misma familia de pila (TTL, ventana, opciones y política
  de IP-ID) y mismo ritmo y tamaños que la víctima, que sigue emitiendo. El clon lleva su propio
  contador de IP-ID: compartir el de la víctima produciría IDs duplicados. No se modelan los RST
  que la víctima enviaría a los SYN-ACK del clon (dependen del switch; se dejan para E4).
- `victima_apagada`: la víctima calla desde 5–60 s antes del episodio hasta 10–60 s después; el
  atacante usa la IP de la víctima con su propia MAC y su propia pila.
- `suplantacion_ip`: el atacante usa la IP de la víctima con su propia MAC mientras ella emite.

En los tres niveles el atacante abre una conexión en los 2 s siguientes al inicio del episodio
y después sigue su ritmo (el de la víctima en `pila_completa`, el suyo en los otros dos): con
ritmos bajos, un episodio corto podía quedar sin una sola trama del atacante.

Determinista con `SEMILLA_BASE_SUPLANTACION + i`. El manifiesto tiene el mismo formato que el de
`generar_clones.py` (más `mac_clon` e `ip_victima` por episodio).

Uso:
    python scripts/lab/generar_suplantacion.py --sesiones 20 --dir-pcap data/pcap_e3b
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

logger = logging.getLogger("ids.lab.suplantacion")

SEMILLA_BASE_SUPLANTACION: int = 79_000
NIVELES: tuple[str, ...] = ("pila_completa", "victima_apagada", "suplantacion_ip")
EPISODIOS_POR_NIVEL: int = 2
SILENCIO_ANTES_S: tuple[float, float] = (5.0, 60.0)
SILENCIO_DESPUES_S: tuple[float, float] = (10.0, 60.0)


def _planificar(rng: np.random.Generator, equipos: list[gc.Equipo]) -> list[dict]:
    huecos = np.linspace(gc.INICIO_MIN_EPISODIO_S, gc.DURACION_S - gc.DURACION_EPISODIO_S[1] - SILENCIO_DESPUES_S[1],
                         EPISODIOS_POR_NIVEL * len(NIVELES))
    victimas = rng.choice(len(equipos), size=len(huecos), replace=False)
    niveles = [n for n in NIVELES for _ in range(EPISODIOS_POR_NIVEL)]
    rng.shuffle(niveles)
    plan = []
    for k, (inicio, iv, nivel) in enumerate(zip(huecos, victimas, niveles)):
        inicio = float(inicio + rng.uniform(0, 20))
        fin = inicio + float(rng.uniform(*gc.DURACION_EPISODIO_S))
        ep = {"episodio": k, "nivel": nivel, "victima": int(iv), "inicio_s": inicio, "fin_s": fin}
        if nivel == "victima_apagada":
            ep["calla_desde_s"] = inicio - float(rng.uniform(*SILENCIO_ANTES_S))
            ep["vuelve_s"] = fin + float(rng.uniform(*SILENCIO_DESPUES_S))
        plan.append(ep)
    return plan


def generar_sesion(semilla: int) -> tuple[list, dict]:
    """Paquetes de la sesión y su manifiesto (equipos y episodios)."""
    rng = np.random.default_rng(semilla)
    equipos = [gc._equipo(rng, n) for n in range(gc.N_EQUIPOS)]
    plan = _planificar(rng, equipos)
    silencios = {ep["victima"]: (ep["calla_desde_s"], ep["vuelve_s"]) for ep in plan if ep["nivel"] == "victima_apagada"}
    paquetes: list = []
    for n, e in enumerate(equipos):
        if n in silencios:
            a, b = silencios[n]
            gc._emitir(paquetes, rng, e, 0.0, a)
            gc._emitir(paquetes, rng, e, b, gc.DURACION_S)
        else:
            gc._emitir(paquetes, rng, e, 0.0, gc.DURACION_S)
    episodios = []
    for ep in plan:
        v = equipos[ep["victima"]]
        if ep["nivel"] == "pila_completa":
            clon = gc.Equipo(mac=v.mac, ip=v.ip, pila=v.pila, conexiones_por_min=v.conexiones_por_min,
                             longitud_media=v.longitud_media, _ipid=int(rng.integers(0, 65536)))
        else:
            clon = gc._equipo(rng, 100 + ep["episodio"])
            clon.ip = v.ip
        # Un episodio sin tramas del atacante no es un episodio: abre una conexión al empezar.
        gc._conexion(paquetes, rng, ep["inicio_s"] + float(rng.uniform(0, 2)), clon, clon.ip, clon.mac,
                     clon.longitud_media)
        gc._emitir(paquetes, rng, clon, ep["inicio_s"], ep["fin_s"])
        episodios.append({**{k: x for k, x in ep.items() if k != "victima"}, "mac_victima": v.mac, "ip_victima": v.ip,
                          "pila_victima": v.pila, "pila_clon": clon.pila, "mac_clon": clon.mac, "ip_clon": clon.ip})
    paquetes.sort(key=lambda p: float(p.time))
    manifiesto = {"semilla": semilla, "duracion_s": gc.DURACION_S,
                  "equipos": [{k: x for k, x in asdict(e).items() if not k.startswith("_")} for e in equipos],
                  "episodios": episodios}
    return paquetes, manifiesto


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(description="Sesiones con clon de pila completa, víctima apagada y suplantación de IP.")
    p.add_argument("--sesiones", type=int, default=20)
    p.add_argument("--inicio", type=int, default=0)
    p.add_argument("--dir-pcap", type=Path, default=_RAIZ / "data" / "pcap_e3b")
    args = p.parse_args(argv)
    for i in range(args.inicio, args.inicio + args.sesiones):
        paquetes, manifiesto = generar_sesion(SEMILLA_BASE_SUPLANTACION + i)
        ruta = args.dir_pcap / f"suplantacion_{i:03d}.pcap"
        gc.escribir_sesion(paquetes, manifiesto, ruta)
        logger.info("%s: %d tramas, %d episodios", ruta.name, len(paquetes), len(manifiesto["episodios"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
