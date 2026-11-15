#!/usr/bin/env python3
"""
Captura y clasificación en tiempo real (E5, OE3; Fig. 1, camino en vivo).

Conecta `AsyncSniffer` → `MotorStreaming` (src/streaming.py): captura por interfaz (requiere root),
ventanas de `--ventana` s, canal supervisado (si se da un dataset para entrenar el XGB al arrancar)
y canal de identidad (perfil de pila + vigilante IP→MAC). Imprime las alertas en vivo y, cada
`--cada` s, las estadísticas (tramas/s, ventanas, alertas, latencia).

Sin root, se puede validar offline reproduciendo un pcap ya capturado:

    python scripts/captura_en_vivo.py --pcap data/pcap/sesion_000.pcap --dataset data/dataset_lab.csv

En el laboratorio, en vivo (requiere root):

    sudo python scripts/captura_en_vivo.py --iface eth0 --ventana 5 --red-local 10.0.0.0/24 \
        --dataset data/dataset_lab.csv
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

logger = logging.getLogger("ids.captura")


def _entrenar_modelo(ruta_dataset: str, objetivo_fa: float):
    """Entrena XGB sobre el dataset congelado y devuelve (predict, umbral) al punto de operación."""
    from scripts.evaluar import cargar_dataset_estricto
    from src import evaluacion as ev
    from src.feature_schema import COLUMNAS_MODELO, ETIQUETA

    df = cargar_dataset_estricto(ruta_dataset)
    predict = ev.ajustar_modelo("xgboost", df[COLUMNAS_MODELO], df[ETIQUETA].to_numpy(), ev.RANDOM_STATE)
    umbral = ev.umbral_para_objetivo(df, predict(df[COLUMNAS_MODELO]), objetivo_fa)
    logger.info("Modelo entrenado; umbral de operación %.4f (%.1f FA/disp-día)", umbral, objetivo_fa)
    return predict, umbral


def _imprimir(resultados) -> None:
    for r in resultados:
        if r.alarma_supervisado or r.alarma_identidad:
            canales = [c for c, on in (("supervisado", r.alarma_supervisado),
                                       ("identidad", r.alarma_identidad)) if on]
            p = f"{r.probabilidad:.3f}" if r.probabilidad is not None else "—"
            logger.warning("ALERTA ventana %d MAC %s [%s] prob=%s estado=%s",
                           r.idx_ventana, r.mac, "+".join(canales), p, r.estado_identidad)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    p = argparse.ArgumentParser(description="Captura y clasificación en tiempo real (E5).")
    p.add_argument("--iface", help="Interfaz para captura en vivo (requiere root).")
    p.add_argument("--pcap", type=Path, help="Pcap a reproducir offline, en vez de capturar.")
    p.add_argument("--ventana", type=float, default=5.0)
    p.add_argument("--dataset", help="Dataset para entrenar el supervisado al arrancar; si falta, solo identidad.")
    p.add_argument("--objetivo-fa", type=float, default=1.0, help="FA/disp-día del umbral de operación.")
    p.add_argument("--red-local", help="Red local (CIDR) para el vigilante IP→MAC, p. ej. 10.0.0.0/24.")
    p.add_argument("--bpf", default=None, help="Filtro BPF para la captura en vivo.")
    p.add_argument("--cada", type=float, default=10.0, help="Segundos entre volcados de estadísticas.")
    args = p.parse_args(argv)
    if not args.iface and not args.pcap:
        p.error("usa --iface (en vivo) o --pcap (offline)")

    from src.streaming import MotorStreaming
    from src.ventanas import ConfigSegmento

    modelo, umbral = (None, 0.5)
    if args.dataset:
        modelo, umbral = _entrenar_modelo(args.dataset, args.objetivo_fa)
    motor = MotorStreaming(config=ConfigSegmento(), modelo=modelo, umbral=umbral,
                           ventana_s=args.ventana, con_identidad=True, red_local=args.red_local)

    if args.pcap:  # offline: reproduce un pcap ya capturado (sin root)
        from src.ventanas import leer_pcap
        t0 = time.perf_counter()
        _imprimir(motor.reproducir(leer_pcap(args.pcap)))
        logger.info("Offline hecho en %.1f s · %s", time.perf_counter() - t0, motor.resumen_metricas())
        return 0

    from scapy.all import AsyncSniffer  # solo en vivo (requiere root)
    sniffer = AsyncSniffer(iface=args.iface, filter=args.bpf, store=False,
                           prn=lambda pkt: _imprimir(motor.procesar_paquete(pkt)))
    parar = {"v": False}
    signal.signal(signal.SIGINT, lambda *_: parar.__setitem__("v", True))
    sniffer.start()
    logger.info("Capturando en %s (ventana %.0fs). Ctrl+C para parar.", args.iface, args.ventana)
    try:
        ultima = time.perf_counter()
        while not parar["v"]:
            time.sleep(0.5)
            if time.perf_counter() - ultima >= args.cada:
                logger.info("Estadísticas: %s", motor.resumen_metricas())
                ultima = time.perf_counter()
    finally:
        sniffer.stop()
        _imprimir(motor.cerrar())
        logger.info("Detenido. %s", motor.resumen_metricas())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
