#!/usr/bin/env python3
"""
Conversión de capturas PCAP a dataset de características (Fase 1 — §3.1 opción A).

Procesa uno o varios archivos .pcap producidos en el laboratorio virtual
(`scripts/lab/`) y los agrega en **ventanas temporales por dispositivo** (dirección
MAC de origen), extrayendo tanto la huella digital IEEE 802.3 (capa 2) como las
características de flujo (capas 3-4). Cada archivo .pcap corresponde a un escenario
etiquetado (benigno o un tipo de ataque en una capa concreta), lo que garantiza
etiquetado perfecto sin fuga entre clases.

El esquema de salida es un superconjunto de `src.feature_schema.COLUMNAS_MODELO`:
incluye las 6 columnas del contrato del modelo más las columnas agregadas de ventana
(`FEATURES_HUELLA_VENTANA`) necesarias para el estudio de ablación (Fase 3), y las
columnas de trazabilidad `etiqueta`, `tipo_ataque`, `capa` y `grupo` (id de ventana
por dispositivo, usado como clave de agrupación en StratifiedGroupKFold para evitar
fuga temporal entre train y test).

Uso (no requiere root; sólo lee archivos .pcap ya capturados):

    python scripts/pcap_to_features.py \
        --pcap data/benigno.pcap --etiqueta 0 --tipo normal --capa ninguna \
        --pcap data/arp_spoof.pcap --etiqueta 1 --tipo arp_spoofing --capa enlace \
        --ventana 5.0 --salida data/dataset_lab.parquet

Los pares (--pcap, --etiqueta, --tipo, --capa) se consumen en orden posicional:
cada --pcap toma la --etiqueta/--tipo/--capa que lo siguen (o los valores por defecto).
"""
from __future__ import annotations

import argparse
import logging
import math
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

# Permite ejecutar el script directamente (python scripts/pcap_to_features.py)
# resolviendo el paquete `src` desde la raíz del proyecto.
_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

from src.feature_schema import (  # noqa: E402
    COLUMNAS_MODELO,
    ETIQUETA,
    FEATURES_HUELLA_VENTANA,
)

logger = logging.getLogger("ids.pcap_to_features")

# EtherType de ARP y dirección de broadcast de capa 2 (constantes IEEE 802.3).
ETHERTYPE_ARP = 0x0806
MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"

# Columnas de trazabilidad añadidas a cada fila (además del contrato del modelo).
COLUMNAS_TRAZA = ["tipo_ataque", "capa", "grupo"]


@dataclass
class _AcumuladorVentana:
    """Estadísticos incrementales de las tramas de un dispositivo en una ventana."""

    longitudes: list[float] = field(default_factory=list)
    iats_ms: list[float] = field(default_factory=list)
    ethertypes: list[int] = field(default_factory=list)
    n_broadcast: int = 0
    n_arp: int = 0
    n_syn: int = 0
    puertos_destino: Counter = field(default_factory=Counter)
    flujos: set = field(default_factory=set)  # (ip_dst, puerto_dst) distintos
    ultimo_ts: float | None = None


def _entropia_shannon(conteos) -> float:
    """Entropía de Shannon (base 2) de una distribución dada por conteos."""
    total = sum(conteos)
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in conteos:
        if c > 0:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def _media(valores: list[float]) -> float:
    return sum(valores) / len(valores) if valores else 0.0


def _desv(valores: list[float], media: float) -> float:
    if len(valores) < 2:
        return 0.0
    var = sum((v - media) ** 2 for v in valores) / (len(valores) - 1)
    return math.sqrt(var)


def _oui_a_entero(mac: str) -> int:
    """Codifica el OUI (primeros 3 octetos de la MAC) en el rango [0, 50)."""
    try:
        oui_hex = mac.replace(":", "").replace("-", "")[:6]
        return int(oui_hex, 16) % 50
    except (ValueError, AttributeError):
        return 0


def _fila_desde_acumulador(
    mac: str,
    idx_ventana: int,
    acc: _AcumuladorVentana,
    ventana_s: float,
    etiqueta: int,
    tipo_ataque: str,
    capa: str,
) -> dict:
    """Convierte los estadísticos acumulados de una ventana en una fila de dataset."""
    n = len(acc.longitudes)
    long_media = _media(acc.longitudes)
    iat_media = _media(acc.iats_ms)

    fila = {
        # --- Contrato del modelo (COLUMNAS_MODELO) ---
        "longitud_trama": long_media,
        "tiempo_entre_tramas_ms": iat_media,
        "num_conexiones_por_min": len(acc.flujos) / ventana_s * 60.0,
        "tasa_syn": acc.n_syn / n if n else 0.0,
        "entropia_puertos_destino": _entropia_shannon(acc.puertos_destino.values()),
        "oui_frecuente": _oui_a_entero(mac),
        # --- Agregados de ventana (FEATURES_HUELLA_VENTANA, para ablación) ---
        "longitud_trama_media": long_media,
        "longitud_trama_std": _desv(acc.longitudes, long_media),
        "iat_media_ms": iat_media,
        "iat_std_ms": _desv(acc.iats_ms, iat_media),
        "tasa_broadcast": acc.n_broadcast / n if n else 0.0,
        "tasa_arp": acc.n_arp / n if n else 0.0,
        "entropia_ethertype": _entropia_shannon(Counter(acc.ethertypes).values()),
        "oui_encoded": _oui_a_entero(mac),
        # --- Trazabilidad / etiquetas ---
        ETIQUETA: int(etiqueta),
        "tipo_ataque": tipo_ataque,
        "capa": capa,
        "grupo": f"{mac}#{idx_ventana}",
    }
    return fila


def procesar_pcap(
    ruta_pcap: str | Path,
    etiqueta: int,
    tipo_ataque: str = "normal",
    capa: str = "ninguna",
    ventana_s: float = 5.0,
    min_tramas_ventana: int = 1,
) -> list[dict]:
    """Procesa un .pcap en ventanas temporales por MAC de origen.

    Args:
        ruta_pcap: Ruta al archivo de captura.
        etiqueta: 0 (benigno) o 1 (malicioso) para todas las tramas del pcap.
        tipo_ataque: Nombre del escenario (p. ej. "arp_spoofing", "syn_flood", "normal").
        capa: Capa del modelo afectada ("enlace", "transporte", "aplicacion", "ninguna").
        ventana_s: Duración de la ventana temporal en segundos.
        min_tramas_ventana: Descarta ventanas con menos tramas que este umbral.

    Returns:
        Lista de filas (dicts) lista para construir un DataFrame.

    Raises:
        RuntimeError: Si Scapy no está instalado.
        FileNotFoundError: Si el pcap no existe.
    """
    ruta = Path(ruta_pcap)
    if not ruta.exists():
        raise FileNotFoundError(f"No existe el pcap: {ruta}")

    try:
        from scapy.all import ARP, TCP, UDP, Ether, IP, PcapReader
    except ImportError as exc:  # pragma: no cover - depende del entorno
        raise RuntimeError("Scapy no está instalado. Ejecutar: pip install scapy") from exc

    # Estado por (mac, indice_de_ventana). La ventana de una trama se calcula
    # respecto al primer timestamp observado en el pcap (t0), de forma determinista.
    acumuladores: dict[tuple[str, int], _AcumuladorVentana] = defaultdict(_AcumuladorVentana)
    ultimo_ts_por_mac: dict[str, float] = {}
    t0: float | None = None

    with PcapReader(str(ruta)) as lector:
        for pkt in lector:
            if Ether not in pkt:
                continue
            eth = pkt[Ether]
            mac = eth.src
            ts = float(pkt.time)
            if t0 is None:
                t0 = ts
            idx_ventana = int((ts - t0) // ventana_s)
            acc = acumuladores[(mac, idx_ventana)]

            # IAT: tiempo desde la última trama del mismo dispositivo (en ms).
            prev = ultimo_ts_por_mac.get(mac)
            if prev is not None:
                acc.iats_ms.append(max((ts - prev) * 1000.0, 0.0))
            ultimo_ts_por_mac[mac] = ts

            acc.longitudes.append(float(len(pkt)))
            etype = int(getattr(eth, "type", 0) or 0)
            acc.ethertypes.append(etype)
            if eth.dst.lower() == MAC_BROADCAST:
                acc.n_broadcast += 1
            if ARP in pkt or etype == ETHERTYPE_ARP:
                acc.n_arp += 1

            if IP in pkt:
                ip_dst = pkt[IP].dst
                if TCP in pkt:
                    tcp = pkt[TCP]
                    # Bandera SYN activa y ACK inactiva => intento de conexión nuevo.
                    if tcp.flags & 0x02 and not tcp.flags & 0x10:
                        acc.n_syn += 1
                    acc.puertos_destino[int(tcp.dport)] += 1
                    acc.flujos.add((ip_dst, int(tcp.dport)))
                elif UDP in pkt:
                    udp = pkt[UDP]
                    acc.puertos_destino[int(udp.dport)] += 1
                    acc.flujos.add((ip_dst, int(udp.dport)))

    filas: list[dict] = []
    for (mac, idx_ventana), acc in acumuladores.items():
        if len(acc.longitudes) < min_tramas_ventana:
            continue
        filas.append(
            _fila_desde_acumulador(
                mac, idx_ventana, acc, ventana_s, etiqueta, tipo_ataque, capa
            )
        )
    logger.info(
        "Procesado %s: %d ventanas (etiqueta=%d, tipo=%s, capa=%s)",
        ruta.name,
        len(filas),
        etiqueta,
        tipo_ataque,
        capa,
    )
    return filas


def construir_dataframe(filas: list[dict]) -> pd.DataFrame:
    """Construye el DataFrame final con columnas ordenadas (contrato + agregados + traza)."""
    columnas = list(dict.fromkeys(COLUMNAS_MODELO + FEATURES_HUELLA_VENTANA + [ETIQUETA] + COLUMNAS_TRAZA))
    df = pd.DataFrame(filas)
    # Garantiza que todas las columnas del contrato existan aunque algún pcap no las poblara.
    for col in columnas:
        if col not in df.columns:
            df[col] = 0
    return df[columnas]


def _parsear_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="PCAP -> dataset de features del IDS (ventanas por MAC).")
    p.add_argument("--pcap", action="append", required=True, help="Ruta a un .pcap (repetible).")
    p.add_argument("--etiqueta", action="append", type=int, help="0=benigno, 1=malicioso (por pcap).")
    p.add_argument("--tipo", action="append", help="Nombre del escenario (por pcap).")
    p.add_argument("--capa", action="append", help="Capa afectada (por pcap).")
    p.add_argument("--ventana", type=float, default=5.0, help="Duración de ventana en segundos.")
    p.add_argument("--min-tramas", type=int, default=1, help="Mínimo de tramas por ventana.")
    p.add_argument("--salida", default="data/dataset_lab.parquet", help="CSV o Parquet de salida.")
    return p.parse_args(argv)


def _valor_por_pcap(lista, i, defecto):
    """Toma el i-ésimo valor de una lista opcional de CLI, con valor por defecto."""
    if lista is None or i >= len(lista):
        return defecto
    return lista[i]


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    args = _parsear_args(argv)

    filas: list[dict] = []
    for i, ruta in enumerate(args.pcap):
        filas.extend(
            procesar_pcap(
                ruta,
                etiqueta=_valor_por_pcap(args.etiqueta, i, 0),
                tipo_ataque=_valor_por_pcap(args.tipo, i, "normal"),
                capa=_valor_por_pcap(args.capa, i, "ninguna"),
                ventana_s=args.ventana,
                min_tramas_ventana=args.min_tramas,
            )
        )

    if not filas:
        logger.error("No se extrajo ninguna ventana. ¿Los pcap contienen tramas Ethernet?")
        return 1

    df = construir_dataframe(filas)
    salida = Path(args.salida)
    salida.parent.mkdir(parents=True, exist_ok=True)
    if salida.suffix == ".parquet":
        df.to_parquet(salida, index=False)
    else:
        df.to_csv(salida, index=False)

    logger.info("Dataset guardado en %s (%d filas, %d columnas)", salida, len(df), df.shape[1])
    logger.info("Distribución de clases: %s", df[ETIQUETA].value_counts().to_dict())
    logger.info("Tipos de ataque: %s", df["tipo_ataque"].value_counts().to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
