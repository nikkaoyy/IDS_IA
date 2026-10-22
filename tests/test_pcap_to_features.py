"""Pruebas del parser PCAP -> dataset de features (scripts/pcap_to_features.py).

Genera un pcap sintético en memoria con Scapy (no requiere root ni captura en vivo),
lo procesa en ventanas y verifica que el dataset resultante cumple el contrato de
características y refleja las estadísticas esperadas por dispositivo y por ventana.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

from src.feature_schema import COLUMNAS_MODELO, ETIQUETA, FEATURES_HUELLA_VENTANA

scapy_all = pytest.importorskip("scapy.all", reason="Scapy requerido para el parser de pcap")

# Carga del script como módulo (vive en scripts/, fuera del paquete src).
_spec = importlib.util.spec_from_file_location(
    "pcap_to_features", _RAIZ / "scripts" / "pcap_to_features.py"
)
pcap_to_features = importlib.util.module_from_spec(_spec)
# Registrar antes de ejecutar: @dataclass (Py 3.14) resuelve cls.__module__ vía sys.modules.
sys.modules["pcap_to_features"] = pcap_to_features
_spec.loader.exec_module(pcap_to_features)


def _escribir_pcap_sintetico(ruta: Path) -> None:
    """Crea un pcap con dos dispositivos: uno benigno y uno con ráfaga de SYN."""
    from scapy.all import ARP, Ether, IP, TCP, wrpcap

    paquetes = []
    base = 1_000_000.0  # timestamp base (s)

    # Dispositivo A (MAC 02:00:00:00:00:0a): tráfico TCP normal, 1 trama/s durante 6 s.
    for i in range(6):
        pkt = (
            Ether(src="02:00:00:00:00:0a", dst="02:00:00:00:00:ff")
            / IP(src="10.0.0.10", dst="10.0.0.1")
            / TCP(sport=40000 + i, dport=80, flags="S")
        )
        pkt.time = base + i
        paquetes.append(pkt)

    # Dispositivo B (MAC 02:00:00:00:00:0b): ráfaga de SYN a muchos puertos (port scan),
    # 20 tramas dentro del primer segundo -> alta tasa_syn y alta entropía de puertos.
    for i in range(20):
        pkt = (
            Ether(src="02:00:00:00:00:0b", dst="02:00:00:00:00:ff")
            / IP(src="10.0.0.11", dst="10.0.0.1")
            / TCP(sport=50000 + i, dport=1000 + i, flags="S")
        )
        pkt.time = base + 0.01 * i
        paquetes.append(pkt)

    # Trama ARP broadcast del dispositivo A (para tasa_arp / tasa_broadcast > 0).
    arp = Ether(src="02:00:00:00:00:0a", dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.0.0.1")
    arp.time = base + 1.5
    paquetes.append(arp)

    wrpcap(str(ruta), paquetes)


def test_procesar_pcap_cumple_contrato(tmp_path):
    ruta = tmp_path / "sintetico.pcap"
    _escribir_pcap_sintetico(ruta)

    filas = pcap_to_features.procesar_pcap(
        ruta, etiqueta=1, tipo_ataque="port_scan", capa="transporte", ventana_s=5.0
    )
    df = pcap_to_features.construir_dataframe(filas)

    # El contrato del modelo y los agregados de ventana deben estar presentes.
    for col in COLUMNAS_MODELO + FEATURES_HUELLA_VENTANA + [ETIQUETA, "tipo_ataque", "capa", "grupo"]:
        assert col in df.columns, f"Falta columna {col}"

    assert len(df) >= 2  # al menos una ventana por dispositivo
    assert (df[ETIQUETA] == 1).all()
    assert (df["tipo_ataque"] == "port_scan").all()
    # 'grupo' es único por (mac, ventana): sirve como clave anti-fuga en CV.
    assert df["grupo"].is_unique


def test_dispositivo_escaneo_tiene_mayor_entropia_puertos(tmp_path):
    ruta = tmp_path / "sintetico.pcap"
    _escribir_pcap_sintetico(ruta)
    filas = pcap_to_features.procesar_pcap(ruta, etiqueta=1, ventana_s=5.0)

    # El dispositivo B (port scan) debe mostrar mayor entropía de puertos destino
    # que el dispositivo A (un solo puerto, el 80).
    por_mac = {}
    for f in filas:
        por_mac.setdefault(f["grupo"].split("#")[0], []).append(f)
    ent_a = max(f["entropia_puertos_destino"] for f in por_mac["02:00:00:00:00:0a"])
    ent_b = max(f["entropia_puertos_destino"] for f in por_mac["02:00:00:00:00:0b"])
    assert ent_b > ent_a


def test_pcap_inexistente_lanza_error():
    with pytest.raises(FileNotFoundError):
        pcap_to_features.procesar_pcap("no_existe.pcap", etiqueta=0)
