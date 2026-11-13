"""
Módulo de captura de tráfico (bloque "Captura de tráfico" de la Fig. 1).

Requiere permisos de captura de red (root/administrador) y la librería Scapy.
"""

from __future__ import annotations
import pandas as pd

from .fingerprint import ExtractorHuellaDigital
from .ventanas import AgregadorVentanas, ConfigSegmento, trama_desde_paquete


def capturar_huellas(iface: str, cantidad: int = 500, timeout: int = 60) -> pd.DataFrame:
    """Captura `cantidad` tramas en `iface` (o hasta `timeout` segundos).

    Args:
        iface: Nombre de la interfaz de red (e.g. 'eth0', 'enp0s3').
        cantidad: Número máximo de tramas a capturar.
        timeout: Tiempo máximo de escucha en segundos.

    Returns:
        DataFrame con las huellas crudas por trama.
    """
    sniff = _obtener_sniff()
    extractor = ExtractorHuellaDigital()
    registros: list[dict] = []

    def _callback(paquete):
        huella = extractor.extraer(paquete)
        if huella is not None:
            registros.append(huella.to_dict())

    sniff(iface=iface, prn=_callback, count=cantidad, timeout=timeout)
    return pd.DataFrame(registros)


def capturar_ventanas(
    iface: str,
    cantidad: int = 500,
    timeout: int = 60,
    config: ConfigSegmento | None = None,
) -> list[dict]:
    """Captura por lotes y agrega con el mismo núcleo que el entrenamiento (OE2).

    El flujo continuo llega en la etapa E5.

    Returns:
        Filas de ventana con las columnas de `COLUMNAS_MODELO`.
    """
    sniff = _obtener_sniff()
    agregador = AgregadorVentanas(config)
    filas: list[dict] = []

    def _callback(paquete):
        trama = trama_desde_paquete(paquete)
        if trama is not None:
            filas.extend(agregador.agregar(trama))

    sniff(iface=iface, prn=_callback, count=cantidad, timeout=timeout)
    filas.extend(agregador.cerrar())
    return filas


def _obtener_sniff():
    """Importa `sniff` de Scapy con un error claro si no está instalado."""
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError(
            "Scapy no está instalado en este entorno de Python. Ejecutar: pip install scapy"
        ) from exc
    return sniff
