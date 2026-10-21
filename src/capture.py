"""
Módulo de captura de tráfico (bloque "Captura de tráfico" de la Fig. 1).

Requiere permisos de captura de red (root/administrador) y la librería Scapy.
"""

from __future__ import annotations
import pandas as pd

from .fingerprint import ExtractorHuellaDigital
from .feature_schema import mapear_huella_a_vector_modelo


def capturar_huellas(
    iface: str,
    cantidad: int = 500,
    timeout: int = 60,
    formato_modelo: bool = False,
) -> pd.DataFrame:
    """Captura `cantidad` tramas en `iface` (o hasta `timeout` segundos).

    Args:
        iface: Nombre de la interfaz de red (e.g. 'eth0', 'enp0s3').
        cantidad: Número máximo de tramas a capturar.
        timeout: Tiempo máximo de escucha en segundos.
        formato_modelo: Si True, mapea cada huella al contrato de características del modelo.

    Returns:
        DataFrame con las huellas capturadas.
    """
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError(
            "Scapy no está instalado en este entorno de Python. Ejecutar: pip install scapy"
        ) from exc

    extractor = ExtractorHuellaDigital()
    registros: list[dict] = []

    def _callback(paquete):
        huella = extractor.extraer(paquete)
        if huella is not None:
            if formato_modelo:
                registros.append(huella.a_vector_modelo())
            else:
                registros.append(huella.to_dict())

    sniff(iface=iface, prn=_callback, count=cantidad, timeout=timeout)
    return pd.DataFrame(registros)
