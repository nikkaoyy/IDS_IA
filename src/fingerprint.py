"""
Módulo de extracción de huella digital de dispositivos (IEEE 802.3).

Corresponde al bloque "Extracción de huella digital" del diagrama de
arquitectura (Fig. 1 del documento del proyecto) y a la línea
`h <- ExtraerHuella(t)` del Algoritmo 1. Da la huella cruda de una trama; lo que consume
el modelo son las ventanas de `src/ventanas.py`.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
import time


@dataclass
class HuellaDigital:
    """Vector de características de huella digital IEEE 802.3 de un dispositivo."""
    mac_origen: str
    oui: str                       # Identificador de fabricante (primeros 3 octetos de la MAC)
    longitud_trama: int
    ethertype: int | None
    tiempo_entre_tramas_ms: float  # Tiempo (IAT) desde la última trama del mismo dispositivo
    es_802_3: bool = False         # True si longitud/tipo <= 1500 (IEEE 802.3 LLC), False si Ethernet II

    def to_dict(self) -> dict:
        return asdict(self)


class ExtractorHuellaDigital:
    """Mantiene el estado necesario (última trama por MAC) para calcular

    el tiempo entre tramas consecutivas (IAT) de un mismo dispositivo.
    """

    def __init__(self):
        # Mapea MAC -> timestamp en segundos de su última trama observada
        self._ultima_marca_tiempo: dict[str, float] = {}

    def extraer(self, paquete) -> HuellaDigital | None:
        """Extrae la huella digital IEEE 802.3 de un paquete capturado con Scapy.

        `paquete` es un objeto Scapy con capa Ethernet (campos `src`, `type`)
        y longitud obtenible con `len()`.
        """
        try:
            mac_origen = str(paquete.src).lower()
        except AttributeError:
            return None

        # Priorizar la marca de tiempo de captura de la trama (paquete.time);
        # recurrir al reloj del sistema solo si no viene provisto.
        ts_captura = getattr(paquete, "time", None)
        ahora = float(ts_captura) if ts_captura is not None else time.time()

        if mac_origen in self._ultima_marca_tiempo:
            anterior = self._ultima_marca_tiempo[mac_origen]
            tiempo_entre_tramas_ms = max((ahora - anterior) * 1000.0, 0.0)
        else:
            # Primera trama observada para esta MAC: IAT inicial en 0.0
            tiempo_entre_tramas_ms = 0.0

        self._ultima_marca_tiempo[mac_origen] = ahora

        oui = mac_origen.upper().replace(":", "").replace("-", "")[:6]
        raw_type = getattr(paquete, "type", None)

        # Distinción IEEE 802.3 vs Ethernet II:
        # En IEEE 802.3 el campo de 2 octetos tras la MAC es Longitud (<= 1500).
        # En Ethernet II representa EtherType (>= 1536 / 0x0600).
        es_802_3 = bool(raw_type is not None and raw_type <= 1500)
        ethertype = None if es_802_3 else raw_type

        return HuellaDigital(
            mac_origen=mac_origen,
            oui=oui,
            longitud_trama=len(paquete),
            ethertype=ethertype,
            tiempo_entre_tramas_ms=tiempo_entre_tramas_ms,
            es_802_3=es_802_3,
        )
