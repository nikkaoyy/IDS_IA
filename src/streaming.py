"""
Inferencia en streaming: captura en vivo → ventanas → modelo + identidad → alerta (E5, OE3; Fig. 1).

Conecta el camino que hasta ahora era por lotes. El núcleo es `MotorStreaming`, que consume tramas
una a una (de `AsyncSniffer` en vivo o de un pcap para prueba) y, al cerrar cada ventana de
`VENTANA_CORTA_S`, evalúa dos canales con exactamente el mismo código que la evaluación por lotes:

- **supervisado**: la fila de 52 columnas la produce el mismo `AgregadorVentanas` de `src/ventanas.py`
  (paridad garantizada con `extraer_ventanas`), y se pasa al modelo al umbral de operación de E2;
- **identidad**: las tramas crudas de la ventana alimentan un `SeguidorIdentidad` por MAC y un
  `VigilanteIP` global (los del canal de E3B/E4C).

No requiere root para la parte offline (reproducir un pcap); la captura en vivo vive en
`scripts/captura_en_vivo.py`. Mide latencia y throughput por ventana.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field

import pandas as pd

from .feature_schema import COLUMNAS_MODELO
from .identidad import SeguidorIdentidad, VigilanteIP
from .ventanas import (
    VENTANA_CORTA_S,
    AgregadorVentanas,
    ConfigSegmento,
    Trama,
    trama_desde_paquete,
)

logger = logging.getLogger("ids.streaming")

US = 1_000_000


@dataclass
class Resultado:
    """Veredicto de una ventana cerrada para un dispositivo."""

    idx_ventana: int
    mac: str
    probabilidad: float | None
    alarma_supervisado: bool
    alarma_identidad: bool
    estado_identidad: str
    latencia_ms: float


@dataclass
class MotorStreaming:
    """Motor incremental: tramas → ventanas → (supervisado + identidad) → alertas.

    `modelo` es una función `X(DataFrame) -> prob` (p. ej. la de `ev.ajustar_modelo`); si es None,
    el canal supervisado se omite y solo corre la identidad. `red_local` activa el `VigilanteIP`
    con la red del segmento. `con_identidad=False` lo apaga (solo supervisado).
    """

    config: ConfigSegmento = field(default_factory=ConfigSegmento)
    modelo: Callable[[pd.DataFrame], pd.Series] | None = None
    umbral: float = 0.5
    ventana_s: float = VENTANA_CORTA_S
    con_identidad: bool = True
    red_local: str | None = None

    def __post_init__(self) -> None:
        self._agregador = AgregadorVentanas(self.config, self.ventana_s)
        self._ventana_us = round(self.ventana_s * US)
        self._t0_us: int | None = None
        self._buffer: dict[int, list[Trama]] = defaultdict(list)  # tramas crudas por ventana (identidad)
        self._seguidores: dict[str, SeguidorIdentidad] = {}
        self._vigilante = VigilanteIP(red=self.red_local) if (self.con_identidad and self.red_local) else None
        self._alertas_vigilante: list[dict] = []
        self.metricas = {"tramas": 0, "ventanas": 0, "alarmas_supervisado": 0,
                         "alarmas_identidad": 0, "alertas_vigilante": 0, "latencia_ms": deque(maxlen=1000)}

    # ---- entrada -------------------------------------------------------------------------
    def procesar_paquete(self, pkt) -> list[Resultado]:
        """Convierte un paquete de Scapy a `Trama` y lo procesa (None si no es IP/ARP legible)."""
        t = trama_desde_paquete(pkt)
        return self.procesar_trama(t) if t is not None else []

    def procesar_trama(self, t: Trama) -> list[Resultado]:
        """Procesa una trama; devuelve los resultados de las ventanas que cierre."""
        self.metricas["tramas"] += 1
        if self._t0_us is None:
            self._t0_us = t.ts_us
        idx = (t.ts_us - self._t0_us) // self._ventana_us
        filas = self._agregador.agregar(t)  # filas de las ventanas que cierran
        resultados = self._evaluar(filas, idx) if filas else []
        self._buffer[idx].append(t)
        return resultados

    def reproducir(self, tramas) -> list[Resultado]:
        """Pasa un iterable de tramas (offline) y devuelve todos los resultados, incluido el cierre."""
        salida = [r for t in tramas for r in self.procesar_trama(t)]
        salida += self.cerrar()
        return salida

    def cerrar(self) -> list[Resultado]:
        """Cierra la ventana en curso (fin de captura)."""
        filas = self._agregador.cerrar()
        idx = (max(self._buffer) + 1) if self._buffer else 0
        return self._evaluar(filas, idx) if filas else []

    # ---- evaluación ----------------------------------------------------------------------
    def _evaluar(self, filas: list[dict], idx_actual: int) -> list[Resultado]:
        t_inicio = time.perf_counter()
        prob_por_fila = self._predecir(filas)
        resultados = []
        for fila, prob in zip(filas, prob_por_fila):
            alarma_sup = prob is not None and prob > self.umbral
            if alarma_sup:
                self.metricas["alarmas_supervisado"] += 1
            resultados.append(Resultado(
                idx_ventana=int(fila["idx_ventana"]), mac=str(fila["mac"]), probabilidad=prob,
                alarma_supervisado=bool(alarma_sup), alarma_identidad=False, estado_identidad="",
                latencia_ms=(time.perf_counter() - t_inicio) * 1000.0))
            self.metricas["ventanas"] += 1
        if self.con_identidad:
            self._identidad(idx_actual, {r.mac: r for r in resultados})
        for r in resultados:
            self.metricas["latencia_ms"].append(r.latencia_ms)
        return resultados

    def _predecir(self, filas: list[dict]) -> list[float | None]:
        if self.modelo is None:
            return [None] * len(filas)
        x = pd.DataFrame(filas)[COLUMNAS_MODELO]
        prob = self.modelo(x)
        return [float(p) for p in prob]

    def _identidad(self, idx_actual: int, por_mac: dict[str, Resultado]) -> None:
        """Vuelca las tramas crudas de las ventanas ya cerradas (idx < actual) a los canales."""
        for k in sorted(c for c in self._buffer if c < idx_actual):
            tramas = self._buffer.pop(k)
            ts = int(self._t0_us + k * self._ventana_us) if self._t0_us is not None else 0
            if self._vigilante is not None:
                alertas = self._vigilante.observar(tramas, ts)
                self._alertas_vigilante += [{"idx": k, **a} for a in alertas]
                self.metricas["alertas_vigilante"] += len(alertas)
            por_equipo: dict[str, list[Trama]] = defaultdict(list)
            for t in tramas:
                por_equipo[t.mac_src].append(t)
            for mac, ts_mac in por_equipo.items():
                seg = self._seguidores.setdefault(mac, SeguidorIdentidad())
                r = seg.observar(ts_mac, ts_us=ts)
                if r["alarma"]:
                    self.metricas["alarmas_identidad"] += 1
                if mac in por_mac:
                    por_mac[mac].alarma_identidad = bool(r["alarma"])
                    por_mac[mac].estado_identidad = r["estado"]

    # ---- métricas ------------------------------------------------------------------------
    def resumen_metricas(self) -> dict:
        lat = list(self.metricas["latencia_ms"])
        return {
            "tramas": self.metricas["tramas"], "ventanas": self.metricas["ventanas"],
            "alarmas_supervisado": self.metricas["alarmas_supervisado"],
            "alarmas_identidad": self.metricas["alarmas_identidad"],
            "alertas_vigilante": self.metricas["alertas_vigilante"],
            "latencia_ms_media": round(sum(lat) / len(lat), 3) if lat else None,
            "latencia_ms_max": round(max(lat), 3) if lat else None,
        }
