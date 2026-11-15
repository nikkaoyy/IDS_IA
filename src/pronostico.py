"""
Pronóstico del comportamiento anómalo (E6, OE3; Fig. 1, «Pronóstico»).

Mantiene la serie temporal de la tasa de alertas por ventana y pronostica los próximos pasos para
**anticipar** un ataque sostenido o un escalamiento antes de que ocurra. El método por defecto es
Holt (suavizado exponencial doble) implementado a mano: determinista, sin dependencias y suficiente
para una tasa con tendencia. `metodo="holt_winters"` usa `statsmodels` si se quiere estacionalidad.

`aviso_temprano` traduce el pronóstico en una señal de OE3: si la tasa prevista supera un umbral o
la tendencia es claramente creciente, se avisa antes de que el detector acumule las alertas.
"""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger("ids.pronostico")


@dataclass
class RegistroTemporalAlertas:
    """Serie temporal de la tasa de alertas por ventana (entrada del pronóstico)."""

    historial_max: int = 1000
    _filas: deque = field(default_factory=lambda: deque(maxlen=1000))

    def registrar(self, ts_s: float, n_alertas: int, score_medio: float | None = None) -> None:
        self._filas.append({"t": ts_s, "n": int(n_alertas), "score": score_medio})

    def serie(self) -> np.ndarray:
        """Tasa de alertas por ventana, en orden temporal."""
        return np.array([f["n"] for f in self._filas], dtype=float)

    def __len__(self) -> int:
        return len(self._filas)


def _holt(serie: np.ndarray, alfa: float, beta: float) -> tuple[float, float]:
    """Suavizado exponencial doble (Holt); devuelve (nivel, tendencia) al final de la serie.

    El llamador garantiza `len(serie) >= 2`.
    """
    nivel = float(serie[0])
    tendencia = float(serie[1] - serie[0])
    for x in serie[1:]:
        nivel_prev = nivel
        nivel = alfa * x + (1 - alfa) * (nivel + tendencia)
        tendencia = beta * (nivel - nivel_prev) + (1 - beta) * tendencia
    return nivel, tendencia


@dataclass
class PronosticadorAnomalias:
    """Pronóstico de la tasa de alertas. `holt` (a mano, por defecto) o `holt_winters` (statsmodels)."""

    metodo: str = "holt"
    alfa: float = 0.5
    beta: float = 0.3
    _nivel: float = 0.0
    _tendencia: float = 0.0
    _modelo: object = None

    def entrenar(self, serie: np.ndarray) -> PronosticadorAnomalias:
        serie = np.asarray(serie, dtype=float)
        if len(serie) < 2:
            raise ValueError("La serie necesita al menos 2 puntos para pronosticar.")
        if self.metodo == "holt_winters":
            from statsmodels.tsa.holtwinters import ExponentialSmoothing
            self._modelo = ExponentialSmoothing(serie, trend="add", seasonal=None).fit()
        else:
            self._nivel, self._tendencia = _holt(serie, self.alfa, self.beta)
        return self

    def pronosticar(self, pasos: int = 5) -> np.ndarray:
        """Tasa de alertas prevista para los próximos `pasos` (no negativa: son conteos)."""
        if self.metodo == "holt_winters":
            pred = np.asarray(self._modelo.forecast(pasos), dtype=float)
        else:
            pred = self._nivel + self._tendencia * np.arange(1, pasos + 1)
        return np.clip(pred, 0.0, None)

    @property
    def tendencia(self) -> str:
        if self._tendencia > 0.1:
            return "creciente"
        if self._tendencia < -0.1:
            return "decreciente"
        return "estable"

    def aviso_temprano(self, umbral: float, pasos: int = 5) -> dict:
        """Señal de OE3: avisa si la tasa prevista supera `umbral` en los próximos `pasos`."""
        pred = self.pronosticar(pasos)
        supera = bool(np.any(pred >= umbral))
        return {"aviso": supera or self.tendencia == "creciente", "tendencia": self.tendencia,
                "pronostico": [round(float(x), 3) for x in pred], "umbral": umbral}

    def backtesting(self, serie: np.ndarray, train_ratio: float = 0.8) -> dict:
        """Evalúa el pronóstico: entrena con el inicio y mide MAE/MAPE sobre la cola."""
        serie = np.asarray(serie, dtype=float)
        n_tr = max(2, int(len(serie) * train_ratio))
        train, test = serie[:n_tr], serie[n_tr:]
        if len(test) == 0:
            raise ValueError("La serie es demasiado corta para el backtesting.")
        self.entrenar(train)
        pred = self.pronosticar(len(test))
        mae = float(np.mean(np.abs(test - pred)))
        mape = float(np.mean(np.abs((test - pred) / (test + 1e-8))) * 100)
        return {"mae": round(mae, 4), "mape": round(mape, 2), "n_test": int(len(test)),
                "tendencia": self.tendencia}
