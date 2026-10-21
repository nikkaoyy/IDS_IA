---
name: add-forecasting
description: >-
  Implementa el módulo de pronóstico de comportamiento anómalo: serie temporal de 
  alertas/scores por ventana + modelo de forecast (Holt-Winters/ARIMA). Cubre OE3 "pronóstico".
when_to_use: >-
  Use when the user asks to implement forecasting, time series prediction,
  anomaly trend prediction, or the "pronóstico" component of OE3.
allowed-tools: Bash, Read, Write, Edit
---

# Implementar Pronóstico de Comportamiento Anómalo

## Contexto

OE3 requiere "pronóstico del comportamiento anómalo": predecir la tendencia de alertas/anomalías
en el futuro cercano para anticipar ataques sostenidos o escalamiento.

## Diseño

### 1. Crear `src/forecast.py`

```python
"""Módulo de pronóstico (OE3): serie temporal de anomalías + forecast."""

import numpy as np
import pandas as pd
from collections import deque

class RegistroTemporalAlertas:
    """Mantiene serie temporal de tasa de alertas por ventana."""
    
    def __init__(self, ventana_seg: float = 60, historial_max: int = 1000):
        self.ventana_seg = ventana_seg
        self._alertas: deque = deque(maxlen=historial_max)
        self._scores: deque = deque(maxlen=historial_max)
    
    def registrar(self, timestamp: float, n_alertas: int, score_medio: float):
        self._alertas.append({"t": timestamp, "n": n_alertas, "score": score_medio})
    
    def como_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame(list(self._alertas))

class PronosticadorAnomalias:
    """Pronóstico de tasa de alertas usando Holt-Winters o regresión."""
    
    def __init__(self, metodo: str = "holt_winters"):
        self.metodo = metodo
    
    def entrenar(self, serie: pd.Series):
        """Entrena el modelo de pronóstico sobre la serie histórica."""
        if self.metodo == "holt_winters":
            # Exponential smoothing
            from statsmodels.tsa.holtwinters import ExponentialSmoothing
            self.modelo = ExponentialSmoothing(
                serie, trend="add", seasonal=None
            ).fit()
        elif self.metodo == "media_movil":
            # Fallback simple sin statsmodels
            self._ventana = 5
            self._ultima_media = serie.rolling(self._ventana).mean().iloc[-1]
    
    def pronosticar(self, pasos: int = 5) -> pd.Series:
        """Pronostica los próximos N pasos."""
        if self.metodo == "holt_winters":
            return self.modelo.forecast(pasos)
        else:
            return pd.Series([self._ultima_media] * pasos)
    
    def evaluar_backtesting(self, serie: pd.Series, train_ratio: float = 0.8) -> dict:
        """Evalúa el pronóstico con backtesting (MAE, MAPE)."""
        n_train = int(len(serie) * train_ratio)
        train, test = serie[:n_train], serie[n_train:]
        self.entrenar(train)
        pred = self.pronosticar(len(test))
        mae = np.mean(np.abs(test.values - pred.values))
        mape = np.mean(np.abs((test.values - pred.values) / (test.values + 1e-8))) * 100
        return {"mae": mae, "mape": mape, "n_test": len(test)}
```

### 2. Integrar con el pipeline

- En modo streaming: alimentar `RegistroTemporalAlertas` con cada ventana
- Periódicamente (cada M ventanas): re-entrenar y pronosticar
- Si el pronóstico indica tendencia creciente → alerta temprana

### 3. Dependencia opcional

Agregar `statsmodels` a requirements.txt (opcional, con fallback a media móvil):
```
statsmodels>=0.14  # Para Holt-Winters/ARIMA; opcional
```

### 4. Evaluación en el pipeline offline

En `ejecutar_experimento_completo()`:
- Simular serie temporal de alertas (ventanas consecutivas del dataset)
- Entrenar pronosticador y reportar MAE/MAPE con backtesting

### 5. Validación

```bash
pip install statsmodels
cd /home/nikka/Documentos/FRED/ids-proyecto/ids_project
python3 -c "
from src.forecast import PronosticadorAnomalias
import pandas as pd
serie = pd.Series([1,2,3,4,5,6,7,8,9,10])
p = PronosticadorAnomalias('media_movil')
p.entrenar(serie)
print('Pronóstico:', p.pronosticar(3).values)
"
```
