---
name: add-streaming
description: >-
  Implementa captura de tráfico en streaming (tiempo real) usando AsyncSniffer + cola + ventanas
  deslizantes, reemplazando la captura por lotes actual. Conecta captura → huella → modelo → alerta.
when_to_use: >-
  Use when the user asks to implement real-time capture, streaming, live inference,
  AsyncSniffer, or connecting the capture pipeline end-to-end.
allowed-tools: Bash, Read, Write, Edit
---

# Implementar Captura en Streaming

## Arquitectura del streaming

```
AsyncSniffer(iface) → Cola thread-safe → Acumulador por MAC (ventana N seg)
    → Al cerrar ventana: extraer features → inferir() → alerta/mitigación
```

## Pasos

### 1. Refactorizar `src/capture.py`

Reemplazar `sniff(count, timeout)` por `AsyncSniffer`:

```python
from scapy.all import AsyncSniffer
from queue import Queue
from threading import Thread

class CapturadorStreaming:
    def __init__(self, iface: str, extractor: ExtractorHuellaDigital,
                 modelo, scaler, columnas: list[str],
                 ventana_seg: float = 5.0):
        self.iface = iface
        self.extractor = extractor
        self.modelo = modelo
        self.scaler = scaler
        self.columnas = columnas
        self.ventana_seg = ventana_seg
        self._cola = Queue()
        self._sniffer = None
    
    def iniciar(self):
        """Inicia captura asíncrona + hilo de procesamiento."""
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            prn=lambda pkt: self._cola.put(pkt),
            store=False,
        )
        self._sniffer.start()
        self._hilo_procesamiento = Thread(target=self._procesar, daemon=True)
        self._hilo_procesamiento.start()
    
    def detener(self):
        if self._sniffer:
            self._sniffer.stop()
    
    def _procesar(self):
        """Hilo que consume la cola, acumula por MAC/ventana, e infiere."""
        # Implementar acumulación por ventana temporal
        pass
```

### 2. Ventanas deslizantes por dispositivo

- Acumular tramas por MAC en ventanas de N segundos
- Al cerrar ventana: calcular features agregadas (media/std/min/max de longitud e IAT)
- Alimentar `inferir()` con el vector de features de la ventana
- Medir latencia: tiempo desde última trama de ventana hasta resultado de inferencia

### 3. Manejo de señales

- Ctrl+C para detener limpiamente
- Logging de estadísticas periódicas (tramas/segundo, ventanas procesadas, alertas)

### 4. Filtro BPF

Agregar opción de filtro BPF para reducir volumen:
```python
AsyncSniffer(iface=iface, filter="ether proto 0x0800", ...)
```

### 5. Script de ejecución

Crear `scripts/captura_en_vivo.py`:
```python
"""Captura y clasificación en tiempo real (requiere root)."""
import argparse
# ...
```

### 6. Métricas de rendimiento

Medir y reportar:
- Latencia por ventana (ms): tiempo desde cierre de ventana hasta predicción
- Throughput: ventanas procesadas por segundo
- Tramas descartadas (si la cola se llena)

### 7. Validación

```bash
# En el laboratorio (requiere root/sudo):
sudo python3 scripts/captura_en_vivo.py --iface eth0 --ventana 5
# Debería mostrar alertas en tiempo real
```
