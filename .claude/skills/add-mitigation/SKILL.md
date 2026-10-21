---
name: add-mitigation
description: >-
  Implementa el módulo de mitigación del IDS: política configurable de respuesta
  (log → alerta → bloqueo MAC → cuarentena) con acciones reales en el laboratorio
  (ebtables/iptables) y simuladas en tests. Cubre OE3 "mecanismos de mitigación".
when_to_use: >-
  Use when the user asks to implement mitigation, response actions, blocking,
  quarantine, or the defense mechanisms of the IDS.
allowed-tools: Bash, Read, Write, Edit
---

# Implementar Mitigación

## Estado actual

`pipeline.py` tiene `registrar_alerta()` y `aplicar_mitigacion()` que solo hacen `logger.info()`.
OE3 requiere mecanismos de mitigación reales.

## Diseño

### 1. Crear `src/mitigation.py`

```python
"""Módulo de mitigación (OE3): política configurable de respuesta a amenazas."""

from enum import IntEnum
from dataclasses import dataclass

class NivelSeveridad(IntEnum):
    INFO = 0
    ADVERTENCIA = 1
    BLOQUEO = 2
    CUARENTENA = 3

@dataclass
class PoliticaMitigacion:
    umbral_alertas: int = 3          # Alertas antes de escalar
    ventana_alertas_seg: float = 60  # Ventana para contar alertas
    nivel_inicial: NivelSeveridad = NivelSeveridad.ADVERTENCIA
    auto_escalar: bool = True        # Escalar automáticamente si persiste

class GestorMitigacion:
    """Gestiona las respuestas a amenazas detectadas."""
    
    def __init__(self, politica: PoliticaMitigacion, modo: str = "simulacion"):
        self.politica = politica
        self.modo = modo  # "simulacion" o "laboratorio"
        self._alertas_por_mac: dict[str, list[float]] = {}
        self._bloqueados: set[str] = set()
    
    def procesar_alerta(self, mac: str, score: float, timestamp: float) -> NivelSeveridad:
        """Registra alerta y decide acción según política."""
        pass
    
    def bloquear_mac(self, mac: str) -> bool:
        """Bloquea MAC. En modo lab: ejecuta ebtables. En simulación: registra."""
        if self.modo == "laboratorio":
            # subprocess.run(["ebtables", "-A", "FORWARD", "-s", mac, "-j", "DROP"])
            pass
        self._bloqueados.add(mac)
        return True
    
    def cuarentena(self, mac: str) -> bool:
        """Aísla el dispositivo. En modo lab: VLAN de cuarentena o regla OVS."""
        pass
    
    def listar_bloqueados(self) -> set[str]:
        return self._bloqueados.copy()
    
    def desbloquear_mac(self, mac: str) -> bool:
        self._bloqueados.discard(mac)
        return True
```

### 2. Integrar con `pipeline.py`

- Reemplazar `registrar_alerta`/`aplicar_mitigacion` por llamadas al `GestorMitigacion`
- El gestor mantiene estado de alertas por MAC y decide escalamiento
- Logging detallado de cada acción tomada

### 3. Configuración

Crear `config/mitigacion.yaml` o usar argumentos CLI:
```yaml
umbral_alertas: 3
ventana_alertas_seg: 60
nivel_inicial: ADVERTENCIA
auto_escalar: true
modo: simulacion  # o "laboratorio"
```

### 4. Tests

- Test de escalamiento: 1 alerta → ADVERTENCIA, 3+ alertas → BLOQUEO
- Test de bloqueo: MAC bloqueada se registra
- Test de desbloqueo: MAC se puede desbloquear
- Test de cuarentena en modo simulación

### 5. Validación

```bash
cd /home/nikka/Documentos/FRED/ids-proyecto/ids_project
python3 -m pytest tests/test_mitigation.py -v
python3 -m src.pipeline  # Debe mostrar acciones de mitigación en el log
```
