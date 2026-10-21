---
name: fix-attack-simulator
description: >-
  Rediseña el simulador de ataque (attack_simulator.py) para que pruebe evasión/suplantación
  de huella digital en vez de detección de tráfico legítimo perturbado. Resuelve §3.3 de CONTEXT_UPGRADE.md.
when_to_use: >-
  Use when the user asks to fix the attack simulator, implement evasion testing, 
  redesign the spoofing simulation, or address §3.3.
allowed-tools: Bash, Read, Write, Edit
---

# Rediseñar Simulador de Ataque

## Problema actual

`simular_ataque_spoofing` toma tráfico **legítimo**, lo perturba, y asume que debería marcarse
como malicioso (`y_esperado = 1`). Esto está invertido.

Un ataque real de huella digital es: un **atacante malicioso intenta parecer legítimo (evasión)**.

## Diseño correcto

### 1. Ataque de evasión (lo principal)

Tomar muestras **maliciosas** y perturbar features para imitar un dispositivo legítimo:

```python
def simular_evasion(X_malicioso: pd.DataFrame, X_legitimo: pd.DataFrame, 
                     nivel: str = "black_box", seed: int = RANDOM_STATE) -> pd.DataFrame:
    """Simula un atacante que intenta evadir la detección imitando tráfico legítimo.
    
    nivel:
        - "black_box": perturbación aleatoria hacia la distribución legítima
        - "white_box": perturbación dirigida usando estadísticos del tráfico legítimo
    """
```

- **Black-box**: perturbar features del tráfico malicioso hacia la media del legítimo con ruido
- **White-box**: usar media y std del tráfico legítimo para generar muestras que caigan
  dentro de la distribución legítima pero manteniendo la "identidad" de ataque

### 2. Spoofing de MAC/OUI

```python
def simular_spoofing_mac(X_dispositivo: pd.DataFrame, mac_objetivo: str) -> pd.DataFrame:
    """Clona la MAC/OUI de un dispositivo legítimo conocido."""
```

- Copiar OUI del dispositivo objetivo
- Imitar patrones de longitud de trama y timing
- Probar si el modelo de identificación de dispositivo lo detecta

### 3. Métricas de evaluación bajo ataque

```python
def evaluar_bajo_ataque(modelo, X_ataque, y_real, X_limpio, y_limpio) -> dict:
    """Compara recall limpio vs recall bajo evasión."""
```

- `recall_limpio`: recall del modelo en datos sin perturbar
- `recall_bajo_ataque`: recall del modelo en datos con evasión
- `tasa_evasion_exitosa`: proporción de muestras maliciosas que el modelo clasifica como legítimas
- `delta_fpr`: cambio en FPR

### 4. Actualizar `pipeline.py`

En `ejecutar_experimento_completo()`:
- Tomar muestras del test que sean **maliciosas** (no legítimas)
- Aplicar `simular_evasion` sobre ellas
- El `y_esperado` sigue siendo 1 (son maliciosas, el modelo debería detectarlas)
- Reportar la caída en recall como "tasa de evasión exitosa"

### 5. Validación

```bash
cd /home/nikka/Documentos/FRED/ids-proyecto/ids_project
python3 -m src.pipeline
```

- La "tasa de detección bajo ataque" debe tener interpretación clara
- Reportar: "De N muestras maliciosas perturbadas, M evadieron la detección (X%)"
- El recall bajo ataque debería ser MENOR que el recall limpio (la evasión funciona parcialmente)
