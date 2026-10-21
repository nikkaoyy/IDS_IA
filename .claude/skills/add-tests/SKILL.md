---
name: add-tests
description: >-
  Agrega tests unitarios e de integración al proyecto IDS usando pytest.
  Cubre extractor de huella, preprocesado, modelos, pipeline e inferencia.
when_to_use: >-
  Use when the user asks to add tests, write tests, improve test coverage,
  or set up pytest for the project.
allowed-tools: Bash, Read, Write, Edit
---

# Agregar Tests al Proyecto IDS

## Setup

1. Instalar pytest:
   ```bash
   cd /home/nikka/Documentos/FRED/ids-proyecto/ids_project
   pip install pytest pytest-cov
   ```

2. Crear estructura de tests:
   ```
   tests/
   ├── __init__.py
   ├── conftest.py          # Fixtures compartidas
   ├── test_data.py         # Tests de carga de datos
   ├── test_fingerprint.py  # Tests del extractor de huella
   ├── test_preprocess.py   # Tests de preprocesamiento
   ├── test_models.py       # Tests de entrenamiento y evaluación
   ├── test_attack.py       # Tests del simulador de ataque
   └── test_pipeline.py     # Tests de integración del pipeline
   ```

## Tests por módulo

### `tests/conftest.py` — Fixtures

```python
import pytest
import pandas as pd
import numpy as np
from src.data import generar_dataset_sintetico, COLUMNAS

@pytest.fixture
def dataset_pequeno():
    """Dataset sintético pequeño para tests rápidos."""
    return generar_dataset_sintetico(n=200)

@pytest.fixture
def dataset_con_ambas_clases(dataset_pequeno):
    """Garantiza que haya al menos 10 muestras de cada clase."""
    df = dataset_pequeno
    assert df["etiqueta"].nunique() == 2, "Dataset de test debe tener ambas clases"
    assert (df["etiqueta"] == 0).sum() >= 10
    assert (df["etiqueta"] == 1).sum() >= 10
    return df
```

### `tests/test_data.py`

- `test_generar_sintetico_tiene_columnas_correctas`: verificar que tiene COLUMNAS + "etiqueta"
- `test_generar_sintetico_tiene_ambas_clases`: verificar clases 0 y 1
- `test_generar_sintetico_es_reproducible`: misma semilla → mismo resultado
- `test_cargar_dataset_fallback_sintetico`: si no hay archivo, genera sintético
- `test_cargar_dataset_valida_columnas`: si falta una columna, ValueError

### `tests/test_fingerprint.py`

- `test_extraer_huella_basica`: crear paquete mock con `src="AA:BB:CC:DD:EE:FF"`, `type=0x0800`, longitud 64
- `test_extraer_sin_capa_ethernet`: paquete sin `.src` devuelve None
- `test_tiempo_entre_tramas`: dos extracciones consecutivas → Δt > 0
- `test_oui_extraido_correctamente`: MAC "AA:BB:CC:DD:EE:FF" → OUI "AABBCC"

### `tests/test_preprocess.py`

- `test_dividir_proporciones`: 75/25 split
- `test_dividir_estratificado`: proporción de clases similar en train y test
- `test_escalador_ajuste_y_transformacion`: scaler.mean_ tiene las dimensiones correctas
- `test_preprocesar_misma_forma`: X transformado tiene misma shape

### `tests/test_models.py`

- `test_entrenar_rf_devuelve_clasificador`: tipo correcto
- `test_entrenar_xgb_devuelve_clasificador`: tipo correcto
- `test_evaluar_devuelve_metricas`: dict con accuracy, precision, recall, f1, FPR
- `test_guardar_y_cargar_modelo`: round-trip con joblib
- `test_evaluar_con_labels_explícitos`: no falla con una sola clase en y_test

### `tests/test_pipeline.py` (integración)

- `test_experimento_completo_corre`: ejecutar_experimento_completo() no lanza excepciones
- `test_experimento_devuelve_modelos`: resultado tiene modelo_rf, modelo_xgb, scaler, columnas
- `test_inferir_trama_unica`: inferir() con un dict válido devuelve 0 o 1

## Ejecutar

```bash
cd /home/nikka/Documentos/FRED/ids-proyecto/ids_project
python3 -m pytest tests/ -v --tb=short
python3 -m pytest tests/ -v --cov=src --cov-report=term-missing
```

## Validación

- Todos los tests pasan
- Cobertura > 70% en cada módulo de `src/`
- No hay warnings de deprecación
