# IDS basado en IA — Huella Digital IEEE 802.3

## Arquitectura

```
Captura (Scapy) -> Extracción de huella IEEE 802.3 -> Preprocesamiento
      -> Clasificación (Random Forest / XGBoost) -> Mitigación / Alerta
                              ^
                              |
                    Simulador de ataque de suplantación
```

Cada módulo en `src/` mapea a un bloque de la Fig. 1 / Algoritmo 1 del artículo.

## Tech stack

- Python 3.10+
- scikit-learn, XGBoost — clasificación (RF y XGBoost)
- Scapy — captura de tráfico de red
- pandas, numpy — manipulación de datos
- joblib — persistencia de modelos

## Estructura del proyecto

```
src/
├── capture.py           # Captura de tráfico en vivo (Scapy, requiere root)
├── fingerprint.py       # Extracción de huella digital IEEE 802.3
├── data.py              # Carga de dataset (CICIDS2017 o sintético)
├── preprocess.py        # Split train/test + escalado
├── models.py            # Entrenamiento, evaluación, persistencia RF/XGBoost
├── attack_simulator.py  # Simulación de ataque de suplantación
├── pipeline.py          # Orquestador del pipeline completo
└── __init__.py
notebooks/               # Jupyter notebook (CRISP-DM)
data/                    # Datasets (no versionados)
models/                  # Modelos entrenados .joblib (no versionados)
```

## Comandos

```bash
# Ejecutar pipeline completo (datos sintéticos si no hay dataset real)
python3 -m src.pipeline

# Instalar dependencias
pip install -r requirements.txt

# Tests (cuando se implementen)
python3 -m pytest tests/ -v

# Linting (cuando se configure)
ruff check src/ tests/
```

## Convenciones de código

- Idioma: código y docstrings en **español** (nombres de funciones, variables, clases, comentarios, logs)
- Docstrings con trazabilidad al artículo (referencia a Fig. 1, Algoritmo 1, Fases, OE1-OE3)
- Tipo de retorno y type hints en todas las funciones públicas
- Constantes globales en MAYÚSCULAS (e.g. `RANDOM_STATE`, `COLUMNAS`)
- Semilla reproducible: usar `RANDOM_STATE = 42` de `src/data.py`
- Modelos se guardan en `models/` con joblib
- Separación limpia: cada módulo tiene una responsabilidad única alineada al artículo

## Estado del proyecto y problemas conocidos

> [!CAUTION] Leer `CONTEXT_UPGRADE.md` antes de hacer cambios significativos.

Problemas críticos documentados en `CONTEXT_UPGRADE.md`:

1. **Features desconectadas**: `fingerprint.py` extrae features (MAC, OUI, longitud, ethertype, Δt) que NO son las que consume el modelo (num_conexiones_por_min, tasa_syn, entropia_puertos_destino). No hay camino funcional captura→modelo.
2. **Resultados tautológicos**: El dataset sintético produce etiquetas como función determinista de 3 features → 100% accuracy siempre. No tiene valor científico.
3. **Simulador invertido**: El ataque perturba tráfico legítimo esperando que se detecte como malicioso. Lo correcto es probar evasión (tráfico malicioso que intenta parecer legítimo).
4. **Sin streaming**: La captura es por lotes (sniff), no en tiempo real.
5. **Sin tests, sin git, sin pyproject.toml**.
6. **CICIDS2017 no tiene campos 802.3** (MAC, OUI, ethertype). Falta decisión de dataset.

## Objetivos específicos del artículo (referencia)

- **OE1**: Caracterizar vectores de ataque por capa TCP/IP e ISO/OSI
- **OE2**: Módulo de huella digital en tiempo real + RF/XGBoost sobre dataset de referencia
- **OE3**: Evaluar desempeño simulando ataque a la huella; diagnóstico, mitigación, pronóstico
