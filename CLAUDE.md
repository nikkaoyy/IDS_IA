# IDS basado en IA — Huella Digital IEEE 802.3

> [!CAUTION] Antes de hacer cambios significativos, leer `docs/historial/CONTEXT_UPGRADE.md` (el
> diagnóstico original, ya resuelto) y `docs/ESTADO.md` (estado y conclusiones vigentes).

## Arquitectura y comandos

```
Captura (Scapy, src/capture.py · src/streaming.py)
   -> Huella IEEE 802.3 por ventana de 5 s (src/ventanas.py, contrato src/feature_schema.py)
   -> Clasificación RF / XGBoost (src/models.py)  +  Identidad del dispositivo (src/identidad.py)
   -> Mitigación en dry-run (src/mitigacion.py)  +  Pronóstico de alertas (src/pronostico.py)
                     ^
       Evasión a nivel de pcap (scripts/lab/retemporizar.py) y generadores de suplantación
```

Cada módulo de `src/` mapea a un bloque de la Fig. 1 / Algoritmo 1 del artículo. El extractor
(`src/ventanas.py`) es el mismo para el lote (`scripts/pcap_to_features.py`) y el streaming.

```
src/        módulos del IDS (captura, ventanas, esquema, modelos, identidad, streaming,
            mitigación, pronóstico, evaluación)
scripts/    evaluaciones por etapa (evaluar*.py), pcap -> ventanas, figuras, pcap demo
scripts/lab/ generadores sintéticos con semilla fija (generar_trafico.py y
            generar_dataset_lab.py CONGELADOS) y retemporizador
configs/    configuración de cada evaluación (rutas de entrada y de salida en reports/)
reports/    cifras congeladas de E1–E6 (JSON/MD): evidencia del informe, no se reescribe
docs/       informes por etapa, ESTADO.md, PCAP_DEMO.md, figuras/, historial/
notebooks/  cierre_e7.ipynb (CRISP-DM, lee reports/)
data/       datasets y pcaps regenerables (no versionados), salvo data/pcap/demo/
models/     modelos .joblib (no versionados)
tests/      pytest
```

```bash
uv venv && uv pip install -e ".[dev]"            # entorno (".[dev,notebook]" para el cuaderno)
.venv/bin/python -m pytest -o addopts="" -q       # suite
.venv/bin/ruff check src/ tests/ scripts/         # lint
.venv/bin/python scripts/lab/generar_dataset_lab.py --salida data/dataset_lab.csv  # corpus E1
.venv/bin/python scripts/verificar_demo_pcap.py   # pcap de demostración
.venv/bin/python scripts/figuras.py               # figuras desde reports/
```

Los comandos completos de reproducción (corpus, generadores de E3, evaluaciones) están en la
sección «Reproducir desde cero» del `README.md`.

## Tech stack

- Python 3.10+ (probado en 3.14; CI en 3.11)
- scikit-learn, XGBoost — clasificación (RF y XGBoost)
- Scapy — captura y síntesis de tráfico
- pandas, numpy — manipulación de datos
- joblib — persistencia de modelos
- statsmodels (opcional, pronóstico Holt-Winters), matplotlib (figuras)

## Convenciones de código

- Idioma: código y docstrings en **español** (nombres de funciones, variables, clases, comentarios, logs)
- Docstrings con trazabilidad al artículo (referencia a Fig. 1, Algoritmo 1, Fases, OE1-OE3)
- Tipo de retorno y type hints en todas las funciones públicas
- Constantes globales en MAYÚSCULAS (e.g. `RANDOM_STATE`, `COLUMNAS`)
- Semilla reproducible: usar `RANDOM_STATE = 42` de `src/data.py`
- Modelos se guardan en `models/` con joblib
- Separación limpia: cada módulo tiene una responsabilidad única alineada al artículo

## Decisiones tomadas

1. **Dataset propio del laboratorio, no CICIDS2017.** CICIDS no trae los campos IEEE 802.3 (MAC,
   OUI, ethertype) ni las señales de pila (TTL, ventana, opciones TCP, IP-ID). Se usa un generador
   sintético con verdad terreno por trama (`scripts/lab/generar_trafico.py`, congelado): 20
   sesiones de desarrollo, sha256 `7f06d099…a945`. El holdout 20–29 está **gastado**: una cifra
   final nueva necesita sesiones nuevas (≥ 30).
2. **Un solo contrato de características.** Esquema 3.0, 52 columnas (`src/feature_schema.py`),
   producido por `src/ventanas.py` tanto en lote como en streaming. Las señales de identidad viven
   en `src/identidad.py`, **fuera** del contrato de ataques.
3. **Evaluación por episodio**, con IC bootstrap, falsas alarmas por dispositivo-día (umbral a
   1 FA/disp-día) y LOAO para medir la transferencia a tipos nuevos. La exactitud por ventana
   queda solo como referencia.
4. **Evasión medida a nivel de pcap.** Se usan `scripts/lab/retemporizar.py` y los generadores de
   suplantación (`generar_clones.py`, `generar_variacion.py`, `generar_suplantacion.py`,
   `generar_contaminacion.py`), no la perturbación de columnas agregadas. `src/attack_simulator.py`
   se conserva, pero no es representativo.
5. **Streaming real:** `src/streaming.py` (AsyncSniffer + ventanas) con paridad probada frente al
   lote; `scripts/captura_en_vivo.py` en vivo (root) o en replay offline.
6. **Mitigación en dry-run por defecto:** sin un `ejecutor` explícito no toca la red.
7. **Proyecto profesionalizado:** git, `pyproject.toml`, pytest, ruff, CI
   (`.github/workflows/tests.yml`), licencia MIT.
8. **Cifras congeladas:** `reports/`, `configs/` y los generadores congelados no se modifican.
   Los evaluadores escriben en `reports/`: ejecutarlos reescribe la evidencia.

## Extensiones conocidas

Todas necesitan el laboratorio físico o sesiones nuevas (detalle en `docs/ESTADO.md`):

- Captura real sobre una interfaz y ejecución real de la mitigación.
- FA del vigilante IP→MAC con DHCP y failover reales (su 0,0 es optimista).
- RST de la víctima frente a un clon de pila completa en un switch.
- Sesiones largas y nuevas (≥ 30) para cualquier cifra final.
- Distinguir `dos_pilas` de un clon por el lapso de aparición; aprender cambios legítimos sin
  aprender clones; defensa en la fase `no_confiable`.

## Objetivos específicos del artículo (referencia)

- **OE1**: Caracterizar vectores de ataque por capa TCP/IP e ISO/OSI
- **OE2**: Módulo de huella digital en tiempo real + RF/XGBoost sobre dataset de referencia
- **OE3**: Evaluar desempeño simulando ataque a la huella; diagnóstico, mitigación, pronóstico
