---
name: fix-feature-contract
description: >-
  Unifica el esquema de features entre el extractor de huella (fingerprint.py), el dataset (data.py),
  el preprocesador, y el modelo. Resuelve el problema crítico §3.1 de CONTEXT_UPGRADE.md donde
  las features extraídas por fingerprint.py NO coinciden con las que consume el modelo.
when_to_use: >-
  Use when the user mentions fixing the feature mismatch, unifying features, connecting the 
  fingerprint to the model, fixing the pipeline integration, or addressing §3.1.
allowed-tools: Bash, Read, Write, Edit
---

# Unificar Esquema de Features (Contrato)

## Contexto del problema

`fingerprint.py` extrae: `mac_origen, oui, longitud_trama, ethertype, tiempo_entre_tramas_ms`
El modelo consume: `longitud_trama, tiempo_entre_tramas_ms, num_conexiones_por_min, tasa_syn, entropia_puertos_destino, oui_frecuente`

**3 features del modelo no existen en el extractor** (`num_conexiones_por_min`, `tasa_syn`, `entropia_puertos_destino`).
**3 features del extractor no van al modelo** (`mac_origen`, `oui` como string, `ethertype`).

## Pasos

### 1. Definir el contrato de features unificado

Crear `src/feature_schema.py` con:
- `FEATURES_HUELLA_802_3`: features de capa 2 (del extractor de huella)
  - `longitud_trama_media`, `longitud_trama_std`, `longitud_trama_min`, `longitud_trama_max`
  - `iat_media_ms`, `iat_std_ms`, `iat_min_ms`, `iat_max_ms` (inter-arrival time)
  - `tasa_broadcast`, `tasa_arp`, `distribucion_ethertypes` (entropía)
  - `oui_encoded` (target encoding o frecuencia)
- `FEATURES_FLUJO`: features de capa 3-4 (para cuando se tenga un dataset de flujo)
  - `num_conexiones_por_min`, `tasa_syn`, `entropia_puertos_destino`
- `FEATURES_MODELO = FEATURES_HUELLA_802_3 + FEATURES_FLUJO`
- `ETIQUETA = "etiqueta"`

### 2. Refactorizar `fingerprint.py`

Cambiar de extracción **por trama** a extracción **por ventana temporal por dispositivo**:
- `ExtractorHuellaDigital` debe acumular tramas por MAC en ventanas de N segundos
- Al cerrar una ventana, calcular estadísticos agregados (media, var, percentiles de longitud e IAT)
- Usar `float(paquete.time)` en vez de `time.time()` para el timestamp
- Distinguir IEEE 802.3 (longitud ≤ 1500) de Ethernet II (EtherType > 1536)
- Calcular OUI encoding como frecuencia relativa, no `int(oui,16) % 1000`

### 3. Actualizar `data.py`

- Generar dataset sintético que use las features del contrato unificado
- Que la etiqueta NO sea función determinista de las features (agregar ruido, solapamiento)
- Desbalancear: ~80% legítimo, ~20% malicioso (realista para IDS)
- Flag explícito `--sintetico` en vez de fallback silencioso

### 4. Actualizar `preprocess.py`

- Importar columnas del contrato (`feature_schema.py`)
- Manejar NaN/inf (CICIDS trae infinitos en Flow Bytes/s)
- Separar features numéricas de categóricas
- Remover StandardScaler para RF/XGBoost (árboles invariantes a escala) o hacerlo opcional

### 5. Actualizar `pipeline.py`

- `inferir()` debe usar las columnas del contrato
- Persistir scaler + columnas + metadata junto con los modelos

### 6. Validación

```bash
cd /home/nikka/Documentos/FRED/ids-proyecto/ids_project
python3 -c "from src.feature_schema import FEATURES_MODELO; print(FEATURES_MODELO)"
python3 -m src.pipeline  # Debe correr sin errores
```

- Verificar que accuracy ya NO sea 1.0 (el dataset no debe ser trivial)
- Verificar que `capture.py` → `fingerprint.py` → `inferir()` sea un camino funcional
