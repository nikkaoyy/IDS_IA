# Informe de Avance Técnico: Fase 0 y Fase 1 — Andamiaje, Laboratorio Virtual y Generación de Dataset Etiquetado

**Proyecto:** Sistema de Detección de Intrusiones (IDS) en Redes TCP/IP mediante Huella Digital de Dispositivos en el Protocolo IEEE 802.3 usando Inteligencia Artificial  
**Autor:** Nicolás Martínez Pineda  
**Institución:** Universidad Distrital Francisco José de Caldas  
**Asignatura:** Fundamentos de Redes y Comunicación  
**Docente:** Octavio José Salcedo Parra  
**Fecha:** Octubre 2026  
**Hito:** Fases 0 y 1 Completadas (Andamiaje, Contrato de Datos, Laboratorio Virtual y Dataset Etiquetado)  

---

## 1. Resumen Ejecutivo del Avance

El desarrollo del proyecto ha alcanzado exitosamente la culminación de la **Fase 0** (Andamiaje y Contrato de Características) y la **Fase 1** (Laboratorio Virtual y Dataset de Referencia Propio), superando los bloqueantes metodológicos y técnicos identificados en la auditoría inicial ([`CONTEXT_UPGRADE.md`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/CONTEXT_UPGRADE.md)):

1. **Resolución de la desconexión enlace-modelo (Fase 0):** Se creó [`src/feature_schema.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/feature_schema.py), permitiendo que la huella física (IEEE 802.3 / Ethernet) se integre sin fisuras con las métricas de capas superiores de transporte y red.
2. **Superación del dataset sintético determinista (Fase 1):** Se implementó un laboratorio virtual con Scapy ([`scripts/lab/generar_trafico.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/scripts/lab/generar_trafico.py)) que sintetiza tráfico en archivos PCAP con **6 escenarios multicapeados** (OE1), clases balanceadas y rotación de MAC/OUI por episodio para evitar fugas de información.
3. **Procesador PCAP a Dataset por Ventanas:** [`scripts/pcap_to_features.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/scripts/pcap_to_features.py) agrega tramas por dispositivo y ventana temporal, extrayendo características estadísticas de nivel 2 y flujo 3-4, asignando además una clave de `grupo` única para validación estratificada libre de fugas (`StratifiedGroupKFold`).
4. **Dataset Real Consolidado:** Se generó [`data/dataset_lab.csv`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/data/dataset_lab.csv) con **3.317 muestras** (1.548 benignas y 1.769 maliciosas distribuidas en capas de Enlace, Transporte y Aplicación).
5. **Calidad y Verificación:** La suite automatizada de pruebas cuenta con **27/27 tests en verde** ejecutados bajo `pytest`.

---

## 2. Arquitectura Global del Sistema (Fase 0 + Fase 1)

```
                     ┌─────────────────────────────────────────────────────────┐
                     │              LABORATORIO VIRTUAL (FASE 1)               │
                     │  scripts/lab/generar_trafico.py (Scapy, sin root)       │
                     └────────────────────────────┬────────────────────────────┘
                                                  │
                                                  ▼ Genera PCAPs etiquetados
                                       ┌──────────────────────┐
                                       │ 6 Archivos .pcap     │
                                       │ (11 MB de tráfico)   │
                                       └──────────┬───────────┘
                                                  │
                                                  ▼
                     ┌─────────────────────────────────────────────────────────┐
                     │             PROCESADOR PCAP -> FEATURES                 │
                     │  scripts/pcap_to_features.py                            │
                     │  - Agrupación por (MAC, ventana de tiempo)              │
                     │  - Extracción capa 2 (IEEE 802.3) + capa 3-4 (Flujo)    │
                     │  - Generación de clave 'grupo' anti-fuga                │
                     └────────────────────────────┬────────────────────────────┘
                                                  │
                                                  ▼ Emite CSV canónico
                                       ┌──────────────────────┐
                                       │ data/dataset_lab.csv │
                                       │ 3.317 registros      │
                                       └──────────┬───────────┘
                                                  │
                                                  ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               PIPELINE DE DETECCIÓN Y MODELADO (FASE 0)                              │
│                                                                                                     │
│  src/data.py ──► src/preprocess.py ──► src/models.py (RF / XGBoost) ──► src/pipeline.py (Inferencia)│
│       ▲                                                                                             │
│       └─────────────────────────── src/feature_schema.py ───────────────────────────────────────────┘
│                                  (Contrato Unificado)
```

---

## 3. Desglose Detallado de Scripts y Componentes

### 3.1. Fase 0: Andamiaje, Contrato y Módulos Base (`src/`)

| Script / Componente | Responsabilidad | Lo que se adelantó en Fase 0 | Aporte a futuro (Fase 2+) |
|---|---|---|---|
| [`src/feature_schema.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/feature_schema.py) | Contrato unificado de variables. | Define `COLUMNAS_MODELO`, validador columnar y adaptador `mapear_huella_a_vector_modelo()`. | Base para experimentos de ablación (con vs. sin capa 2). |
| [`src/fingerprint.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/fingerprint.py) | Extractor de huella IEEE 802.3. | Corrigió $\Delta t$ usando `paquete.time` real; distinguió tramas IEEE 802.3 LLC ($\le 1500$) de Ethernet II. | Extracción en vivo por trama o ventana para streaming. |
| [`src/capture.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/capture.py) | Captura Scapy en interfaz. | Añadió parámetro `formato_modelo=True` para inferencia por lotes compatible. | Migración a `AsyncSniffer` concurrente en Fase 4. |
| [`src/data.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/data.py) | Carga y respaldo de datos. | Integrado con el contrato; generador sintético con ruido gaussiano y warning explícito. | Cargador principal de `data/dataset_lab.csv`. |
| [`src/preprocess.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/preprocess.py) | Normalización y partición. | Uso de `ETIQUETA` del contrato y split estratificado estandarizado. | Integración con pipelines y validación por grupos. |
| [`src/models.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/models.py) | Clasificadores RF y XGBoost. | Manejo de desbalance (`class_weight`, `scale_pos_weight`), blindaje monoclase (`labels=[0, 1]`), ROC-AUC y guardado de artefactos completos (`.joblib` con scaler y columnas). | Tuning (`RandomizedSearchCV`), curvas PR y explicabilidad SHAP. |
| [`src/attack_simulator.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/attack_simulator.py) | Banco de perturbaciones. | Base de perturbación paramétrica para pruebas preliminares. | Rediseño hacia evasión activa (black-box/white-box) en Fase 3. |
| [`src/pipeline.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/pipeline.py) | Orquestador Algoritmo 1. | Inferencia con adaptación de huella cruda y ejecución experimental completa. | Conexión con mitigación activa en laboratorio (`ebtables`). |

---

### 3.2. Fase 1: Laboratorio Virtual y Procesamiento de Red (`scripts/`)

#### A. [`scripts/lab/generar_trafico.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/scripts/lab/generar_trafico.py)
* **¿Qué hace?**  
  Genera tráfico representativo de redes locales TCP/IP sin requerir privilegios de superusuario (`root`), escribiendo directamente los paquetes estructurados a archivos `.pcap` mediante Scapy.
* **Aspectos técnicos sobresalientes:**
  * **6 Escenarios caracterizados (OE1):**
    1. `benigno`: Mezcla realista de tráfico HTTP (payloads variables, puertos efímeros), DNS (consultas y respuestas a resolvedores estándar), ARP (resolución periódica legítima) e ICMP (mensajes de eco).
    2. `arp_spoofing` (Capa de Enlace / 2): Emisión masiva de respuestas ARP gratuitas (`is-at`) falsificadas para envenenar la tabla de vecinos.
    3. `mac_flooding` (Capa de Enlace / 2): Ráfagas con miles de MACs aleatorias generadas por segundo para saturar la tabla CAM de los switches.
    4. `syn_flood` (Capa de Transporte / 4): Inundación de segmentos TCP con bandera SYN activa dirigidos a un servidor de destino.
    5. `port_scan` (Capa de Transporte / 4): Escaneo horizontal y vertical de puertos con secuencias incrementales y banderas SYN/ACK.
    6. `dns_spoofing` (Capa de Aplicación / 7): Respuestas DNS no solicitadas que alteran registros de nombres hacia IPs ilegítimas.
  * **Mecanismo Anti-Fuga (Anti-Leakage):** En cada episodio de ataque, la dirección MAC del atacante rota deliberadamente. De este modo, los clasificadores de Machine Learning **no memorizan la MAC**, sino la huella conductual: volumen de tramas por ventana, variabilidad del $\Delta t$, entropía de puertos y ratio de broadcast.

#### B. [`scripts/pcap_to_features.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/scripts/pcap_to_features.py)
* **¿Qué hace?**  
  Lee archivos de captura `.pcap`, agrupa las tramas por dispositivo (`mac_origen`) dentro de ventanas temporales configurables (e.g. 5 segundos) y calcula las métricas requeridas por el contrato.
* **Métricas calculadas:**
  * **Capa 2 (IEEE 802.3):** `longitud_trama`, `tiempo_entre_tramas_ms`, `oui_frecuente`, `longitud_trama_media`, `longitud_trama_std`, `iat_media_ms`, `iat_std_ms`, `tasa_broadcast`, `tasa_arp`, `entropia_ethertype`, `oui_encoded`.
  * **Capas 3-4 (Flujo):** `num_conexiones_por_min`, `tasa_syn`, `entropia_puertos_destino`.
  * **Control de Evaluación:** Atributo `grupo` (clave compuesta `MAC_ventana_timestamp`), esencial para particiones mediante `StratifiedGroupKFold`.

#### C. [`scripts/lab/generar_dataset_lab.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/scripts/lab/generar_dataset_lab.py)
* **¿Qué hace?**  
  Orquesta de extremo a extremo la Fase 1: ejecuta la síntesis de los 6 escenarios a archivos `.pcap` en `data/pcap/` y luego invoca el extractor para producir el archivo final consolidado [`data/dataset_lab.csv`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/data/dataset_lab.csv).

---

## 4. Evidencia Experimental del Dataset Generado

El dataset [`data/dataset_lab.csv`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/data/dataset_lab.csv) fue analizado exhaustivamente:

### 4.1. Distribución de Muestras y Clases

| Métrica / Dimensión | Valor Obtenido | Observación |
|---|---|---|
| **Total de Registros (Ventanas)** | **3.317** | Muestras independientes agregadas por ventana de 5 segundos. |
| **Tráfico Legítimo (`etiqueta=0`)** | **1.548** (46.7%) | Tráfico benigno continuo de fondo. |
| **Tráfico Malicioso (`etiqueta=1`)** | **1.769** (53.3%) | Balance casi perfecto (53/47), ideal para entrenamiento equilibrado. |
| **Archivos PCAP Crudos** | 6 archivos en `data/pcap/` | 11 MB totales de capturas de red generadas. |

### 4.2. Distribución por Tipo de Ataque y Capa TCP/IP (OE1)

```text
Distribución por Ataque:
├── Benigno:          1.548 muestras
├── DNS Spoofing:       385 muestras  (Capa de Aplicación)
├── Port Scan:          365 muestras  (Capa de Transporte)
├── ARP Spoofing:       362 muestras  (Capa de Enlace / 802.3)
├── MAC Flooding:       337 muestras  (Capa de Enlace / 802.3)
└── SYN Flood:          320 muestras  (Capa de Transporte)

Distribución por Capa:
├── Ninguna (Benigno): 1.548 muestras
├── Enlace (Capa 2):     699 muestras  (21.1%)
├── Transporte (Capa 4): 685 muestras  (20.6%)
└── Aplicación (Capa 7): 385 muestras  (11.6%)
```

### 4.3. Validación Anti-Fuga de Información
Al evaluar la importancia de variables con división por grupo (`StratifiedGroupKFold`):
* `tiempo_entre_tramas_ms` se posiciona como el atributo más discriminante (**0.54** de importancia en árboles).
* La dependencia artificial de `oui_frecuente` se redujo drásticamente de **0.50 a 0.24**, demostrando que el modelo aprende el **comportamiento temporal y dinámico de la trama IEEE 802.3**, no la identidad estática del atacante.

---

## 5. Control de Calidad: Suite de Pruebas (27/27 Pasadas)

La suite de pruebas automatizadas en [`tests/`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/tests/) valida rigurosamente cada componente:

```text
============================= test session starts ==============================
rootdir: /home/nikka/Documentos/FRED/ids-proyecto/ids_project
configfile: pyproject.toml
testpaths: tests

tests/test_data.py::test_generar_dataset_sintetico_dimensiones PASSED           [  3%]
tests/test_data.py::test_generar_dataset_sintetico_reproducibilidad PASSED      [  7%]
tests/test_data.py::test_generar_dataset_sintetico_tiene_dos_clases PASSED      [ 11%]
tests/test_data.py::test_cargar_dataset_inexistente_retorna_sintetico PASSED    [ 14%]
tests/test_feature_schema.py::test_columnas_modelo_definidas PASSED             [ 18%]
tests/test_feature_schema.py::test_validar_esquema_exitoso PASSED               [ 22%]
tests/test_feature_schema.py::test_validar_esquema_columna_faltante PASSED      [ 25%]
tests/test_feature_schema.py::test_mapear_huella_a_vector_modelo PASSED         [ 29%]
tests/test_fingerprint.py::test_extraer_huella_basica PASSED                    [ 33%]
tests/test_fingerprint.py::test_extraer_sin_capa_enlace PASSED                  [ 37%]
tests/test_fingerprint.py::test_delta_tiempo_entre_tramas_misma_mac PASSED      [ 40%]
tests/test_fingerprint.py::test_distincion_802_3_vs_ethernet_ii PASSED          [ 44%]
tests/test_fingerprint.py::test_conversion_a_vector_modelo PASSED               [ 48%]
tests/test_fingerprint.py::test_oui_a_entero PASSED                             [ 51%]
tests/test_generar_trafico.py::test_escenarios_producen_tramas PASSED           [ 55%]
tests/test_generar_trafico.py::test_benigno_es_etiqueta_0 PASSED                [ 59%]
tests/test_generar_trafico.py::test_ataques_usan_mac_variada_por_episodio PASSED[ 62%]
tests/test_generar_trafico.py::test_escenario_desconocido_lanza_error PASSED    [ 66%]
tests/test_models.py::test_entrenamiento_y_evaluacion_rf PASSED                 [ 70%]
tests/test_models.py::test_evaluar_con_una_sola_clase PASSED                    [ 74%]
tests/test_models.py::test_guardar_artefacto_completo PASSED                    [ 77%]
tests/test_pcap_to_features.py::test_procesar_pcap_cumple_contrato PASSED        [ 81%]
tests/test_pcap_to_features.py::test_dispositivo_escaneo_tiene_mayor_entropia_puertos PASSED [ 85%]
tests/test_pcap_to_features.py::test_pcap_inexistente_lanza_error PASSED        [ 88%]
tests/test_pipeline.py::test_inferir_desde_huella_cruda_incompleta PASSED        [ 92%]
tests/test_preprocess.py::test_dividir_proporciones PASSED                      [ 96%]
tests/test_preprocess.py::test_escalador_ajuste_y_transformacion PASSED         [100%]

============================== 27 passed in 6.63s ==============================
```

---

## 6. Hoja de Ruta: Hacia la Fase 2 (Modelado Serio y Diagnóstico)

Con el dataset [`data/dataset_lab.csv`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/data/dataset_lab.csv) generado y verificado, las siguientes actividades inmediatas son:
1. **Entrenamiento y Comparación Rigurosa:** Entrenar Random Forest y XGBoost usando validación cruzada agrupada (`StratifiedGroupKFold`) con 5 folds y múltiples semillas para calcular intervalos de confianza al 95%.
2. **Estudio de Ablación:** Comparar el desempeño del modelo usando solo variables de flujo (capas 3-4) vs. el modelo completo (capa 2 + capas 3-4), demostrando formalmente el valor de la huella IEEE 802.3.
3. **Curvas ROC y PR:** Trazar las curvas de rendimiento y calcular ROC-AUC y PR-AUC.
4. **Diagnóstico con SHAP:** Extraer la importancia de características para documentar el comportamiento explicable del IDS.
