# CONTEXT_UPGRADE.md — Auditoría del proyecto y plan de mejora

> Documento para traspaso a otro modelo/agente. Objetivo: que valide la factibilidad
> de lo propuesto aquí y arranque la construcción. Fecha de auditoría: 2026-10-21.
> Autor del proyecto: Nicolás Martínez Pineda (U. Distrital Francisco José de Caldas,
> asignatura Fundamentos de Redes y Comunicación).

---

## 1. Objetivos del proyecto (fuente de verdad)

**General:** prototipo de IDS basado en IA que identifique en tiempo real la huella digital
de dispositivos conectados vía IEEE 802.3 y clasifique tráfico malicioso en las capas TCP/IP,
en entornos de red simulados.

**Específicos:**
1. **OE1** — Caracterizar vectores de ataque/vulnerabilidades por capa TCP/IP e ISO/OSI
   (revisión técnica/documental) para fijar criterios de diseño.
2. **OE2** — Módulo de huella digital en tiempo real basado en parámetros IEEE 802.3, integrado
   con Random Forest y XGBoost entrenados sobre un dataset de referencia en ciberseguridad;
   distingue tráfico legítimo vs. malicioso.
3. **OE3** — Evaluar desempeño y capacidad de defensa simulando un ataque dirigido a la huella
   digital; comparar RF vs. XGBoost con precisión, sensibilidad y FPR; generar **diagnóstico,
   mecanismos de mitigación y pronóstico** del comportamiento anómalo.

## 2. Estado actual (qué existe)

Proyecto Python de ~250 líneas, 56 KB, sin git, sin tests, sin dataset real.

```
src/capture.py          sniff() de Scapy -> DataFrame de huellas
src/fingerprint.py      ExtractorHuellaDigital (MAC, OUI, longitud, ethertype, Δt)
src/data.py             CSV real (CICIDS) o dataset SINTÉTICO de respaldo
src/preprocess.py       split estratificado + StandardScaler
src/models.py           RF(200) y XGB(200, depth 6) + métricas + joblib
src/attack_simulator.py spoofing simulado (perturba features de tráfico legítimo)
src/pipeline.py         inferir() por trama + ejecutar_experimento_completo()
notebooks/…ipynb        duplica casi todo el código de src/ (7 fases CRISP-DM)
```

**Verificado ejecutando** `python -m src.pipeline` (copia aislada, venv con sklearn/xgboost):
corre de punta a punta, pero con resultados que **no significan nada** (ver §3.1 y §3.2):

| Modelo | acc | prec | recall | f1 | FPR |
|---|---|---|---|---|---|
| Random Forest | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |
| XGBoost | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 |

Detección "bajo ataque": RF 0.153, XGB 0.154.

## 3. Veredicto

**La estructura de carpetas/módulos está bien** (separación captura → huella → preproceso →
modelo → ataque → orquestador mapea limpio al Algoritmo 1 y a la Fig. 1). **El contenido
técnico no cumple todavía los objetivos**: hoy es un esqueleto que ejecuta, no un prototipo que
demuestre OE2 ni OE3. Hay un problema de diseño de fondo (§3.1) que invalida la cadena completa
si no se resuelve antes de seguir.

### 3.1 CRÍTICO — La "huella 802.3" no está conectada con los modelos

- `fingerprint.py` extrae: `mac_origen, oui, longitud_trama, ethertype, tiempo_entre_tramas_ms`.
- Los modelos consumen: `longitud_trama, tiempo_entre_tramas_ms, num_conexiones_por_min,
  tasa_syn, entropia_puertos_destino, oui_frecuente`.
- **Tres de las seis features (`num_conexiones_por_min`, `tasa_syn`, `entropia_puertos_destino`) son
  de flujo/capa 3-4 y el extractor de huella nunca las produce.** `capture.py` devuelve un
  DataFrame que no es compatible con `inferir()` (faltan columnas; además trae `mac_origen`,
  `oui` str y `ethertype` que el modelo no espera). Es decir: **no hay camino en vivo funcional**.
- `oui_frecuente` en sintético es ruido uniforme (0–49) sin relación con la etiqueta; el RF le
  da importancia 0.009 (verificado; `tasa_syn` 0.49 y `entropia_puertos_destino` 0.47 explican
  casi todo; clase maliciosa ≈ 9 % del dataset). Así que, tal cual, **la huella 802.3 no aporta nada al clasificador** — que
  es justo la tesis del proyecto.
- **CICIDS2017/2018 (CICFlowMeter) no contiene MAC, OUI ni campos Ethernet.** Son features de
  flujo (Flow Duration, Fwd Packet Length, SYN Flag Count, IAT…). No se puede entrenar un
  modelo de "huella 802.3" con CICIDS tal cual; la columna `oui_frecuente` no existe en él.
  `cargar_dataset()` además exige columnas con nombres propios (`tasa_syn`, …) que ningún dataset
  público trae: falta una capa de mapeo/ingeniería de features.

**Decisión de diseño pendiente (bloqueante).** Opciones:
- **A (recomendada, alineada con "entornos simulados"):** generar el dataset propio en un
  laboratorio virtual (Mininet / GNS3 / namespaces + Scapy), con dispositivos de OUI/ritmos
  conocidos, tráfico benigno y ataques reales a escala (ARP spoofing, MAC flooding/spoofing,
  SYN flood, port scan, DNS spoof), capturado en pcap y etiquetado por escenario. Aquí sí existe
  huella 802.3 real y se cumple OE2 de forma honesta.
- **B:** usar CICIDS para el componente de flujo (capas 3-4, OE1/OE2 "dataset de referencia")
  y un dataset propio/pcap para la huella 802.3; modelo de dos etapas o features concatenadas
  por ventana temporal. Más fiel al enunciado ("dataset de referencia") pero más trabajo.
- **C:** usar un dataset que sí traiga capa 2 (p. ej. datasets de IoT con MAC como
  *UNSW-IoT/IoT Sentinel/CIC IoT 2023*, o *CIC-IDS-2017 pcaps crudos* re-procesados con Scapy
  para extraer MAC/ethertype por flujo). Los PCAP de CICIDS2017 sí traen Ethernet.

→ El modelo que reciba este doc debe **elegir una opción y justificarla** antes de escribir código.

### 3.2 CRÍTICO — Los resultados actuales son tautológicos

- `etiqueta` en el sintético es función **determinista** de tres features
  (`score>=2` sobre umbrales). Árboles recuperan esa regla exacta → 100% en todo, FPR 0.
  Cualquier comparación RF vs. XGB sobre esto no tiene valor científico.
- El dataset sintético es i.i.d. uniforme, balanceo ~sin ruido; no hay solapamiento de clases,
  desbalance (en IDS real suele ser 80/20 o peor), ni deriva.
- **Mínimo para que sea defendible:** datos reales (opción A/B/C), ruido/solapamiento, split
  que evite fuga (por sesión/ventana temporal o por dispositivo, no aleatorio por fila),
  validación cruzada, intervalos de confianza o varias semillas.

### 3.3 CRÍTICO — El simulador de ataque no mide "capacidad de defensa"

- `simular_ataque_spoofing` toma tráfico **legítimo**, lo perturba y **asume que debería marcarse
  malicioso** (`y_esperado = 1`). Un ataque de huella real es lo contrario: un **atacante
  malicioso intenta parecer un dispositivo legítimo (evasión)**. La métrica correcta es: de las
  muestras maliciosas perturbadas para imitar una huella legítima, ¿cuántas siguen detectadas
  (recall bajo evasión) y cuánto cae vs. recall limpio?
- Además la perturbación solo es una distorsión sobre features que el modelo usa (tasa_syn +0.3–0.6
  empuja hacia la zona maliciosa por construcción). El 0.15 de "detección" no tiene interpretación.
- Falta modelar: **spoofing de MAC/OUI** (clonar la MAC de un dispositivo legítimo conocido),
  **jitter de tiempos** para imitar el patrón de otro dispositivo, **replicar longitud de tramas**.
  Y distinguir *atacante con conocimiento del modelo (white-box)* de *sin conocimiento (black-box)*.
- Además, de existir un módulo de **identificación de dispositivo** (fingerprinting), el ataque
  correcto es "dispositivo X suplanta a Y": ¿lo detecta el sistema como identidad inconsistente?
  Hoy **no existe un modelo que identifique el dispositivo**; solo hay clasificador binario
  malicioso/legítimo. El enunciado ("identificar la huella digital de los dispositivos") pide
  además una **capa de identificación/autenticación de dispositivo** (baseline por MAC/OUI +
  similitud de huella, o clasificador multiclase por dispositivo) que hoy falta.

### 3.4 Alto — Bugs / deficiencias en el código

| Dónde | Problema |
|---|---|
| `fingerprint.py:33,46` | `defaultdict(lambda: time.time())` + `time.time()` en el callback: Δt se mide con el **reloj de procesamiento**, no con `paquete.time` (timestamp real de captura). Distorsiona el tiempo entre tramas y hace que la primera trama de cada MAC dé Δt≈0. Usar `float(paquete.time)` y `None`/NaN en la primera. |
| `fingerprint.py:57` | Para tramas IEEE 802.3 (LLC) el campo `type` es **longitud**, no EtherType (≤1500). No se distingue 802.3 de Ethernet II. Tampoco se capturan campos propios de 802.3/802.2: LLC/SNAP (DSAP/SSAP), VLAN 802.1Q, longitud vs. tipo, padding, FCS. |
| `fingerprint.py:62-69` | `oui_a_entero` hace `int(oui,16) % 1000` → colisiona OUIs distintos y no se usa en ningún lado. Un OUI es categórico: usar tabla IEEE OUI + frecuencia/target encoding, no módulo. |
| `fingerprint.py` | Huella = 1 trama. Una huella útil es **por dispositivo y ventana** (estadísticos agregados: media/var/percentiles de longitud e IAT, distribución de ethertypes, tasa ARP, broadcast ratio…). Además no hay estado por-dispositivo persistente (baseline). |
| `capture.py:38` | `sniff(count, timeout)` bloquea y devuelve lote: **no es "tiempo real"**. Falta bucle streaming (`AsyncSniffer`/cola + hilo de inferencia), manejo de Ctrl-C, filtro BPF, y alimentar `inferir()`. |
| `pipeline.py:40-48` | `inferir()` espera dict con las 6 columnas del modelo; el extractor no las produce (ver §3.1). `registrar_alerta`/`aplicar_mitigacion` solo loguean; **mitigación no implementada** (OE3). |
| `pipeline.py:27` | `logging.basicConfig` a nivel de módulo en import (efecto secundario). |
| `pipeline.py:85-96` | `ejecutar_experimento_completo` hace todo en una función, no devuelve métricas serializables ni persiste el `scaler`/`columnas` (solo guarda los dos modelos). **No se puede reconstruir la inferencia en otro proceso** sin scaler → modelos guardados son inutilizables en vivo. |
| `preprocess.py` | StandardScaler innecesario para RF/XGB (árboles invariantes a escala); inofensivo pero oculta que deben tratarse categóricas (OUI) y NaN. No hay manejo de infinitos/NaN (CICIDS trae `inf`/`NaN` en Flow Bytes/s etc.), duplicados, ni selección de features. |
| `models.py` | Sin `class_weight`/`scale_pos_weight` para desbalance; sin tuning; sin ROC-AUC/PR-AUC (más informativas que accuracy en IDS); `confusion_matrix().ravel()` revienta si el test tiene una sola clase (ocurre justo en la evaluación bajo ataque con y todo =1 → se salva solo por `labels` implícitos; frágil: pasar `labels=[0,1]`). |
| `data.py:54` | `except FileNotFoundError` cae silenciosamente a sintético: **un experimento "real" puede correr con datos falsos sin avisar**. Debe ser explícito (`--sintetico`) y los resultados deben etiquetarse como tales. |
| `requirements.txt` | Sin versiones fijadas, sin `matplotlib` (el notebook lo usa), sin `pytest`. `scapy` no instalado por defecto en el entorno actual. |
| Repo | Sin git, sin tests, sin `pyproject`/`Makefile`, sin CI. El **notebook duplica código** de `src/` (viola DRY y divergirá: p.ej. su extractor no calcula Δt y el de `src/` sí). Debe importar de `src/`. |
| README | `data/cicids2017_procesado.csv` se presenta como "placeholder" pero no existe y no hay script que lo produzca. |

### 3.5 Medio — Cobertura de objetivos (matriz de trazabilidad)

| Objetivo | Estado | Falta |
|---|---|---|
| OE1 caracterización de vectores por capa | ⚠️ Solo una tabla de 4 filas en el notebook | Documento/tabla completa por capa (Enlace→Aplicación, TCP/IP y OSI), mapeo vector→feature observable→detectable con la huella. Es entregable documental, hay que escribirlo. |
| OE2 huella en tiempo real | ❌ Parcial | Streaming, features por ventana, identificación de dispositivo, integración extractor→modelo, dataset coherente (§3.1). |
| OE2 RF + XGBoost sobre dataset de referencia | ⚠️ Código listo, datos no | Dataset real y pipeline de features. |
| OE3 simulación de ataque a la huella | ❌ Mal planteado | Rediseñar como evasión/suplantación (§3.3). |
| OE3 métricas (precisión, sensibilidad, FPR) | ✅ Implementadas | Añadir AUC, curva ROC/PR, matriz de confusión, CV, significancia. |
| OE3 **diagnóstico** | ❌ Solo texto "completar" | Análisis automático de errores (qué ataques se pierden, importancia de features, por qué). |
| OE3 **mitigación** | ❌ Solo `logger.info` | Implementar acciones: lista de bloqueo por MAC/OUI, cuarentena simulada (en lab: `iptables`/`ebtables`/regla OpenFlow o simulación en el pipeline), umbrales, política de severidad. |
| OE3 **pronóstico** del comportamiento anómalo | ❌ No existe | Serie temporal de tasa de alertas/anomalía por ventana + modelo simple (ARIMA/Holt-Winters/Prophet o regresión sobre ventanas) con evaluación (MAE/MAPE); requiere tráfico con dimensión temporal continua. |
| Tiempo real | ❌ | Medir latencia por trama/ventana y throughput (métrica de aceptación, p.ej. <50 ms/ventana). |
| "Clasificar en las distintas capas del modelo TCP/IP" | ❌ | El clasificador es binario. Falta clasificación **multiclase** (tipo de ataque → capa: enlace/red/transporte/aplicación) o al menos reportar por-ataque. |
| Reproducibilidad / documentación | ⚠️ | Tests, semillas, versiones, scripts de generación de datos. |

## 4. Lo que SÍ está bien (conservar)

- Modularización y nombres alineados al artículo (Fig. 1 / Algoritmo 1). Buena base.
- Semilla global (`RANDOM_STATE`), split estratificado, métricas FPR/recall bien calculadas.
- Comentarios con trazabilidad a fases del documento; README honesto en pendientes.
- Persistencia con joblib (completar con scaler/columnas/metadata).
- Elección RF + XGBoost es la correcta según el enunciado; hiperparámetros base razonables.

## 5. Plan de construcción propuesto (para validar factibilidad)

**Fase 0 — Decisiones y andamiaje (1-2 días)**
1. Elegir estrategia de datos A/B/C (§3.1) y justificar (factibilidad de laboratorio, tiempo, GB).
2. `git init`, `pyproject.toml`/`requirements.txt` con versiones, `pytest`, `ruff`, estructura
   `src/ids/…`, `tests/`, `scripts/`, `docs/`. Notebook pasa a importar de `src/`.
3. Definir **esquema de features** único (contrato) compartido por captura, entrenamiento e inferencia.

**Fase 1 — Datos reales (núcleo)**
4. Laboratorio simulado reproducible (Mininet o netns + Scapy/hping3/ettercap/arpspoof/nmap) con
   scripts que generen pcap benigno y por cada ataque (ARP spoofing, MAC spoofing/flooding,
   SYN flood, port scan, DNS spoof, DDoS ligero), etiquetados por escenario y capa.
5. `scripts/pcap_to_features.py`: pcap → ventanas de N s por dispositivo (MAC) → features
   802.3 (ethertype/long, IAT stats, broadcast ratio, ARP rate, VLAN…) + features de flujo
   (SYN rate, entropía de puertos, conexiones/min). Salida CSV/Parquet con etiqueta, capa, tipo.
6. (Si opción B/C) importar CICIDS2017/2018 y/o pcaps, mapear columnas, limpiar inf/NaN.

**Fase 2 — Modelado serio**
7. Split por escenario/sesión (sin fuga), `StratifiedGroupKFold`, desbalance (`class_weight`,
   `scale_pos_weight`), `RandomizedSearchCV`, métricas + ROC/PR-AUC, multi-seed con media±IC.
8. Modelos: (a) binario legítimo/malicioso; (b) multiclase tipo/capa de ataque;
   (c) módulo de **identificación de dispositivo** (baseline por MAC + clasificador/embedding
   de huella; alerta si la huella de una MAC conocida diverge).
9. Importancia de features (SHAP/permutación) → **diagnóstico** y prueba de que la huella 802.3
   aporta (ablación: con vs. sin features de capa 2).

**Fase 3 — Ataque a la huella (OE3)**
10. Simulador de evasión/suplantación: MAC clonada, jitter/longitud imitando dispositivo legítimo,
    black-box vs. white-box (ZOO/HopSkipJump o perturbación dirigida de features alcanzables).
    Métrica: recall limpio vs. recall bajo ataque, ΔFPR, tasa de evasión exitosa. Reentrenamiento
    adversarial como defensa y comparación.

**Fase 4 — Tiempo real + mitigación + pronóstico**
11. Captura streaming (AsyncSniffer + cola + ventanas deslizantes) → modelos persistidos
    (con scaler/columnas/versión) → alertas; medir latencia y throughput.
12. Mitigación: política configurable (log → alerta → bloqueo MAC/OUI → cuarentena), implementada
    en el lab (ebtables/iptables o regla OVS) y como simulación en tests.
13. Pronóstico: serie temporal de alertas/score por ventana + forecast (Holt-Winters/ARIMA/
    Prophet) con backtesting.

**Fase 5 — Entregables**
14. Informe OE1 (vectores por capa), tablas RF vs. XGB, figuras (ROC, confusión, importancias,
    latencia), `README` reproducible (`make data`, `make train`, `make eval`, `make live`).

## 6. Criterios de aceptación sugeridos

- Dataset con ≥ N muestras por clase y ≥ K tipos de ataque en ≥ 3 capas; sin fuga entre train/test.
- RF y XGB reportan accuracy, precision, recall, F1, **FPR**, ROC-AUC con IC (≥5 semillas/folds).
- Ablación demostrando aporte (o ausencia de aporte, reportado honestamente) de la huella 802.3.
- Evasión simulada: recall bajo ataque documentado frente a limpio, y efecto de la defensa.
- Streaming funcionando en el lab con latencia por ventana medida.
- Mitigación ejecutada (aunque sea sobre red simulada) y pronóstico con error de backtesting.
- ≥ tests unitarios de extractor, preprocesado, `inferir`, evaluación y simulador.

## 7. Riesgos / preguntas abiertas para el siguiente modelo

1. **Permisos y entorno:** ¿hay laboratorio con interfaces reales / permiso para Mininet y captura
   con root? (el código dice "laboratorio de la asignatura"). Si no, ¿se acepta pcap sintético
   generado con Scapy?
2. **Alcance de "huella digital":** ¿dispositivo identificado por patrón de tramas (fingerprinting
   pasivo) o simple MAC/OUI? Si es solo MAC, el spoofing de MAC la rompe trivialmente → el valor
   del proyecto depende de usar patrones temporales/longitud, no el identificador.
3. **"Dataset de referencia":** ¿el docente exige CICIDS específicamente o basta con uno de
   referencia + dataset propio? Esto decide la opción A/B/C.
4. **Tiempo real:** ¿qué latencia/throughput se considera cumplido en una red simulada?
5. **Volumen:** CICIDS2017 completo ≈ 50 GB de pcap / ~1 GB CSV; confirmar almacenamiento.
6. Sin control de versiones actualmente; hacer `git init` antes de modificar nada.

## 8. Hallazgos por archivo (referencia rápida)

- `src/data.py:44` etiqueta determinista → resultados 1.0 (§3.2). `:54` fallback silencioso.
- `src/attack_simulator.py:21-25` perturbación sobre features que definen la etiqueta; `y_esperado=1` sobre tráfico legítimo.
- `src/fingerprint.py:33,46,57,62-69` reloj incorrecto, 802.3 vs Ethernet II, OUI mod 1000.
- `src/capture.py:38` captura por lotes, no streaming; salida incompatible con modelo.
- `src/pipeline.py:40-48,85-87` mitigación vacía; scaler no persistido; `inferir` acoplado a columnas inexistentes en vivo.
- `src/models.py:41` `ravel()` frágil con una sola clase; sin AUC ni class_weight.
- `src/preprocess.py` escalado innecesario, sin limpieza de NaN/inf/categóricas.
- `notebooks/…ipynb` duplica `src/`; extractor distinto al de `src/`.
- Raíz: sin git, tests, versiones, matplotlib en requirements.
