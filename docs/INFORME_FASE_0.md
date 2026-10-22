# Informe de Avance Técnico: Fase 0 — Decisiones, Andamiaje y Contrato de Características

**Proyecto:** Sistema de Detección de Intrusiones (IDS) en Redes TCP/IP mediante Huella Digital de Dispositivos en el Protocolo IEEE 802.3 usando Inteligencia Artificial  
**Autor:** Nicolás Martínez Pineda  
**Institución:** Universidad Distrital Francisco José de Caldas  
**Asignatura:** Fundamentos de Redes y Comunicación  
**Docente:** Octavio José Salcedo Parra  
**Fecha:** Octubre 2026  
**Fase:** Fase 0 — Decisiones Técnicas y Andamiaje Arquitectónico  

---

## 1. Resumen Ejecutivo del Avance

Durante la auditoría inicial del proyecto ([`CONTEXT_UPGRADE.md`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/CONTEXT_UPGRADE.md)) se identificó que, si bien la estructura modular inicial (`src/`) era conceptualmente acertada, existían **bloqueantes de diseño críticos**:
1. La huella digital física/enlace (IEEE 802.3) estaba desacoplada de los modelos de Machine Learning (las variables extraídas no coincidían con las esperadas por el clasificador).
2. El dataset de respaldo era determinista, produciendo métricas tautológicas del 100%.
3. El código no contaba con control de versiones (Git), carecía de suite de pruebas (`tests/`), mantenía dependencias sin fijar y el notebook duplicaba código de `src/`.

La **Fase 0** resolvió estos problemas estructurales, dotando al proyecto de un andamiaje profesional, un **contrato formal de características**, correcciones en el cálculo de métricas de red y una suite de pruebas automatizadas, dejando el sistema listo para la captura e inyección de datos reales en la Fase 1.

---

## 2. Matriz de Estado: Antes vs. Después de la Fase 0

| Componente / Aspecto | Estado Inicial (Pre-Fase 0) | Estado Actual (Post-Fase 0) | Impacto / Beneficio |
|---|---|---|---|
| **Contrato de Características** | Inexistente. `fingerprint.py` producía campos de red (MAC, OUI, EtherType) y `models.py` consumía métricas de flujo (SYN, puertos). | Centralizado en [`src/feature_schema.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/feature_schema.py) con función adaptadora y validador. | Permite que el extractor alimente de forma real y directa a los modelos. |
| **Tiempo entre tramas ($\Delta t$)** | Calculado con `time.time()` (reloj del CPU al procesar). Primera trama arrojaba $\Delta t \approx 0$. | Calculado mediante `paquete.time` (timestamp real de llegada en la tarjeta de red). | Precisión en microsegundos y preservación de ritmos reales entre paquetes. |
| **Identificación de Protocolo** | No diferenciaba longitud de EtherType en tramas Ethernet. | Discrimina entre tramas IEEE 802.3 LLC ($\le 1500$) y Ethernet II ($\ge 1536$). | Rigor técnico con respecto al estándar IEEE 802.3 del artículo. |
| **Dataset de Prueba** | Regla determinista fija (`score >= 2`), produciendo 100% de precisión artificial. | Incorpora ruido gaussiano y solapamiento probabilístico. Alerta en log el uso de datos sintéticos. | Evita falsas expectativas y fuerza a los clasificadores a aprender fronteras de decisión. |
| **Evaluación de Modelos** | Frágil: `confusion_matrix().ravel()` fallaba ante lotes de prueba con una sola clase. | Blindado con `labels=[0, 1]`. Incorpora cálculo de ROC-AUC y balanceo (`class_weight`, `scale_pos_weight`). | Estabilidad numérica y reporte de métricas realistas ante desbalance. |
| **Persistencia de Modelos** | Solo guardaba el archivo `.joblib` del estimador (inútil sin el escalador ni la lista de columnas). | Módulo [`guardar_artefacto_completo()`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/models.py#L83-L97) (modelo + scaler + columnas + metadatos). | Despliegue en tiempo real autocontenido e inferencia reproducible. |
| **Cuaderno Jupyter** | Duplicaba funciones de `src/` (violando principio DRY). | Cuaderno refactorizado para importar directamente los módulos de `src/`. | Sincronización garantizada: cualquier cambio en `src/` se refleja en el notebook. |
| **Control de Calidad y Pruebas** | 0 pruebas automatizadas, sin Git. | Repositorio Git inicializado (`main`), `pyproject.toml`, `.gitignore`, 6 suites de prueba con `pytest`. | Trazabilidad de código y prevención de regresiones. |
| **Asistencia con IA** | Sin soporte para agentes. | Configurado [`CLAUDE.md`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/CLAUDE.md) y 10 skills en `.claude/skills/`. | Automatización de tareas de desarrollo con mínimo consumo de tokens. |

---

## 3. Desglose Módulo por Módulo: Adelantos y Proyección Futura

```
ids_project/
├── src/
│   ├── feature_schema.py   <-- [NUEVO] Contrato unificado de características
│   ├── fingerprint.py      <-- [ACTUALIZADO] Extractor de huella IEEE 802.3
│   ├── capture.py          <-- [ACTUALIZADO] Capturador Scapy con mapeo al modelo
│   ├── data.py             <-- [ACTUALIZADO] Carga y generación con contrato y ruido
│   ├── preprocess.py       <-- [ACTUALIZADO] Partición estratificada y escalado
│   ├── models.py           <-- [ACTUALIZADO] Clasificadores balanceados y artefactos
│   ├── attack_simulator.py <-- Base de simulación de perturbaciones
│   └── pipeline.py         <-- [ACTUALIZADO] Inferencia con adaptador y orquestación
```

---

### 3.1. `src/feature_schema.py` (Nuevo)

* **¿Qué hace?**  
  Es la piedra angular de la arquitectura. Establece la fuente única de verdad para las características que viajan a través de todo el sistema. Define [`COLUMNAS_MODELO`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/feature_schema.py#L39-L46) (`longitud_trama`, `tiempo_entre_tramas_ms`, `num_conexiones_por_min`, `tasa_syn`, `entropia_puertos_destino`, `oui_frecuente`).
* **¿Qué se adelantó en la Fase 0?**  
  * Creación desde cero del módulo.
  * Implementación de [`validar_esquema(df)`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/feature_schema.py#L49-L67), que comprueba integridad columnar antes de entrenar o inferir.
  * Implementación de [`mapear_huella_a_vector_modelo()`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/feature_schema.py#L69-L97), función adaptadora que convierte la salida cruda de captura en el vector exacto que esperan los algoritmos de IA.
  * Definición de `FEATURES_HUELLA_VENTANA` para la futura agregación estadística en ventanas de tiempo.
* **Aporte actual:**  
  Eliminó el desacople entre captura y modelo. Hizo posible que `inferir()` funcione con tramas en vivo.
* **Aporte a futuro:**  
  Permitirá en la Fase 1 realizar **estudios de ablación** (entrenar con y sin características de huella física) para demostrar empíricamente el valor del protocolo IEEE 802.3 frente a ataques de suplantación.

---

### 3.2. `src/fingerprint.py` (Actualizado)

* **¿Qué hace?**  
  Extrae la huella de enlace de cada trama Ethernet/802.3 que ingresa al sistema.
* **¿Qué se adelantó en la Fase 0?**  
  * **Corrección de $\Delta t$:** Se sustituyó `time.time()` por `paquete.time`. Si el paquete fue capturado en un archivo PCAP o por la tarjeta de red, se extrae el timestamp hardware/kernel con precisión de microsegundos, eliminando el sesgo introducido por el tiempo de CPU en Python.
  * **Distinción 802.3 vs Ethernet II:** Se implementó la lógica estándar según la norma IEEE: si el campo `type` es $\le 1500$, representa la longitud de carga útil de la trama IEEE 802.3; si es $\ge 1536$, es el EtherType (e.g. IPv4, ARP).
  * **Método `a_vector_modelo()`:** La dataclass `HuellaDigital` ahora puede autoconvertirse al esquema del modelo de forma nativa.
* **Aporte actual:**  
  Garantiza fidelidad física en las mediciones de red y coherencia con el artículo base.
* **Aporte a futuro:**  
  Servirá de base para el módulo de ventanas deslizantes (agregación por dispositivo en streaming) en la Fase 4.

---

### 3.3. `src/capture.py` (Actualizado)

* **¿Qué hace?**  
  Interfaz con el hardware de red y Scapy para capturar tráfico en interfaces físicas o virtuales (`eth0`, `lo`, `tap0`).
* **¿Qué se adelantó en la Fase 0?**  
  * Se agregó el parámetro `formato_modelo=True` en [`capturar_huellas()`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/capture.py#L15-L48).
  * Ahora puede entregar directamente DataFrames listos para inferencia por lotes, integrando el contrato de características.
* **Aporte actual:**  
  Permite capturas de prueba en laboratorio o sobre tráfico simulado sin scripts intermediarios de conversión.
* **Aporte a futuro:**  
  En la Fase 4 se extenderá a `AsyncSniffer` con colas concurrentes y ventanas de $N$ segundos para lograr captura en tiempo real continuo sin pérdida de paquetes.

---

### 3.4. `src/data.py` (Actualizado)

* **¿Qué hace?**  
  Gestiona la provisión de datos para entrenamiento y validación de los modelos.
* **¿Qué se adelantó en la Fase 0?**  
  * Se conectó directamente a `src.feature_schema` (eliminando constantes duplicadas).
  * Se rediseñó [`generar_dataset_sintetico()`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/data.py#L23-L46) introduciendo ruido gaussiano ($\mu=0, \sigma=0.15$) y límites de probabilidad realistas.
  * Se añadió un registro de advertencia explícito (`logger.warning`) cuando se utilizan datos sintéticos para evitar la ilusión de resultados reales en las métricas.
* **Aporte actual:**  
  Permite ejecutar pruebas del pipeline con un grado de dificultad estadístico no trivial.
* **Aporte a futuro:**  
  En la Fase 1 servirá para cargar el dataset etiquetado definitivo generado en el laboratorio virtual (`data/dataset_lab.csv`).

---

### 3.5. `src/preprocess.py` (Actualizado)

* **¿Qué hace?**  
  Acondiciona los datos antes de ingresarlos a los clasificadores mediante partición y normalización.
* **¿Qué se adelantó en la Fase 0?**  
  * Se unificó el uso de la constante `ETIQUETA` desde el contrato de características.
  * Se mantuvo la partición estratificada (`stratify=y`) para preservar la proporción de tráfico legítimo y malicioso.
* **Aporte actual:**  
  Asegura que las transformaciones numéricas aplicadas en el entrenamiento se conserven idénticas durante la prueba.
* **Aporte a futuro:**  
  En la Fase 2 incorporará pipelines con manejo de valores infinitos/NaN y selección de características avanzadas.

---

### 3.6. `src/models.py` (Actualizado)

* **¿Qué hace?**  
  Entrena, evalúa y almacena los clasificadores principales: Random Forest (Breiman, 2001) y XGBoost (Chen & Guestrin, 2016).
* **¿Qué se adelantó en la Fase 0?**  
  * **Manejo de desbalance:** Se incorporó `class_weight="balanced"` en Random Forest y cálculo dinámico de `scale_pos_weight` en XGBoost, permitiendo detectar ataques infrecuentes.
  * **Robustez en métricas:** Se parametrizó `confusion_matrix(y_test, y_pred, labels=[0, 1])`, evitando errores en ejecuciones donde el conjunto de prueba contenga solo una clase (como en la simulación de ataque).
  * **Métricas adicionales:** Se añadió cálculo de `roc_auc_score` con soporte de probabilidades.
  * **Persistencia Integral:** Se creó [`guardar_artefacto_completo()`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/models.py#L83-L97), empaquetando en un único archivo `.joblib`: el modelo, el escalador ajustado, los nombres de columnas y metadatos de versión/fecha.
* **Aporte actual:**  
  Genera modelos listos para producción e inferencia autónoma sin pérdida de preprocesamiento.
* **Aporte a futuro:**  
  En la Fase 2 alojará la búsqueda de hiperparámetros (`RandomizedSearchCV`), validación cruzada (`StratifiedGroupKFold`) y análisis de explicabilidad con valores SHAP.

---

### 3.7. `src/attack_simulator.py`

* **¿Qué hace?**  
  Simula la alteración maliciosa de huellas digitales en la red (suplantación de OUI, variación de tamaño de trama e inyección de banderas SYN).
* **Aporte actual:**  
  Sirve como banco de pruebas para evaluar la respuesta del clasificador ante datos fuera de distribución.
* **Aporte a futuro (Fase 3):**  
  Siguiendo el skill [`fix-attack-simulator`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/.claude/skills/fix-attack-simulator/SKILL.md), se rediseñará para evaluar **evasión real** (muestras maliciosas diseñadas deliberadamente para imitar la huella de un dispositivo benigno en escenarios de caja negra y caja blanca).

---

### 3.8. `src/pipeline.py` (Actualizado)

* **¿Qué hace?**  
  Orquesta todo el flujo (Algoritmo 1 del artículo científico), conectando desde la llegada de la trama hasta la respuesta de alerta y mitigación.
* **¿Qué se adelantó en la Fase 0?**  
  * Se adaptó [`inferir()`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/src/pipeline.py#L40-L57) para aceptar huellas crudas de enlace y auto-completar las características faltantes mediante el contrato.
  * Se actualizó la función `ejecutar_experimento_completo()` para reportar métricas con mayor rigor.
* **Aporte actual:**  
  Proporciona un comando ejecutable directo (`python3 -m src.pipeline`) para validar la salud de todo el proyecto de extremo a extremo.
* **Aporte a futuro (Fase 4):**  
  Conectará las alertas con el gestor de mitigación activo ([`src/mitigation.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/.claude/skills/add-mitigation/SKILL.md)) y el modelo de pronóstico temporal ([`src/forecast.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/.claude/skills/add-forecasting/SKILL.md)).

---

## 4. Infraestructura, Entorno y Pruebas Creadas

### 4.1. Suite de Pruebas Unitarias ([`tests/`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/tests/))
Se implementaron 6 módulos de prueba con `pytest` que verifican el cumplimiento de requisitos:
1. [`tests/test_feature_schema.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/tests/test_feature_schema.py): Valida la consistencia de columnas y la función adaptadora.
2. [`tests/test_fingerprint.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/tests/test_fingerprint.py): Prueba tiempos $\Delta t$, extracción de OUI y distinción IEEE 802.3 vs Ethernet II.
3. [`tests/test_data.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/tests/test_data.py): Verifica reproducibilidad de semillas y consistencia dimensional.
4. [`tests/test_preprocess.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/tests/test_preprocess.py): Comprueba proporciones del split y normalización.
5. [`tests/test_models.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/tests/test_models.py): Evalúa entrenamiento, manejo de matrices mono-clase y serialización de artefactos.
6. [`tests/test_pipeline.py`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/tests/test_pipeline.py): Prueba la inferencia unitaria de una trama en el pipeline.

### 4.2. Empaquetado y Configuración
* [`pyproject.toml`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/pyproject.toml): Configuración moderna de empaquetado Python con metadata del autor, requerimientos mínimos y directivas de `ruff` y `pytest`.
* [`.gitignore`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/.gitignore): Aislamiento de datasets (`.csv`, `.pcap`), modelos compilados (`.joblib`), entornos virtuales y cachés.
* [`docs/DATA_STRATEGY.md`](file:///home/nikka/Documentos/FRED/ids-proyecto/ids_project/docs/DATA_STRATEGY.md): Documento técnico de justificación de la Opción A (laboratorio virtual frente a CICIDS2017).

---

## 5. Próximos Pasos: Transición a la Fase 1

Con la Fase 0 cerrada, el andamiaje está listo para iniciar la **Fase 1 (Generación de Datos en Laboratorio Virtual)**:
1. **Topología de red simulada:** Diseñar el script de laboratorio en `scripts/lab/` (Mininet o Network Namespaces de Linux) con múltiples hosts y OUIs diferenciados.
2. **Generación de escenarios:**
   * Tráfico normal de fondo (HTTP, DNS, ARP, ICMP).
   * Escenarios de ataque etiquetados: ARP Spoofing (capa 2), MAC Flooding (capa 2), SYN Flood (capa 4), Escaneo de Puertos (capa 4).
3. **Conversor PCAP a Dataset:** Implementar `scripts/pcap_to_features.py` para construir el dataset consolidado `data/dataset_lab.csv`, sustituyendo definitivamente los datos sintéticos.
