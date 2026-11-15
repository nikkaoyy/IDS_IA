# Culminación de la implementación sintética — mejoras al documento inicial

> Complemento al anteproyecto `IDS_IA_NicolasMartinez_20241020098.pdf` (en esta misma carpeta).
> Recoge lo que **de verdad se diseñó, implementó y midió** en la culminación de la implementación
> **sintética** (laboratorio virtual, sin red física), y propone con qué sustituir o precisar las
> secciones VI (Diseño e implementación), VII (Resultados) y las conclusiones del documento inicial.
> Las cifras son reales y trazables en `reports/` y `docs/ESTADO.md` del repositorio. Lo que queda
> para el **laboratorio físico** se marca al final; eso lo completa el autor con el IDS en la red.

---

## 1. Mejoras respecto al documento inicial

El anteproyecto fijó correctamente los objetivos (OE1–OE3) y la metodología CRISP-DM. La
implementación obligó a precisar —y en algunos puntos a **corregir honestamente**— cinco decisiones
de diseño que en el documento quedaban genéricas. Cada cambio se registró antes de medir y está
trazado en los commits.

| Tema | Documento inicial | Lo que se hizo, y por qué |
|---|---|---|
| **Fuente de datos** | CICIDS2017/2018 + captura propia (V-C) | CICIDS **no contiene los campos IEEE 802.3** (MAC/OUI/ethertype, TTL, ventana TCP, IP-ID): no sirve para una huella de capa 2/pila. Se construyó un **generador sintético propio del laboratorio** (`scripts/lab/generar_trafico.py`) con **verdad terreno por trama**, ataques en instantes Poisson y fondo benigno realista, y un **holdout reservado** (sesiones 20–29) que nunca se abrió. El dataset quedó **congelado** (sha256 `7f06d099…a945`). |
| **Vector de huella** | MAC, OUI, longitud, ethertype, Δt (≈5 rasgos) | Se separó en dos contratos: (a) **ataques**: 52 columnas (esquema 3.0) de capa 2, ARP, TCP, DNS, ventanas largas de 60 s, globales de segmento y «respuestas sin petición»; (b) **identidad**: TTL, ventana TCP, firma de opciones, continuidad/salto de IP-ID y SEQ, en `src/identidad.py`, **fuera** del contrato de ataques para no contaminar el marcador. |
| **Simulador de ataque** | «Perturba la huella (MAC/OUI/longitud/tasa) en la tabla» | Perturbar columnas que son **agregados de ventana** es ficción: un atacante no escribe `iat_media_ms` en un paquete. Se reemplazó por perturbación **a nivel de pcap** (`scripts/lab/retemporizar.py`, que solo cambia `pkt.time` de tramas reales, con invariantes verificados) y por **generadores de suplantación** (clones de MAC, de pila, víctima apagada, contaminación). El `attack_simulator.py` original se dejó intacto pero **declarado no representativo**. |
| **Evaluación** | Exactitud, F1 y tasa de FP por ventana | Se evalúa por **episodio** (la unidad que decide), con **IC bootstrap**, **falsas alarmas por dispositivo-día** (presupuesto operativo) y **LOAO** (leave-one-attack-out) para medir transferencia a tipos no vistos. La vista por ventana queda solo como referencia. |
| **Alcance de OE3** | Diagnóstico, mitigación y pronóstico (genéricos) | Se implementaron los tres como módulos reales: **streaming** en vivo (`src/streaming.py`), **mitigación** escalable en dry-run (`src/mitigacion.py`) y **pronóstico** de la tasa de alertas (`src/pronostico.py`), y se añadió un eje que el documento no preveía: **evasión medida a nivel de pcap** (fase E4). |

---

## 2. Diseño e implementación (versión precisa)

La arquitectura de la Fig. 1 se mantiene, pero cada módulo tiene ahora una implementación concreta y
dos canales de detección en paralelo (clasificador de tráfico **y** huella de identidad), no uno.

### 2.1 Módulos reales

- **Captura (tiempo real).** `AsyncSniffer` → cola → `MotorStreaming` (`src/streaming.py`), con
  ventanas de 5 s, filtro BPF y parada limpia. CLI `scripts/captura_en_vivo.py` (en vivo con root, o
  reproducción offline de un pcap). Métricas de latencia y throughput por ventana.
- **Extracción de huella (ataques).** `src/ventanas.py` (`AgregadorVentanas`, incremental) produce
  las 52 columnas. El streaming usa **el mismo** agregador que el lote: paridad de features probada.
- **Preprocesado.** `src/preprocess.py`: escalador ajustado **solo con el benigno de train**
  (sin fuga).
- **Clasificación.** Random Forest y XGBoost (`src/models.py`), validación cruzada **anidada por
  sesión** (5×5), umbral elegido para **≤ 1 falsa alarma por dispositivo-día**.
- **Identidad del dispositivo** (canal nuevo, implícito en el OE2 original). `src/identidad.py`:
  perfil robusto de pila por equipo (**mediana y MAD**, alarma si z > 6), IP-ID juzgado **por
  flujo**, firma de opciones TCP, y un **vigilante IP→MAC** (`VigilanteIP`) que detecta conflicto y
  reasignación, y que además **lee ARP** (capa 2). Defensas: congelación en alerta, estado
  `no_confiable`, y la **tercera vía** de aprendizaje (adopción por persistencia exclusiva) que baja
  las falsas alarmas sin absorber el clon.
- **Mitigación.** `src/mitigacion.py`: política escalable `registro → alerta → bloqueo de MAC →
  cuarentena`, en **dry-run por defecto** (imprime el comando `ebtables`/VLAN, **no toca la red** sin
  un ejecutor explícito).
- **Pronóstico.** `src/pronostico.py`: serie de la tasa de alertas + Holt (suavizado exponencial
  doble; `statsmodels` opcional), con **aviso temprano** por tendencia y backtesting (MAE/MAPE).
- **Simulación/evasión.** Generadores propios congelados (clones 77000+, variación 78000+,
  suplantación 79000+, contaminación 80000+) y el re-temporizador, todos con pruebas de determinismo.

### 2.2 Flujo de inferencia (precisión del Algoritmo 1)

El Algoritmo 1 del documento (por trama) sigue siendo válido como vista conceptual, pero la decisión
real ocurre **por ventana de 5 s y por episodio**, con dos marcadores en paralelo:

```
trama → AgregadorVentanas → (al cerrar ventana)
        ├── fila de 52 columnas → preprocesar → P(malicioso) ≷ umbral(1 FA/disp-día)   [supervisado]
        └── tramas crudas → SeguidorIdentidad (perfil de pila) + VigilanteIP (IP→MAC)   [identidad]
   → OR de canales (reportado por separado y con su costo en FA) → mitigación (dry-run) + pronóstico
```

Parámetros fijados y reproducibles: `K_TRAMAS_ATAQUE = 2`, `VENTANA_CORTA_S = 5`, ventana larga de
60 s (12 cortas), `RANDOM_STATE = 42`, dataset congelado por sha256.

---

## 3. Discusión de resultados

Todos los números son del laboratorio sintético (sesiones de 15 min) y están en `reports/`. La
lectura honesta importa tanto como la cifra.

### 3.1 OE2 — el clasificador de tráfico detecta lo conocido, no lo nuevo

- XGBoost: **recall por episodio 0,894** [0,856, 0,936] a **0,89 FA/disp-día** (PR-AUC 0,989);
  Random Forest 0,878. Cumple el objetivo sobre el **catálogo conocido**.
- Pero en **LOAO** (tipo de ataque fuera del entrenamiento) el recall cae a **0,228** [0,168, 0,286].
  Y un detector entrenado **solo con benigno** (anomalías) da **0,185** a este presupuesto de FA.
- **Discusión:** confirma, con cifra, la premisa del anteproyecto (las firmas no anticipan el día
  cero) **y** acota la promesa de la IA: un clasificador de tráfico agregado tampoco detecta lo no
  visto por arte de magia. Lo poco que transfiere viene de contadores de **violación de protocolo**
  (respuestas sin petición), no de la huella 802.3 en sí.

### 3.2 OE1/OE2 — la huella de identidad es el aporte diferencial, con un límite claro

- Detecta clones que **cambian la pila**: ingenuo **0,975**, ritmo **1,000**, en segundos, a **0,38
  FA/disp-día** (tras juzgar el IP-ID por flujo; antes eran 16,19 por una señal mal diseñada).
- La víctima apagada (1,00) y la suplantación de IP (0,95) se detectan por el vínculo IP→MAC.
- **Donde se rompe:** el **clon de pila completa** (misma MAC, TTL, ventana, opciones, IP-ID y ritmo)
  se detecta solo en **0,20** de los episodios (0,325 en sesiones nuevas), y **únicamente** cuando la
  víctima usa un contador de IP-ID global (Windows, IoT); con Linux/macOS/Android, **0 de 47**.
- **Falsas alarmas con variación benigna realista** (actualización, VPN, dos pilas, descubrimiento):
  **826/disp-día**, sin que `no_confiable` las esconda (0,128 de las ventanas). La **tercera vía**
  (adopción por persistencia exclusiva + valores de construcción) las baja a **382** (−54 %, IC sin
  solape) **sin perder detección** (ritmo 1,000 → 0,975: un clon absorbido de 40). La mitad que queda
  es de un equipo con **dos pilas concurrentes**, que a nivel de huella es **indistinguible de un
  clon**: el límite de fondo del canal de identidad.
- **Contaminación del perfil:** con el clon presente durante el aprendizaje al 20 %, el perfil lo
  **absorbe** en el 80 % de los casos (la detección cae de 0,95 a 0,83). La fase de construcción no
  tiene defensa todavía.

### 3.3 OE3 — evasión, mitigación y pronóstico

- **Evasión a nivel de pcap (E4):** los ataques de **volumen** (syn/mac/scan/icmp) **pierden su
  efecto** antes de bajar por debajo del umbral de etiquetado (recall nunca < 0,5 a ninguna
  intensidad). El **ARP spoofing lento** sí se vuelve **invisible por construcción** para el
  supervisado (recall **1,000 → 0,000** al separar sus tramas 5 s) sin dejar de envenenar; el que lo
  sigue viendo no es un mejor clasificador de volumen sino el **vigilante de identidad IP→MAC**
  (1,000, con **0,0 FA/disp-día** sobre variación benigna).
- **Streaming (E5):** el motor en vivo reproduce el lote con **paridad de features probada**; en una
  sesión de prueba, 1014 ventanas, 62 alarmas de identidad, latencia media **0,011 ms** por ventana.
- **Mitigación (E6):** escala a bloqueo/cuarentena por ventana deslizante, en **dry-run** (comando
  `ebtables` correcto, registrado, no ejecutado).
- **Pronóstico (E6):** Holt sobre la tasa de alertas marca tendencia creciente y da **aviso temprano**
  antes de que se acumulen las alertas (backtesting MAE < 1 en una tendencia lineal).

### 3.4 Comparación RF vs XGBoost (lo que pedía OE3)

A igualdad de presupuesto (1 FA/disp-día), **XGBoost domina**: recall por episodio 0,894 vs 0,878 y
PR-AUC 0,989 vs 0,986, con **menos falsas alarmas** (0,89 vs 1,19/disp-día). La diferencia es
pequeña pero consistente entre semillas.

---

## 4. Conclusiones

1. El **prototipo software del IDS está completo (OE1–OE3), probado y reproducible** en el laboratorio
   sintético: captura en streaming, extracción de huella (52 columnas + identidad), clasificación
   RF/XGBoost, evasión medida, mitigación y pronóstico, con un cuaderno de cierre de punta a punta.
2. La **respuesta a la pregunta de investigación** es matizada y honesta: la IA sobre la huella 802.3
   **sí aporta** una capa de detección que las firmas no dan —identifica la **suplantación de
   identidad** de un dispositivo en segundos y con pocas falsas alarmas—, pero **no** convierte un
   clasificador de tráfico en un detector de día cero (LOAO 0,228), y tiene un **límite de fondo**: un
   atacante que imita la pila completa, o un equipo legítimo con dos pilas, son indistinguibles a
   nivel de huella.
3. La contribución metodológica más fuerte es **cómo se mide**: por episodio, con intervalos de
   confianza, con presupuesto de falsas alarmas por dispositivo-día, declarando cada decisión antes de
   medir y reportando cada predicción fallida (p. ej. `dos_pilas`). Esto evita el «sesgo del autor» y
   hace las cifras defendibles.
4. La defensa contra el ataque **lento** no es un mejor clasificador de volumen, sino una **señal de
   identidad (IP→MAC)** que no depende de la tasa: es el resultado que mejor sostiene el valor del
   enfoque de huella.

---

## 5. Pendiente para el laboratorio físico (lo completa el autor)

Todo lo anterior es **laboratorio sintético**. Las siguientes cifras son **optimistas** hasta
validarlas con tráfico real, y son la parte que el autor cierra con el IDS en la red física:

- **Captura en vivo** sobre una interfaz real (`--iface`), y **ejecución real** de la mitigación
  (pasar el `ejecutor` de `ebtables`/VLAN con root).
- **Falsas alarmas del vigilante con DHCP y failover reales** (el 0,0 actual no los representa).
- **Imitación de huella a nivel de paquete** (un atacante que escribe TTL/ventana/opciones de una
  pila legítima) y los **RST de la víctima** frente al clon de pila completa en un switch.
- **Sesiones largas** (todo está medido en 15 min) y una **captura propia etiquetada** que sustituya
  al generador sintético sin cambiar el resto del pipeline (el gancho ya está previsto).

> Trazabilidad: cada etapa tiene su informe en `docs/INFORME_*.md`, sus cifras en `reports/*.json`, y
> su historial de commits en el repositorio. Estado y conclusiones vivas: `docs/ESTADO.md`.
