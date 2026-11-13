# Informe E2 — Evaluación del clasificador por episodio y por dispositivo

> Etapa E2 (OE2, OE3) sobre la base `dc56b92` (E1 cerrado). Trabajo del 2026-11-13. El
> pedido está en `PEDIDO-E2.md`. No incluye E3–E6. `docs/INFORME_FASE_1.md` no se modificó.

## Resumen

Umbral fijado por validación anidada para **≤ 1 falsa alarma por dispositivo-día**. Todas
las cifras van con su IC al 95 %.

| | Random Forest | XGBoost |
|---|---|---|
| **Recall por episodio — validación** (20 sesiones, 188 episodios) | 0,787 [0,732, 0,843] | 0,787 [0,734, 0,840] |
| **Recall por episodio — holdout 20–29** (10 sesiones, 89 episodios) | 0,728 [0,638, 0,822] | 0,787 [0,697, 0,865] |
| Falsas alarmas por dispositivo-día — validación | 0,95 [0,24, 1,81] | 1,04 [0,00, 2,58] |
| Falsas alarmas por dispositivo-día — holdout | **2,66 [0,00, 6,32]** | 0,29 [0,00, 0,88] |
| Tiempo hasta la detección, mediana — validación / holdout | 10 s / 10 s | 10 s / 10 s |
| **LOAO: recall por episodio del tipo nunca visto** (media de 6) | **0,028** (0,000–0,065) | **0,111** (0,000–0,179) |
| PR-AUC por ventana (solo referencia) — validación | 0,981 [0,969, 0,989] | 0,984 [0,973, 0,991] |

**Respuesta a la pregunta del pedido (§6).** El sistema detecta el catálogo del
generador, no ataques en general. Si un tipo de ataque nunca aparece en el entrenamiento,
su recall por episodio cae a **0,00–0,07 con RF y a 0,00–0,18 con XGB**, frente a 0,48–1,00
cuando sí aparece. Esto ocurre con el mismo presupuesto de falsas alarmas.

| bloque | commit | resultado |
|---|---|---|
| 1. Evaluación por episodio y dispositivo con IC | `cd01e1a` | `src/evaluacion.py`, 10 pruebas sintéticas |
| 2. RF/XGB, umbral anidado, falsas alarmas | `8050745` | `reports/evaluacion_e2.{json,md}` |
| 3. Ablaciones, LOAO, multiclase, permutación | `8036e9e` | `reports/ablaciones_e2.{json,md}` |
| 4. Holdout abierto una sola vez | `e43a28f` (código) + `30e8874` (cifras) | `reports/holdout_e2.json`, sello `reports/.holdout_abierto` |
| 5. Este informe | commit siguiente | — |

## 1. Estado de partida verificado

- Base `dc56b92`, árbol limpio. Suite con el CSV: 72 passed y 5 xfailed estrictos (77
  pruebas), como dice el pedido. ✔
- Dataset `data/dataset_lab.csv`: 78 988 filas, sha256 `3f4d28bc…9e04eced`. Coincide con
  `reports/dataset_lab_2026-11-12.json`. ✔
- Holdout: `SESIONES_RESERVADAS = range(20, 30)` en `src/data.py:43`. Ninguna sesión 20–29
  estaba en el dataset. ✔
- Suite al cierre de cada bloque: bloque 1, 82 passed + 5 xfailed; bloques 2 a 4, **88
  passed + 5 xfailed** (~4 min 40 s).

## 2. Bloque 1 — cómo se cuenta

`src/evaluacion.py` reparte con `StratifiedGroupKFold`: grupos por `sesion`, estratificación
por `tipo_ataque`, y `verificar_holdout` antes de cada reparto. Definiciones operativas,
también registradas en `definiciones` de `reports/evaluacion_e2.json`:

- **Falsa alarma**: ventana benigna *limpia* (`n_tramas_ataque == 0`) con `prob > umbral`.
- **Ventana ambigua**: `0 < n_tramas_ataque < K` (K = 2), etiquetada benigna. No cuenta ni
  como falsa alarma ni como acierto. Hay 750 en desarrollo y 307 en el holdout.
- **Dispositivo-día**: lapso observado de cada par (sesión, MAC), desde su primera hasta su
  última ventana, × 5 s, sumado y dividido entre 86 400. Las MAC efímeras de cada sesión
  cuentan como un solo dispositivo. En desarrollo: 873 dispositivos, **6,71
  dispositivo-días**.
- **Episodio detectado**: al menos una de sus ventanas etiquetadas tiene alarma. **Tiempo
  hasta la detección**: desde el inicio de la primera ventana con alguna trama del episodio
  (aunque quede bajo K) hasta el cierre de la primera ventana etiquetada con alarma. El
  mínimo es 5 s.
- **IC 95 %**: percentiles 2,5 y 97,5 de 1000 réplicas bootstrap con semilla 42. Las
  razones por dispositivo y el PR-AUC remuestrean **sesiones**. El recall y los tiempos
  remuestrean **episodios** (o atacantes). En cada réplica se promedian las semillas.

Pruebas (`tests/test_evaluacion.py`):
- Con ruido puro, el recall por episodio no supera el azar + 0,25.
- Con señal perfecta, el recall es 1,0 y no hay falsas alarmas.
- El IC con 8 sesiones tiene ancho > 0.
- El reparto nunca mezcla sesiones y rechaza el holdout.
- El umbral respeta el objetivo; las ventanas ambiguas no son falsas alarmas; el tiempo
  hasta la detección se calcula bien.
- El PR-AUC ponderado vectorizado coincide con sklearn hasta 1e-12.

## 3. Bloque 2 — modelos, umbral y falsas alarmas

### 3.1 El objetivo: ≤ 1 falsa alarma por dispositivo-día

El umbral se elige en cada fold externo con 3 folds internos agrupados por sesión. Se
toman las probabilidades fuera de fold de las ventanas benignas limpias del entrenamiento
y el umbral es su k-ésima mayor, con k = ⌊objetivo × dispositivo-días internos⌋. Ese
umbral se aplica, sin tocarlo, al test del fold.

Por qué **1 por dispositivo-día**:

1. **La carga de alertas crece con el tamaño de la red, no con el tráfico.** Expresar el
   objetivo por dispositivo-día lo hace transferible. Una red de oficina de ~50 equipos
   (el laboratorio tiene ~44 por sesión) recibiría ~50 alarmas falsas al día, unas 2 por
   hora laboral, que un operador puede revisar. Equivale a un FPR por ventana de
   1/17 280 ≈ **5,8 × 10⁻⁵** (17 280 ventanas de 5 s por día). El FPR medido en el
   umbral es 8,8 × 10⁻⁵ con RF y 9,7 × 10⁻⁵ con XGB.
2. **Es lo más estricto que el dataset puede medir.** El desarrollo suma 6,71
   dispositivo-días, y el entrenamiento de cada fold externo, donde se elige el umbral,
   ~5,4. Con objetivo 0,25, k = 1: el umbral queda en la probabilidad benigna más alta y
   el objetivo se fija con una sola observación. Con 1, k = 4–5: falsas alarmas internas
   entre 0,73 y 0,94 por dispositivo-día en los 25 folds.
3. **El codo de la curva está ahí** (tabla 3.3). Bajar a 0,25 cuesta 9–17 puntos de
   recall por episodio. Subir a 4 los gana, pero multiplica las falsas alarmas por 3,5–6.

Consecuencia que el artículo debe declarar: con 6,71 dispositivo-días, el número
absoluto de falsas alarmas por semilla es pequeño (~6). Por eso el IC de la tasa es ancho
([0,24, 1,81] en RF). La cifra cumple el objetivo en media, pero **el dataset no permite
afirmarlo con precisión**.

### 3.2 Cifras reales

`python scripts/evaluar.py --config configs/e2.json` (salida de consola completa):

```
Escrito /home/nikka/Documentos/FRED/IDS/reports/evaluacion_e2.json y /home/nikka/Documentos/FRED/IDS/reports/evaluacion_e2.md
random_forest: recall episodio 0.787 [0.732, 0.843] · FA/disp-día 0.95 [0.24, 1.81] · PR-AUC 0.981 [0.969, 0.989]
xgboost: recall episodio 0.787 [0.734, 0.840] · FA/disp-día 1.04 [0.00, 2.58] · PR-AUC 0.984 [0.973, 0.991]
```

Bloque de cifras de `reports/evaluacion_e2.md`, copiado tal cual:

```
Conteos: 20 sesiones, 188 episodios, 97 atacantes, 873 dispositivos (6.71 dispositivo-días),
78988 ventanas (5715 maliciosas, 72523 benignas limpias, 750 ambiguas).

| Métrica                                | random_forest        | xgboost              |
|----------------------------------------|----------------------|----------------------|
| Recall por episodio                    | 0.787 [0.732, 0.843] | 0.787 [0.734, 0.840] |
| Recall por atacante                    | 0.827 [0.751, 0.899] | 0.856 [0.784, 0.918] |
| Falsas alarmas / dispositivo-día       | 0.95 [0.24, 1.81]    | 1.04 [0.00, 2.58]    |
| Dispositivos con ≥1 falsa alarma       | 0.005 [0.002, 0.009] | 0.002 [0.000, 0.006] |
| Tiempo hasta la detección, mediana (s) | 10.0 [10.0, 10.0]    | 10.0 [5.0, 10.0]     |
| Tiempo hasta la detección, p90 (s)     | 60.0 [40.0, 85.0]    | 55.0 [40.0, 80.0]    |
| PR-AUC (ventana, referencia)           | 0.981 [0.969, 0.989] | 0.984 [0.973, 0.991] |
| Recall por ventana en el umbral        | 0.697 [0.599, 0.766] | 0.714 [0.613, 0.786] |
| FPR por ventana en el umbral (×10⁻³)   | 0.088 [0.022, 0.169] | 0.097 [0.000, 0.237] |

| Tipo         | RF episodio                 | RF ventana | RF t. med. (s)    | XGB episodio                | XGB ventana | XGB t. med. (s)   |
|--------------|-----------------------------|------------|-------------------|-----------------------------|-------------|-------------------|
| arp_spoofing | 0.800 [0.676, 0.900] (n=34) | 0.371      | 10.0 [10.0, 15.0] | 0.824 [0.706, 0.941] (n=34) | 0.436       | 10.0 [5.0, 12.5]  |
| dns_spoofing | 0.727 [0.573, 0.873] (n=30) | 0.335      | 10.0 [10.0, 25.0] | 0.733 [0.600, 0.867] (n=30) | 0.396       | 10.0 [5.0, 15.0]  |
| icmp_flood   | 0.439 [0.265, 0.600] (n=31) | 0.125      | 22.5 [15.0, 40.0] | 0.484 [0.290, 0.677] (n=31) | 0.145       | 30.0 [15.0, 35.0] |
| mac_flooding | 1.000 [1.000, 1.000] (n=34) | 0.981      | 5.0 [5.0, 5.0]    | 1.000 [1.000, 1.000] (n=34) | 0.985       | 5.0 [5.0, 5.0]    |
| port_scan    | 0.729 [0.571, 0.879] (n=28) | 0.364      | 25.0 [17.5, 40.0] | 0.714 [0.536, 0.893] (n=28) | 0.374       | 32.5 [15.0, 50.0] |
| syn_flood    | 1.000 [1.000, 1.000] (n=31) | 0.747      | 10.0 [5.0, 10.0]  | 0.935 [0.839, 1.000] (n=31) | 0.747       | 5.0 [5.0, 10.0]   |

| Intensidad | random_forest               | xgboost                     |
|------------|-----------------------------|-----------------------------|
| media      | 0.839 [0.745, 0.919] (n=62) | 0.871 [0.774, 0.952] (n=62) |
| rafaga     | 0.606 [0.453, 0.747] (n=34) | 0.706 [0.559, 0.853] (n=34) |
| suave      | 0.820 [0.743, 0.896] (n=92) | 0.761 [0.674, 0.848] (n=92) |

Umbrales elegidos (25 folds): RF 0.7900–0.8750 (mediana 0.8400); XGB 0.9891–0.9975 (mediana 0.9925).
```

### 3.3 Sensibilidad al objetivo (cada objetivo con su propio umbral anidado)

```
| Objetivo | Modelo        | Recall episodio      | FA/disp-día medidas | T. mediana (s)    |
|----------|---------------|----------------------|---------------------|-------------------|
| 0.25     | random_forest | 0.695 [0.636, 0.753] | 0.30 [0.00, 0.69]   | 10.0 [10.0, 10.0] |
| 0.25     | xgboost       | 0.622 [0.559, 0.691] | 0.60 [0.00, 1.60]   | 10.0 [5.0, 10.0]  |
| 1        | random_forest | 0.787 [0.732, 0.843] | 0.95 [0.24, 1.81]   | 10.0 [10.0, 10.0] |
| 1        | xgboost       | 0.787 [0.734, 0.840] | 1.04 [0.00, 2.58]   | 10.0 [5.0, 10.0]  |
| 4        | random_forest | 0.874 [0.831, 0.918] | 5.66 [2.46, 9.58]   | 10.0 [5.0, 10.0]  |
| 4        | xgboost       | 0.910 [0.872, 0.947] | 3.58 [1.23, 6.39]   | 5.0 [5.0, 10.0]   |
| 16       | random_forest | 0.954 [0.926, 0.981] | 14.39 [7.66, 22.49] | 5.0 [5.0, 10.0]   |
| 16       | xgboost       | 0.968 [0.941, 0.989] | 15.94 [10.25, 22.49]| 5.0 [5.0, 5.0]    |
```

### 3.4 La métrica por ventana engaña

Un PR-AUC de 0,98 por ventana convive con un **recall por episodio de 0,79** y un recall
por ventana de 0,70 en el umbral operativo. La métrica por ventana premia acertar en
`mac_flooding`, que aporta 2 943 de las 5 715 ventanas maliciosas. En cambio, el 21 % de
los episodios pasa sin una sola alarma. Esto confirma la decisión de Nico: la puerta de
0,85 por ventana queda solo como referencia.

## 4. Bloque 3 — ablaciones, leave-one-attack-out, multiclase y permutación

`python scripts/ablaciones.py --config configs/e2.json`: RF y XGB, semilla 42, el mismo
reparto y el mismo umbral anidado que el bloque 2. Las tablas completas están en
`reports/ablaciones_e2.md`.

### 4.1 Leave-one-attack-out (LOAO)

Cada entrenamiento excluye todas las filas de los episodios de un tipo, incluidas sus
ventanas ambiguas, que llevan `tipo_ataque = normal`. El umbral interno se elige también
sin ese tipo. El test se deja intacto.

```
| Tipo excluido | Modelo        | Sin el tipo en train        | Con el tipo en train | Caída  | FA/disp-día       |
|---------------|---------------|-----------------------------|----------------------|--------|-------------------|
| arp_spoofing  | random_forest | 0.000 [0.000, 0.000] (n=34) | 0.824 [0.676, 0.941] | +0.824 | 1.04 [0.30, 1.92] |
| dns_spoofing  | random_forest | 0.033 [0.000, 0.100] (n=30) | 0.733 [0.567, 0.867] | +0.700 | 1.34 [0.30, 2.67] |
| icmp_flood    | random_forest | 0.065 [0.000, 0.161] (n=31) | 0.516 [0.323, 0.677] | +0.452 | 1.79 [0.60, 3.26] |
| mac_flooding  | random_forest | 0.000 [0.000, 0.000] (n=34) | 1.000 [1.000, 1.000] | +1.000 | 1.19 [0.00, 2.95] |
| port_scan     | random_forest | 0.036 [0.000, 0.107] (n=28) | 0.714 [0.536, 0.857] | +0.679 | 1.19 [0.15, 2.47] |
| syn_flood     | random_forest | 0.032 [0.000, 0.097] (n=31) | 1.000 [1.000, 1.000] | +0.968 | 0.89 [0.00, 2.03] |
| arp_spoofing  | xgboost       | 0.000 [0.000, 0.000] (n=34) | 0.824 [0.706, 0.941] | +0.824 | 0.60 [0.00, 1.81] |
| dns_spoofing  | xgboost       | 0.167 [0.033, 0.301] (n=30) | 0.733 [0.600, 0.867] | +0.567 | 0.74 [0.00, 1.82] |
| icmp_flood    | xgboost       | 0.129 [0.032, 0.258] (n=31) | 0.484 [0.290, 0.677] | +0.355 | 0.45 [0.00, 1.33] |
| mac_flooding  | xgboost       | 0.029 [0.000, 0.088] (n=34) | 1.000 [1.000, 1.000] | +0.971 | 0.74 [0.00, 2.04] |
| port_scan     | xgboost       | 0.179 [0.036, 0.321] (n=28) | 0.714 [0.536, 0.893] | +0.536 | 0.74 [0.00, 2.06] |
| syn_flood     | xgboost       | 0.161 [0.064, 0.290] (n=31) | 0.935 [0.839, 1.000] | +0.774 | 1.49 [0.30, 2.95] |
```

Las falsas alarmas siguen cerca de 1 por dispositivo-día. El tipo nuevo no se pierde por
un umbral más conservador: el modelo no lo distingue del benigno.

### 4.2 Ablación por conjunto de características

```
| Conjunto | Modelo        | n col. | Recall episodio      | FA/disp-día       | PR-AUC ventana       |
|----------|---------------|--------|----------------------|-------------------|----------------------|
| capa2    | random_forest | 14     | 0.197 [0.144, 0.250] | 0.30 [0.00, 0.75] | 0.893 [0.837, 0.930] |
| capas3_4 | random_forest | 18     | 0.000 [0.000, 0.000] | 0.00 [0.00, 0.00] | 0.907 [0.855, 0.939] |
| completo | random_forest | 49     | 0.803 [0.750, 0.862] | 1.49 [0.31, 2.84] | 0.981 [0.968, 0.989] |
| capa2    | xgboost       | 14     | 0.399 [0.335, 0.473] | 1.34 [0.46, 2.26] | 0.902 [0.850, 0.936] |
| capas3_4 | xgboost       | 18     | 0.505 [0.436, 0.580] | 1.04 [0.45, 1.63] | 0.922 [0.879, 0.950] |
| completo | xgboost       | 49     | 0.787 [0.734, 0.840] | 1.04 [0.00, 2.58] | 0.984 [0.973, 0.991] |
```

**`capas3_4` con RF da 0,000: no es un fallo del código, el punto de operación es
inalcanzable.** Comprobado aparte: el umbral queda en **1,0 en los 5 folds**. Con solo
esas 18 características, el RF da P = 1 a 31 ventanas benignas limpias fuera de fold
(junto a 2 410 maliciosas). Para no pasar de 1 falsa alarma por dispositivo-día, el umbral
tiene que ser 1,0, y `prob > 1,0` no se cumple nunca. Es decir, con capas 3-4 solas el RF
no puede operar con ese presupuesto de falsas alarmas. XGB, cuyas probabilidades no se
saturan, llega a 0,505.

Por tipo (recall por episodio), lo esperable: la capa 2 sola detecta `mac_flooding` (RF
0,65; XGB 1,00) y casi nada más. Las capas 3-4 detectan `syn_flood` (XGB 0,90) y
`port_scan` (XGB 0,57), pero no `arp_spoofing` (0,09). Ningún subconjunto se acerca al
completo: los ataques necesitan la combinación de familias.

### 4.3 Multiclase

```
| Etiqueta    | Modelo        | Exactitud bal. (ventana) | F1 macro (ventana) | Acierto por episodio | Acierto entre detectados |
|-------------|---------------|--------------------------|--------------------|----------------------|--------------------------|
| tipo_ataque | random_forest | 0.843                    | 0.855              | 0.941                | 0.962                    |
| tipo_ataque | xgboost       | 0.910                    | 0.899                | 0.963                | 0.968                    |
| capa        | random_forest | 0.832                    | 0.850                | 0.941                | 0.962                    |
| capa        | xgboost       | 0.906                    | 0.897                | 0.963                | 0.968                    |
```

En la vista por episodio, la clase asignada es la no benigna más votada entre sus
ventanas etiquetadas. Cuando el sistema detecta un episodio, acierta su tipo el 96–97 % de
las veces. Es coherente con el LOAO: cada tipo del catálogo tiene una firma propia y
fácil de separar de los demás. El resultado sirve para diagnóstico (OE3), pero no prueba
generalización. Tipo y capa dan cifras casi iguales porque en este catálogo cada tipo
pertenece a una sola capa.

### 4.4 Importancia por permutación

Para cada fold de la semilla 42 se permuta en test una característica, o una familia
entera con la misma permutación, 5 veces. Se mide la caída de PR-AUC y la de recall por
episodio en el umbral anidado del fold.

```
RF (base: PR-AUC 0.976, recall episodio 0.802)    XGB (base: PR-AUC 0.981, recall episodio 0.797)
| Familia    | Caída recall ep. | Caída PR-AUC |   | Familia    | Caída recall ep. | Caída PR-AUC |
| capa2      | +0.505 ± 0.100   | +0.478       |   | capa2      | +0.297 ± 0.068   | +0.555       |
| tcp        | +0.467 ± 0.086   | +0.303       |   | largas_60s | +0.249 ± 0.057   | +0.141       |
| largas_60s | +0.385 ± 0.070   | +0.079       |   | tcp        | +0.159 ± 0.073   | +0.176       |
| dns        | +0.105 ± 0.040   | +0.018       |   | arp        | +0.109 ± 0.044   | +0.012       |
| arp        | +0.056 ± 0.030   | +0.007       |   | dns        | +0.036 ± 0.035   | +0.014       |
| globales   | +0.031 ± 0.055   | +0.004       |   | globales   | -0.009 ± 0.028   | +0.002       |

Característica más importante en ambos: longitud_trama_std (RF caída PR-AUC +0.092,
XGB +0.253); siguen longitud_trama_media e ips_origen_distintas.
```

La primera característica de ambos modelos, por mucho, es la **dispersión de la longitud
de trama**. Es una característica de capa 2 que depende de qué tamaños de paquete emite
cada herramienta del generador. Las características semánticas de ARP y DNS
(`arp_cambios_vinculo`, `dns_respuestas_sin_consulta`…) pesan poco. El modelo se apoya
más en *cómo* emite el generador que en *qué* viola cada ataque.

### 4.5 Lo que más duele

| # | Hallazgo | Cifra | Dónde |
|---|---|---|---|
| 1 | Un tipo de ataque no visto en el entrenamiento pasa casi entero | recall 0,000–0,065 (RF), 0,000–0,179 (XGB) | §4.1 |
| 2 | La característica principal es un artefacto de emisión (longitud de trama), no la semántica del ataque | `longitud_trama_std`: −0,25 de PR-AUC en XGB | §4.4 |
| 3 | `icmp_flood` es el ataque peor detectado incluso con entrenamiento | validación 0,44/0,48, holdout 0,36/0,50 | §3.2, §5 |
| 4 | Las ráfagas se escapan más | validación 0,61/0,71, holdout 0,48/0,67 | §3.2, §5 |
| 5 | En el holdout, RF supera el objetivo de falsas alarmas | 2,66 [0,00, 6,32] FA/dispositivo-día | §5 |
| 6 | Una sola familia de características no basta; RF con capas 3-4 ni siquiera puede operar con 1 FA/dispositivo-día | recall 0,20 (capa 2), 0,00 (capas 3-4, umbral saturado) | §4.2 |
| 7 | El 21 % de los episodios no recibe ninguna alarma aunque el PR-AUC por ventana sea 0,98 | recall por episodio 0,787 | §3.4 |
| 8 | El dataset solo suma 6,7 dispositivo-días: la tasa de falsas alarmas tiene IC de un orden de magnitud | [0,24, 1,81] | §3.1 |

## 5. Bloque 4 — holdout 20–29, abierto una sola vez

Datos: `python scripts/lab/generar_dataset_lab.py --inicio 20 --sesiones 10 --romper-holdout
--salida data/holdout_e2.csv --dir-pcap data/pcap_holdout`. Generador congelado, sin
cambios. Resultado: 40 307 ventanas (37 803 benignas, 2 504 maliciosas), sha256
`78c56297…83fe5b4`. El CSV, su sidecar y los pcap quedan fuera de git (`.gitignore`).

El script se confirmó en `e43a28f` **antes** de abrir el holdout, con el árbol limpio. Así
el sello apunta a un commit que existe y contiene el código exacto de la apertura.
Procedimiento, para cada una de las 5 semillas:
1. Umbral: probabilidades fuera de fold sobre todo el desarrollo (5 folds por sesión) con
   el mismo objetivo de 1 FA/dispositivo-día.
2. Modelo final entrenado con las 20 sesiones de desarrollo.
3. Alarma en el holdout si `prob > umbral`.

**Primera corrida** (salida completa, sin las líneas de log):

```
$ .venv/bin/python scripts/evaluar_holdout.py --config configs/e2.json
Escrito /home/nikka/Documentos/FRED/IDS/reports/holdout_e2.json; sello /home/nikka/Documentos/FRED/IDS/reports/.holdout_abierto (commit e43a28f34415d4fe32ce8e4afa316f950f648260, 2026-11-13T10:49:44)
Holdout: 10 sesiones (sesion_020…sesion_029), 40307 ventanas, sha256 78c562970eb08e27d4f627de78f1b7f95164d4831c95b7f4417f78be583fe5b4
random_forest: recall episodio 0.728 [0.638, 0.822] · recall atacante 0.804 [0.696, 0.900] · FA/disp-día 2.66 [0.00, 6.32] · t. mediana 10.0 [10.0, 15.0] s · PR-AUC 0.975 [0.963, 0.987]
    arp_spoofing: 0.463 [0.237, 0.713] (n=16)
    dns_spoofing: 0.867 [0.667, 1.000] (n=15)
    icmp_flood: 0.357 [0.143, 0.643] (n=14)
    mac_flooding: 1.000 [1.000, 1.000] (n=14)
    port_scan: 0.693 [0.466, 0.894] (n=15)
    syn_flood: 1.000 [1.000, 1.000] (n=15)
xgboost: recall episodio 0.787 [0.697, 0.865] · recall atacante 0.792 [0.667, 0.896] · FA/disp-día 0.29 [0.00, 0.88] · t. mediana 10.0 [5.0, 10.0] s · PR-AUC 0.959 [0.941, 0.982]
    arp_spoofing: 0.750 [0.500, 0.938] (n=16)
    dns_spoofing: 0.733 [0.533, 0.933] (n=15)
    icmp_flood: 0.500 [0.214, 0.786] (n=14)
    mac_flooding: 1.000 [1.000, 1.000] (n=14)
    port_scan: 0.733 [0.467, 0.933] (n=15)
    syn_flood: 1.000 [1.000, 1.000] (n=15)
código de salida: 0
```

**Segunda corrida:**

```
$ .venv/bin/python scripts/evaluar_holdout.py --config configs/e2.json
NEGADO: El holdout ya se abrió (commit e43a28f34415d4fe32ce8e4afa316f950f648260, 2026-11-13T10:49:44); ver /home/nikka/Documentos/FRED/IDS/reports/.holdout_abierto. Solo un bug demostrado justifica --romper-holdout-una-vez --motivo.
código de salida: 3
holdout_e2.json intacto: sí (a320a3953da540f6a970130e834cf97adff3400392aaaf7dcd4d625736c73616)
sello intacto: sí
```

No hubo reapertura (`"reaperturas": []` en el sello).

### 5.1 Validación frente a holdout (se reporta tal cual; no se reajustó nada)

| Métrica | RF validación | RF holdout | XGB validación | XGB holdout |
|---|---|---|---|---|
| Recall por episodio | 0,787 [0,732, 0,843] | 0,728 [0,638, 0,822] | 0,787 [0,734, 0,840] | 0,787 [0,697, 0,865] |
| Recall por atacante | 0,827 [0,751, 0,899] | 0,804 [0,696, 0,900] | 0,856 [0,784, 0,918] | 0,792 [0,667, 0,896] |
| FA / dispositivo-día | 0,95 [0,24, 1,81] | **2,66 [0,00, 6,32]** | 1,04 [0,00, 2,58] | 0,29 [0,00, 0,88] |
| Dispositivos con ≥1 FA | 0,005 | 0,007 | 0,002 | 0,002 |
| T. hasta detección, mediana / p90 | 10 / 60 s | 10 / 55 s | 10 / 55 s | 10 / 35 s |
| PR-AUC por ventana | 0,981 | 0,975 | 0,984 | 0,959 |
| `arp_spoofing` | 0,800 | **0,463** | 0,824 | 0,750 |
| `icmp_flood` | 0,439 | 0,357 | 0,484 | 0,500 |
| ráfaga | 0,606 | **0,483** | 0,706 | 0,667 |

- **RF empeora en el holdout.** Su recall cae 6 puntos, sobre todo en `arp_spoofing`
  (0,80 → 0,46). Sus falsas alarmas suben a 2,66 por dispositivo-día: el umbral elegido en
  desarrollo no cumple el objetivo en sesiones nuevas. Con 3,46 dispositivo-días, eso son
  unas 9 alarmas falsas por semilla en todo el holdout, y el IC incluye el 0.
- **XGB se mantiene**: el mismo recall por episodio (0,787) y menos falsas alarmas (0,29).
- Todos los IC de validación y holdout se solapan. Con 10 sesiones y 89 episodios, el
  holdout no permite afirmar diferencias menores de ~10 puntos.

## 6. ¿El sistema detecta ataques o detecta el catálogo del generador?

**Detecta el catálogo.** Recall por episodio de un tipo de ataque ausente del
entrenamiento, con el mismo presupuesto de ~1 falsa alarma por dispositivo-día:

| | arp | dns | icmp | mac | port_scan | syn | media |
|---|---|---|---|---|---|---|---|
| RF, tipo nunca visto | 0,000 | 0,033 | 0,065 | 0,000 | 0,036 | 0,032 | **0,028** |
| XGB, tipo nunca visto | 0,000 | 0,167 | 0,129 | 0,029 | 0,179 | 0,161 | **0,111** |
| Con el tipo en entrenamiento (RF / XGB) | 0,82 / 0,82 | 0,73 / 0,73 | 0,52 / 0,48 | 1,00 / 1,00 | 0,71 / 0,71 | 1,00 / 0,94 | 0,80 / 0,79 |

Lo que sostiene esa respuesta:

1. **El LOAO.** Fuera del catálogo, el recall queda en 0–18 %. Un detector de «anomalía
   frente al benigno» debería conservar parte de la detección de un *flood* nuevo, porque
   todo *flood* dispara volumen y tasa. Pero sin `mac_flooding` en el entrenamiento, el RF
   no detecta ni un episodio de las 34 inundaciones MAC (0,000), pese a ser el ataque más
   ruidoso del dataset.
2. **La permutación.** La característica que más pesa es la dispersión de la longitud de
   trama, que refleja las herramientas del generador. Las violaciones de protocolo (ARP
   no solicitado, DNS sin consulta) pesan poco.
3. **La multiclase.** Identificar el tipo es más fácil (96–97 % entre detectados) que
   detectar un tipo nuevo (3–11 %). Cada ataque del catálogo es una firma bien separada.
4. **El holdout no lo contradice.** Usa el mismo catálogo y el mismo generador con
   semillas nuevas, así que confirma que el modelo **generaliza a sesiones nuevas del
   catálogo conocido** (recall 0,73–0,79), no a ataques nuevos.

Formulación que propongo para el artículo: *«Con ≤ 1 falsa alarma por dispositivo-día, el
clasificador detecta el 79 % [73, 84] de los episodios de los seis ataques que conoce, en
una mediana de 10 s, y lo sostiene en 10 sesiones reservadas (XGB 79 % [70, 87]). No
detecta ataques ausentes del entrenamiento (3–11 % de recall por episodio en
leave-one-attack-out). Es un detector de firmas aprendidas, no de anomalías.»*

## 7. RF frente a XGBoost

- **En validación, empate**: recall por episodio 0,787 en ambos, con IC casi idénticos, y
  falsas alarmas 0,95 frente a 1,04.
- **En el holdout, XGB es más estable**: mantiene el recall y baja a 0,29 FA por
  dispositivo-día. RF pierde 6 puntos y sube a 2,66. Los IC se solapan, así que es una
  tendencia, no una diferencia demostrada.
- **XGB degrada menos fuera del catálogo** (LOAO 0,11 frente a 0,03) y **sin saturar sus
  probabilidades**: RF asigna P = 1 a benignas y eso lo deja sin punto de operación en
  `capas3_4`.
- Coste: ~1 s por ajuste de XGB con 8 hilos frente a ~2,5 s de RF, en este equipo.

Recomendación: **XGBoost como modelo principal** del artículo y RF como comparación.

## 8. Limitaciones que el artículo debe declarar

1. **Pocas ventanas por episodio y episodios muy desiguales.** Mediana de ventanas
   etiquetadas por episodio: 11 en `arp_spoofing`, 14–15 en el resto y 27 en
   `mac_flooding`, con un máximo de 559. 14 de los 188 episodios tienen ≤ 2 ventanas. El
   recall por episodio se calcula sobre 28–34 episodios por tipo (14–16 en el holdout), y
   por eso sus IC tienen ±10–20 puntos.
2. **Un solo laboratorio virtual.** Una topología, un generador, un conjunto de
   herramientas de ataque con sus variantes (3–7 por tipo). La permutación muestra que el
   modelo usa artefactos de emisión de esas herramientas. Nada garantiza que se
   transfieran a otra red ni a otras implementaciones del mismo ataque.
3. **Sesiones sintéticas.** El benigno es tráfico generado (E1 lo ensanchó), no usuarios
   reales. Las falsas alarmas medidas son contra ese benigno.
4. **Pocos dispositivo-días.** 6,71 en desarrollo y 3,46 en el holdout. El objetivo de 1
   FA por dispositivo-día está cerca de la resolución del dataset, y su IC abarca casi un
   orden de magnitud.
5. **Catálogo cerrado.** El LOAO muestra que no se detectan ataques nuevos. Cualquier
   afirmación sobre «detección de ataques» debe limitarse a los seis tipos entrenados.
6. **La separabilidad de E1 sigue ahí.** Cinco de seis ataques superan 0,85 de exactitud
   balanceada con una sola regla (xfail en `tests/test_separabilidad.py`). Las cifras de
   este informe miden un problema que el generador hace relativamente fácil.

## 9. Desviaciones

1. **`src/models.py:28,48`: XGBoost con 8 hilos en vez de `n_jobs=-1`.** En este equipo, un
   proceso del escritorio ocupa un núcleo entero. Con 16 hilos, OpenMP espera al hilo
   rezagado y cada ajuste pasa de 1,5 s a 32 s (medido con 60 000 filas). Las predicciones
   son idénticas bit a bit con 4, 8, 12, 15 y 16 hilos. No cambian hiperparámetros ni
   resultados.
2. **XGBoost no usa la semilla.** Con `subsample = colsample = 1`
   (`src/models.py:45-49`), `random_state` no cambia el modelo: predicciones idénticas con
   semilla 1 y 99 (comprobado). En XGB, las 5 semillas solo varían el reparto en folds. No
   cambié los hiperparámetros para no tocar el modelo de Fase 1.
3. **Ablaciones con una semilla** (`configs/e2.json:32`, `ablaciones.semillas = [42]`), no
   5. El bootstrap por sesiones y episodios sigue dando los IC. La evaluación principal
   (5 semillas) muestra que la variación entre semillas es menor que esos IC: el
   «completo» de una semilla da 0,803 frente a 0,787 con cinco en RF.
4. **`FEATURES_LARGAS` no es solo capas 3-4** (`src/feature_schema.py:76`): incluye
   `arp_*_60s`, `dns_*_60s` y `n_tramas_60s`. La ablación `capas3_4` usa
   `FEATURES_TCP + FEATURES_LARGAS` tal como pide el pedido. Por eso no es una ablación
   pura de capas 3-4.
5. **Bloque 4 en dos commits** (`e43a28f` código, `30e8874` cifras), no uno. Así el sello
   del holdout apunta a un commit existente con el código exacto de la apertura. Si se
   enmendara el commit del código para añadir las cifras, el sello apuntaría a un commit
   que ya no existe.
6. **Los informes de los bloques 2 y 3 se generaron con el árbol sucio.** El JSON registra
   el commit padre (`cd01e1a`, `8050745`) con `"arbol_con_cambios": true`. El código que
   los produjo es el que entró en el commit de su bloque. La única diferencia posterior es
   el renombre de variables locales por `ruff`; el Markdown regenerado desde el JSON con
   el código confirmado coincide byte a byte (comprobado en el bloque 2).
7. **La última semilla de XGB figura con 33 450 s** (`corridas[4].segundos` en
   `reports/evaluacion_e2.json`), frente a ~21 s de las otras. El equipo se suspendió
   durante la noche a mitad de la corrida. El proceso continuó sin reiniciarse y el
   resultado no depende del tiempo.
8. **No hay ficha `reports/dataset_lab_<fecha>.json` del holdout.**
   `scripts/lab/ficha_dataset.py:122` la nombraría `dataset_lab_2026-11-13.json`, como si
   fuera un dataset de desarrollo. Su sha256, filas, sesiones, etiquetas y el sidecar de
   generación (comando y semillas) están en `dataset_holdout` de `reports/holdout_e2.json`.
9. **El pedido menciona «el pipeline de `src/preprocess.py`».** Se usa
   `ajustar_escalador` + `preprocesar` (`src/preprocess.py:62,69`), ajustados solo con el
   train de cada fold. `dividir()` no se usa porque reparte filas y no hace validación
   cruzada por sesión.

## 10. Commits y lo que queda para Nico

```
30e8874 IDS E2: bloque 4 (cifras) — holdout 20–29 abierto una vez
e43a28f IDS E2: bloque 4 (código) — apertura única del holdout con sello
8036e9e IDS E2: bloque 3 — ablaciones, leave-one-attack-out, multiclase e importancia por permutación
8050745 IDS E2: bloque 2 — RF y XGBoost con umbral anidado y falsas alarmas por dispositivo-día
cd01e1a IDS E2: bloque 1 — evaluación por episodio y dispositivo con IC
```

(El bloque 5, este informe, es el commit que sigue a `30e8874`.)

Para Nico:

1. **`git push`**: no se hizo.
2. **Decidir el mensaje del artículo** a partir del §6: detector de firmas de seis ataques
   conocidos, no de anomalías. Si la tesis requiere detección de ataques nuevos, eso es
   trabajo nuevo (detección de anomalías sobre el benigno, otras características) y no
   cabe en E2.
3. **Modelo principal**: propongo XGBoost (§7).
4. **Addendum a `docs/INFORME_FASE_1.md`**: si ese informe cita métricas por ventana o
   implica detección general, toca enmendarlo con un addendum, como en E1. No lo hice
   porque el pedido no lo incluía.
5. **El holdout está gastado.** Cualquier cambio de modelo o de características posterior
   necesita sesiones reservadas nuevas (≥ 30) si se quiere otra cifra final limpia.
6. **El dataset es corto en dispositivo-días** (§8.4). Si el artículo necesita una cifra
   de falsas alarmas precisa, hacen falta sesiones benignas más largas o más numerosas.
   El generador está congelado, así que eso sería otra etapa.
7. **E3–E6** siguen fuera del alcance. No se adelantó nada.
