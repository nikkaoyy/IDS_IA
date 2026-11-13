# Addendum al §4.3 del Informe de Fase 1 — Validación anti-fuga

> Enmienda el §4.3 de `docs/INFORME_FASE_1.md`, que está radicado y **no se modifica**.
> Etapa E1, bloque 5. Fecha: 2026-11-13. Cifras medidas sobre `data/dataset_lab.csv`
> (sha256 `3f4d28bcd1d2fee5cd5aeab0ae31d5213262a097f7a051fe87b6e63f9e04eced`, 78 988 ventanas,
> 20 sesiones, ficha en `reports/dataset_lab_2026-11-12.json`).
> Reproducible con `python scripts/medir_agrupacion.py`, que escribe `reports/agrupacion_4_3.json`.

## 1. Qué decía el informe radicado

El §4.3 afirma que, al evaluar con división por grupo (`StratifiedGroupKFold`):

- `tiempo_entre_tramas_ms` es el atributo más discriminante (**0,54** de importancia);
- la dependencia de `oui_frecuente` baja de **0,50 a 0,24**, lo que demostraría que el modelo
  aprende el comportamiento temporal y no la identidad del atacante.

El §3.B describe la clave de grupo como `MAC_ventana_timestamp`, «esencial para particiones
mediante `StratifiedGroupKFold`».

## 2. Qué dice el código hoy

- `scripts/pcap_to_features.py:126` construye `grupo = mac + "#" + idx_ventana`.
- `src/preprocess.py:18` (ya en `0026bc3`) lo reconoce: «`grupo` vale `mac#ventana` y es
  único por fila, así que no sirve como grupo». Agrupar por una clave única por fila es
  lo mismo que no agrupar: cada fila es su propio grupo.
- Medido en el dataset nuevo: 78 341 valores distintos de `grupo` para 78 988 filas. Dentro
  de cada sesión es único. Solo se repite entre sesiones, sobre todo en la fila agregada
  `__efimeras__#ventana`, que existe en todas las sesiones.
- `dividir()` (`src/preprocess.py:50`) ya no usa `grupo`: reparte por **sesión**
  (`grupos_de_division`) y, sin sesión, por dispositivo.
- `tiempo_entre_tramas_ms` y `oui_frecuente` **no existen** en el contrato actual
  (`src/feature_schema.py`, versión 2.0): el IAT por MAC es hoy `iat_media_ms` /
  `iat_std_ms`, y `oui_frecuente` salió del modelo porque `OUI % 50` colisiona y no es
  ordinal (`src/feature_schema.py:11`).

## 3. La diferencia medida

Cuatro esquemas de validación de 4 folds, todos estratificados por etiqueta, con los
modelos de `src/models.py` (RF de 200 árboles con `class_weight="balanced"`; XGBoost con
`scale_pos_weight`). Media de los 4 folds (desviación típica entre paréntesis para la
exactitud balanceada, EB).

| esquema | modelo | exactitud | EB | recall | FPR | F1 |
|---|---|---|---|---|---|---|
| sin agrupar (por fila) | RF | 0,9948 | 0,9747 (0,0017) | 0,9512 | 0,0018 | 0,9637 |
| `grupo` (lo del informe) | RF | 0,9948 | 0,9745 (0,0014) | 0,9508 | 0,0018 | 0,9635 |
| dispositivo (MAC) | RF | 0,9845 | 0,9087 (0,0118) | 0,8201 | 0,0027 | 0,8845 |
| **sesión** (actual) | RF | 0,9892 | **0,9338** (0,0331) | 0,8699 | 0,0023 | 0,9146 |
| sin agrupar (por fila) | XGBoost | 0,9945 | 0,9866 | 0,9774 | 0,0041 | 0,9628 |
| `grupo` (lo del informe) | XGBoost | 0,9944 | 0,9874 | 0,9792 | 0,0044 | 0,9622 |
| dispositivo (MAC) | XGBoost | 0,9862 | 0,9370 | 0,8794 | 0,0054 | 0,9020 |
| **sesión** (actual) | XGBoost | 0,9905 | **0,9589** | 0,9227 | 0,0049 | 0,9287 |

Lectura:

1. **Agrupar por `grupo` no cambia nada** frente a no agrupar: la EB se mueve 0,0002 (RF),
   bien por debajo de la variación entre folds. La validación del informe era, en la
   práctica, un reparto por fila.
2. **La fuga existe y se mide.** Pasar de fila a sesión baja la EB del RF en **0,041** y su
   recall en **0,081**, y la del XGBoost en 0,028 y 0,055. Repartir por dispositivo baja
   todavía más el recall del RF (0,820), porque un mismo atacante aparece en varias
   sesiones como MAC propia o clonada y el reparto por MAC lo deja siempre fuera del
   entrenamiento.
3. **La exactitud simple oculta la fuga.** Con el 92,8 % de ventanas benignas, pasa de
   0,995 a 0,989: parece nada, y es la diferencia entre detectar el 95 % y el 87 % de las
   ventanas de ataque.
4. Con sesiones, la desviación entre folds se multiplica por 20 (0,0017 → 0,0331): con 5
   sesiones de prueba por fold, una cifra aislada no basta. E2 debe dar intervalos.

## 4. Importancia de las variables que cita el §4.3

| variable (equivalente actual) | sin agrupar | `grupo` | dispositivo | sesión |
|---|---|---|---|---|
| `iat_media_ms` (≈ `tiempo_entre_tramas_ms`) | 0,046 (puesto 6) | 0,045 (6) | 0,046 (6) | 0,047 (5) |
| `iat_std_ms` | 0,031 (puesto 11) | 0,032 (11) | 0,032 (11) | 0,033 (11) |
| `oui_frecuente` | no medible: fuera del contrato desde la versión 2.0 | | | |

Las cinco más importantes en todos los esquemas son `longitud_trama_std` (≈ 0,19),
`n_tramas_60s`, `longitud_trama_media`, `tasa_syn` e `ips_origen_distintas`.

- La cifra de **0,54** para el tiempo entre tramas **no se reproduce**: el IAT pesa
  alrededor de 0,05 y ocupa el puesto 5–6 de 52.
- La importancia apenas varía entre esquemas, como era de esperar. La importancia de
  Gini sale del modelo ajustado, y cambiar el reparto de validación no cambia lo que el
  modelo aprende, solo dónde se evalúa. Por eso el paso de 0,50 a 0,24 de `oui_frecuente`
  no puede atribuirse a la validación agrupada: si ocurrió, se debió a otros cambios del
  pipeline de entonces, y hoy no puede comprobarse porque la variable ya no existe.

## 5. Enmienda

Donde el §4.3 dice que la validación agrupada evita la fuga y que las importancias lo
demuestran, debe leerse:

> La clave `grupo` (`mac#ventana`) es única por fila dentro de cada sesión, así que agrupar
> por ella equivale a no agrupar. La unidad independiente es la **sesión**: con ella, la
> exactitud balanceada del Random Forest baja de 0,975 a 0,934 y su recall de 0,951 a 0,870
> (XGBoost: 0,987 → 0,959 y 0,977 → 0,923). Desde la etapa E0, `dividir()` reparte por
> sesión. Las importancias citadas no se reproducen con el contrato actual:
> `tiempo_entre_tramas_ms` corresponde a `iat_media_ms`, que pesa 0,05 (puesto 5–6), y
> `oui_frecuente` salió del modelo. La importancia no depende del esquema de validación,
> así que no sirve como prueba de ausencia de fuga.
