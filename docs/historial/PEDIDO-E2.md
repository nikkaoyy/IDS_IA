# Pedido E2 — evaluación del clasificador (OE2, OE3)

Repo: `/home/nikka/Documentos/FRED/IDS`, rama `main`, base `dc56b92` (E1 cerrado).
Guardar este archivo en la raíz del repo como `PEDIDO-E2.md`.

## Estado verificado (2026-11-13, medido desde un clon sobre `dc56b92`)

- Suite completa: **77 pruebas** (sin el CSV: 68 passed, 9 skipped; con `data/dataset_lab.csv`: 72 passed, 5 xfailed estrictos).
- Dataset: `reports/dataset_lab_2026-11-12.json` → **78 988 filas**, clases 73 273 / 5 715, `sha256 3f4d28bcd1d2fee5cd5aeab0ae31d5213262a097f7a051fe87b6e63f9e04eced`, generado en el commit `70cd3e6`. Reproducible byte a byte.
- Holdout: `SESIONES_RESERVADAS = range(20, 30)` en `src/data.py:43`, con las tres compuertas (`generar_dataset_lab.py`, `cargar_dataset()`, `dividir()`). **Nunca abierto: no hay ninguna sesión 20–29 en el dataset.**
- Puerta de E1 (`scripts/baseline_reglas.py`, `UMBRAL_PUERTA = 0.85`, exactitud balanceada máxima en 4 folds): solo `icmp_flood` cumple (0,837). Declaradas como xfail estricto en `tests/test_separabilidad.py`: arp 0,977 · dns 0,979 · mac 0,996 · port_scan 0,891 · syn 0,990.
- Esquema: `VERSION_ESQUEMA = 2.0`, `COLUMNAS_MODELO` sin cambios; `variante` e `intensidad` son columnas de traza (`COLUMNAS_TRAZA`).
- Entorno: `.venv/bin/activate` está roto (apunta a una ruta vieja); usar **`.venv/bin/python`** siempre. Sin el CSV, `test_separabilidad` se salta con su motivo. Generar el dataset cuesta ~12 min (`python scripts/lab/generar_dataset_lab.py --sesiones 20`); la suite, ~2–3 min.

La verdad es el repositorio: si algo de este pedido contradice el código, manda el código y repórtalo como desviación con `archivo:línea`.

## Decisión ya tomada por Nico (no la reabras)

La puerta de 0,85 **por ventana** deja de ser criterio de aceptación y queda como métrica de referencia documentada. La métrica que decide es **por episodio**, con intervalo de confianza: una ventana benigna de más pesa distinto que un episodio de ataque perdido, y `mac_flooding` aporta 2 688 de sus 2 943 ventanas en una sola variante, así que la métrica por ventana mide el generador, no la detección.

## Lo que NO se toca

- `scripts/lab/generar_trafico.py` y `scripts/lab/generar_dataset_lab.py`: el generador queda **congelado**. Cambiarlo reabre la puerta de E1 y mezcla dos etapas.
- `docs/INFORME_FASE_1.md`: se enmienda con addendum, nunca reescribiendo.
- `VERSION_ESQUEMA`, `COLUMNAS_MODELO` y el contrato de características: ninguna característica cambia de nombre ni de semántica.
- `DESVIACIONES_DECLARADAS` de `tests/test_separabilidad.py`: no se vacía ni se edita a la ligera.
- El holdout 20–29: se abre **una sola vez** en el bloque 4, y nada más lo toca.
- `data/*.csv`, `data/*.pcap`, sidecars: siguen fuera de git.
- No hagas `git push`: el push lo decide Nico.
- No toques los avisos de `ruff` que ya venían en el archivo (`src/data.py`).

## Bloque 1 — `src/evaluacion.py`: reparto honesto e IC

1. Reparto **agrupado por sesión** (`StratifiedGroupKFold` o equivalente), estratificado por `tipo_ataque`; el holdout 20–29 excluido por `verificar_holdout`.
2. Benigno agregado **por dispositivo**; ataque agregado **por episodio y por atacante**. Esas dos vistas deciden; la vista por ventana se conserva solo como referencia.
3. **IC al 95 % por bootstrap remuestreando sesiones** (no filas), ≥1 000 réplicas, semilla fija; y bootstrap por episodios para el recall.
4. 5 folds × 5 semillas; semilla y partición registradas en el JSON de salida.

Criterio: `tests/test_evaluacion.py` con casos sintéticos — con etiquetas sin señal el recall por episodio cae al azar; con señal perfecta da 1,0; el IC con 8 sesiones tiene ancho > 0; el reparto nunca mezcla sesiones entre train y test.

## Bloque 2 — modelo, umbral y falsas alarmas

1. RF y XGBoost sobre `COLUMNAS_MODELO` con el pipeline de `src/preprocess.py`; semillas fijas.
2. **Umbral en validación anidada** para un FPR objetivo numérico: elige el número (candidato: ≤1 falsa alarma por dispositivo-día) y **justifícalo en el informe**; no lo dejes como «el mejor umbral».
3. Métricas: PR-AUC, recall por ataque, FPR en el umbral, **falsas alarmas por dispositivo y por día**, recall **por episodio** y **tiempo hasta la detección** (segundos desde el inicio del episodio).

Criterio: `python scripts/evaluar.py --config configs/e2.json` escribe `reports/evaluacion_e2.json` con esas cifras para los dos modelos, más el Markdown derivado. Pega en el informe el bloque de cifras reales, no un resumen.

## Bloque 3 — ablaciones y multiclase

1. Ablación **capa 2 / capas 3-4 / completo** (`FEATURES_CAPA2`, `FEATURES_TCP`+`FEATURES_LARGAS`, todas).
2. **Leave-one-attack-out**: seis entrenamientos, cada uno sin un tipo de ataque, midiendo el recall del tipo excluido. Es la prueba de si el modelo aprende huella o aprende el catálogo.
3. Multiclase por `tipo_ataque` y por `capa`; importancia por **permutación** (no por impureza).

Criterio: `reports/ablaciones_e2.json` con las 3 ablaciones, los 6 LOAO y la importancia por permutación; y una tabla en el informe con lo que más duele.

## Bloque 4 — abrir el holdout una sola vez

1. `scripts/evaluar_holdout.py`: entrena con todas las sesiones no reservadas usando la configuración congelada de E2 (`configs/e2.json`), evalúa sobre las sesiones 20–29 y escribe `reports/holdout_e2.json` con fecha, commit, `sha256` del dataset, configuración y cifras con IC.
2. Sello `reports/.holdout_abierto` con commit y hora: una segunda corrida **se niega** y sale con código 3, salvo `--romper-holdout-una-vez` (solo para un bug demostrado, y deja constancia en el JSON).
3. Si el holdout sale peor que la validación, **se reporta tal cual**: no se reajusta nada y no se vuelve a abrir.

Criterio: primera corrida escribe el JSON; segunda sale con código 3 y no toca el archivo. Pega las dos salidas.

## Bloque 5 — informe y decisión

`docs/INFORME_E2.md`: resumen en tabla, cifras con IC, RF vs XGBoost, ablaciones, holdout, y **la respuesta explícita a una pregunta: ¿el sistema detecta ataques o detecta el catálogo del generador?** — con la cifra de LOAO delante. Cierra con las limitaciones que el artículo debe declarar (ventanas por episodio, un solo laboratorio virtual, sesiones sintéticas).

## Fuera del alcance

E3 (identidad), E4 (evasión a nivel de pcap), E5 (streaming), E6. No adelantes ninguna.

## Cierre

Un commit por bloque, suite verde al cerrar cada uno, `git status` limpio, e informe con la salida real de cada criterio. Al final: `git log --oneline` con los commits del E2 y la lista de lo que queda para Nico.
