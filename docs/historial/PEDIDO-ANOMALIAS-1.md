# PEDIDO-ANOMALIAS-1 — detector de anomalías entrenado solo con benigno

Repo: `/home/nikka/Documentos/FRED/IDS`, rama `main`, base `72f5f8f` (extractor cerrado, esquema 3.0).
Guardar en la raíz del repo como `PEDIDO-ANOMALIAS-1.md`. Se ejecuta antes que `PEDIDO-E3A-1.md`.

## Por qué

E2 y el extractor dejaron una cifra que hay que contrastar, no repetir: el supervisado detecta los seis ataques
del catálogo con **0,894** de recall por episodio (XGB, esquema 3.0, ≈0,89 FA/dispositivo-día) y con **0,228** de
LOAO medio cuando el tipo no está en el entrenamiento. La pregunta del artículo es si existe una vía que **no
dependa de haber visto el ataque**. La única que no depende es un detector entrenado **solo con benigno**.

Esto no es una etapa del plan original: es un experimento de contraste. Si sale mal, es un resultado (y publicado).

## Estado verificado (2026-11-13, sobre `72f5f8f`)

- Esquema 3.0 con 52 columnas; `COLUMNAS_MODELO` sin cambios y `variante`/`intensidad` como traza.
- El marcador del extractor usa las **38 columnas sin capa 2** (`sin_capa2`). Para comparar peras con peras, este
  pedido usa el mismo conjunto y deja el conjunto completo como segunda corrida, etiquetada.
- Utilidades que ya existen y **no se reescriben**: `src/evaluacion.py` → `repartos_por_sesion`,
  `umbral_para_objetivo`, `falsas_alarmas_por_dispositivo_dia`, `tabla_episodios`, `tabla_dispositivos`,
  `ic_media_por_unidad`, `ic_razon_por_sesion`, `resumir`; y `scripts/evaluar.py` como modelo de CLI y de JSON.
- Dataset de desarrollo: 20 sesiones, 78 988 ventanas, sha256 `7f06d099…a945`. **Holdout 20–29 gastado**: no se abre.
- `.venv/bin/python` (el `activate` está roto). Suite completa ~4 min.

## Regla que define el pedido

**Ningún dato malicioso toca el ajuste del modelo ni la calibración del umbral.** El detector aprende el
comportamiento benigno de los dispositivos y el umbral sale del cuantil de sus propios puntajes benignos. El
malicioso se usa **solo para medir**. Un pedido que use una etiqueta de ataque para elegir hiperparámetros está
haciendo supervisado con otro nombre.

Se verifica con una prueba, no con una promesa: `tests/test_anomalias.py` debe incluir un caso que pase un
DataFrame con etiqueta 1 al ajuste y compruebe que el pipeline **no la usa** (o que falla explícitamente si se la
intentan colar como dato de entrenamiento).

## Bloque 1 — `src/anomalias.py` y su CLI

1. Modelos: **IsolationForest** (principal), **LocalOutlierFactor** con `novelty=True` e **IsolationForest sobre
   PCA** como contraste ligero. Nada de autoencoder salvo que quepa en menos de tres minutos por fold; si no cabe,
   se declara fuera y por qué.
2. `scripts/evaluar_anomalias.py --config configs/anomalias.json`:
   `{conjunto: "sin_capa2"|"completo", modelos: [...], n_folds: 5, semillas: [...], objetivo_falsas_alarmas_dispositivo_dia: 1.0, n_bootstrap: 1000, semilla_bootstrap: 42, salidas: {...}}`.
3. Puntaje por ventana → umbral por **cuantil sobre benigno fuera de fold** usando `umbral_para_objetivo` para que
   el objetivo sea el mismo ≤1 FA/dispositivo-día. Si el cuantil no se alcanza con los datos, **se reporta** con el
   valor más cercano y su FA real; no se relaja el objetivo.
4. Preprocesado con `src/preprocess.py` (escalador ajustado solo con benigno de train).

Criterio: `tests/test_anomalias.py` con casos sintéticos — etiquetas benignas con dos dispositivos separables dan
FA≈0; un dispositivo con una anomalía evidente da alarma; el ajuste nunca recibe etiqueta 1.

## Bloque 2 — Evaluación con el mismo protocolo del extractor

1. 5 folds **por sesión** con `repartos_por_sesion`; en cada fold el modelo se ajusta con el benigno de train y se
   predice sobre todo el test (benigno y malicioso).
2. Métricas, con IC por bootstrap de episodios estratificado por tipo: **recall por episodio** por tipo y media,
   recall por atacante, **falsas alarmas por dispositivo-día**, PR-AUC por ventana y **tiempo hasta la detección**.
3. Las mismas dos vistas que E2: por ventana (referencia) y por episodio (la que decide).

Criterio: `reports/anomalias.json` con todo lo anterior para cada modelo y conjunto, y `reports/anomalias.md`
derivado. Pega el bloque de cifras reales en el informe.

## Bloque 3 — La comparación que importa, y el riesgo

1. Tabla única: **supervisado con el tipo en el entrenamiento** (0,894) · **supervisado LOAO** (0,228) ·
   **anomalías** (lo que salga), todo en recall por episodio al mismo presupuesto de falsas alarmas.
2. **Sonda de deriva**: los 5 dispositivos legítimos con más alarmas y su tasa. Si el detector castiga a dos o tres
   dispositivos concretos, eso es lo que hay que decir —un detector de anomalías que marca siempre al mismo equipo
   no sirve en producción—.
3. Por ataque: qué tipos detecta sin haberlos visto (todos son «no vistos» para este modelo) y cuáles se le pasan.
   `icmp_flood` y los ataques de ráfaga son los sospechosos.
4. Si el resultado es peor que el supervisado, **se escribe así**: el informe no suaviza y no se reajusta nada
   después de ver las cifras.

## Criterio de aceptación (pega la salida real)

```bash
cd ~/Documentos/FRED/IDS
.venv/bin/python -m pytest -o addopts="" -q tests/test_anomalias.py
.venv/bin/python scripts/evaluar_anomalias.py --config configs/anomalias.json
.venv/bin/python -c "import json;d=json.load(open('reports/anomalias.json'));print({k:v['resumen'] for k,v in d['resultados'].items()})"
```

y `docs/INFORME_ANOMALIAS.md` con: resumen en tabla, la comparación del punto 1, la sonda de deriva, y una respuesta
explícita —**¿un detector sin ataques en el entrenamiento sirve para ataques desconocidos, a este presupuesto de
falsas alarmas?**— con la cifra delante.

## Lo que NO se toca

- `scripts/lab/*` (generadores), `src/ventanas.py` y el contrato de 52 columnas: **el extractor está cerrado**.
- `scripts/baseline_reglas.py`, la puerta de E1 y `configs/e2.json`.
- El holdout 20–29: no se abre, ni con `--romper-holdout-una-vez`.
- `docs/INFORME_FASE_1.md`, `docs/INFORME_E1.md`, `docs/INFORME_E2.md`, `docs/INFORME_EXTRACTOR.md`: addendum
  aparte si hace falta, nunca reescritura.
- E3, E4, E5, E6: no se adelantan (E3 va en el pedido siguiente).
- `data/*.csv`, `data/*.pcap`, sidecars: fuera de git. Sin `git push`.

## Cierre

Un commit por bloque, `git status` limpio, y un reporte de cinco líneas: qué modelo ganó, la cifra frente a 0,894 y
0,228, la peor tasa de deriva por dispositivo y qué queda para Nico.
