# PEDIDO-E4R-1 — robustez del detector: recall frente a la intensidad y el suelo que pone el efecto

Repo: `~/Documentos/FRED/IDS`, rama `main`, base `bb59773` (E3 cerrado).
Guardar en la raíz del repo como `PEDIDO-E4R-1.md`.

## Qué es esta fase y por qué es defensiva

Es la **fase de prueba de robustez (testing adversarial) del IDS**: medir cuánto se le escapan a
nuestro propio detector los ataques a medida que bajan de intensidad, y cuál es el suelo que
ningún detector por ventana puede cruzar. No se construye ninguna herramienta nueva de ataque ni
de evasión: se **reutiliza el corpus de ataques ya congelado** (`generar_trafico.py`, semillas
0–19, que ya sortea intensidades `rafaga`, `media` y `suave`) y se mide el detector contra él. El
objetivo es encontrar y documentar las debilidades del defensor para que queden reportadas, que es
lo contrario de evadirlo con fin ofensivo.

Dos motivos concretos:

1. `src/attack_simulator.py` mide "evasión" copiando columnas de una fila legítima
   (`iat_media_ms`, `longitud_trama_media`). Eso es ficción de tabla: son agregados de ventana, no
   campos que un atacante escriba en un paquete. Se deja como está (no se toca) y en su lugar se
   mide lo honesto: **el pcap congelado pasa por `src/ventanas.py` y el modelo ve lo que vería en
   vivo**. La etiqueta sigue siendo 1; la caída de recall al bajar la intensidad es la medida.
2. De E3B: el canal de identidad quedó con **826 FA/disp-día** con variación benigna. Cualquier
   "recall del sistema" que sea un OR de canales está comprado con ese presupuesto. Aquí **los
   canales se reportan por separado** y el OR se da solo con su costo en FA al lado.

## Estado verificado (2026-11-14, sobre `bb59773`)

- E3B cerrado: `docs/INFORME_E3B.md`, `reports/identidad_e3b.json`.
- Contrato de ataques intacto: 52 columnas, `VERSION_ESQUEMA = 3.0`, dataset sha256 `7f06d099…a945`
  (20 sesiones). `models/` no se versiona: el modelo se reentrena con el script.
- `K_TRAMAS_ATAQUE = 2` (`scripts/pcap_to_features.py`), `VENTANA_CORTA_S = 5.0`.
- Punto de operación: XGB con umbral de validación anidada a **1 FA/disp-día** (`configs/e2.json`).
  Es el umbral que se usa; no se reajusta.
- `data/*.pcap`, `data/*.csv` fuera de git: se regeneran con los generadores congelados.

## Bloque 1 — Recall vs intensidad y la categoría "invisible por construcción"

Canal supervisado. Se reutiliza `src/evaluacion.py` (`predecir_fuera_de_fold`, `tabla_episodios`,
`resumir`) sobre el dataset congelado, al punto de operación de E2:

1. **Recall por episodio vs intensidad** (`rafaga`/`media`/`suave`) y por tipo, con IC bootstrap
   por episodio, latencia hasta la detección y FA/disp-día. La intensidad `suave` es el caso más
   silencioso que el generador produce: es el extremo bajo de la curva.
2. **Invisible por construcción**: hoy `tabla_episodios` agrupa solo ventanas con `etiqueta==1`, de
   modo que un episodio cuyas ventanas nunca llegan a `K=2` **desaparece del denominador sin que
   nadie lo cuente**. Hay que contarlo aparte: por tipo e intensidad, cuántos episodios nunca
   alcanzan K (máximo de `n_tramas_ataque` por ventana < K en todo el episodio). Son episodios que
   el sistema no puede ni etiquetar, así que el canal supervisado no puede verlos por diseño: no es
   evasión del modelo, es un límite del esquema de etiquetado por ventana.
3. Se reporta el recall de dos formas, con las dos cifras juntas: sobre los episodios **etiquetables**
   (como hace E2) y sobre **todos** los episodios de ataque (incluidos los invisibles, que cuentan
   como no detectados). La diferencia es el peaje del muestreo por ventana.

Criterio: `tests/test_evaluar_robustez.py` con un caso sintético donde un episodio queda por debajo
de K en todas sus ventanas y se cuenta como invisible, no como detectado ni ausente.

## Bloque 2 — Los canales por separado, y el OR con su precio

1. **(a) Supervisado**: lo del bloque 1.
2. **(b) Identidad** (`src/identidad.py`) y **(c) vigilante IP→MAC** (`VigilanteIP`): se corren
   sobre los mismos pcaps de ataque. Se espera —y se registra antes de medir— que detecten ≈ 0 de
   los floods y escaneos, porque vigilan la **suplantación de identidad de pila**, no el volumen ni
   los puertos. Su recall sobre estos tipos y su FA (las de E3B como referencia, más las medidas
   aquí) se reportan igual.
3. **(d) El OR** de los tres canales, con su FA sumada al lado. La frase que esto decide: cuánto
   recall extra sobre floods/escaneos aporta encender identidad y vigilante, y a cambio de cuántas
   FA/disp-día. Si el extra de recall es ≈ 0 y el costo son las 826 FA/disp-día de E3B, se escribe así.

Criterio: tabla por canal con recall por tipo y FA/disp-día; el OR con su FA.

## Bloque 3 — Invariantes de efecto (el suelo lo pone la física, no el detector)

Análisis razonado, no generación. Para cada ataque, el invariante que lo mantiene siendo ataque y
la tasa mínima que lo conserva, cruzada con las tasas reales de la intensidad `suave` del generador
congelado (`RANGOS_ATAQUE` en `generar_trafico.py`): ¿la `suave` ya está por debajo del suelo de
efecto, o todavía por encima?

| Ataque | Invariante de efecto | Qué fija la tasa mínima |
|---|---|---|
| `syn_flood` | agotar el backlog (N) antes del primer reintento SYN-ACK | medios-abiertos/s = f(N, RTO) |
| `arp_spoofing` | refrescar antes del `gc_stale` de la caché (≈60 s Linux, ≈30 s Windows) | ARP/s mínimo |
| `mac_flooding` | inserciones/s ≥ tamaño de la tabla CAM / su tiempo de envejecimiento | MACs/s |
| `port_scan` | puertos distintos/hora suficientes para cubrir el rango | puertos/hora |
| `dns_spoofing` | la respuesta forjada llega antes que la legítima | ventana de RTT |

Criterio: tabla con, por ataque, la tasa mínima que conserva el efecto, la tasa `suave` del
generador, y el recall del canal supervisado en `suave`. Donde la `suave` ya cae por debajo del
suelo de efecto **y** el recall es 0 por etiqueta, se escribe **«invisible por construcción»** y no
se cuenta como evasión del modelo.

## Bloque 4 — Informe y cierre

`reports/robustez_e4.json` (+ `.md` derivado) y `docs/INFORME_E4R.md` con: recall vs intensidad por
tipo, la cuenta de invisibles por construcción, la tabla por canal con su FA, la tabla de
invariantes, y la frase del artículo: **a qué intensidad el recall del supervisado cae por debajo
de 0,5, con su intervalo, y cuántos ataques son invisibles por etiqueta antes de llegar ahí**.
Cierre: un commit por bloque, `docs/ESTADO.md` actualizado (fila E4R y conclusiones), `git status`
limpio.

## Criterio de aceptación (pega la salida real)

```bash
cd ~/Documentos/FRED/IDS
.venv/bin/python -m pytest -o addopts="" -q tests/test_evaluar_robustez.py
.venv/bin/python scripts/evaluar_robustez.py --config configs/robustez.json
.venv/bin/python -c "import json;d=json.load(open('reports/robustez_e4.json'));print(d['resumen'])"
```

## Lo que NO se toca

- El contrato de 52 columnas, `VERSION_ESQUEMA` 3.0, `COLUMNAS_MODELO`, el dataset (`7f06d099…a945`)
  y `models/`.
- `scripts/lab/*` (todos los generadores), `src/attack_simulator.py`, `src/ventanas.py`,
  `src/identidad.py` y sus umbrales, `src/evaluacion.py`: se usan como están, no se modifican.
- El holdout 20–29, `scripts/evaluar_holdout.py`, E5, E6, E7.
- Interfaces reales: nada. Sin `git push`.

## Cierre

Reporte de cinco líneas: recall en `suave` (la intensidad más baja que hay), cuántos y qué ataques
son invisibles por construcción, el recall extra del OR y su costo en FA, la FA de cada canal, y qué
queda para E5.
