# PEDIDO-E5C-1 — aprender un cambio legítimo sin aprender un clon (las 826 FA/disp-día)

Repo: `~/Documentos/FRED/IDS`, rama `main`, base `00e3112` (E4C cerrado).

**La verdad es el repositorio.** Primer paso: `git log --oneline -3`, `git status --porcelain` vacío.

## El problema que ataca

E3B dejó el límite más grande del canal de identidad: con variación benigna realista (actualización,
VPN, dos pilas, descubrimiento) el perfil dispara **826 FA/disp-día**, y `no_confiable` no las
esconde (0,128 de las ventanas). El mecanismo: un valor legítimo nuevo (un TTL/ventana que cambia al
actualizarse, una segunda interfaz) aparece **después** de construido el perfil; la congelación en
alerta impide aprenderlo, y como nunca se aprende nunca llega a las `MIN_APARICIONES_VALOR = 2`
apariciones que lo eximirían → alarma hasta el fin de la sesión. La ablación de E3B mostró la
tensión: **congelar** da FA persistentes sobre el cambio legítimo; **no congelar** absorbe el clon.
Falta una tercera vía.

## La idea (registrada antes de medir)

Distinguir un cambio legítimo de un clon por su firma temporal, apoyándose en un hecho del corpus
congelado: **los clones empiezan a los 300 s** (`INICIO_MIN_EPISODIO_S`), mucho después de los
60 s (12 ventanas) de construcción del perfil. Dos reglas, ninguna toca `UMBRAL_DESVIACION`,
`MIN_VENTANAS_PERFIL`, `MIN_VENTANAS_CRUCE` ni la gracia de 600 s:

1. **Los valores de la fase de construcción son del equipo.** Un valor de TTL o ventana visto durante
   las primeras `MIN_VENTANAS_PERFIL` ventanas se exime aunque aparezca una sola vez (hoy exige 2).
   Arregla la segunda pila minoritaria (`dos_pilas`) y el descubrimiento, que están presentes desde
   el principio pero no acumulan 2 apariciones en 12 ventanas. A prueba de clones: ninguno aparece
   en el primer minuto.
2. **Adopción por persistencia exclusiva.** Un valor nuevo post-construcción que dispara se vuelve
   *candidato*. Se adopta (pasa a eximido) solo si se repite en `VENTANAS_ADOPCION` ventanas en las
   que el valor **viejo** (la mediana del perfil para esa señal) **no** aparece: es un cambio limpio
   (actualización, VPN). Un clon emite **a la vez** que la víctima, así que el valor viejo sigue
   apareciendo, la ventana nunca es exclusiva, el candidato nunca se adopta y se sigue acusando.

Las dos reglas viven detrás de `ADOPCION_MODO`: `"persistencia"` (nuevo, por defecto) y
`"apariciones"` (la de E3B, para reproducir las 826 en el mismo informe).

## Bloque 1 — las dos reglas en `src/identidad.py`

1. `perfil_desde_senales` guarda, por señal de valor, el conjunto de valores vistos en las primeras
   `MIN_VENTANAS_PERFIL` ventanas (`<senal>_construccion`).
2. `desviacion_senales` exime un valor si: cuenta ≥ `MIN_APARICIONES_VALOR`, **o** está en el
   conjunto de construcción, **o** está en el conjunto de adoptados del seguidor.
3. `SeguidorIdentidad` lleva, por señal, los candidatos y sus ventanas exclusivas; adopta un valor
   tras `VENTANAS_ADOPCION` ventanas exclusivas y lo inyecta en el perfil. Con
   `ADOPCION_MODO == "apariciones"`, las dos reglas se apagan y el comportamiento es el de E3B.

Criterio: `tests/test_identidad.py` con cuatro casos — (a) un valor presente desde la construcción
no dispara aunque sea minoritario; (b) un cambio limpio y persistente se adopta tras
`VENTANAS_ADOPCION` y deja de disparar; (c) un segundo valor que **coexiste** con el viejo (un clon)
no se adopta y sigue disparando; (d) con `ADOPCION_MODO = "apariciones"` se reproduce el
comportamiento viejo (el cambio sigue disparando).

## Bloque 2 — medir FA y detección, antes y después

`scripts/evaluar_adopcion.py` reutiliza los ayudantes de `scripts/evaluar_identidad.py` (no los
copia): las 20 sesiones de variación benigna (78000–78019) para la FA y las de clones (77000–77019)
y suplantación (79000–79019) para la detección. Para `modo` en `("apariciones", "persistencia")`:

1. **FA por tipo de variación** (actualización, VPN, dos pilas, descubrimiento, deriva lenta) y
   global, en ventanas y eventos por disp-día, con la proporción `no_confiable` al lado —las dos
   cifras juntas, como en E3B.
2. **Detección por nivel de clon** (ingenuo, ritmo, pila completa, víctima apagada, suplantación de
   IP) con su latencia.

Criterio duro: la FA con variación **baja** de forma clara y la detección **no baja** respecto a E3B
(ingenuo 0,975, ritmo 1,000, pila completa 0,20, víctima apagada 1,00, suplantación 0,95). Si la FA
baja pero la detección también, la regla no sirve y se reporta así. `reports/adopcion_e5c.json`
(+ `.md`) con la tabla antes/después.

## Bloque 3 — informe y cierre

`docs/INFORME_E5C.md` con: FA por tipo antes/después, detección por nivel antes/después, los casos
que la regla no arregla (si los hay), y la frase del artículo: **cuánto bajan las falsas alarmas con
variación legítima sin perder detección de clones**. `docs/ESTADO.md` actualizado, un commit por
bloque, `git status` limpio, y **push** al remoto.

## Criterio de aceptación (pega la salida real)

```bash
cd ~/Documentos/FRED/IDS
.venv/bin/python -m pytest -o addopts="" -q tests/test_identidad.py
.venv/bin/python scripts/evaluar_adopcion.py --config configs/adopcion_e5c.json
.venv/bin/python -c "import json;d=json.load(open('reports/adopcion_e5c.json'));print(d['resumen'])"
```

## Lo que NO se toca

- El contrato de 52 columnas, `VERSION_ESQUEMA` 3.0, `COLUMNAS_MODELO`, el dataset (`7f06d099…a945`).
- Los generadores congelados (`generar_trafico.py`, `generar_clones.py`, `generar_variacion.py`,
  `generar_suplantacion.py`, `generar_contaminacion.py`): se leen, no se editan.
- `UMBRAL_DESVIACION`, `MIN_VENTANAS_PERFIL`, `MIN_VENTANAS_CRUCE`, la gracia de 600 s, y el resto de
  la ablación de E3B. El único cambio de lógica es el de este pedido, detrás de `ADOPCION_MODO`.
- El holdout 20–29, E4R/E4C ya cerrados, E6, E7.

## Cierre

Reporte de cinco líneas: FA con variación antes/después (global y el peor tipo), detección por nivel
antes/después, qué variación no se arregla, y qué queda para E6.
