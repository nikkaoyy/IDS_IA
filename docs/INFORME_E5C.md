# Informe E5C — aprender un cambio legítimo sin aprender un clon

PEDIDO-E5C-1 · rama `main` · tres bloques, un commit cada uno (`242d99a`, `2a6cfd0`, y este cierre).
Cifras de `reports/adopcion_e5c.json` (IC al 95 % por bootstrap, 1000 réplicas, semilla 42). El
diario, con lo registrado antes de medir, está en `PROGRESO-E5C-1.md`.

## El problema

E3B dejó el límite más grande del canal de identidad: con variación benigna realista el perfil
dispara **826 FA/disp-día**, y `no_confiable` no las esconde (0,128 de las ventanas). La ablación
mostró la tensión: **congelar** en alerta da FA persistentes sobre un cambio legítimo; **no
congelar** absorbe el clon. Faltaba una tercera vía.

## La tercera vía (registrada antes de medir)

Dos reglas detrás de `ADOPCION_MODO` (`"persistencia"` por defecto; `"apariciones"` = E3B), que no
tocan `UMBRAL_DESVIACION`, `MIN_VENTANAS_PERFIL`, `MIN_VENTANAS_CRUCE` ni la gracia de 600 s:

1. **Los valores de la construcción son del equipo**: un TTL/ventana visto en las primeras 12
   ventanas se exime aunque aparezca una sola vez. A prueba de clones: empiezan a los 300 s.
2. **Adopción por persistencia exclusiva**: un valor nuevo post-construcción se adopta tras
   `VENTANAS_ADOPCION = 6` ventanas **exclusivas** (sin el valor viejo). Un clon coexiste con la
   víctima → nunca exclusivo → no se adopta → se sigue acusando.

## Resultado

El modo `apariciones` reproduce exactamente las **826,2** FA/disp-día de E3B, así que la comparación
antes/después es fiel.

### Falsas alarmas con variación benigna (ventanas/disp-día)

| Grupo | apariciones (E3B) | persistencia (E5C) |
|---|---|---|
| **con variación (todas)** | 826,2 [729,9, 919,5] | **381,5 [326,2, 442,0]** |
| sin variación (control + gateway) | 9,7 [0,0, 27,5] | 9,7 [0,0, 27,5] |
| actualización | 2392,9 | **566,5** |
| VPN | 251,6 | **92,8** |
| descubrimiento | 144,6 | **62,6** |
| **dos pilas** | 1337,4 | **1177,2** |
| deriva lenta | 4,9 | 4,9 |
| ventanas en `no_confiable` (con variación) | 0,128 | 0,128 |

Los IC de la FA global **no se solapan** (826 [730, 920] → 381,5 [326, 442]): la bajada del **54 %** es
clara. Y no es por silenciar: la proporción `no_confiable` es idéntica (0,128), así que la mejora es
**aprendizaje real** del cambio legítimo, no un detector apagado con otro nombre.

### Detección por nivel de clon

| Nivel | apariciones (E3B) | persistencia (E5C) |
|---|---|---|
| ingenuo | 0,975 | 0,975 |
| ritmo | 1,000 | **0,975** |
| pila completa | 0,200 | 0,200 |
| víctima apagada | 1,000 | 1,000 |
| suplantación de IP | 0,950 | 0,950 |

## Lo que la regla arregla, y lo que no (honesto)

- **Arregla** la actualización (−76 %), la VPN (−63 %) y el descubrimiento (−57 %): son cambios
  **exclusivos** (el equipo deja de usar el valor viejo), que es justo lo que la regla 2 adopta.
- **No arregla `dos_pilas`** (1337 → 1177, apenas −12 %): **la predicción registrada falló**. Una
  segunda pila concurrente que se hace visible después de la construcción es, a nivel de pila,
  indistinguible de un clon: coexiste con la pila principal, nunca es exclusiva, no se adopta y
  sigue disparando. No se añadió una tercera regla a posteriori (sería ajustar tras ver las cifras).
  Es la ambigüedad de fondo del canal de identidad y queda como límite declarado.
- **Regresión de detección**: ritmo baja de 1,000 a 0,975 — **un** clon de ~40 se adopta porque la
  víctima calló 30 s seguidos y la pila del clon se volvió exclusiva. Es el **riesgo que se registró
  antes de medir**, ahora realizado. El resto de niveles no cambia. Es el precio de la regla 2, y se
  reporta sin reajustar `VENTANAS_ADOPCION`.

## Frase para el artículo

> Una tercera vía entre congelar y no congelar —adoptar un valor nuevo solo cuando persiste de forma
> **exclusiva**, y eximir los que el equipo ya mostraba al construir su perfil— **reduce las falsas
> alarmas con variación benigna de 826 a 382 (381,5 exacto) por dispositivo-día (−54 %, con intervalos que no se
> solapan)** sin apagarse en `no_confiable` y sin perder la detección de los clones que cambian la
> pila (ingenuo 0,975, ritmo 0,975, pila completa 0,20). El precio es un clon de ritmo absorbido de
> cada cuarenta, cuando la víctima calla medio minuto. La mitad de las falsas alarmas que quedan son
> de un equipo con **dos pilas concurrentes**, que a nivel de huella es indistinguible de un clon:
> ese es el límite de fondo del canal de identidad.

## Para E6

- **Discriminar `dos_pilas` de un clon por el lapso de aparición**: una pila legítima aparece
  salpicada toda la sesión; un clon es una racha contigua y tardía. Registrarlo antes de medir y
  medirlo en sesiones nuevas.
- Acotar la regresión de ritmo: exigir que el valor viejo haya estado **presente** en una ventana
  reciente antes de empezar a contar exclusividad (para que una víctima que calla no cuente como
  cambio), midiendo que no reintroduce FA.
- Todo sigue medido en sesiones sintéticas de 15 min; falta el laboratorio real (DHCP, failover).

## Aceptación (salida real)

```text
$ .venv/bin/python -m pytest -o addopts="" -q tests/test_identidad.py
........................................                                 [100%]
40 passed in 0.17s

$ .venv/bin/python scripts/evaluar_adopcion.py --config configs/adopcion_e5c.json
Escrito reports/adopcion_e5c.json y reports/adopcion_e5c.md

$ .venv/bin/python -c "import json;d=json.load(open('reports/adopcion_e5c.json'));print(d['resumen'])"
{'fa_con_variacion': {'apariciones': 826.2, 'persistencia': 381.5}, 'no_confiable_con_variacion': {'apariciones': 0.128, 'persistencia': 0.128}, 'fa_por_tipo': {'actualizacion': {'apariciones': 2392.9, 'persistencia': 566.5}, 'vpn': {'apariciones': 251.6, 'persistencia': 92.8}, 'dos_pilas': {'apariciones': 1337.4, 'persistencia': 1177.2}, 'descubrimiento': {'apariciones': 144.6, 'persistencia': 62.6}, 'deriva_lenta': {'apariciones': 4.9, 'persistencia': 4.9}}, 'deteccion_por_nivel': {'ingenuo': {'apariciones': 0.975, 'persistencia': 0.975}, 'pila_completa': {'apariciones': 0.2, 'persistencia': 0.2}, 'ritmo': {'apariciones': 1.0, 'persistencia': 0.975}, 'suplantacion_ip': {'apariciones': 0.95, 'persistencia': 0.95}, 'victima_apagada': {'apariciones': 1.0, 'persistencia': 1.0}}}
```
