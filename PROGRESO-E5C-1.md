PARAR — PEDIDO-E5C-1 cerrado: tres bloques, informe, ESTADO, aceptación y push.

# Progreso — PEDIDO-E5C-1

## Bloque 1 — las dos reglas (registrado antes de medir)

- **Regla 1**: un valor de TTL/ventana visto en las primeras `MIN_VENTANAS_PERFIL` ventanas se
  exime aunque aparezca una sola vez (`<senal>_construccion` en el perfil). A prueba de clones:
  empiezan a los 300 s, mucho después de los 60 s de construcción.
- **Regla 2**: un valor nuevo post-construcción se adopta tras `VENTANAS_ADOPCION = 6` ventanas
  **exclusivas** (sin el valor viejo = la mediana del perfil). Un clon coexiste con la víctima →
  nunca exclusivo → no se adopta → se sigue acusando.
- Detrás de `ADOPCION_MODO` (`"persistencia"` por defecto, `"apariciones"` = E3B).
- No se toca `UMBRAL_DESVIACION`, `MIN_VENTANAS_PERFIL`, `MIN_VENTANAS_CRUCE`, la gracia de 600 s.
- `tests/test_identidad.py` (40 passed, +4 E5C): valor de construcción minoritario no dispara;
  cambio limpio se adopta y deja de disparar; clon que coexiste no se adopta y sigue disparando;
  `apariciones` reproduce el comportamiento viejo. Dos tests de reperfilado de E3B se fijaron al
  modo `apariciones` (el reperfilado es una capa independiente).

### Expectativas registradas (se contrastan, no se ajustan)

- FA con variación baja claramente, sobre todo `actualizacion` (2393) y `dos_pilas` (1337).
- `dos_pilas` se arregla por la regla 1 (segunda pila desde el inicio); `actualizacion`/`vpn` por
  la regla 2 (cambio exclusivo). `deriva_lenta` ya pasaba.
- La detección por nivel **no baja**: ingenuo 0,975, ritmo 1,000, pila completa 0,20, víctima
  apagada 1,00, suplantación 0,95. Riesgo declarado: si un clon consigue 6 ventanas exclusivas
  (la víctima calla 30 s seguidos), su valor se adoptaría; se mide y se reporta si pasa.

## Bloque 2 — resultado (`reports/adopcion_e5c.json`)

`apariciones` reproduce exactamente las 826,2 FA/disp-día de E3B → la comparación es fiel.

| Grupo | apariciones (E3B) | persistencia (E5C) |
|---|---|---|
| **con variación (todas)** | 826,2 | **381,5** (−54 %) |
| actualización | 2392,9 | 566,5 |
| VPN | 251,6 | 92,8 |
| descubrimiento | 144,6 | 62,6 |
| **dos_pilas** | 1337,4 | **1177,2** (apenas −12 %) |
| deriva_lenta | 4,9 | 4,9 |
| ventanas en `no_confiable` | 0,128 | 0,128 |

| Nivel | apariciones | persistencia |
|---|---|---|
| ingenuo | 0,975 | 0,975 |
| ritmo | 1,000 | **0,975** |
| pila completa | 0,20 | 0,20 |
| víctima apagada | 1,00 | 1,00 |
| suplantación IP | 0,95 | 0,95 |

Lectura honesta:
- La FA con variación baja a la mitad y **no** por silenciar (no_confiable igual, 0,128): es
  aprendizaje real del cambio legítimo. Lo arreglan la actualización, la VPN y el descubrimiento
  (regla 2, cambio exclusivo).
- **La predicción sobre `dos_pilas` falló**: la regla 1 casi no lo mejora (−12 %). Una segunda pila
  concurrente que se hace visible después de la construcción es, a nivel de pila, indistinguible de
  un clon (coexiste con la principal → nunca exclusiva → no se adopta). Es la ambigüedad de fondo;
  no se añade una tercera regla a posteriori. Queda como límite declarado para E6 (discriminar por
  el **lapso** de aparición: una pila legítima aparece salpicada toda la sesión; un clon es una
  racha contigua tardía).
- **Regresión de detección**: ritmo 1,000 → 0,975. Un clon de ~40 se adopta porque la víctima calló
  30 s seguidos y su pila se volvió exclusiva — el riesgo registrado antes de medir, ahora realizado.
  El resto de niveles no cambia. Es el precio de la regla 2 y se reporta sin ajustar `VENTANAS_ADOPCION`.
