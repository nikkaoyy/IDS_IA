SEGUIR — bloque 1 hecho (dos reglas de adopción); sigue el bloque 2 (medir FA y detección).

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
