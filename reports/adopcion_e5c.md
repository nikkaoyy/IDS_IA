# Adopción sin absorber el clon (E5C) — cifras

Generado por `scripts/evaluar_adopcion.py` el 2026-11-14T21:21:36 en el commit `242d99aacf2ebc0573753f34103e071b774e7d29` (árbol con cambios).
`VENTANAS_ADOPCION = 6`.

## Falsas alarmas con variación benigna (ventanas/disp-día)

| Grupo | apariciones (E3B) | persistencia (E5C) |
|---|---|---|
| **con variación (todas)** | 826.2 [729.9, 919.5] | 381.5 [326.2, 442.0] |
| sin variación (control + gateway) | 9.7 [0.0, 27.5] | 9.7 [0.0, 27.5] |
| actualizacion | 2392.9 [2021.8, 2782.4] | 566.5 [486.7, 672.7] |
| vpn | 251.6 [90.5, 442.7] | 92.8 [36.7, 153.5] |
| dos_pilas | 1337.4 [1071.0, 1628.1] | 1177.2 [886.3, 1484.7] |
| descubrimiento | 144.6 [2.4, 325.5] | 62.6 [0.0, 185.4] |
| deriva_lenta | 4.9 [0.0, 12.3] | 4.9 [0.0, 12.3] |
| ventanas en `no_confiable` (con variación) | 0.128 [0.124, 0.133] | 0.128 [0.124, 0.133] |

## Detección por nivel de clon

| Nivel | apariciones (E3B) | persistencia (E5C) |
|---|---|---|
| ingenuo | 0.975 [0.925, 1.000] | 0.975 [0.925, 1.000] |
| pila_completa | 0.200 [0.075, 0.325] | 0.200 [0.075, 0.325] |
| ritmo | 1.000 [1.000, 1.000] | 0.975 [0.925, 1.000] |
| suplantacion_ip | 0.950 [0.875, 1.000] | 0.950 [0.875, 1.000] |
| victima_apagada | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |

