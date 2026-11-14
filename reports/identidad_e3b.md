# E3B — cifras

Generado por `scripts/evaluar_identidad.py --partes b` el 2026-11-14T02:16:29 en el commit `211d2b625f9d00ef9e4ff8f733c53101b4e87c81` (árbol con cambios).

## Bloque 1 — IP-ID por equipo (descartado) frente a por flujo

| Medida | Por equipo (E3A) | Por flujo |
|---|---|---|
| FA/disp-día | 16.19 [9.41, 23.67] | 0.38 [0.00, 1.13] |
| Dispositivos con alguna FA | 0.092 [0.062, 0.123] | 0.004 [0.000, 0.012] |
| Detección ingenuo | 0.975 [0.925, 1.000] | 0.975 [0.925, 1.000] |
| Latencia mediana ingenuo (s) | 4.2 [3.0, 5.1] | 3.7 [3.0, 4.6] |
| Detección ritmo | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| Latencia mediana ritmo (s) | 10.0 [6.6, 17.0] | 10.0 [6.6, 17.0] |
| FA/disp-día por flujo + reperfilado 24 (registrado, lava el clon) | | 12.05 [0.38, 25.58] |

## Bloque 2 — legítimos con variación real (sin clones), defensas por defecto (sin reperfilado)

| Grupo | Disp. | FA ventanas/disp-día | FA eventos/disp-día | Disp. con FA | Ventanas no_confiable | Nunca confiables | Reperfilados | FA por señal (ventanas) |
|---|---|---|---|---|---|---|---|---|
| con variación (todas) | 200 | 826.2 [729.9, 919.5] | 362.9 [303.1, 418.2] | 0.43 [0.39, 0.48] | 0.128 [0.124, 0.133] | 0.00 [0.00, 0.00] | 0 | tcp_window 665, ttl 662, ipid_salto_log2 268 |
| sin variación (control + gateway) | 60 | 9.7 [0.0, 27.5] | 4.9 [0.0, 12.9] | 0.03 [0.00, 0.08] | 0.101 [0.096, 0.107] | 0.00 [0.00, 0.00] | 0 | ipid_contadores 5, ipid_continuidad 1 |
| actualizacion | 40 | 2392.9 [2021.8, 2782.4] | 564.0 [461.0, 668.7] | 0.97 [0.93, 1.00] | 0.157 [0.144, 0.171] | 0.00 [0.00, 0.00] | 0 | ttl 562, tcp_window 418 |
| vpn | 40 | 251.6 [90.5, 442.7] | 88.0 [36.8, 143.7] | 0.23 [0.10, 0.38] | 0.156 [0.138, 0.179] | 0.00 [0.00, 0.00] | 0 | tcp_window 96, ttl 7 |
| dos_pilas | 40 | 1337.4 [1071.0, 1628.1] | 1029.2 [834.7, 1214.7] | 0.82 [0.70, 0.95] | 0.126 [0.116, 0.138] | 0.00 [0.00, 0.00] | 0 | ipid_salto_log2 268, tcp_window 151, ipid_continuidad 94 |
| descubrimiento | 40 | 144.6 [2.4, 325.5] | 125.3 [2.4, 277.4] | 0.10 [0.03, 0.20] | 0.084 [0.082, 0.086] | 0.00 [0.00, 0.00] | 0 | ttl 59, ipid_continuidad 1 |
| deriva_lenta | 40 | 4.9 [0.0, 12.3] | 4.9 [0.0, 12.3] | 0.05 [0.00, 0.12] | 0.159 [0.140, 0.185] | 0.00 [0.00, 0.00] | 0 | ipid_continuidad 2 |
| control | 40 | 14.7 [0.0, 41.5] | 7.3 [0.0, 19.5] | 0.05 [0.00, 0.12] | 0.149 [0.134, 0.169] | 0.00 [0.00, 0.00] | 0 | ipid_contadores 5, ipid_continuidad 1 |
| gateway | 20 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.00 [0.00, 0.00] | 0.062 [0.061, 0.062] | 0.00 [0.00, 0.00] | 0 | — |

## Bloque 2 — legítimos con variación real (sin clones), con el reperfilado registrado (24)

| Grupo | Disp. | FA ventanas/disp-día | FA eventos/disp-día | Disp. con FA | Ventanas no_confiable | Nunca confiables | Reperfilados | FA por señal (ventanas) |
|---|---|---|---|---|---|---|---|---|
| con variación (todas) | 200 | 776.6 [697.6, 853.0] | 362.9 [303.1, 418.2] | 0.43 [0.39, 0.48] | 0.132 [0.126, 0.138] | 0.00 [0.00, 0.00] | 7 | tcp_window 665, ttl 560, ipid_salto_log2 268 |
| sin variación (control + gateway) | 60 | 9.7 [0.0, 27.5] | 4.9 [0.0, 12.9] | 0.03 [0.00, 0.08] | 0.101 [0.096, 0.107] | 0.00 [0.00, 0.00] | 0 | ipid_contadores 5, ipid_continuidad 1 |
| actualizacion | 40 | 2143.8 [1881.0, 2425.8] | 564.0 [461.0, 668.7] | 0.97 [0.93, 1.00] | 0.178 [0.167, 0.191] | 0.00 [0.00, 0.00] | 7 | ttl 460, tcp_window 418 |
| vpn | 40 | 251.6 [90.5, 442.7] | 88.0 [36.8, 143.7] | 0.23 [0.10, 0.38] | 0.156 [0.138, 0.179] | 0.00 [0.00, 0.00] | 0 | tcp_window 96, ttl 7 |
| dos_pilas | 40 | 1337.4 [1071.0, 1628.1] | 1029.2 [834.7, 1214.7] | 0.82 [0.70, 0.95] | 0.126 [0.116, 0.138] | 0.00 [0.00, 0.00] | 0 | ipid_salto_log2 268, tcp_window 151, ipid_continuidad 94 |
| descubrimiento | 40 | 144.6 [2.4, 325.5] | 125.3 [2.4, 277.4] | 0.10 [0.03, 0.20] | 0.084 [0.082, 0.086] | 0.00 [0.00, 0.00] | 0 | ttl 59, ipid_continuidad 1 |
| deriva_lenta | 40 | 4.9 [0.0, 12.3] | 4.9 [0.0, 12.3] | 0.05 [0.00, 0.12] | 0.159 [0.140, 0.185] | 0.00 [0.00, 0.00] | 0 | ipid_continuidad 2 |
| control | 40 | 14.7 [0.0, 41.5] | 7.3 [0.0, 19.5] | 0.05 [0.00, 0.12] | 0.149 [0.134, 0.169] | 0.00 [0.00, 0.00] | 0 | ipid_contadores 5, ipid_continuidad 1 |
| gateway | 20 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.00 [0.00, 0.00] | 0.062 [0.061, 0.062] | 0.00 [0.00, 0.00] | 0 | — |

## Bloque 3 — tabla por nivel de clon

Ingenuo y ritmo sobre las sesiones de E3A; los otros tres sobre las sesiones de `generar_suplantacion.py`. Detección = alarma de identidad sobre la MAC víctima o del vigilante sobre la IP víctima dentro del episodio.

### señal de contadores por grupos (corrección post hoc)

| Nivel | Episodios | Detección | Por identidad | Por vigilante | Latencia mediana (s) | FA/disp-día de sus sesiones |
|---|---|---|---|---|---|---|
| ingenuo | 40 | 0.975 [0.925, 1.000] | 0.975 [0.925, 1.000] | 0.000 [0.000, 0.000] | 3.7 [3.0, 4.6] | 0.38 [0.00, 1.13] |
| ritmo | 40 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 10.0 [6.6, 17.0] | 0.38 [0.00, 1.13] |
| pila_completa | 40 | 0.200 [0.075, 0.325] | 0.200 [0.075, 0.325] | 0.000 [0.000, 0.000] | 8.6 [2.1, 47.9] | 0.38 [0.00, 1.13] |
| suplantacion_ip | 40 | 0.950 [0.875, 1.000] | 0.000 [0.000, 0.000] | 0.950 [0.875, 1.000] | 3.9 [3.0, 4.1] | 0.38 [0.00, 1.13] |
| victima_apagada | 40 | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 4.6 [3.0, 5.0] | 0.38 [0.00, 1.13] |

Pila completa por familia de la víctima: android 0/7, iot 5/7, linux 0/10, macos 0/10, windows 3/6.

### señal de contadores por cadenas (registrada)

| Nivel | Episodios | Detección | Por identidad | Por vigilante | Latencia mediana (s) | FA/disp-día de sus sesiones |
|---|---|---|---|---|---|---|
| ingenuo | 40 | 0.975 [0.925, 1.000] | 0.975 [0.925, 1.000] | 0.000 [0.000, 0.000] | 3.7 [3.0, 4.6] | 21.08 [16.55, 25.97] |
| ritmo | 40 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 10.0 [6.6, 17.0] | 21.08 [16.55, 25.97] |
| pila_completa | 40 | 0.250 [0.125, 0.375] | 0.250 [0.125, 0.375] | 0.000 [0.000, 0.000] | 14.6 [2.1, 39.6] | 20.30 [14.26, 27.43] |
| suplantacion_ip | 40 | 0.950 [0.875, 1.000] | 0.050 [0.000, 0.125] | 0.950 [0.875, 1.000] | 3.9 [3.0, 4.1] | 20.30 [14.26, 27.43] |
| victima_apagada | 40 | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 4.6 [3.0, 5.0] | 20.30 [14.26, 27.43] |

Pila completa por familia de la víctima: android 0/7, iot 6/7, linux 0/10, macos 0/10, windows 4/6.

### sin señal de contadores

| Nivel | Episodios | Detección | Por identidad | Por vigilante | Latencia mediana (s) | FA/disp-día de sus sesiones |
|---|---|---|---|---|---|---|
| ingenuo | 40 | 0.975 [0.925, 1.000] | 0.975 [0.925, 1.000] | 0.000 [0.000, 0.000] | 3.7 [3.0, 4.6] | 0.38 [0.00, 1.13] |
| ritmo | 40 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 10.0 [6.6, 17.0] | 0.38 [0.00, 1.13] |
| pila_completa | 40 | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | — | 0.38 [0.00, 1.13] |
| suplantacion_ip | 40 | 0.950 [0.875, 1.000] | 0.000 [0.000, 0.000] | 0.950 [0.875, 1.000] | 3.9 [3.0, 4.1] | 0.38 [0.00, 1.13] |
| victima_apagada | 40 | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 4.6 [3.0, 5.0] | 0.38 [0.00, 1.13] |

Pila completa por familia de la víctima: android 0/7, iot 0/7, linux 0/10, macos 0/10, windows 0/6.

### confirmación en sesiones nuevas (grupos)

| Nivel | Episodios | Detección | Por identidad | Por vigilante | Latencia mediana (s) | FA/disp-día de sus sesiones |
|---|---|---|---|---|---|---|
| ingenuo | 40 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 4.1 [2.9, 5.3] | 0.75 [0.00, 1.88] |
| ritmo | 40 | 0.975 [0.925, 1.000] | 0.975 [0.925, 1.000] | 0.000 [0.000, 0.000] | 11.7 [8.6, 15.0] | 0.75 [0.00, 1.88] |
| pila_completa | 40 | 0.325 [0.175, 0.475] | 0.325 [0.175, 0.475] | 0.000 [0.000, 0.000] | 7.7 [2.5, 33.1] | 0.75 [0.00, 1.88] |
| suplantacion_ip | 40 | 0.975 [0.925, 1.000] | 0.000 [0.000, 0.000] | 0.975 [0.925, 1.000] | 3.0 [2.2, 4.4] | 0.75 [0.00, 1.88] |
| victima_apagada | 40 | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 2.8 [2.2, 4.2] | 0.75 [0.00, 1.88] |

Pila completa por familia de la víctima: android 0/8, iot 10/13, linux 0/5, macos 0/7, windows 3/7.

