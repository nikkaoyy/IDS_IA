# E3B — cifras

Generado por `scripts/evaluar_identidad.py --partes b` el 2026-11-14T02:48:58 en el commit `0d8061e324e3848046f43bc05d51efce60b3cf96` (árbol con cambios).

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

## Bloque 4 — contaminación del perfil (clon de ritmo, defensas por defecto)

| Condición | Episodios | Detección | Cobertura | Absorción | Latencia mediana (s) | Detección de ráfagas |
|---|---|---|---|---|---|---|
| limpio | 40 | 0.950 [0.875, 1.000] | 0.558 [0.487, 0.624] | 0.000 [0.000, 0.000] | 3.5 [2.8, 4.2] | — |
| contaminado_5 | 40 | 0.975 [0.925, 1.000] | 0.576 [0.508, 0.635] | 0.225 [0.100, 0.375] | 3.0 [2.2, 3.6] | 0.575 [0.475, 0.688] (80 ráfagas) |
| contaminado_20 | 40 | 0.825 [0.700, 0.925] | 0.462 [0.380, 0.544] | 0.800 [0.675, 0.900] | 3.2 [2.5, 4.6] | 0.530 [0.487, 0.580] (400 ráfagas) |
| continuo_20 | 40 | 0.850 [0.750, 0.950] | 0.441 [0.352, 0.528] | 1.000 [1.000, 1.000] | 5.1 [3.6, 9.5] | 0.333 [0.292, 0.375] (480 ráfagas) |

## Bloque 4 — ablación de defensas

| Configuración | Condición | Detección | Cobertura | Absorción | FA/disp-día (contaminación) | FA/disp-día con variación | FA/disp-día sin variación | Ventanas no_confiable (variación) |
|---|---|---|---|---|---|---|---|---|
| todas | limpio | 0.950 [0.875, 1.000] | 0.558 [0.487, 0.624] | 0.000 [0.000, 0.000] | 112.49 [74.76, 152.91] | 826.2 [729.9, 919.5] | 9.7 [0.0, 27.5] | 0.128 [0.124, 0.133] |
| todas | contaminado_5 | 0.975 [0.925, 1.000] | 0.576 [0.508, 0.635] | 0.225 [0.100, 0.375] | 112.49 [74.76, 152.91] | 826.2 [729.9, 919.5] | 9.7 [0.0, 27.5] | 0.128 [0.124, 0.133] |
| todas | contaminado_20 | 0.825 [0.700, 0.925] | 0.462 [0.380, 0.544] | 0.800 [0.675, 0.900] | 112.49 [74.76, 152.91] | 826.2 [729.9, 919.5] | 9.7 [0.0, 27.5] | 0.128 [0.124, 0.133] |
| todas | continuo_20 | 0.850 [0.750, 0.950] | 0.441 [0.352, 0.528] | 1.000 [1.000, 1.000] | 112.49 [74.76, 152.91] | 826.2 [729.9, 919.5] | 9.7 [0.0, 27.5] | 0.128 [0.124, 0.133] |
| sin_congelar | limpio | 0.950 [0.875, 1.000] | 0.441 [0.371, 0.505] | 0.000 [0.000, 0.000] | 28.22 [15.82, 43.26] | 265.0 [210.1, 325.4] | 3.2 [0.0, 8.1] | 0.128 [0.124, 0.133] |
| sin_congelar | contaminado_5 | 0.825 [0.700, 0.925] | 0.401 [0.318, 0.482] | 1.000 [1.000, 1.000] | 28.22 [15.82, 43.26] | 265.0 [210.1, 325.4] | 3.2 [0.0, 8.1] | 0.128 [0.124, 0.133] |
| sin_congelar | contaminado_20 | 0.825 [0.700, 0.925] | 0.369 [0.293, 0.456] | 1.000 [1.000, 1.000] | 28.22 [15.82, 43.26] | 265.0 [210.1, 325.4] | 3.2 [0.0, 8.1] | 0.128 [0.124, 0.133] |
| sin_congelar | continuo_20 | 0.825 [0.725, 0.925] | 0.371 [0.297, 0.449] | 1.000 [1.000, 1.000] | 28.22 [15.82, 43.26] | 265.0 [210.1, 325.4] | 3.2 [0.0, 8.1] | 0.128 [0.124, 0.133] |
| sin_no_confiable | limpio | 1.000 [1.000, 1.000] | 0.681 [0.622, 0.736] | 0.000 [0.000, 0.000] | 1354.38 [1168.94, 1535.75] | 3755.6 [3460.6, 4009.3] | 852.7 [569.0, 1194.4] | 0.000 [0.000, 0.000] |
| sin_no_confiable | contaminado_5 | 1.000 [1.000, 1.000] | 0.683 [0.629, 0.732] | 0.000 [0.000, 0.000] | 1354.38 [1168.94, 1535.75] | 3755.6 [3460.6, 4009.3] | 852.7 [569.0, 1194.4] | 0.000 [0.000, 0.000] |
| sin_no_confiable | contaminado_20 | 1.000 [1.000, 1.000] | 0.703 [0.638, 0.756] | 0.050 [0.000, 0.125] | 1354.38 [1168.94, 1535.75] | 3755.6 [3460.6, 4009.3] | 852.7 [569.0, 1194.4] | 0.000 [0.000, 0.000] |
| sin_no_confiable | continuo_20 | 1.000 [1.000, 1.000] | 0.679 [0.635, 0.723] | 0.200 [0.075, 0.325] | 1354.38 [1168.94, 1535.75] | 3755.6 [3460.6, 4009.3] | 852.7 [569.0, 1194.4] | 0.000 [0.000, 0.000] |
| con_tope | limpio | 0.950 [0.875, 1.000] | 0.558 [0.487, 0.624] | 0.000 [0.000, 0.000] | 112.49 [74.76, 152.91] | 826.2 [729.9, 919.5] | 9.7 [0.0, 27.5] | 0.128 [0.124, 0.133] |
| con_tope | contaminado_5 | 0.975 [0.925, 1.000] | 0.576 [0.508, 0.635] | 0.225 [0.100, 0.375] | 112.49 [74.76, 152.91] | 826.2 [729.9, 919.5] | 9.7 [0.0, 27.5] | 0.128 [0.124, 0.133] |
| con_tope | contaminado_20 | 0.825 [0.700, 0.925] | 0.462 [0.380, 0.544] | 0.800 [0.675, 0.900] | 112.49 [74.76, 152.91] | 826.2 [729.9, 919.5] | 9.7 [0.0, 27.5] | 0.128 [0.124, 0.133] |
| con_tope | continuo_20 | 0.850 [0.750, 0.950] | 0.441 [0.352, 0.528] | 1.000 [1.000, 1.000] | 112.49 [74.76, 152.91] | 826.2 [729.9, 919.5] | 9.7 [0.0, 27.5] | 0.128 [0.124, 0.133] |
| con_reperfilado | limpio | 0.950 [0.875, 1.000] | 0.558 [0.487, 0.624] | 0.000 [0.000, 0.000] | 112.49 [74.76, 152.91] | 776.6 [697.6, 853.0] | 9.7 [0.0, 27.5] | 0.132 [0.126, 0.138] |
| con_reperfilado | contaminado_5 | 0.975 [0.925, 1.000] | 0.576 [0.508, 0.635] | 0.225 [0.100, 0.375] | 112.49 [74.76, 152.91] | 776.6 [697.6, 853.0] | 9.7 [0.0, 27.5] | 0.132 [0.126, 0.138] |
| con_reperfilado | contaminado_20 | 0.825 [0.700, 0.925] | 0.462 [0.380, 0.544] | 0.800 [0.675, 0.900] | 112.49 [74.76, 152.91] | 776.6 [697.6, 853.0] | 9.7 [0.0, 27.5] | 0.132 [0.126, 0.138] |
| con_reperfilado | continuo_20 | 0.850 [0.750, 0.950] | 0.441 [0.352, 0.528] | 1.000 [1.000, 1.000] | 112.49 [74.76, 152.91] | 776.6 [697.6, 853.0] | 9.7 [0.0, 27.5] | 0.132 [0.126, 0.138] |

FA fuera de los episodios y las ráfagas, por grupo de dispositivos (FA/disp-día; la víctima es la dueña legítima de la MAC):

| Configuración | no víctimas | limpio | contaminado_5 | contaminado_20 | continuo_20 |
|---|---|---|---|---|---|
| todas | 0.0 [0.0, 0.0] (0) | 2.5 [0.0, 7.4] (1) | 0.0 [0.0, 0.0] (0) | 146.4 [29.3, 303.0] (60) | 582.5 [323.4, 869.0] (238) |
| sin_congelar | 0.0 [0.0, 0.0] (0) | 2.5 [0.0, 7.4] (1) | 0.0 [0.0, 0.0] (0) | 46.3 [14.6, 85.8] (19) | 134.6 [56.3, 230.5] (55) |
| sin_no_confiable | 1386.0 [1135.7, 1650.0] (1419) | 1087.7 [608.2, 1592.8] (442) | 945.3 [584.5, 1275.4] (387) | 1200.1 [705.2, 1740.6] (492) | 2104.9 [1462.5, 2812.0] (860) |
| con_tope | 0.0 [0.0, 0.0] (0) | 2.5 [0.0, 7.4] (1) | 0.0 [0.0, 0.0] (0) | 146.4 [29.3, 303.0] (60) | 582.5 [323.4, 869.0] (238) |
| con_reperfilado | 0.0 [0.0, 0.0] (0) | 2.5 [0.0, 7.4] (1) | 0.0 [0.0, 0.0] (0) | 146.4 [29.3, 303.0] (60) | 582.5 [323.4, 869.0] (238) |

Regla registrada: una defensa se queda si apagarla empeora detección, cobertura o absorción en ≥ 0.05 o las FA en ≥ 1.0/disp-día.

- **sin aprendizaje en alerta**: queda — limpio: cobertura 0.558 → 0.441; contaminado_5: deteccion 0.975 → 0.825; contaminado_5: cobertura 0.576 → 0.401; contaminado_5: absorcion 0.225 → 1.000; contaminado_20: cobertura 0.462 → 0.369; contaminado_20: absorcion 0.800 → 1.000; continuo_20: cobertura 0.441 → 0.371.
- **no_confiable**: queda — FA contaminación: 112.49 → 1354.38; FA con variación: 826.24 → 3755.61; FA sin variación: 9.73 → 852.65.
- **tope diario (apagado tras la ablación)**: apagada — no cambia ninguna cifra.
- **reperfilado (apagado en el bloque 2)**: apagada — no cambia ninguna cifra.

