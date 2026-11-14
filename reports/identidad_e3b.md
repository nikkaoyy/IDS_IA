# E3B — cifras

Generado por `scripts/evaluar_identidad.py --partes b` el 2026-11-14T01:57:53 en el commit `2b480965b3a1306e79b2f71c004c96babca430e9` (árbol con cambios).

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
| con variación (todas) | 200 | 824.3 [725.4, 918.0] | 361.0 [299.2, 417.4] | 0.43 [0.39, 0.47] | 0.128 [0.124, 0.133] | 0.00 [0.00, 0.00] | 0 | tcp_window 665, ttl 662, ipid_salto_log2 268 |
| sin variación (control + gateway) | 60 | 1.6 [0.0, 4.9] | 1.6 [0.0, 4.9] | 0.02 [0.00, 0.05] | 0.101 [0.096, 0.107] | 0.00 [0.00, 0.00] | 0 | ipid_continuidad 1 |
| actualizacion | 40 | 2392.9 [2021.8, 2782.4] | 564.0 [461.0, 668.7] | 0.97 [0.93, 1.00] | 0.157 [0.144, 0.171] | 0.00 [0.00, 0.00] | 0 | ttl 562, tcp_window 418 |
| vpn | 40 | 251.6 [90.5, 442.7] | 88.0 [36.8, 143.7] | 0.23 [0.10, 0.38] | 0.156 [0.138, 0.179] | 0.00 [0.00, 0.00] | 0 | tcp_window 96, ttl 7 |
| dos_pilas | 40 | 1327.7 [1057.7, 1623.3] | 1019.5 [818.2, 1207.7] | 0.80 [0.68, 0.93] | 0.126 [0.116, 0.138] | 0.00 [0.00, 0.00] | 0 | ipid_salto_log2 268, tcp_window 151, ipid_continuidad 94 |
| descubrimiento | 40 | 144.6 [2.4, 325.5] | 125.3 [2.4, 277.4] | 0.10 [0.03, 0.20] | 0.084 [0.082, 0.086] | 0.00 [0.00, 0.00] | 0 | ttl 59, ipid_continuidad 1 |
| deriva_lenta | 40 | 4.9 [0.0, 12.3] | 4.9 [0.0, 12.3] | 0.05 [0.00, 0.12] | 0.159 [0.140, 0.185] | 0.00 [0.00, 0.00] | 0 | ipid_continuidad 2 |
| control | 40 | 2.4 [0.0, 7.4] | 2.4 [0.0, 7.4] | 0.03 [0.00, 0.07] | 0.149 [0.134, 0.169] | 0.00 [0.00, 0.00] | 0 | ipid_continuidad 1 |
| gateway | 20 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.00 [0.00, 0.00] | 0.062 [0.061, 0.062] | 0.00 [0.00, 0.00] | 0 | — |

## Bloque 2 — legítimos con variación real (sin clones), con el reperfilado registrado (24)

| Grupo | Disp. | FA ventanas/disp-día | FA eventos/disp-día | Disp. con FA | Ventanas no_confiable | Nunca confiables | Reperfilados | FA por señal (ventanas) |
|---|---|---|---|---|---|---|---|---|
| con variación (todas) | 200 | 774.6 [693.7, 851.7] | 361.0 [299.2, 417.4] | 0.43 [0.39, 0.47] | 0.132 [0.126, 0.138] | 0.00 [0.00, 0.00] | 7 | tcp_window 665, ttl 560, ipid_salto_log2 268 |
| sin variación (control + gateway) | 60 | 1.6 [0.0, 4.9] | 1.6 [0.0, 4.9] | 0.02 [0.00, 0.05] | 0.101 [0.096, 0.107] | 0.00 [0.00, 0.00] | 0 | ipid_continuidad 1 |
| actualizacion | 40 | 2143.8 [1881.0, 2425.8] | 564.0 [461.0, 668.7] | 0.97 [0.93, 1.00] | 0.178 [0.167, 0.191] | 0.00 [0.00, 0.00] | 7 | ttl 460, tcp_window 418 |
| vpn | 40 | 251.6 [90.5, 442.7] | 88.0 [36.8, 143.7] | 0.23 [0.10, 0.38] | 0.156 [0.138, 0.179] | 0.00 [0.00, 0.00] | 0 | tcp_window 96, ttl 7 |
| dos_pilas | 40 | 1327.7 [1057.7, 1623.3] | 1019.5 [818.2, 1207.7] | 0.80 [0.68, 0.93] | 0.126 [0.116, 0.138] | 0.00 [0.00, 0.00] | 0 | ipid_salto_log2 268, tcp_window 151, ipid_continuidad 94 |
| descubrimiento | 40 | 144.6 [2.4, 325.5] | 125.3 [2.4, 277.4] | 0.10 [0.03, 0.20] | 0.084 [0.082, 0.086] | 0.00 [0.00, 0.00] | 0 | ttl 59, ipid_continuidad 1 |
| deriva_lenta | 40 | 4.9 [0.0, 12.3] | 4.9 [0.0, 12.3] | 0.05 [0.00, 0.12] | 0.159 [0.140, 0.185] | 0.00 [0.00, 0.00] | 0 | ipid_continuidad 2 |
| control | 40 | 2.4 [0.0, 7.4] | 2.4 [0.0, 7.4] | 0.03 [0.00, 0.07] | 0.149 [0.134, 0.169] | 0.00 [0.00, 0.00] | 0 | ipid_continuidad 1 |
| gateway | 20 | 0.0 [0.0, 0.0] | 0.0 [0.0, 0.0] | 0.00 [0.00, 0.00] | 0.062 [0.061, 0.062] | 0.00 [0.00, 0.00] | 0 | — |

