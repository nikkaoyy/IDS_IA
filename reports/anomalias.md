# Detector de anomalías entrenado solo con benigno — cifras

Generado por `scripts/evaluar_anomalias.py` el 2026-11-14T00:36:51 en el commit `596209615deb83309f5ec7eaffd0caec8eec37b7`. Dataset sha256 `7f06d099477a474b12db73001f3ee56a8e14e93bb41501c8b49ee94e4032a945`.

5 folds por sesión × 5 semillas [42, 43, 44, 45, 46]; umbral por validación anidada (3 folds internos, solo benigno) para **≤ 1 falsa alarma por dispositivo-día**; IC 95 % con 1000 réplicas. Conteos: 188 episodios, 873 dispositivos (6.71 dispositivo-días).

## Métricas que deciden

| Modelo / conjunto | Recall episodio | Recall atacante | FA/disp-día | Disp. con ≥1 FA | T. mediana (s) | PR-AUC ventana | Folds sobre el objetivo |
|---|---|---|---|---|---|---|---|
| isolation_forest/sin_capa2 | 0.185 [0.132, 0.244] | 0.309 [0.225, 0.398] | 1.16 [0.21, 2.29] | 0.007 [0.002, 0.012] | 5.0 [5.0, 10.0] | 0.304 [0.259, 0.350] | 10/25 |
| lof/sin_capa2 | 0.132 [0.087, 0.181] | 0.219 [0.138, 0.291] | 1.16 [0.00, 2.84] | 0.002 [0.000, 0.006] | 5.0 [5.0, 10.0] | 0.451 [0.396, 0.516] | 5/25 |
| isolation_forest_pca/sin_capa2 | 0.133 [0.093, 0.177] | 0.233 [0.165, 0.301] | 1.28 [0.18, 2.83] | 0.004 [0.001, 0.009] | 5.0 [5.0, 10.0] | 0.286 [0.252, 0.325] | 11/25 |
| isolation_forest/completo | 0.170 [0.119, 0.227] | 0.289 [0.206, 0.379] | 1.28 [0.47, 2.38] | 0.006 [0.003, 0.010] | 5.0 [5.0, 10.0] | 0.238 [0.202, 0.278] | 9/25 |
| lof/completo | 0.113 [0.070, 0.156] | 0.198 [0.126, 0.270] | 0.83 [0.00, 2.08] | 0.002 [0.000, 0.005] | 5.0 [5.0, 10.0] | 0.439 [0.387, 0.502] | 5/25 |
| isolation_forest_pca/completo | 0.168 [0.119, 0.220] | 0.297 [0.212, 0.377] | 0.51 [0.00, 1.26] | 0.002 [0.000, 0.004] | 5.0 [5.0, 10.0] | 0.247 [0.213, 0.285] | 5/25 |

## Recall por episodio y tipo (todos los tipos son «no vistos» para este detector)

| Modelo / conjunto | arp_spoofing | dns_spoofing | icmp_flood | mac_flooding | port_scan | syn_flood |
|---|---|---|---|---|---|---|
| isolation_forest/sin_capa2 | 0.024 [0.000, 0.071] | 0.073 [0.000, 0.180] | 0.000 [0.000, 0.000] | 0.559 [0.412, 0.707] | 0.179 [0.036, 0.321] | 0.252 [0.123, 0.394] |
| lof/sin_capa2 | 0.218 [0.106, 0.347] | 0.067 [0.000, 0.167] | 0.335 [0.187, 0.503] | 0.029 [0.000, 0.088] | 0.000 [0.000, 0.000] | 0.129 [0.032, 0.258] |
| isolation_forest_pca/sin_capa2 | 0.118 [0.041, 0.224] | 0.127 [0.040, 0.233] | 0.006 [0.000, 0.019] | 0.188 [0.076, 0.318] | 0.143 [0.029, 0.264] | 0.213 [0.090, 0.348] |
| isolation_forest/completo | 0.012 [0.000, 0.035] | 0.073 [0.000, 0.180] | 0.000 [0.000, 0.000] | 0.559 [0.412, 0.707] | 0.164 [0.036, 0.307] | 0.187 [0.065, 0.316] |
| lof/completo | 0.176 [0.076, 0.294] | 0.067 [0.000, 0.167] | 0.232 [0.103, 0.394] | 0.059 [0.000, 0.147] | 0.000 [0.000, 0.000] | 0.129 [0.032, 0.258] |
| isolation_forest_pca/completo | 0.194 [0.076, 0.329] | 0.127 [0.027, 0.260] | 0.058 [0.000, 0.142] | 0.224 [0.094, 0.371] | 0.171 [0.036, 0.314] | 0.226 [0.097, 0.361] |

## Recall por ventana y tipo (referencia)

| Modelo / conjunto | arp_spoofing | dns_spoofing | icmp_flood | mac_flooding | port_scan | syn_flood |
|---|---|---|---|---|---|---|
| isolation_forest/sin_capa2 | 0.002 | 0.009 | 0.000 | 0.058 | 0.025 | 0.036 |
| lof/sin_capa2 | 0.040 | 0.008 | 0.186 | 0.002 | 0.000 | 0.015 |
| isolation_forest_pca/sin_capa2 | 0.021 | 0.013 | 0.002 | 0.010 | 0.013 | 0.030 |
| isolation_forest/completo | 0.001 | 0.009 | 0.000 | 0.056 | 0.023 | 0.018 |
| lof/completo | 0.028 | 0.008 | 0.103 | 0.002 | 0.000 | 0.016 |
| isolation_forest_pca/completo | 0.035 | 0.015 | 0.013 | 0.008 | 0.019 | 0.033 |

## Sonda de deriva: dispositivos legítimos con más falsas alarmas (media de semillas)

**isolation_forest/sin_capa2**: 7.8 falsas alarmas en total; 11 de 854 MAC con alguna; los 5 primeros concentran 69 %.

| MAC | Sesiones | Falsas alarmas | Dispositivo-días | FA/disp-día | Cuota |
|---|---|---|---|---|---|
| `a4:83:e7:cf:70:df` | 1 | 1.4 | 0.010 | 135.2 | 18 % |
| `a4:83:e7:a2:b5:a5` | 1 | 1.2 | 0.010 | 118.5 | 15 % |
| `00:0c:29:68:76:b6` | 1 | 1.0 | 0.010 | 99.9 | 13 % |
| `00:0c:29:bd:0c:6a` | 1 | 1.0 | 0.010 | 96.0 | 13 % |
| `00:50:56:cc:eb:c0` | 1 | 0.8 | 0.010 | 77.2 | 10 % |

**lof/sin_capa2**: 7.8 falsas alarmas en total; 2 de 854 MAC con alguna; los 5 primeros concentran 100 %.

| MAC | Sesiones | Falsas alarmas | Dispositivo-días | FA/disp-día | Cuota |
|---|---|---|---|---|---|
| `f4:8e:38:8a:25:c1` | 1 | 4.4 | 0.010 | 434.5 | 56 % |
| `3c:52:82:cb:0c:43` | 1 | 3.4 | 0.010 | 341.6 | 44 % |
| `00:0c:29:00:ec:3e` | 1 | 0.0 | 0.001 | 0.0 | 0 % |
| `00:0c:29:02:67:0b` | 1 | 0.0 | 0.010 | 0.0 | 0 % |
| `00:0c:29:03:5e:d1` | 1 | 0.0 | 0.010 | 0.0 | 0 % |

**isolation_forest_pca/sin_capa2**: 8.6 falsas alarmas en total; 7 de 854 MAC con alguna; los 5 primeros concentran 93 %.

| MAC | Sesiones | Falsas alarmas | Dispositivo-días | FA/disp-día | Cuota |
|---|---|---|---|---|---|
| `3c:52:82:cb:0c:43` | 1 | 3.2 | 0.010 | 321.5 | 37 % |
| `dc:a6:32:7c:4e:8e` | 1 | 2.6 | 0.010 | 249.6 | 30 % |
| `a4:83:e7:cf:70:df` | 1 | 1.0 | 0.010 | 96.5 | 12 % |
| `00:50:56:74:51:00` | 1 | 0.6 | 0.010 | 57.9 | 7 % |
| `b8:27:eb:f3:2a:f7` | 1 | 0.6 | 0.010 | 57.6 | 7 % |

**isolation_forest/completo**: 8.6 falsas alarmas en total; 10 de 854 MAC con alguna; los 5 primeros concentran 84 %.

| MAC | Sesiones | Falsas alarmas | Dispositivo-días | FA/disp-día | Cuota |
|---|---|---|---|---|---|
| `3c:52:82:c0:0b:8f` | 1 | 3.0 | 0.010 | 288.0 | 35 % |
| `3c:52:82:10:5a:1b` | 1 | 1.6 | 0.010 | 152.8 | 19 % |
| `f4:8e:38:99:e6:96` | 1 | 1.2 | 0.010 | 115.2 | 14 % |
| `00:0c:29:bd:0c:6a` | 1 | 1.0 | 0.010 | 96.0 | 12 % |
| `00:50:56:50:97:c4` | 1 | 0.4 | 0.010 | 38.6 | 5 % |

**lof/completo**: 5.6 falsas alarmas en total; 2 de 854 MAC con alguna; los 5 primeros concentran 100 %.

| MAC | Sesiones | Falsas alarmas | Dispositivo-días | FA/disp-día | Cuota |
|---|---|---|---|---|---|
| `3c:52:82:cb:0c:43` | 1 | 3.4 | 0.010 | 341.6 | 61 % |
| `f4:8e:38:8a:25:c1` | 1 | 2.2 | 0.010 | 217.2 | 39 % |
| `00:0c:29:00:ec:3e` | 1 | 0.0 | 0.001 | 0.0 | 0 % |
| `00:0c:29:02:67:0b` | 1 | 0.0 | 0.010 | 0.0 | 0 % |
| `00:0c:29:03:5e:d1` | 1 | 0.0 | 0.010 | 0.0 | 0 % |

**isolation_forest_pca/completo**: 3.4 falsas alarmas en total; 3 de 854 MAC con alguna; los 5 primeros concentran 100 %.

| MAC | Sesiones | Falsas alarmas | Dispositivo-días | FA/disp-día | Cuota |
|---|---|---|---|---|---|
| `3c:52:82:cb:0c:43` | 1 | 2.0 | 0.010 | 200.9 | 59 % |
| `dc:a6:32:7c:4e:8e` | 1 | 1.2 | 0.010 | 115.2 | 35 % |
| `a4:83:e7:37:c0:38` | 1 | 0.2 | 0.010 | 19.6 | 6 % |
| `00:0c:29:00:ec:3e` | 1 | 0.0 | 0.001 | 0.0 | 0 % |
| `00:0c:29:02:67:0b` | 1 | 0.0 | 0.010 | 0.0 | 0 % |

## Referencias del supervisado (leídas de sus informes)

| Referencia | Recall episodio |
|---|---|
| supervisado_random_forest_completo_con_tipo | 0.878 [0.834, 0.922] |
| supervisado_xgboost_completo_con_tipo | 0.894 [0.856, 0.936] |
| supervisado_random_forest_sin_capa2_loao | 0.068 [0.032, 0.105] |
| supervisado_xgboost_sin_capa2_loao | 0.228 [0.168, 0.286] |
