# Ablaciones E2 — cifras

Generado por `scripts/ablaciones.py` el 2026-11-13T10:21:53 en el commit `8050745cfb4685a112914192c41b53f6ac44b57c` (árbol con cambios). Dataset sha256 `3f4d28bcd1d2fee5cd5aeab0ae31d5213262a097f7a051fe87b6e63f9e04eced`. Semillas [42], umbral anidado para ≤ 1 FA/dispositivo-día.

## Leave-one-attack-out (recall por episodio del tipo excluido)

| Tipo excluido | Modelo | Sin el tipo en train | Con el tipo en train | Caída | FA/disp-día |
|---|---|---|---|---|---|
| arp_spoofing | random_forest | 0.000 [0.000, 0.000] (n=34) | 0.824 [0.676, 0.941] | +0.824 | 1.04 [0.30, 1.92] |
| dns_spoofing | random_forest | 0.033 [0.000, 0.100] (n=30) | 0.733 [0.567, 0.867] | +0.700 | 1.34 [0.30, 2.67] |
| icmp_flood | random_forest | 0.065 [0.000, 0.161] (n=31) | 0.516 [0.323, 0.677] | +0.452 | 1.79 [0.60, 3.26] |
| mac_flooding | random_forest | 0.000 [0.000, 0.000] (n=34) | 1.000 [1.000, 1.000] | +1.000 | 1.19 [0.00, 2.95] |
| port_scan | random_forest | 0.036 [0.000, 0.107] (n=28) | 0.714 [0.536, 0.857] | +0.679 | 1.19 [0.15, 2.47] |
| syn_flood | random_forest | 0.032 [0.000, 0.097] (n=31) | 1.000 [1.000, 1.000] | +0.968 | 0.89 [0.00, 2.03] |
| arp_spoofing | xgboost | 0.000 [0.000, 0.000] (n=34) | 0.824 [0.706, 0.941] | +0.824 | 0.60 [0.00, 1.81] |
| dns_spoofing | xgboost | 0.167 [0.033, 0.301] (n=30) | 0.733 [0.600, 0.867] | +0.567 | 0.74 [0.00, 1.82] |
| icmp_flood | xgboost | 0.129 [0.032, 0.258] (n=31) | 0.484 [0.290, 0.677] | +0.355 | 0.45 [0.00, 1.33] |
| mac_flooding | xgboost | 0.029 [0.000, 0.088] (n=34) | 1.000 [1.000, 1.000] | +0.971 | 0.74 [0.00, 2.04] |
| port_scan | xgboost | 0.179 [0.036, 0.321] (n=28) | 0.714 [0.536, 0.893] | +0.536 | 0.74 [0.00, 2.06] |
| syn_flood | xgboost | 0.161 [0.064, 0.290] (n=31) | 0.935 [0.839, 1.000] | +0.774 | 1.49 [0.30, 2.95] |

## Ablación por conjunto de características

| Conjunto | Modelo | n col. | Recall episodio | FA/disp-día | PR-AUC ventana |
|---|---|---|---|---|---|
| capa2 | random_forest | 14 | 0.197 [0.144, 0.250] | 0.30 [0.00, 0.75] | 0.893 [0.837, 0.930] |
| capas3_4 | random_forest | 18 | 0.000 [0.000, 0.000] | 0.00 [0.00, 0.00] | 0.907 [0.855, 0.939] |
| completo | random_forest | 49 | 0.803 [0.750, 0.862] | 1.49 [0.31, 2.84] | 0.981 [0.968, 0.989] |
| capa2 | xgboost | 14 | 0.399 [0.335, 0.473] | 1.34 [0.46, 2.26] | 0.902 [0.850, 0.936] |
| capas3_4 | xgboost | 18 | 0.505 [0.436, 0.580] | 1.04 [0.45, 1.63] | 0.922 [0.879, 0.950] |
| completo | xgboost | 49 | 0.787 [0.734, 0.840] | 1.04 [0.00, 2.58] | 0.984 [0.973, 0.991] |

Recall por episodio y tipo:

| Conjunto | Modelo | arp_spoofing | dns_spoofing | icmp_flood | mac_flooding | port_scan | syn_flood |
|---|---|---|---|---|---|---|---|
| capa2 | random_forest | 0.06 | 0.20 | 0.03 | 0.65 | 0.00 | 0.19 |
| capas3_4 | random_forest | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| completo | random_forest | 0.82 | 0.73 | 0.52 | 1.00 | 0.71 | 1.00 |
| capa2 | xgboost | 0.26 | 0.43 | 0.26 | 1.00 | 0.00 | 0.35 |
| capas3_4 | xgboost | 0.09 | 0.30 | 0.16 | 1.00 | 0.57 | 0.90 |
| completo | xgboost | 0.82 | 0.73 | 0.48 | 1.00 | 0.71 | 0.94 |

## Multiclase

| Etiqueta | Modelo | Exactitud bal. (ventana) | F1 macro (ventana) | Acierto por episodio | Acierto entre detectados |
|---|---|---|---|---|---|
| tipo_ataque | random_forest | 0.843 | 0.855 | 0.941 | 0.962 |
| tipo_ataque | xgboost | 0.910 | 0.899 | 0.963 | 0.968 |
| capa | random_forest | 0.832 | 0.850 | 0.941 | 0.962 |
| capa | xgboost | 0.906 | 0.897 | 0.963 | 0.968 |

## Importancia por permutación — random_forest

Base (media de folds): PR-AUC 0.976, recall por episodio 0.802. 5 repeticiones por fold.

| Familia | Caída recall episodio | Caída PR-AUC | Δ FA/disp-día |
|---|---|---|---|
| capa2 | +0.505 ± 0.100 | +0.478 ± 0.033 | -0.89 |
| tcp | +0.467 ± 0.086 | +0.303 ± 0.074 | -0.35 |
| largas_60s | +0.385 ± 0.070 | +0.079 ± 0.020 | -1.11 |
| dns | +0.105 ± 0.040 | +0.018 ± 0.014 | -0.64 |
| arp | +0.056 ± 0.030 | +0.007 ± 0.004 | -0.32 |
| globales | +0.031 ± 0.055 | +0.004 ± 0.003 | -0.14 |

| Característica (top 10 por caída de PR-AUC) | Caída PR-AUC | Caída recall episodio |
|---|---|---|
| longitud_trama_std | +0.0917 | +0.1483 |
| ips_origen_distintas | +0.0588 | +0.0997 |
| longitud_trama_media | +0.0407 | +0.1007 |
| n_rst | +0.0124 | -0.0097 |
| n_tramas_60s | +0.0123 | +0.0509 |
| ips_destino_distintas_60s | +0.0115 | +0.0378 |
| n_icmp_echo | +0.0113 | -0.0102 |
| entropia_puertos_destino | +0.0088 | +0.0607 |
| iat_std_ms | +0.0079 | +0.0657 |
| arp_cambios_vinculo_60s | +0.0077 | +0.0940 |

## Importancia por permutación — xgboost

Base (media de folds): PR-AUC 0.981, recall por episodio 0.797. 5 repeticiones por fold.

| Familia | Caída recall episodio | Caída PR-AUC | Δ FA/disp-día |
|---|---|---|---|
| capa2 | +0.297 ± 0.068 | +0.555 ± 0.018 | +1.39 |
| largas_60s | +0.249 ± 0.057 | +0.141 ± 0.020 | -0.22 |
| tcp | +0.159 ± 0.073 | +0.176 ± 0.063 | +11.52 |
| arp | +0.109 ± 0.044 | +0.012 ± 0.007 | +0.03 |
| dns | +0.036 ± 0.035 | +0.014 ± 0.012 | -0.03 |
| globales | -0.009 ± 0.028 | +0.002 ± 0.002 | +0.18 |

| Característica (top 10 por caída de PR-AUC) | Caída PR-AUC | Caída recall episodio |
|---|---|---|
| longitud_trama_std | +0.2525 | +0.0789 |
| longitud_trama_media | +0.0772 | +0.0411 |
| ips_origen_distintas | +0.0437 | +0.0159 |
| ips_destino_distintas_60s | +0.0248 | +0.0095 |
| n_tramas_60s | +0.0235 | +0.0251 |
| iat_std_ms | +0.0173 | +0.0371 |
| iat_media_ms | +0.0173 | +0.0072 |
| entropia_puertos_destino | +0.0163 | +0.0127 |
| n_rst | +0.0161 | -0.0043 |
| n_icmp_echo | +0.0113 | +0.0007 |
