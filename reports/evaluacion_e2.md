# Evaluación E2 — cifras

Generado por `scripts/evaluar.py` el 2026-11-13T00:51:52 en el commit `cd01e1a37ef6da68be95a6c1ef12e85ecf96a4f8` (árbol con cambios).
Dataset `data/dataset_lab.csv` sha256 `3f4d28bcd1d2fee5cd5aeab0ae31d5213262a097f7a051fe87b6e63f9e04eced`.

5 folds agrupados por sesión × 5 semillas [42, 43, 44, 45, 46]; umbral por validación anidada (3 folds internos) para **≤ 1 falsa alarma por dispositivo-día**; IC 95 % con 1000 réplicas bootstrap (semilla 42).

Conteos: 20 sesiones, 188 episodios, 97 atacantes, 873 dispositivos (6.71 dispositivo-días), 78988 ventanas (5715 maliciosas, 72523 benignas limpias, 750 ambiguas).

## Métricas que deciden (por episodio, atacante y dispositivo)

| Métrica | random_forest | xgboost |
|---|---|---|
| Recall por episodio | 0.787 [0.732, 0.843] | 0.787 [0.734, 0.840] |
| Recall por atacante | 0.827 [0.751, 0.899] | 0.856 [0.784, 0.918] |
| Falsas alarmas / dispositivo-día | 0.95 [0.24, 1.81] | 1.04 [0.00, 2.58] |
| Dispositivos con ≥1 falsa alarma | 0.005 [0.002, 0.009] | 0.002 [0.000, 0.006] |
| Tiempo hasta la detección, mediana (s) | 10.0 [10.0, 10.0] | 10.0 [5.0, 10.0] |
| Tiempo hasta la detección, p90 (s) | 60.0 [40.0, 85.0] | 55.0 [40.0, 80.0] |

## Referencia por ventana

| Métrica | random_forest | xgboost |
|---|---|---|
| PR-AUC | 0.981 [0.969, 0.989] | 0.984 [0.973, 0.991] |
| Recall por ventana en el umbral | 0.697 [0.599, 0.766] | 0.714 [0.613, 0.786] |
| FPR por ventana en el umbral (×10⁻³) | 0.088 [0.022, 0.169] | 0.097 [0.000, 0.237] |

## Recall por tipo de ataque

| Tipo | random_forest episodio | random_forest ventana | random_forest t. mediana (s) | xgboost episodio | xgboost ventana | xgboost t. mediana (s) |
|---|---|---|---|---|---|---|
| arp_spoofing | 0.800 [0.676, 0.900] (n=34) | 0.371 | 10.0 [10.0, 15.0] | 0.824 [0.706, 0.941] (n=34) | 0.436 | 10.0 [5.0, 12.5] |
| dns_spoofing | 0.727 [0.573, 0.873] (n=30) | 0.335 | 10.0 [10.0, 25.0] | 0.733 [0.600, 0.867] (n=30) | 0.396 | 10.0 [5.0, 15.0] |
| icmp_flood | 0.439 [0.265, 0.600] (n=31) | 0.125 | 22.5 [15.0, 40.0] | 0.484 [0.290, 0.677] (n=31) | 0.145 | 30.0 [15.0, 35.0] |
| mac_flooding | 1.000 [1.000, 1.000] (n=34) | 0.981 | 5.0 [5.0, 5.0] | 1.000 [1.000, 1.000] (n=34) | 0.985 | 5.0 [5.0, 5.0] |
| port_scan | 0.729 [0.571, 0.879] (n=28) | 0.364 | 25.0 [17.5, 40.0] | 0.714 [0.536, 0.893] (n=28) | 0.374 | 32.5 [15.0, 50.0] |
| syn_flood | 1.000 [1.000, 1.000] (n=31) | 0.747 | 10.0 [5.0, 10.0] | 0.935 [0.839, 1.000] (n=31) | 0.747 | 5.0 [5.0, 10.0] |

## Recall por intensidad

| Intensidad | random_forest | xgboost |
|---|---|---|
| media | 0.839 [0.745, 0.919] (n=62) | 0.871 [0.774, 0.952] (n=62) |
| rafaga | 0.606 [0.453, 0.747] (n=34) | 0.706 [0.559, 0.853] (n=34) |
| suave | 0.820 [0.743, 0.896] (n=92) | 0.761 [0.674, 0.848] (n=92) |

## Sensibilidad al objetivo de falsas alarmas

| Objetivo (FA/disp-día) | Modelo | Recall episodio | FA/disp-día medidas | T. mediana (s) |
|---|---|---|---|---|
| 0.25 | random_forest | 0.695 [0.636, 0.753] | 0.30 [0.00, 0.69] | 10.0 [10.0, 10.0] |
| 0.25 | xgboost | 0.622 [0.559, 0.691] | 0.60 [0.00, 1.60] | 10.0 [5.0, 10.0] |
| 1 | random_forest | 0.787 [0.732, 0.843] | 0.95 [0.24, 1.81] | 10.0 [10.0, 10.0] |
| 1 | xgboost | 0.787 [0.734, 0.840] | 1.04 [0.00, 2.58] | 10.0 [5.0, 10.0] |
| 4 | random_forest | 0.874 [0.831, 0.918] | 5.66 [2.46, 9.58] | 10.0 [5.0, 10.0] |
| 4 | xgboost | 0.910 [0.872, 0.947] | 3.58 [1.23, 6.39] | 5.0 [5.0, 10.0] |
| 16 | random_forest | 0.954 [0.926, 0.981] | 14.39 [7.66, 22.49] | 5.0 [5.0, 10.0] |
| 16 | xgboost | 0.968 [0.941, 0.989] | 15.94 [10.25, 22.49] | 5.0 [5.0, 5.0] |

## Umbrales elegidos (validación anidada)

| Modelo | mín | mediana | máx |
|---|---|---|---|
| random_forest | 0.7900 | 0.8400 | 0.8750 |
| xgboost | 0.9891 | 0.9925 | 0.9975 |

Las particiones (sesiones de test por fold y semilla) están en el JSON, en `modelos.<modelo>.corridas[].folds[].sesiones_test`.
