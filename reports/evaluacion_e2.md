# Evaluación E2 — cifras

Generado por `scripts/evaluar.py` el 2026-11-13T22:09:43 en el commit `b092487fb7b19b43c139440120c0617bc498f630` (árbol con cambios).
Dataset `data/dataset_lab.csv` sha256 `7f06d099477a474b12db73001f3ee56a8e14e93bb41501c8b49ee94e4032a945`.

5 folds agrupados por sesión × 5 semillas [42, 43, 44, 45, 46]; umbral por validación anidada (3 folds internos) para **≤ 1 falsa alarma por dispositivo-día**; IC 95 % con 1000 réplicas bootstrap (semilla 42).

Conteos: 20 sesiones, 188 episodios, 97 atacantes, 873 dispositivos (6.71 dispositivo-días), 78988 ventanas (5715 maliciosas, 72523 benignas limpias, 750 ambiguas).

## Métricas que deciden (por episodio, atacante y dispositivo)

| Métrica | random_forest | xgboost |
|---|---|---|
| Recall por episodio | 0.878 [0.834, 0.922] | 0.894 [0.856, 0.936] |
| Recall por atacante | 0.918 [0.862, 0.967] | 0.938 [0.887, 0.979] |
| Falsas alarmas / dispositivo-día | 1.19 [0.37, 2.18] | 0.89 [0.00, 2.06] |
| Dispositivos con ≥1 falsa alarma | 0.005 [0.002, 0.009] | 0.003 [0.000, 0.007] |
| Tiempo hasta la detección, mediana (s) | 5.0 [5.0, 10.0] | 5.0 [5.0, 5.0] |
| Tiempo hasta la detección, p90 (s) | 40.0 [25.0, 60.0] | 35.0 [25.0, 40.0] |

## Referencia por ventana

| Métrica | random_forest | xgboost |
|---|---|---|
| PR-AUC | 0.986 [0.974, 0.993] | 0.989 [0.978, 0.994] |
| Recall por ventana en el umbral | 0.802 [0.742, 0.849] | 0.841 [0.783, 0.881] |
| FPR por ventana en el umbral (×10⁻³) | 0.110 [0.034, 0.203] | 0.083 [0.000, 0.193] |

## Recall por tipo de ataque

| Tipo | random_forest episodio | random_forest ventana | random_forest t. mediana (s) | xgboost episodio | xgboost ventana | xgboost t. mediana (s) |
|---|---|---|---|---|---|---|
| arp_spoofing | 0.900 [0.794, 0.988] (n=34) | 0.542 | 10.0 [5.0, 10.0] | 0.912 [0.824, 1.000] (n=34) | 0.654 | 5.0 [5.0, 10.0] |
| dns_spoofing | 0.800 [0.660, 0.920] (n=30) | 0.433 | 10.0 [5.0, 20.0] | 0.867 [0.733, 0.967] (n=30) | 0.551 | 7.5 [5.0, 10.0] |
| icmp_flood | 0.755 [0.600, 0.897] (n=31) | 0.710 | 5.0 [5.0, 5.0] | 0.806 [0.645, 0.935] (n=31) | 0.755 | 5.0 [5.0, 5.0] |
| mac_flooding | 1.000 [1.000, 1.000] (n=34) | 0.987 | 5.0 [5.0, 5.0] | 1.000 [1.000, 1.000] (n=34) | 0.992 | 5.0 [5.0, 5.0] |
| port_scan | 0.786 [0.636, 0.914] (n=28) | 0.466 | 20.0 [15.0, 35.0] | 0.786 [0.643, 0.929] (n=28) | 0.552 | 20.0 [15.0, 30.0] |
| syn_flood | 1.000 [1.000, 1.000] (n=31) | 0.804 | 5.0 [5.0, 10.0] | 0.968 [0.903, 1.000] (n=31) | 0.836 | 5.0 [5.0, 10.0] |

## Recall por intensidad

| Intensidad | random_forest | xgboost |
|---|---|---|
| media | 0.945 [0.887, 0.994] (n=62) | 0.935 [0.871, 0.984] (n=62) |
| rafaga | 0.800 [0.659, 0.912] (n=34) | 0.824 [0.676, 0.941] (n=34) |
| suave | 0.861 [0.791, 0.926] (n=92) | 0.891 [0.826, 0.957] (n=92) |

## Sensibilidad al objetivo de falsas alarmas

| Objetivo (FA/disp-día) | Modelo | Recall episodio | FA/disp-día medidas | T. mediana (s) |
|---|---|---|---|---|
| 0.25 | random_forest | 0.832 [0.783, 0.884] | 0.36 [0.03, 0.84] | 10.0 [5.0, 10.0] |
| 0.25 | xgboost | 0.846 [0.798, 0.899] | 0.45 [0.00, 1.05] | 5.0 [5.0, 10.0] |
| 1 | random_forest | 0.878 [0.834, 0.922] | 1.19 [0.37, 2.18] | 5.0 [5.0, 10.0] |
| 1 | xgboost | 0.894 [0.856, 0.936] | 0.89 [0.00, 2.06] | 5.0 [5.0, 5.0] |
| 4 | random_forest | 0.917 [0.880, 0.955] | 4.80 [2.06, 8.45] | 5.0 [5.0, 5.0] |
| 4 | xgboost | 0.926 [0.893, 0.963] | 3.58 [1.21, 6.32] | 5.0 [5.0, 5.0] |
| 16 | random_forest | 0.944 [0.912, 0.974] | 12.87 [6.64, 20.80] | 5.0 [5.0, 5.0] |
| 16 | xgboost | 0.957 [0.931, 0.984] | 13.11 [8.86, 17.43] | 5.0 [5.0, 5.0] |

## Umbrales elegidos (validación anidada)

| Modelo | mín | mediana | máx |
|---|---|---|---|
| random_forest | 0.7400 | 0.7800 | 0.8350 |
| xgboost | 0.9800 | 0.9843 | 0.9874 |

Las particiones (sesiones de test por fold y semilla) están en el JSON, en `modelos.<modelo>.corridas[].folds[].sesiones_test`.
