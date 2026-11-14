# Ablaciones E2 — cifras

Generado por `scripts/ablaciones.py` el 2026-11-13T19:12:24 en el commit `7fb1019b495aca498b41d5bc9e197608e08eccdb` (árbol con cambios). Dataset sha256 `3f4d28bcd1d2fee5cd5aeab0ae31d5213262a097f7a051fe87b6e63f9e04eced`. Semillas [42], umbral anidado para ≤ 1 FA/dispositivo-día.

## Leave-one-attack-out (recall por episodio del tipo excluido; conjunto `completo`)

- **random_forest**: media de los seis 0.028 [0.006, 0.055] (con el tipo en train 0.798 [0.745, 0.850]); mínimo 0.000 (arp_spoofing)
- **xgboost**: media de los seis 0.111 [0.067, 0.156] (con el tipo en train 0.782 [0.729, 0.837]); mínimo 0.000 (arp_spoofing)

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
