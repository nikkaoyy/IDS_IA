# Ablaciones E2 — cifras

Generado por `scripts/ablaciones.py` el 2026-11-13T19:22:44 en el commit `7fb1019b495aca498b41d5bc9e197608e08eccdb` (árbol con cambios). Dataset sha256 `3f4d28bcd1d2fee5cd5aeab0ae31d5213262a097f7a051fe87b6e63f9e04eced`. Semillas [42], umbral anidado para ≤ 1 FA/dispositivo-día.

## Leave-one-attack-out (recall por episodio del tipo excluido; conjunto `sin_capa2`)

- **random_forest**: media de los seis 0.044 [0.016, 0.076] (con el tipo en train 0.616 [0.557, 0.680]); mínimo 0.000 (arp_spoofing)
- **xgboost**: media de los seis 0.116 [0.074, 0.156] (con el tipo en train 0.702 [0.645, 0.757]); mínimo 0.000 (arp_spoofing)

| Tipo excluido | Modelo | Sin el tipo en train | Con el tipo en train | Caída | FA/disp-día |
|---|---|---|---|---|---|
| arp_spoofing | random_forest | 0.000 [0.000, 0.000] (n=34) | 0.500 [0.324, 0.647] | +0.500 | 1.64 [0.31, 3.22] |
| dns_spoofing | random_forest | 0.100 [0.000, 0.233] (n=30) | 0.433 [0.267, 0.600] | +0.333 | 1.49 [0.31, 2.92] |
| icmp_flood | random_forest | 0.129 [0.032, 0.258] (n=31) | 0.290 [0.160, 0.452] | +0.161 | 2.38 [0.46, 4.85] |
| mac_flooding | random_forest | 0.000 [0.000, 0.000] (n=34) | 1.000 [1.000, 1.000] | +1.000 | 1.79 [0.00, 4.29] |
| port_scan | random_forest | 0.000 [0.000, 0.000] (n=28) | 0.536 [0.357, 0.714] | +0.536 | 1.94 [0.44, 3.86] |
| syn_flood | random_forest | 0.032 [0.000, 0.097] (n=31) | 0.935 [0.839, 1.000] | +0.903 | 1.49 [0.30, 3.09] |
| arp_spoofing | xgboost | 0.000 [0.000, 0.000] (n=34) | 0.882 [0.765, 0.971] | +0.882 | 1.04 [0.00, 2.66] |
| dns_spoofing | xgboost | 0.033 [0.000, 0.100] (n=30) | 0.567 [0.400, 0.733] | +0.533 | 1.49 [0.30, 3.06] |
| icmp_flood | xgboost | 0.097 [0.000, 0.226] (n=31) | 0.258 [0.129, 0.419] | +0.161 | 0.74 [0.29, 1.32] |
| mac_flooding | xgboost | 0.294 [0.147, 0.441] (n=34) | 1.000 [1.000, 1.000] | +0.706 | 1.34 [0.00, 2.89] |
| port_scan | xgboost | 0.143 [0.036, 0.286] (n=28) | 0.536 [0.357, 0.714] | +0.393 | 1.49 [0.45, 2.87] |
| syn_flood | xgboost | 0.129 [0.032, 0.258] (n=31) | 0.968 [0.903, 1.000] | +0.839 | 1.64 [0.62, 2.76] |
