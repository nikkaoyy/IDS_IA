# Ablaciones E2 — cifras

Generado por `scripts/ablaciones.py` el 2026-11-13T21:15:39 en el commit `b092487fb7b19b43c139440120c0617bc498f630` (árbol con cambios). Dataset sha256 `7f06d099477a474b12db73001f3ee56a8e14e93bb41501c8b49ee94e4032a945`. Semillas [42], umbral anidado para ≤ 1 FA/dispositivo-día.

## Leave-one-attack-out (recall por episodio del tipo excluido; conjunto `sin_capa2`)

- **random_forest**: media de los seis 0.068 [0.032, 0.105] (con el tipo en train 0.728 [0.665, 0.784]); mínimo 0.000 (mac_flooding)
- **xgboost**: media de los seis 0.228 [0.168, 0.286] (con el tipo en train 0.829 [0.776, 0.878]); mínimo 0.100 (dns_spoofing)

| Tipo excluido | Modelo | Sin el tipo en train | Con el tipo en train | Caída | FA/disp-día |
|---|---|---|---|---|---|
| arp_spoofing | random_forest | 0.147 [0.029, 0.265] (n=34) | 0.588 [0.412, 0.765] | +0.441 | 2.38 [0.45, 5.15] |
| dns_spoofing | random_forest | 0.100 [0.000, 0.233] (n=30) | 0.500 [0.333, 0.667] | +0.400 | 1.64 [0.15, 3.42] |
| icmp_flood | random_forest | 0.097 [0.000, 0.194] (n=31) | 0.742 [0.581, 0.903] | +0.645 | 1.94 [0.46, 3.76] |
| mac_flooding | random_forest | 0.000 [0.000, 0.000] (n=34) | 1.000 [1.000, 1.000] | +1.000 | 1.49 [0.15, 3.55] |
| port_scan | random_forest | 0.000 [0.000, 0.000] (n=28) | 0.571 [0.393, 0.750] | +0.571 | 1.04 [0.30, 1.94] |
| syn_flood | random_forest | 0.065 [0.000, 0.161] (n=31) | 0.968 [0.903, 1.000] | +0.903 | 2.23 [0.75, 4.06] |
| arp_spoofing | xgboost | 0.294 [0.147, 0.441] (n=34) | 0.853 [0.735, 0.942] | +0.559 | 0.89 [0.15, 1.77] |
| dns_spoofing | xgboost | 0.100 [0.000, 0.233] (n=30) | 0.567 [0.400, 0.733] | +0.467 | 1.34 [0.30, 2.64] |
| icmp_flood | xgboost | 0.161 [0.064, 0.290] (n=31) | 0.839 [0.710, 0.968] | +0.677 | 0.89 [0.15, 1.74] |
| mac_flooding | xgboost | 0.265 [0.146, 0.412] (n=34) | 1.000 [1.000, 1.000] | +0.735 | 1.04 [0.00, 2.52] |
| port_scan | xgboost | 0.321 [0.143, 0.500] (n=28) | 0.750 [0.571, 0.893] | +0.429 | 1.04 [0.30, 2.09] |
| syn_flood | xgboost | 0.226 [0.097, 0.387] (n=31) | 0.968 [0.903, 1.000] | +0.742 | 0.60 [0.15, 1.18] |
