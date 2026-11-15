# Régimen invisible del ARP lento (E4C) — cifras

Generado por `scripts/evaluar_robustez.py` el 2026-11-14T20:24:20 en el commit `afd9c8b9bdee0b200ddc413ed3de95ab9ddb9bdf` (árbol con cambios).
Dataset `data/dataset_lab.csv` sha256 `7f06d099477a474b12db73001f3ee56a8e14e93bb41501c8b49ee94e4032a945`. Umbral de operación 0.9086 (XGB, 1 FA/disp-día de E2).

Episodios ARP retemporizados sobre el corpus congelado; DNS en su tiempo nativo (la carrera es su suelo de efecto, no la tasa). Detección por canal: supervisado sobre ventanas etiquetadas; identidad y vigilante por solape temporal.

## ARP: recall por canal frente al paso entre tramas

| Paso | n | Ventanas etiq. (media) | Invisibles | Supervisado | Identidad | Vigilante | OR | Horizonte (s) |
|---|---|---|---|---|---|---|---|---|
| nativo | 2 | 11.0 | 0 | 1.000 | 0.500 | 1.000 | 1.000 | 60.0 |
| 5s | 2 | 0.0 | 2 | 0.000 | 1.000 | 1.000 | 1.000 | 305.0 |
| 15s | 2 | 0.0 | 2 | 0.000 | 1.000 | 1.000 | 1.000 | 310.0 |
| 30s | 2 | 0.0 | 2 | 0.000 | 1.000 | 1.000 | 1.000 | 307.5 |
| 60s | 2 | 0.0 | 2 | 0.000 | 1.000 | 1.000 | 1.000 | 305.0 |

## DNS spoofing (tiempo nativo, la carrera)

Supervisado 1.000 · identidad 0.500 · vigilante 0.500 · OR 1.000 (n=2, 0 invisibles).

## Veredicto de las predicciones registradas

- **P1** (con paso ≥ 30 s el ARP es invisible para el supervisado): **se cumple**. El supervisado queda ciego a partir de **5s**.
- **P2** (el vigilante con el bloque 1 sí ve el ARP lento): **se cumple**.

FA del vigilante sobre las 20 sesiones de variación benigna de E3B: **0.0/disp-día** (0 alertas en 2.71 disp-día). Sesgo declarado: el generador de variación no tiene DHCP ni failover, así que esta cifra es optimista.

## Invariantes de efecto (citados, no medidos)

| Ataque | `suave` | Invariante | Suelo | Lectura |
|---|---|---|---|---|
| arp_spoofing | 0,25–0,8 ARP/s, 120–400 s | refrescar antes del gc_stale de la caché (≈60 s Linux, ≈30 s Windows) | ≥ 1/60 s ≈ 0,017 ARP/s | `suave` por encima del suelo: sigue envenenando la caché |
| dns_spoofing | 0,3–0,7 resp/s, 120–400 s | la respuesta forjada llega antes que la legítima (ventana de RTT) | 1 respuesta por consulta dentro de la ventana de RTT | el efecto lo pone la carrera por consulta, no la tasa agregada |
