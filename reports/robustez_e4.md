# Robustez del detector (E4R) — cifras

Generado por `scripts/evaluar_robustez.py` el 2026-11-14T19:31:06 en el commit `cbcea22f95013a868a727a544537c9c806900f7c`.
Dataset `data/dataset_lab.csv` sha256 `7f06d099477a474b12db73001f3ee56a8e14e93bb41501c8b49ee94e4032a945` (78988 ventanas).

Canal supervisado: XGBoost, validación anidada al punto de operación de E2 (≤ 1 FA/disp-día), 5 folds × 5 semillas.

## Recall por intensidad (episodios etiquetables vs todos, con invisibles)

| Intensidad | Recall etiquetable (IC) | Etiquetables | Invisibles | Recall sobre todos |
|---|---|---|---|---|
| media | 0.935 [0.871, 0.984] | 62 | 0 | 0.935 |
| rafaga | 0.824 [0.676, 0.941] | 34 | 0 | 0.824 |
| suave | 0.891 [0.826, 0.957] | 92 | 0 | 0.891 |

## Recall por tipo de ataque (etiquetable vs todos)

| Tipo | Recall etiquetable (IC) | Etiquetables | Invisibles | Recall sobre todos |
|---|---|---|---|---|
| arp_spoofing | 0.912 [0.824, 1.000] | 34 | 0 | 0.912 |
| dns_spoofing | 0.867 [0.733, 0.967] | 30 | 0 | 0.867 |
| icmp_flood | 0.806 [0.645, 0.935] | 31 | 0 | 0.806 |
| mac_flooding | 1.000 [1.000, 1.000] | 34 | 0 | 1.000 |
| port_scan | 0.786 [0.643, 0.929] | 28 | 0 | 0.786 |
| syn_flood | 0.968 [0.903, 1.000] | 31 | 0 | 0.968 |

Invisibles por construcción (máx `n_tramas_ataque` < K=2 en todas sus ventanas): **0** episodios.
El IC mostrado es el de los episodios etiquetables (de `ev.resumir`); la columna «sobre todos» añade los invisibles como no detectados y no lleva IC propio.

## Canales por separado y el OR

Detección por episodio etiquetable; el supervisado entra en el OR con la semilla 42. Identidad y vigilante por solape temporal sobre los pcaps de ataque.

| Tipo | Supervisado(42) | Identidad | Vigilante | OR |
|---|---|---|---|---|
| arp_spoofing | 0.912 | 0.324 | 0.000 | 0.971 |
| dns_spoofing | 0.867 | 0.333 | 0.000 | 0.867 |
| icmp_flood | 0.806 | 0.452 | 0.000 | 0.903 |
| mac_flooding | 1.000 | 0.000 | 0.000 | 1.000 |
| port_scan | 0.786 | 0.714 | 0.000 | 0.929 |
| syn_flood | 0.968 | 0.581 | 0.000 | 1.000 |
| **global** | 0.894 | 0.388 | 0.000 | 0.947 |

El OR añade **+0.053** de recall sobre el supervisado. Costo en FA/disp-día sobre estas sesiones: supervisado 0.89, vigilante 0.0, identidad 122.06 (referencia E3B con variación benigna: 826.24); OR total 122.95.

## Invariantes de efecto (el suelo lo pone la física, no el detector)

Tasa `suave` real del generador congelado (`RANGOS_ATAQUE`) frente al suelo teórico que conserva el efecto, y el recall del supervisado medido en `suave`.

| Ataque | `suave` (generador) | Invariante | Suelo de efecto | Recall `suave` | Invisibles `suave` |
|---|---|---|---|---|---|
| syn_flood | 0,4–2,5 SYN/s, 120–400 s | agotar el backlog (N) antes del primer reintento SYN-ACK (RTO) | N/RTO ≈ 64/3 ≈ 21 medios-abiertos/s | 1.000 | 0 |
| arp_spoofing | 0,25–0,8 ARP/s, 120–400 s | refrescar antes del gc_stale de la caché (≈60 s Linux, ≈30 s Windows) | ≥ 1/60 s ≈ 0,017 ARP/s | 1.000 | 0 |
| mac_flooding | 1–6 MAC/s, 60–300 s | inserciones/s ≥ tamaño de la tabla CAM / su tiempo de envejecimiento | ≈ 8192/300 ≈ 27 MAC/s | 1.000 | 0 |
| port_scan | 0,3–0,6 sondas/s, 40–120 puertos | puertos distintos/hora suficientes para cubrir el rango objetivo | depende del rango; top-puertos se cubre lento | 0.882 | 0 |
| dns_spoofing | 0,3–0,7 resp/s, 120–400 s | la respuesta forjada llega antes que la legítima (ventana de RTT) | 1 respuesta por consulta dentro de la ventana de RTT | 0.778 | 0 |
| icmp_flood | 0,5–2 ICMP/s, 60–300 s | saturar el ancho de banda o la CPU del objetivo (BlackNurse: tipo 3/3) | depende del enlace; muy por encima de unas pocas/s | 0.714 | 0 |

Donde la `suave` cae bajo el suelo de efecto y el recall es 0 por etiqueta, el ataque es «invisible por construcción» y no cuenta como evasión del modelo.

