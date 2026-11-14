SEGUIR — bloque 1 hecho; sigue el bloque 2 (benigno con variación real).

# Progreso — PEDIDO-E3B-1

Primera línea: semáforo (`SEGUIR` con el siguiente paso, o `PARAR` con el motivo).

## Bloque 1 — IP-ID por flujo (registrado antes de medir)

- `ipid_continuidad` e `ipid_salto_log2` se calculan **por flujo**: destino, protocolo y
  puertos, con flujos de al menos 3 tramas (2 saltos). Cada flujo aporta su valor y la
  desviación se juzga flujo a flujo (máximo de los z), igual que TTL y ventana se juzgan por
  valor: un clon minoritario no queda escondido en una mediana. El perfil hace la mediana y
  la MAD sobre los valores de todos los flujos.
- La versión por equipo queda **descartada** y accesible con `IPID_MODO = "equipo"`, solo
  para reproducir la cifra de E3A en el mismo informe.
- Se mide sobre las mismas 20 sesiones de E3A (semillas 77000–77019, pcap sin regenerar).
- Exigencia del pedido: la detección no baja de 0,975 / 1,000, y FA ≤ 1/disp-día.

Resultado del bloque 1 (`reports/identidad_e3b.json`, sección `ipid`):

| Medida | Por equipo (E3A, descartada) | Por flujo |
|---|---|---|
| FA/disp-día | 16,19 [9,41, 23,67] | **0,38 [0,00, 1,13]** (1 FA en 2,66 disp-día) |
| Dispositivos con alguna FA | 0,092 | 0,004 |
| Detección ingenuo / ritmo | 0,975 / 1,000 | **0,975 / 1,000** |
| Latencia mediana ingenuo / ritmo (s) | 4,2 / 10,0 | 3,7 / 10,0 |

Cumple las dos exigencias: la detección no baja y las FA quedan dentro del presupuesto de
E2. La causa de las 16,2 era el IP-ID medido entre flujos.
