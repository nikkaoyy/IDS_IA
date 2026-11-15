# Informe E4 — Evasión a nivel de pcap (OE3)

Fase E4 del plan (`docs/PLAN_IMPLEMENTACION.md`): medir si el IDS puede ser **evadido** perturbando
el tráfico a nivel de pcap, no de tabla. Se cierra con dos pedidos defensivos ya ejecutados y
publicados, que juntos cubren la superficie de evasión del catálogo:

- **E4R** (`docs/INFORME_E4R.md`, `reports/robustez_e4.json`): recall del detector frente a la
  **intensidad** del ataque, sobre el corpus congelado, canal por canal.
- **E4C** (`docs/INFORME_E4C.md`, `reports/robustez_e4c.json`): el **re-temporizador** de pcaps
  (`scripts/lab/retemporizar.py`, que solo cambia `pkt.time` de tramas existentes, con cuatro
  invariantes verificadas) y el **régimen invisible** del ARP lento, con el vigilante IP→MAC
  extendido para leerlo.

Ninguno de los dos fabrica tráfico: el `attack_simulator.py` de tabla (que copiaba agregados de
ventana imposibles de escribir en un paquete) se dejó intacto y se sustituyó por la medición
honesta sobre pcaps reales.

## Por qué no un generador de evasión que imite la huella

El plan contemplaba un generador que produjera tráfico de ataque imitando la huella legítima a
nivel de paquete. Dos caminos lo vuelven innecesario para cerrar la pregunta de E4:

1. Para los ataques de **volumen** (syn_flood, mac_flooding, port_scan, icmp_flood), bajar la tasa
   hasta esquivar el etiquetado por ventana **destruye el efecto del ataque** (ver invariantes
   abajo): dejan de ser el ataque. E4R lo midió: el supervisado los detecta mientras conservan
   efecto (recall nunca < 0,5 a ninguna intensidad del generador).
2. Para los ataques cuyo efecto **sobrevive** a tasa baja (arp_spoofing, dns_spoofing), E4C produjo
   el régimen invisible **con el corpus existente** (re-temporizando tramas reales) y mostró que el
   canal que los sigue viendo no es un mejor clasificador de volumen, sino la **señal de identidad**.

Es decir: la evasión a nivel de pcap que importa ya está medida, y la defensa está identificada.
El generador de imitación de huella queda como trabajo de laboratorio real (abajo), no como hueco
de esta fase.

## Superficie de evasión por ataque

Cruce de los invariantes de efecto (la física del objetivo, no el detector) con lo medido:

| Ataque | ¿Evadible bajando la tasa? | Qué pasa al bajarla | Canal que lo detecta |
|---|---|---|---|
| `syn_flood` | No sin perder efecto | Suelo ≈ 21 medios-abiertos/s (backlog/RTO); por debajo no agota la cola | supervisado, mientras tiene efecto |
| `mac_flooding` | No sin perder efecto | Suelo ≈ 27 MAC/s (CAM/aging); por debajo no desborda la tabla | supervisado, mientras tiene efecto |
| `port_scan` | Parcial | Conserva efecto lento, pero recorre menos puertos/hora | supervisado (recall por intensidad en E4R) |
| `icmp_flood` | No sin perder efecto | No satura el enlace a pocas/s | supervisado, mientras tiene efecto |
| `arp_spoofing` | **Sí** (hasta el `gc_stale`, ≈60 s) | A paso ≥ 5 s es **invisible por construcción** para el supervisado (1,000 → 0,000) | **vigilante IP→MAC** (1,000, 0,0 FA) tras E4C |
| `dns_spoofing` | Por carrera, no por tasa | El efecto es ganar la carrera por consulta, no la tasa agregada | supervisado (nativo 1,000); carrera medida en E4C |

## Cifras que cierran E4

- **Recall supervisado por intensidad** (E4R, corpus congelado): media 0,935 · suave 0,891 ·
  ráfaga 0,824. **No baja de 0,5 a ninguna intensidad**; **0 episodios invisibles por
  construcción** sobre el corpus sin retemporizar.
- **El OR de canales** sube el recall solo **+0,053** y a cambio de **+122 FA/disp-día** (826 con
  variación benigna): encender identidad y vigilante no compensa frente a floods ni escaneos.
- **ARP lento** (E4C): a paso ≥ 5 s entre tramas, el supervisado cae de **1,000 a 0,000**
  (invisible por construcción, no fallo del modelo); el **vigilante IP→MAC** (extendido para leer
  ARP, con la red del corpus corregida) lo detecta al **1,000** con **0,0 FA/disp-día** sobre
  variación benigna.

## Frase para el artículo

> El IDS por ventana se evade a nivel de pcap solo donde el ataque sobrevive a tasa baja: el ARP
> spoofing ralentizado a 5 s entre tramas se vuelve invisible al clasificador (recall 1,000 →
> 0,000) sin dejar de envenenar, mientras que los ataques de volumen pierden su efecto antes de
> esquivar el etiquetado (recall nunca < 0,5 a ninguna intensidad). La defensa contra la evasión
> lenta no es un mejor clasificador de volumen, sino una señal de identidad (IP→MAC) que no depende
> de la tasa y detecta el ARP lento al 100 % con 0 falsas alarmas.

## Límite declarado (laboratorio real)

La evasión por **imitación de huella a nivel de paquete** (un atacante que escribe TTL, ventana y
opciones de una pila legítima) y la FA del vigilante con **DHCP y failover reales** necesitan una
**captura propia del laboratorio real**; sobre el corpus sintético toda cifra de evasión es
optimista. Queda para el laboratorio físico, no como hueco de software de esta fase.

## Trazabilidad

- E4R: commits de robustez (`dc3c808`, `c8bbe92`, `cbcea22`, `9b42040`), `reports/robustez_e4.*`.
- E4C: commits `41d0c9f`, `afd9c8b`, `bddff3e`, `00e3112`, `reports/robustez_e4c.*`,
  `scripts/lab/retemporizar.py`.
