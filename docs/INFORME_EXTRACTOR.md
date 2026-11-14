# Informe del extractor — PEDIDO-EXTRACTOR-1 (v2)

> Trabajo del 2026-11-13 sobre la base `f7b72f0` (iteración 0), cerrado en el commit que
> añade este informe. Pedido: `PEDIDO-EXTRACTOR-1.md`; bitácora: `PROGRESO-EXTRACTOR.md`;
> cifras: `reports/extractor_final.json` (lo genera `scripts/extractor_final.py`) y
> `reports/extractor/loao_it*.json`. No se tocó `scripts/lab/*`, ni el holdout, ni
> `scripts/baseline_reglas.py`, ni `configs/e2.json`. Sin `git push`.

## Resumen

**¿Se transfiere algo entre ataques? Sí, poco, y lo atribuible está en un solo tipo.**

- Con la familia «respuestas sin petición previa» (esquema 3.0), el LOAO medio de XGBoost
  pasa de **0,116 [0,074, 0,156] a 0,228 [0,168, 0,286]**: los IC no se solapan. El de
  Random Forest pasa de 0,044 [0,016, 0,076] a 0,068 [0,032, 0,105], y aquí los IC se
  solapan.
- La única transferencia que se puede atribuir a la familia es **arp_spoofing**: sube de 0
  a 0,294 en XGB y de 0 a 0,147 en RF. Es la primera vez que se detecta sin estar en el
  entrenamiento.
- **icmp_flood**, el tipo que más usa el contador, *no* mejora al quedar excluido (0,161 en
  XGB, 0,097 en RF). La predicción escrita antes de medir falló en este punto.
- El criterio de parada v2 se cumple **al pie de la letra** en XGB: 3 de 6 tipos quedan
  ≥ 0,25 al ser excluidos. Pero solo uno de esos tres es mérito de la familia (§3).
- El pedido se cierra por ese criterio y porque se agotó el presupuesto de 4 h. Solo se
  midió una de las cinco familias. Las otras cuatro no se probaron, lo que **no** equivale
  a un resultado negativo.

Lo que transfiere es la **semántica del protocolo** (un equipo no contesta lo que nadie
preguntó), no la huella IEEE 802.3. Quitar la capa 2 no movió el LOAO (iteración 0). La
respuesta para el artículo está en el §6.

## 1. Marcador

LOAO: se entrena sin un tipo de ataque y se mide el recall por episodio de ese tipo, con el
umbral fijado por validación anidada para ≤ 1 falsa alarma por dispositivo-día. Se da la
media de los seis tipos con IC al 95 % (bootstrap de episodios estratificado por tipo, 1000
réplicas) y el resultado por tipo. Semilla 42. Conjunto `sin_capa2` (la línea base
semántica de la iteración 0). Dataset de desarrollo de 20 sesiones. El holdout 20–29 está
gastado y no se abrió.

```
.venv/bin/python scripts/ablaciones.py --config configs/e2.json --partes loao \
    --conjunto sin_capa2 --salida reports/extractor/loao_it1_respuestas.json
.venv/bin/python scripts/extractor_final.py
```

## 2. LOAO medio por modelo frente a la línea base semántica

| Medida | Random Forest | XGBoost |
|---|---|---|
| E2, todas las características (2.0) | 0,028 [0,006, 0,055] | 0,111 [0,067, 0,156] |
| Línea base semántica: 2.0 sin capa 2 | 0,044 [0,016, 0,076] | 0,116 [0,074, 0,156] |
| **3.0 sin capa 2 (familia 1)** | **0,068 [0,032, 0,105]** | **0,228 [0,168, 0,286]** |
| Objetivo de parada (línea base + 0,15) | 0,194 | 0,266 |
| Recall con el tipo en el entrenamiento (3.0) | 0,728 [0,665, 0,784] | 0,829 [0,776, 0,878] |

## 3. Transferencia por familia

Familia 1, **respuestas sin petición previa**: una respuesta ARP, DNS, ICMP echo reply o un
error ICMP cuya petición (o datagrama citado) no aparece en los 5 s previos. Es un solo
contador para los cuatro protocolos. La predicción se escribió antes de medir (commit
`b092487`).

Recall por episodio del tipo excluido, antes (línea base) → después (3.0):

| Tipo (cubierto) | Predicción | RF antes → después | XGB antes → después | ¿Se cumple? |
|---|---|---|---|---|
| icmp_flood | ≥ +0,15 | 0,129 [0,032, 0,258] → 0,097 [0,000, 0,194] | 0,097 [0,000, 0,226] → 0,161 [0,064, 0,290] | **No** |
| arp_spoofing | ≥ +0,10 | 0,000 [0,000, 0,000] → 0,147 [0,029, 0,265] | 0,000 [0,000, 0,000] → 0,294 [0,147, 0,441] | **Sí** |
| dns_spoofing | ≤ +0,10 | 0,100 [0,000, 0,233] → 0,100 [0,000, 0,233] | 0,033 [0,000, 0,100] → 0,100 [0,000, 0,233] | Sí |

Tipos no cubiertos (la familia no debía moverlos):

| Tipo | RF antes → después | XGB antes → después |
|---|---|---|
| mac_flooding | 0,000 → 0,000 | 0,294 [0,147, 0,441] → 0,265 [0,146, 0,412] |
| port_scan | 0,000 → 0,000 | 0,143 [0,036, 0,286] → 0,321 [0,143, 0,500] |
| syn_flood | 0,032 [0,000, 0,097] → 0,065 [0,000, 0,161] | 0,129 [0,032, 0,258] → 0,226 [0,097, 0,387] |

**Decisión fijada de antemano: la familia se queda.** El LOAO medio sube en los dos modelos
y arp_spoofing sube ≥ 0,10.

**Por qué el criterio de parada se cumple solo al pie de la letra.** Los tres tipos de XGB
que quedan ≥ 0,25 son arp_spoofing, mac_flooding y port_scan:
- **mac_flooding** ya estaba en 0,294 en la línea base.
- **port_scan** sube +0,18, pero el contador es > 0 en solo el 1,9 % de sus ventanas.
  Además, su recall *con* el tipo en el entrenamiento también cambia (0,536 → 0,750) sin
  nada nuevo que aprender. Lo atribuyo a la varianza de reentrenar con una columna más (del
  orden de ±0,1–0,2 por tipo, con IC que se solapan con la línea base).
- **arp_spoofing** es el único atribuible.

**La asimetría arp/icmp.** El contador separa bien icmp_flood del benigno (AUC univariada
0,853; > 0 en el 70,6 % de sus ventanas frente al 0,06 % del benigno). arp_spoofing lo
separa peor (AUC 0,652; 30,5 % de las ventanas). Aun así, la transferencia va hacia
arp_spoofing y no hacia icmp_flood. La hipótesis coherente con las cifras, que **no se ha
verificado**, es esta:
- **Excluido arp_spoofing:** el entrenamiento tiene a icmp_flood con el contador alto en la
  mayoría de sus ventanas. El modelo aprende «respuesta no pedida → ataque» y la aplica a
  ARP.
- **Excluido icmp_flood:** los positivos del contador en el entrenamiento son las pocas
  ventanas de arp_spoofing (y alguna de dns_spoofing), y llegan acompañadas de los
  contadores propios de ARP. El modelo aprende la conjunción («respuesta no pedida *y*
  ARP»), que no aparece en un flood ICMP.

Conclusión: un contador compartido solo transfiere desde un tipo de entrenamiento que
dependa mucho de él. No basta con que sea el mismo contador.

**Iteraciones que no mejoraron:** ninguna; solo se midió una familia. La predicción fallida
para icmp_flood es la negativa de esta iteración y queda con su cifra arriba.

## 4. Características vivas en 3.0

El contrato 3.0 (`src/feature_schema.py`) tiene 52 columnas. El marcador usa las 38 que no
son de capa 2: **15 de contexto, 20 propias de un solo ataque y 3 compartidas**. Esa
proporción es la explicación estructural de que el LOAO sea bajo (iteración 0, §4 de
`PROGRESO-EXTRACTOR.md`). Por la regla de diseño del pedido, en él no se añadió ninguna
característica propia de un solo ataque; las que ya existían se listan como diagnóstico.

| Característica | Alcance | Qué viola o qué mide | Fuente en el pcap |
|---|---|---|---|
| `arp_requests` | contexto | peticiones ARP emitidas | ARP op 1 |
| `arp_replies` | contexto | respuestas ARP emitidas | ARP op 2 |
| `arp_replies_no_solicitadas` | propio:arp_spoofing | respuesta ARP sin petición (psrc, pdst) | ARP op 2 sin op 1 previo en 5 s |
| `arp_gratuitos` | propio:arp_spoofing | anuncio de vínculo sin petición | ARP con psrc == pdst |
| `arp_cambios_vinculo` | propio:arp_spoofing | una IP conocida aparece con otra MAC | tabla IP->MAC de ARP |
| `arp_ether_distinto_hwsrc` | propio:arp_spoofing | la MAC de enlace no coincide con la que declara ARP | Ether.src frente a ARP.hwsrc |
| `arp_gateway_reclamado` | propio:arp_spoofing | alguien que no es el gateway dice serlo (NaN sin gateway declarado) | ARP psrc == IP del gateway |
| `n_syn` | contexto | aperturas TCP | flags SYN sin ACK |
| `tasa_syn` | contexto | proporción de aperturas | flags SYN / tramas |
| `syn_medio_abiertos` | propio:syn_flood | SYN sin SYN-ACK ni RST tras 1 s | seguimiento de flujos TCP |
| `ratio_syn_medio_abiertos` | propio:syn_flood | ídem, normalizado por SYN evaluables | seguimiento de flujos TCP |
| `n_rst` | contexto | reinicios TCP | flag RST |
| `ips_origen_distintas` | contexto | IP de origen que usa la MAC | IP.src |
| `ips_destino_distintas` | contexto | abanico de destinos | IP.dst |
| `puertos_destino_distintos` | contexto | abanico de puertos | TCP/UDP dport |
| `entropia_puertos_destino` | contexto | reparto de puertos | TCP/UDP dport |
| `conexiones_distintas` | contexto | pares (ip, puerto) de destino | IP.dst + dport |
| `n_icmp_echo` | contexto | echo request emitidos | ICMP tipo 8 |
| `dns_consultas` | contexto | consultas DNS | DNS qr=0 |
| `dns_respuestas` | contexto | respuestas DNS emitidas | DNS qr=1 |
| `dns_respuestas_sin_consulta` | propio:dns_spoofing | respuesta DNS sin consulta (ip, puerto, txid) | DNS qr=1 sin qr=0 previo en 5 s |
| `dns_multiples_respuestas_txid` | propio:dns_spoofing | dos respondedores para el mismo txid | DNS qr=1 repetido |
| `dns_resolver_no_autorizado` | propio:dns_spoofing | responde quien no es resolver (NaN sin resolvers declarados) | IP.src de DNS qr=1 |
| `n_tramas_60s` | contexto | volumen en 60 s | tramas |
| `arp_replies_no_solicitadas_60s` | propio:arp_spoofing | ver arp_replies_no_solicitadas | ídem, 60 s |
| `arp_cambios_vinculo_60s` | propio:arp_spoofing | ver arp_cambios_vinculo | ídem, 60 s |
| `syn_medio_abiertos_60s` | propio:syn_flood | ver syn_medio_abiertos (también port_scan) | ídem, 60 s |
| `dns_respuestas_sin_consulta_60s` | propio:dns_spoofing | ver dns_respuestas_sin_consulta | ídem, 60 s |
| `puertos_destino_distintos_60s` | propio:port_scan | abanico de puertos sostenido | dport, 60 s |
| `ips_destino_distintas_60s` | contexto | abanico de destinos sostenido | IP.dst, 60 s |
| `macs_nuevas_por_s` | propio:mac_flooding | aparición de MAC nunca vistas | MAC origen del segmento |
| `macs_activas` | propio:mac_flooding | MAC que emiten en la ventana | MAC origen del segmento |
| `ratio_macs_una_trama` | propio:mac_flooding | MAC que emiten una sola trama | MAC origen del segmento |
| `syn_sin_synack_max_destino` | propio:syn_flood | presión de SYN sobre un destino | flujos TCP por destino |
| `syn_medio_abiertos_max_destino` | propio:syn_flood | conexiones medio abiertas sobre un destino | flujos TCP por destino |
| `respuestas_no_solicitadas` | compartido | respuesta de protocolo que nadie pidió (ARP, DNS, ICMP echo, error ICMP) | ARP reply sin request (psrc, pdst) previo; respuesta DNS sin consulta (ip, puerto, txid); ICMP echo reply sin echo request (ips, id, seq); error ICMP 3/11 que cita un datagrama que su destinatario no envió; ventana de 5 s |
| `tasa_respuestas_no_solicitadas` | compartido | ídem, por trama | ídem |
| `respuestas_no_solicitadas_60s` | compartido | ídem, en 60 s | ídem |

### 4.1 En el contrato pero fuera del marcador, y retiradas

- **`FEATURES_CAPA2` (14 columnas)** sigue en el contrato, porque E2 la usa, pero no entra
  en el marcador LOAO. Mide la composición de la ventana, no cómo construye la trama la
  herramienta (ARP 60 B y SYN 60 B miden lo mismo en ataque y benigno).
  `longitud_trama_std` vale NaN en el 22 % del benigno. Y quitarla no cambia el LOAO (RF
  0,028 → 0,044; XGB 0,111 → 0,116).
- **Retiradas del contrato en este pedido:** ninguna. Tampoco hubo limpiezas de artefacto.
- **Nunca entran (huellas de la herramienta, iteración 0):** la ventana TCP 8192 (100 % del
  TCP de ataque; benigno 29200/64240) y el TTL 64 (100 % del IP de ataque; benigno
  64/128/48–50).

## 5. Efectos colaterales del esquema 3.0

- **Dataset**: regenerado con el generador congelado. 78 988 ventanas, sha256
  `7f06d099…a945`, ficha `reports/dataset_lab_2026-11-13.json`. El de 2.0 (`3f4d28bc…eced`)
  queda fuera de git en `data/dataset_lab_esquema2.0.csv`.
- **E2 recalculado** (validación de 20 sesiones, todas las características): recall por
  episodio RF 0,787 → 0,878 [0,834, 0,922] y XGB 0,787 → 0,894 [0,856, 0,936];
  FA/dispositivo-día 1,19 y 0,89. Las cifras de 2.0 quedan en
  `reports/historico/evaluacion_e2_esquema2.0.*`. **El holdout no se recalculó**: sus cifras
  siguen siendo las de 2.0 y no hay cifra limpia de holdout para 3.0.
- **Puerta de separabilidad de E1**: icmp_flood pasa a desviación declarada. Un árbol de
  profundidad 2 sobre `respuestas_no_solicitadas` llega a 0,974 de exactitud balanceada (FPR
  0,052). La causa es el extractor, no el generador. Ahora los seis tipos tienen un contador
  que los delata por sí solo, lo cual es coherente con un detector de firmas.

## 6. ¿Qué dice esto del enfoque de huella 802.3 para ataques desconocidos?

1. **La huella de capa 2 no aporta nada a la detección de ataques nuevos.** Quitarla no
   cambia el LOAO. Lo poco que transfiere viene de contadores de protocolo (ARP, DNS, ICMP)
   que el extractor lee por encima de la capa 2.
2. **Un clasificador supervisado sobre contadores propios es un detector del catálogo
   conocido.** Con el tipo en el entrenamiento alcanza 0,73–0,83 de recall por episodio;
   sin él, 0,07–0,23 de media al mismo nivel de falsas alarmas. A ≤ 1 FA/dispositivo-día no
   detecta un ataque nuevo en más de 1 de cada 4 episodios de media.
3. **Los contadores compartidos ayudan, pero dependen de qué haya en el entrenamiento.** Un
   solo contador compartido duplicó el LOAO medio de XGB, pero solo transfirió hacia un
   tipo. Si se quiere que el sistema generalice, la vía son más violaciones compartidas
   (familias 2–5, sin medir) o un detector de anomalías entrenado solo con benigno, que no
   depende de haber visto el ataque. Las dos cosas serían trabajo nuevo.
4. **Mensaje propuesto para el artículo:** el sistema detecta los seis ataques del catálogo
   con un recall por episodio de 0,88–0,89 a ≈ 1 FA/dispositivo-día. Su capacidad frente a
   ataques no vistos es limitada (LOAO medio 0,228 en XGB) y procede de contadores de
   violación de protocolo, no de la huella 802.3.

## 7. Limitaciones

- Solo se midió **una** de las cinco familias. No se puede hablar de «negativa demostrada»
  (que exigía dos familias seguidas sin efecto), ni afirmar nada sobre las familias 2–5.
- El LOAO usa el dataset de desarrollo (20 sesiones, 28–34 episodios por tipo). Los IC por
  tipo son anchos: ±0,15 es habitual.
- La variación entre reentrenamientos al añadir columnas (del orden de ±0,1–0,2 por tipo) no
  se ha medido de forma sistemática, por ejemplo con varias semillas en el LOAO. Las
  subidas de port_scan y syn_flood podrían ser ruido o algo más.
- La hipótesis de la asimetría arp/icmp (§3) no está verificada. Se comprobaría con un LOAO
  sin icmp_flood en el que los contadores ARP no estén disponibles.
- El LOAO con el conjunto `completo` (con capa 2) no se volvió a medir en 3.0.
- Todo es tráfico sintético de un generador congelado. Los ataques nuevos que mide el LOAO
  son variantes de los mismos seis, no ataques realmente desconocidos.

## 8. Commits

| Commit | Qué |
|---|---|
| `f7b72f0` | Iteración 0: diagnóstico y línea base semántica |
| `b092487` | Iteración 1: pedido v2 y predicción de cobertura, escrita antes de medir |
| `41a47ec` | Iteración 1: familia «respuestas sin petición previa», esquema 3.0, E2 recalculado |
| (este) | Cierre: este informe, `reports/extractor_final.json` completo, addendum de E2, `PARAR` |
