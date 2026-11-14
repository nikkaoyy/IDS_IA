SEGUIR — iteración 1 en curso: familia compartida 1, «respuestas sin petición previa» (pedido v2).

# Progreso — PEDIDO-EXTRACTOR-1

La primera línea es el semáforo del bucle: `SEGUIR` o `PARAR` (con el motivo).

## Marcador

LOAO: recall por episodio del tipo excluido, media de los seis tipos con IC 95 %
(bootstrap de episodios estratificado por tipo, 1000 réplicas). Umbral anidado para
≤ 1 FA por dispositivo-día. Semilla 42. Comando:

```
.venv/bin/python scripts/ablaciones.py --config configs/e2.json --partes loao \
    --conjunto <conjunto> --salida reports/extractor/loao_itN_<nombre>.json
```

| Medida | RF | XGB | Fuente |
|---|---|---|---|
| E2, todas las características (esquema 2.0) | 0,028 [0,006, 0,055] | 0,111 [0,067, 0,156] | `reports/extractor/loao_it0_completo.json` |
| **Línea base semántica**: sin `FEATURES_CAPA2` (35 características) | **0,044 [0,016, 0,076]** | **0,116 [0,074, 0,156]** | `reports/extractor/loao_it0_sin_capa2.json` |
| Parada por transferencia (pedido v2): media ≥ línea base + 0,15, **o** 3 de 6 tipos ≥ 0,25 | ≥ 0,19 | ≥ 0,27 | — |

**Pedido v2 (desde la iteración 1).** Basta con que se cumpla en **un** modelo (RF *o*
XGB), o que 3 de los 6 tipos superen 0,25 al quedar excluidos. También se para por
negativa demostrada: dos familias compartidas seguidas que no mueven ninguno de los tipos
que declararon cubrir. El listón «ningún tipo < 0,30» de la v1 queda retirado.

Presupuesto: 4 h desde el inicio de la iteración 0 (2026-11-13 ≈ 19:05), contadas de
forma continua también para la v2. Consumido al cerrar la iteración 0: ≈ 0 h 35 min; al
escribir la predicción de la iteración 1 (19:48): ≈ 0 h 43 min.

LOAO por tipo en la línea base semántica (sin capa 2):

| Tipo excluido | RF | XGB |
|---|---|---|
| arp_spoofing | 0,000 | 0,000 |
| dns_spoofing | 0,100 | 0,033 |
| icmp_flood | 0,129 | 0,097 |
| mac_flooding | 0,000 | 0,294 |
| port_scan | 0,000 | 0,143 |
| syn_flood | 0,032 | 0,129 |

## Lo que dijo el diagnóstico (iteración 0)

Fuente: `reports/extractor_diagnostico.json`, con la separación univariada sobre el dataset
y la comparación de tramas en los 20 pcap de desarrollo.

1. **`longitud_trama_*` no mide cómo construye la trama la herramienta, sino qué trae la
   ventana.** Dentro de cada clase de protocolo, ataque y benigno miden lo mismo: ARP 60 B
   (100 % ambos), SYN 60 B con cabecera de 20 B (100 % ambos), ICMP unreachable 70 B. La
   media baja y la desviación vale 0 porque, en el laboratorio, la MAC atacante solo emite
   el ataque. Juicio: **mixta** (composición). Excepciones con trama distinta («sí»): las
   respuestas DNS falsas (112–128 B frente a 108–110 B) y el UDP de `mac_flooding` (60 B
   frente a 75–1242 B).
2. **`longitud_trama_std` es NaN en las ventanas de una sola trama**: el 22 % de las
   benignas, el 0 % de las de ataque. Parte de su peso viene de ese NaN.
3. **Quitar la capa 2 no arregla el LOAO** (RF 0,028 → 0,044; XGB 0,111 → 0,116). Solo
   baja el recall con el tipo en el entrenamiento (RF 0,80 → 0,62; XGB 0,78 → 0,70). La
   capa 2 ayuda a reconocer tipos conocidos, pero no es la razón de que los tipos nuevos
   pasen sin detectarse.
4. **Lectura estructural:** las características semánticas que funcionan hoy son
   contadores *específicos de un ataque*: `arp_cambios_vinculo` para ARP,
   `syn_medio_abiertos` para SYN, `dns_respuestas` para DNS. En LOAO, el contador del tipo
   excluido nunca tuvo un positivo en el entrenamiento, así que el modelo no aprende que
   subirlo es un ataque. Una familia nueva específica de un tipo mejorará ese tipo *con*
   entrenamiento, pero no necesariamente su LOAO. Lo que puede transferirse entre tipos es
   lo que varios ataques comparten: tramas en estados que el protocolo no admite, respuestas
   sin petición, presión de estado sobre un tercero. Las familias se diseñan para que sus
   contadores sean comunes a varios ataques cuando la semántica lo permita, por ejemplo
   «respuestas no solicitadas» para ARP, DNS e ICMP echo reply.
5. **Huellas de herramienta sin característica, que no deben entrar nunca:** ventana TCP
   8192 en el 100 % del TCP de ataque (benigno 29200/64240) y TTL 64 en el 100 % del IP de
   ataque (benigno 64/128/48–50).
6. **Violaciones que ningún contador ve hoy:**
   - `port_scan`: TCP sin flags (503 tramas), FIN suelto (453) y FIN+PSH+URG (466), con 0
     en el benigno.
   - `icmp_flood`: ICMP unreachable (10 250 de ataque frente a 1 499 benignas) y 29 204
     echo reply que `n_icmp_echo` no cuenta.

Las 3 características que más separan cada ataque del benigno, con su juicio:

| Ataque | 1.ª | 2.ª | 3.ª |
|---|---|---|---|
| arp_spoofing | arp_cambios_vinculo_60s 0,964 (no) | longitud_trama_media 0,215 (mixta) | arp_cambios_vinculo 0,778 (no) |
| dns_spoofing | dns_respuestas 0,972 (mixta) | entropia_puertos_destino 0,890 (mixta) | puertos_destino_distintos_60s 0,878 (mixta) |
| icmp_flood | conexiones_distintas 0,289 (mixta) | puertos_destino_distintos 0,289 (mixta) | puertos_destino_distintos_60s 0,330 (mixta) |
| mac_flooding | n_tramas_60s 0,081 (mixta) | macs_nuevas_por_s 0,877 (no) | longitud_trama_media 0,131 (sí) |
| port_scan | puertos_destino_distintos_60s 0,799 (no) | entropia_puertos_destino 0,785 (no) | syn_medio_abiertos_60s 0,764 (no) |
| syn_flood | syn_medio_abiertos 0,992 (no) | syn_medio_abiertos_60s 0,991 (no) | tasa_syn 0,980 (mixta) |

(Los números son AUC; < 0,5 significa que el ataque tiene valores *menores* que el benigno.)
Para `icmp_flood` no separa nada propio de ICMP: sus tres primeras características miden lo
que a la ventana atacante le *falta* (flujos TCP/UDP).

## Iteración 1 — familia «respuestas sin petición previa» (predicción escrita antes de medir)

**Qué viola.** Un equipo legítimo no contesta lo que nadie preguntó. Una respuesta de
protocolo (ARP reply, respuesta DNS, ICMP echo reply o error ICMP) sin la petición
correspondiente en los 5 s previos es una afirmación no pedida sobre la red.

**Qué contador lo ve.** Un solo contador compartido por los cuatro protocolos, sin columna
propia por protocolo:
- `respuestas_no_solicitadas`: suma, en la ventana de 5 s, de
  - ARP reply sin request (psrc, pdst) previo (lógica existente);
  - respuesta DNS sin consulta con el mismo (ip, puerto, txid) (lógica existente);
  - ICMP echo reply sin echo request con el mismo (ip origen↔destino, id, seq);
  - error ICMP (tipo 3 o 11) cuyo datagrama citado no salió del destinatario del error
    hacia ese par (ip, proto, puertos) en los 5 s previos.
- `tasa_respuestas_no_solicitadas`: lo mismo, dividido entre las tramas de la ventana.
- `respuestas_no_solicitadas_60s`: la suma en 60 s.

**Comprobado en el pcap** (20 sesiones de desarrollo, `data/pcap/`):
- Los 31 701 echo reply benignos tienen su request previo; los 29 204 de `icmp_flood`, ninguno.
- Los 1 499 unreachable benignos citan un datagrama que su destinatario sí envió; los
  10 250 de `icmp_flood` citan datagramas que nunca pasaron por el segmento.
- En el dataset, `arp_replies_no_solicitadas` y `dns_respuestas_sin_consulta` valen 0 en el
  100 % de las ventanas benignas limpias.

**Cobertura declarada (predicción falsable).** Solo se ve una respuesta *sin* petición. Las
variantes que responden a una petición real (carreras ARP y DNS, MITM DNS) o que envenenan
por request o gratuito no quedan cubiertas: son de la familia 3.

| Tipo | Variantes cubiertas (episodios) | Cota del recall LOAO por esta familia |
|---|---|---|
| icmp_flood | echo_reply (10) + unreachable (11) de 31 | 0,68 |
| arp_spoofing | respuesta_gateway (3) + respuesta_host (7) de 34 | 0,29 |
| dns_spoofing | kaminsky (3) de 30 | 0,10 |

Predicción con el conjunto sin capa 2: al quedar excluidos, **`icmp_flood` sube ≥ +0,15 y
`arp_spoofing` ≥ +0,10 en al menos un modelo**; `dns_spoofing` sube como mucho +0,10. Los
otros tres tipos no deberían moverse por esta familia.

**Decisión fijada de antemano.** La familia se queda si el LOAO medio sube en al menos un
modelo **y** `icmp_flood` o `arp_spoofing` sube ≥ 0,10 al quedar excluido. Si no se cumple,
`git revert` del commit de características y se anota la negativa con la cifra.

## Orden de las familias (por lo visto en el pcap)

1. **ICMP por tipo**: `icmp_flood` es el peor tipo, también con entrenamiento (0,26–0,52), y
   hoy es invisible salvo el echo request. Echo reply y unreachable se pueden contar como
   «respuesta sin petición» y «error sin flujo que lo provoque», que son contadores comunes
   a otros ataques.
2. **Flags TCP que el benigno no produce**: nulo, FIN suelto y Xmas aparecen en `port_scan`
   con 0 en el benigno.
3. **Presión sobre la tabla CAM** (`mac_flooding`).
4. **Vínculo IP↔MAC**, vista corta (`arp_spoofing`, LOAO 0,000 con los dos modelos).
5. DNS consultas/respuestas por equipo.
6. SYN sin completar por destino.
7. Abanico de puertos frente a fuerza bruta.

## Registro de iteraciones

| It. | Qué | LOAO RF | LOAO XGB | ¿Mejora? | Commit |
|---|---|---|---|---|---|
| 0 | Diagnóstico + línea base sin capa 2 | 0,044 [0,016, 0,076] | 0,116 [0,074, 0,156] | (línea base) | ver `git log` |

### Cierre de la iteración 0

- Iteración 0, diagnóstico: `reports/extractor_diagnostico.json` y el LOAO sin capa 2.
- Línea base semántica: LOAO RF 0,044 [0,016, 0,076], XGB 0,116 [0,074, 0,156]. Con todas
  las características: 0,028 y 0,111.
- Sigue la iteración 1: la familia «ICMP por tipo», con su justificación escrita aquí antes
  de medir.
