PARAR — pedido cerrado el 2026-11-13: criterio de parada v2 cumplido al pie de la letra en XGB (3 de 6 tipos ≥ 0,25; solo arp_spoofing atribuible a la familia) y presupuesto de 4 h agotado. Informe: docs/INFORME_EXTRACTOR.md.

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

## Iteración 1 — resultado (medido después de escribir la predicción)

**Esquema 3.0.** `FEATURES_RESPUESTAS` (3 columnas) en `src/feature_schema.py`; extracción en
`src/ventanas.py` (echo id/seq y datagrama citado por los errores ICMP, leídos de la trama).
Dataset regenerado con el generador congelado: 78 988 ventanas, sha256 `7f06d099…a945`,
ficha `reports/dataset_lab_2026-11-13.json`. El dataset 2.0 queda fuera de git en
`data/dataset_lab_esquema2.0.csv`.

Ventanas con `respuestas_no_solicitadas` > 0: benigno 0,06 %, icmp_flood 70,6 %,
arp_spoofing 30,5 %, dns_spoofing 1,4 % (pocas ventanas, pero con ráfagas: media 11,6),
port_scan 1,9 % y syn_flood 0,9 % (tramas de la MAC atacante fuera del ataque: 10 ARP reply
en port_scan y 116 respuestas DNS + ICMP en syn_flood), mac_flooding 0 %.

LOAO sin capa 2 (`reports/extractor/loao_it1_respuestas.json`), recall por episodio del
tipo excluido:

| Tipo excluido | RF antes → después | XGB antes → después |
|---|---|---|
| **arp_spoofing** (cubre) | 0,000 → **0,147** [0,029, 0,265] | 0,000 → **0,294** [0,147, 0,441] |
| **dns_spoofing** (cubre, ≤ +0,10) | 0,100 → 0,100 [0,000, 0,233] | 0,033 → 0,100 [0,000, 0,233] |
| **icmp_flood** (cubre) | 0,129 → 0,097 [0,000, 0,194] | 0,097 → 0,161 [0,064, 0,290] |
| mac_flooding | 0,000 → 0,000 | 0,294 → 0,265 [0,146, 0,412] |
| port_scan | 0,000 → 0,000 | 0,143 → 0,321 [0,143, 0,500] |
| syn_flood | 0,032 → 0,065 [0,000, 0,161] | 0,129 → 0,226 [0,097, 0,387] |
| **Media de los seis** | 0,044 → **0,068** [0,032, 0,105] | 0,116 → **0,228** [0,168, 0,286] |

**Contraste con la predicción.**
- `arp_spoofing` ≥ +0,10: **se cumple** (+0,147 en RF, +0,294 en XGB). Es la primera vez
  que el tipo se detecta sin estar en el entrenamiento.
- `icmp_flood` ≥ +0,15: **no se cumple** (+0,065 en XGB, −0,032 en RF). Con el tipo en el
  entrenamiento el contador sí funciona (RF 0,29 → 0,74, XGB 0,26 → 0,84). Hipótesis, sin
  verificar: excluido icmp_flood, los positivos del contador en el entrenamiento vienen de
  arp_spoofing y van acompañados de sus contadores ARP. El árbol aprende «respuestas no
  pedidas *y* ARP», no «respuestas no pedidas». Que sea un solo contador no basta para que
  el modelo lo trate como compartido.
- `dns_spoofing` ≤ +0,10: se cumple (+0,000 en RF, +0,067 en XGB).
- **Tipos no cubiertos que se mueven:** port_scan +0,18 y syn_flood +0,10 en XGB. El
  contador vale casi siempre 0 en sus ventanas, y port_scan *con* entrenamiento también
  cambia (0,536 → 0,750) sin nada nuevo que ver. Lo leo como varianza de reentrenar con una
  columna más (del orden de ±0,1–0,2 por tipo, con IC que se solapan con la línea base), no
  como efecto de la familia.

**Decisión (regla fijada de antemano): la familia se queda.** El LOAO medio sube en los dos
modelos y arp_spoofing sube ≥ 0,10.

**Criterio de parada v2: se cumple al pie de la letra en XGB, con matices.** Tres tipos
quedan ≥ 0,25 al ser excluidos: arp_spoofing 0,294, mac_flooding 0,265 y port_scan 0,321.
Pero mac_flooding ya estaba en 0,294 en la línea base, y la subida de port_scan no se puede
atribuir a la familia. Solo arp_spoofing es transferencia atribuible. La media de XGB
(0,228) se queda por debajo del objetivo de 0,266; la de RF (0,068), muy lejos de 0,194. El
cierre tiene que decirlo así: el criterio se cumplió, pero lo que la familia transfiere
de verdad es un tipo.

**Puerta de separabilidad E1.** Con 3.0, un árbol de profundidad 2 sobre
`respuestas_no_solicitadas` separa icmp_flood con exactitud balanceada 0,974 (FPR 0,052) en
el dataset completo, por encima de 0,85. La causa es que el extractor ve por fin la
violación (respuestas ICMP sin petición), no que el generador se haya vuelto trivial: está
congelado. Se declara como sexta desviación en `tests/test_separabilidad.py`, con xfail
estricto igual que las otras cinco. Ahora ningún tipo pasa la puerta univariada: cada uno
tiene un contador que lo delata. El marcador sigue siendo el LOAO (regla 4).

**E2 en 3.0.** Cifras recalculadas en `reports/evaluacion_e2.json` / `.md`; las de 2.0
quedan en `reports/historico/evaluacion_e2_esquema2.0.*`.
Con todas las características: recall por episodio RF 0,787 → **0,878** [0,834, 0,922] y
XGB 0,787 → **0,894** [0,856, 0,936]; FA/dispositivo-día 1,19 y 0,89; PR-AUC 0,986 y 0,989.
Mejora el reconocimiento de tipos conocidos (sobre todo icmp_flood); el holdout sigue cerrado.

**Presupuesto.** ≈ 3 h 10 min consumidas. Otra familia necesita ≈ 6 min de regeneración y
≈ 50 min de LOAO, así que no cabe en lo que queda. El criterio de parada y el presupuesto
llevan los dos al cierre.

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
| 1 | Familia 1: respuestas sin petición previa (esquema 3.0) | 0,068 [0,032, 0,105] | 0,228 [0,168, 0,286] | Sí: se queda (arp_spoofing +0,15 / +0,29; icmp_flood falla la predicción) | ver `git log` |

### Cierre de la iteración 0

- Iteración 0, diagnóstico: `reports/extractor_diagnostico.json` y el LOAO sin capa 2.
- Línea base semántica: LOAO RF 0,044 [0,016, 0,076], XGB 0,116 [0,074, 0,156]. Con todas
  las características: 0,028 y 0,111.
- Sigue la iteración 1: la familia «ICMP por tipo», con su justificación escrita aquí antes
  de medir.

### Cierre de la iteración 1

- Iteración 1: familia «respuestas sin petición previa» (esquema 3.0, dataset `7f06d099…a945`) — se queda.
- LOAO medio: RF 0,068 [0,032, 0,105], XGB 0,228 [0,168, 0,286] (línea base 0,044 / 0,116); tipos declarados, RF/XGB: arp_spoofing 0,147/0,294, icmp_flood 0,097/0,161 (predicción fallida), dns_spoofing 0,100/0,100.
- Sigue el cierre: criterio de parada cumplido por la letra (XGB: arp 0,294, mac 0,265, port_scan 0,321 ≥ 0,25), pero solo arp_spoofing es atribuible a la familia; informe `docs/INFORME_EXTRACTOR.md` y `PARAR`.

### Cierre del pedido

- Cierre: `docs/INFORME_EXTRACTOR.md` y `reports/extractor_final.json` (características vivas en 3.0 con su alcance y fuente, transferencia y respuesta explícita); addendum en `docs/INFORME_E2.md`.
- LOAO final sin capa 2: RF 0,068 [0,032, 0,105], XGB 0,228 [0,168, 0,286] (línea base 0,044 / 0,116); arp_spoofing 0,147/0,294, icmp_flood 0,097/0,161, dns_spoofing 0,100/0,100.
- Se transfiere poco y de forma atribuible solo hacia arp_spoofing. Las familias 2–5 quedan sin medir, sin que eso sea una negativa. `PARAR`.
