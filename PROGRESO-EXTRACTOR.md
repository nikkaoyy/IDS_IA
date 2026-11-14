SEGUIR — iteración 0 (diagnóstico) cerrada; siguiente: iteración 1, familia «ICMP por tipo».

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
| Objetivo de parada: línea base + 0,20, y ningún tipo < 0,30 | ≥ 0,244 | ≥ 0,316 | — |

El criterio de parada se aplica a **los dos modelos**: se da por cumplido cuando lo cumplen
ambos.

Presupuesto: 4 h desde el inicio de la iteración 0 (2026-11-13 ≈ 19:05). Consumido al
cerrar la iteración 0: ≈ 0 h 35 min.

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
