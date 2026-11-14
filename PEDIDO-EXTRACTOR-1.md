# PEDIDO-EXTRACTOR-1 (v2) — que el modelo detecte el ataque y no un contador propietario

Repo: `/home/nikka/Documentos/FRED/IDS`, rama `main`, base `f7b72f0` (iteración 0 del extractor).
Reemplaza la v1: cambia el diagnóstico de partida, el diseño de las familias y el criterio de parada.
Se sigue ejecutando en bucle, una iteración por vuelta, con el estado en `PROGRESO-EXTRACTOR.md`.

## Corrección de la premisa (medida en la iteración 0)

La v1 decía que el atajo era `longitud_trama_std` y que quitando la capa 2 el modelo miraría el ataque. **La medición lo desmiente:** sin `FEATURES_CAPA2` el LOAO queda en RF **0,044** [0,016–0,076] y XGB **0,116** [0,074–0,156], frente a 0,028 y 0,111 con todo. Quitar el artefacto de la herramienta no mueve nada.

La causa real, según el mismo diagnóstico: las características que separan bien son **contadores propios de un solo ataque**, y al excluir un tipo su contador no tiene un solo positivo en el entrenamiento. No hay nada que transferir. Por eso el problema no se arregla quitando features, sino **cambiando qué se cuenta**: contadores que varios ataques comparten.

Esto no invalida E2 ni la puerta de E1: la conclusión (detecta el catálogo) sigue en pie. Cambia el remedio.

## Estado verificado

- Iteración 0 en `f7b72f0`: `reports/extractor_diagnostico.json` y `PROGRESO-EXTRACTOR.md` escritos; suite 93 passed + 5 xfailed.
- Línea base semántica (sin capa 2) = el listón a batir: **RF 0,044**, **XGB 0,116** de LOAO medio por episodio.
- Dataset de desarrollo: 20 sesiones, 78 988 ventanas, sha256 `3f4d28bc…eced`, regenerable en ~12 min.
- **Holdout 20–29 gastado** (`reports/.holdout_abierto`, commit `e43a28f`): no se abre en este pedido.
- Entorno: `.venv/bin/python` (el `activate` está roto); suite completa ~4 min.

## Reglas duras (sin cambios: una que se rompa se revierte)

1. **Generador congelado**: no se toca `scripts/lab/generar_trafico.py` ni `generar_dataset_lab.py`.
2. **Ninguna característica entra por subir una métrica**: entra por lo que viola el ataque, justificada en `PROGRESO-EXTRACTOR.md` antes de medir. Si no mejora, `git revert` y la negativa queda documentada con su cifra.
3. **Se lee el pcap, no el generador**, para descubrir qué distingue un ataque del benigno.
4. El marcador es **LOAO medio y por tipo**, no la puerta de 0,85.
5. Esquema a 3.0 completo cuando cambie el contrato (extracción, dataset regenerado, ficha, cifras de E2 recalculadas; las viejas quedan como históricas).
6. **El holdout no se abre.** Nada de `--romper-holdout-una-vez`.
7. Un commit por iteración, `git status` limpio, sin `git push`.

## Nuevo diseño de familias: contadores compartidos

Cada familia declara **antes de medirse** qué ataques debería cubrir (predicción falsable). Si no mueve el LOAO de esos tipos, la familia se retira y se anota como negativa. Cinco candidatas, una por iteración:

| # | Familia | Qué viola | Ataques que debería cubrir (predicción) |
|---|---|---|---|
| 1 | **Respuestas sin petición previa**: respuesta de protocolo sin solicitud en la misma ventana o en la anterior, por tipo de protocolo | Un equipo legítimo no contesta lo que nadie preguntó | arp_spoofing, dns_spoofing, icmp_flood (`echo_reply`), sin importar cuál se excluya |
| 2 | **Flujos iniciados que nunca se completan**: SYN sin SYN-ACK, ratio de conexiones medio abiertas por destino, RST temprano | Ningún flujo legítimo queda colgado a propósito | syn_flood, port_scan |
| 3 | **Reclamación de rol**: alguien que no es el gateway/resolver responde con su rol, o una IP conocida aparece con MAC nueva | El rol de gateway y de resolver es único en la red | arp_spoofing, dns_spoofing |
| 4 | **Abanico de identidad**: un origen hacia muchos destinos/puertos, y muchas MAC origen emitiendo a la vez, normalizado por tramas | Un equipo final conversa con pocos pares; un ataque de volumen multiplica pares | mac_flooding, port_scan, syn_flood |
| 5 | **Tasa de eventos de control por encima de lo humano**: tramas de gestión/control por segundo frente al mismo equipo en ventanas tranquilas | Los protocolos de control son raros por naturaleza | los seis, sobre todo los de ráfaga |

Regla de diseño: si un contador sirve para **un solo** ataque, no entra en este pedido — se queda en el informe como diagnóstico de por qué el LOAO no sube.

## Protocolo de cada vuelta del bucle

Lee `PROGRESO-EXTRACTOR.md`; si la primera línea dice `PARAR`, no hagas nada y explica por qué. Después, una sola de estas:

1. **Siguiente familia compartida** de la tabla: predicción de cobertura escrita primero, extracción en `src/ventanas.py`, pruebas en `tests/test_ventanas.py`, esquema 3.0, dataset regenerado, **LOAO medido** y `reports/extractor_final.json` actualizado. Sin mejora → `git revert` + negativa anotada.
2. **Limpieza de artefacto** de una feature que dependa de la herramienta (una por vuelta, como máximo dos en todo el pedido).
3. **Cierre**: si se cumple el criterio de parada, escribe el informe y `PARAR`.

Nunca dos familias por vuelta. No se reajustan hiperparámetros.

## Criterio de parada (corregido)

Se para cuando ocurra **lo primero** de:

- **Transferencia lograda**: LOAO medio ≥ **0,19** en RF (parte de 0,044) o ≥ **0,27** en XGB (parte de 0,116), es decir +0,15 sobre la línea base; **o** al menos **3 de los 6 tipos** con recall por episodio ≥ 0,25 al quedar excluidos.
- **Negativa demostrada**: dos familias compartidas seguidas no mueven el LOAO de ninguno de los tipos que declararon cubrir. Entonces se para, se escribe el resultado negativo con sus cifras y se cierra el pedido: eso también es un hallazgo del artículo.
- **Cuatro horas** de trabajo.

El listón anterior («ningún tipo por debajo de 0,30») queda retirado: con contadores que hoy son propietarios, es inalcanzable por construcción y habría empujado a ajustar el generador.

## Criterio de aceptación

`reports/extractor_final.json` y `docs/INFORME_EXTRACTOR.md` con:

- Tabla de **transferencia**: familia → tipos que declaró cubrir → recall por episodio de cada uno al quedar excluido, antes y después, con IC bootstrap.
- LOAO medio por modelo, con IC, frente a la línea base semántica (0,044 / 0,116).
- Features vivas en 3.0, cada una con su justificación semántica en una línea y su fuente en el pcap; y las retiradas con su motivo.
- Las iteraciones que no mejoraron, con su cifra.
- Una respuesta explícita: **¿se transfiere algo entre ataques?** Con la cifra; y si no se transfiere, qué dice eso del enfoque de huella 802.3 para ataques desconocidos.

## Qué NO se toca

`scripts/lab/*`, el holdout, `scripts/baseline_reglas.py`, `configs/e2.json` (salvo rutas de salida), `docs/INFORME_E1.md` y `docs/INFORME_E2.md` (addendum, no reescritura), más E3–E6, que no se adelantan. `data/*.csv`, `data/*.pcap` y sidecars fuera de git. Sin `git push`.

## Reporte de cada vuelta

Tres líneas: iteración hecha, cifra de LOAO que deja (media y los tipos que declaró cubrir), y qué sigue. Al final de `PROGRESO-EXTRACTOR.md` y al chat.
