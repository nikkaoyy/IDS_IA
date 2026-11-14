# PEDIDO-EXTRACTOR-1 — que el modelo detecte ataques y no la herramienta del generador

Repo: `/home/nikka/Documentos/FRED/IDS`, rama `main`, base `7fb1019` (E2 cerrado).
Se ejecuta **en bucle**: una iteración por vuelta, con estado en `PROGRESO-EXTRACTOR.md`.
Este archivo manda; el prompt del bucle solo dice «avanza una iteración».

## Por qué existe este pedido

E2 midió lo que había que medir y salió el problema: **leave-one-attack-out da 0,028 (RF) y 0,111 (XGB)** de recall por episodio sobre un tipo que no estaba en el entrenamiento, frente a 0,80 / 0,79 cuando sí estaba. Si se excluye `arp_spoofing`, su recall cae a **0,0** sobre 34 episodios (`reports/ablaciones_e2.json`).

La causa mecánica también está medida: la característica que más pesa es **`longitud_trama_std`**, que describe cómo construye las tramas la herramienta del laboratorio, no lo que viola el ataque. Mientras eso siga así, cualquier cifra nueva sobre este dataset vuelve a medir el generador.

Esto se arregla en el extractor (`src/ventanas.py` + `src/feature_schema.py` + `src/pcap_to_features.py`), no en el modelo ni en el generador.

## Estado verificado (2026-11-13, sobre `7fb1019`)

- Contrato vigente: `VERSION_ESQUEMA = "2.0"`; familias `FEATURES_CAPA2` (14), `FEATURES_ARP` (7), `FEATURES_TCP` (11), `FEATURES_DNS` (5), `FEATURES_LARGAS` (7), `FEATURES_GLOBALES` (5).
- Dataset de desarrollo: 20 sesiones, 78 988 ventanas, sha256 `3f4d28bc…eced`, regenerable en ~12 min.
- **Holdout 20–29 gastado**: abierto una vez el 2026-11-13 (`reports/.holdout_abierto`, commit `e43a28f`). No se vuelve a tocar en este pedido. Todo lo que aquí se mida se mide sobre las sesiones de desarrollo.
- Umbral operativo de referencia: ≤1 falsa alarma por dispositivo-día (validación anidada, `configs/e2.json`).
- Entorno: `.venv/bin/python` (el `activate` está roto). La suite entera tarda ~4 min; sin los CSV se saltan 9 pruebas.

## Reglas duras (una iteración que las rompa se revierte)

1. **El generador está congelado**: no se toca `scripts/lab/generar_trafico.py` ni `scripts/lab/generar_dataset_lab.py`. Cambiar el ataque para que se detecte mejor es hacer trampa; cambiar lo que *vemos* del ataque, no.
2. **Ninguna característica entra porque suba una métrica.** Entra porque se puede decir en una frase qué viola el ataque y qué contador lo ve, y porque se comprobó en el pcap. Primero la justificación escrita en `PROGRESO-EXTRACTOR.md`, después la medida. Si la medida no mejora, se queda igual y se documenta la negativa.
3. **Se lee el pcap, no el generador.** Para descubrir qué distingue un ataque del benigno, abre los `.pcap` de `data/pcap/` y compara tramas. Leer `generar_trafico.py` para copiar sus constantes reintroduce el sesgo que E2 destapó.
4. **El marcador es LOAO, no la puerta de 0,85.** Cada iteración se evalúa con `scripts/ablaciones.py` y se reporta el recall por episodio del tipo excluido, media de los seis y por tipo.
5. **El esquema sube a 3.0** cuando el contrato cambie, y el cambio va completo: `feature_schema.py`, extractor, dataset regenerado, ficha nueva y las cifras de E2 recalculadas sobre el dataset nuevo (las viejas quedan como históricas, no se borran).
6. **El holdout no se abre.** Ni con `--romper-holdout-una-vez`. Si una conclusión necesita holdout, se anota como pendiente para sesiones ≥30.
7. Un commit por iteración. `git status` limpio al cerrar cada una. Sin `git push`: lo hace Nico.

## Protocolo de iteración (lo que ejecuta cada vuelta del bucle)

Al empezar la vuelta, lee `PROGRESO-EXTRACTOR.md`. Si la primera línea dice `PARAR`, no hagas nada más y di por qué.

Cada vuelta hace **exactamente una** de estas cosas, la primera que esté pendiente:

1. **Diagnóstico (iteración 0, obligatoria y única).** Sin tocar el modelo: mide la distribución de las features actuales por ataque y por benigno sobre el dataset de desarrollo, y escribe `reports/extractor_diagnostico.json` con: para cada ataque, las 3 features que más lo separan del benigno, y una columna nueva `depende_de_herramienta` (sí/no/mixta) con el motivo en una línea. Además, un experimento: entrena con **`FEATURES_CAPA2` fuera** (solo ARP, TCP, DNS, largas y globales) y mide LOAO. Ese número es la línea base semántica y se escribe en el progreso.
2. **Una familia de features semánticas** de la lista de abajo, con su justificación escrita antes de medir, su extracción en `src/ventanas.py`, sus pruebas en `tests/test_ventanas.py`, el esquema a 3.0 si toca, dataset regenerado y LOAO medido. Si LOAO no sube, `git revert` del commit de features y se anota la negativa con la cifra.
3. **Una limpieza de artefacto**: neutralizar una feature que dependa de la herramienta (probar a quitarla y mirar si el LOAO sube o el holdout de desarrollo empeora). Se documenta igual que una familia.

Nunca dos familias en la misma vuelta. Nunca reajustar hiperparámetros del modelo en este pedido: el modelo se queda como está salvo que una feature nueva lo obligue (NaN, tipo, escala) y eso se dice.

## Familias semánticas candidatas (una por iteración)

Cada una se justifica por lo que **viola** el ataque. Elige el orden por lo que veas en el pcap.

- **ICMP por tipo.** Hoy solo hay `n_icmp_echo`: `icmp_flood` con `echo_reply` y `unreachable` (BlackNurse) es invisible. Contadores por tipo (echo request, echo reply, destination unreachable, time exceeded) y tasa por segundo.
- **Flags TCP que el benigno no produce.** Conteo de tramas sin flags (Null), FIN sin ACK, SYN+FIN, Xmas, y `syn_sin_ack` por destino. Justificación: esos estados no existen en una conexión legítima de un equipo final.
- **Presión sobre la tabla CAM.** MACs origen distintas por ventana, MACs origen nuevas por segundo, y repetición de una misma MAC origen emitiendo a muchos destinos. Justificación: `mac_flooding` desborda la tabla de conmutación, no solo cambia destinos.
- **Vínculo IP↔MAC.** Ya hay `arp_cambios_vinculo`; falta la vista corta: cambios de vínculo en 5 s, número de MACs distintas anunciando la misma IP, y si la IP reclamada estaba activa en el tráfico previo.
- **DNS sin respuesta legítima.** Respuesta con txid que no corresponde a una consulta pendiente, respuesta desde una IP que no es el resolver, y respuestas duplicadas por txid — ya hay contadores; falta el cociente consultas/respuestas por ventana y por equipo.
- **SYN sin completar, por destino y por ventana.** `syn_medio_abiertos` existe; falta el máximo por destino y la tasa de SYNs con ACK ausente frente a conexiones completadas.
- **Puertos destino tocados por un mismo origen** (abanico) frente a muchos orígenes tocando un mismo puerto (fuerza bruta).

## Criterio de aceptación del pedido

Al terminar (o al parar), `reports/extractor_final.json` y una sección nueva en `docs/INFORME_EXTRACTOR.md` con:

- LOAO por episodio: **media y por tipo**, antes y después, con IC bootstrap.
- La lista de features vivas en 3.0, cada una con su justificación semántica en una línea y su fuente en el pcap.
- Las features retiradas y por qué.
- Las iteraciones que **no** mejoraron, con su cifra (las negativas son resultado, no fracaso).
- Una respuesta explícita: ¿subió el LOAO lo suficiente para decir que el modelo mira el ataque y no la herramienta? Con la cifra delante.

**Criterio de parada** (lo que escribe `PARAR` en el progreso): la media de LOAO por episodio sube ≥0,20 sobre la línea base semántica **y** ningún tipo queda por debajo de 0,30; o tres vueltas seguidas sin mejora; o cuatro horas de trabajo. Lo que se cumpla primero.

## Qué NO se toca

- `scripts/lab/*` (generador y orquestador), `configs/e2.json` salvo la ruta de salida, y el holdout.
- `scripts/baseline_reglas.py` y la puerta de E1: siguen como referencia histórica.
- `docs/INFORME_E1.md` y `docs/INFORME_E2.md`: se enmiendan con addendum si hace falta, no se reescriben.
- E3, E4, E5, E6: no se adelantan. Este pedido es el extractor y nada más.
- `data/*.csv`, `data/*.pcap`, sidecars: fuera de git. Sin `git push`.

## Cierre de cada vuelta (lo que se reporta al bucle)

Tres líneas: qué iteración se hizo, la cifra de LOAO que dejó, y qué sigue. Eso va al final de `PROGRESO-EXTRACTOR.md` y al chat. Nada de resúmenes largos: la cifra y el commit.
