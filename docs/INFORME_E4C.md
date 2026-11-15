# Informe E4C — el ARP lento que el detector por ventana no ve, y el vigilante que sí

PEDIDO-E4C-1 · rama `main` · cuatro bloques, un commit cada uno (`41d0c9f`, `afd9c8b`, `bddff3e`,
y este cierre). Cifras de `reports/robustez_e4c.json` (y su `.md`). El diario de decisiones, con lo
registrado antes de cada medida, está en `PROGRESO-E4C-1.md`.

## Qué prueba esta fase

Es la prueba de robustez que E4R dejó pendiente: llevar un ataque al **régimen donde el detector
por ventana no puede verlo** y medir qué canal, si alguno, lo sigue viendo. No se fabricó ni una
trama: la única pieza que toca pcaps es un **re-temporizador** que mueve en el tiempo tramas ya
existentes del corpus congelado, con cuatro invariantes verificadas en código (bytes, número,
monotonía, orden por flujo). El vigilante IP→MAC se extendió para leer el ARP (una mejora de
detección, defensiva).

## Resumen

| Pregunta | Respuesta, con su cifra |
|---|---|
| ¿Veía el vigilante el ARP spoofing? | **No** (E4R: 0,000). Dos causas: era ciego a la capa 2 **y** nacía con la red equivocada (10.20.0.0/16 del lab de identidad, no la 10.0.0.0/24 del corpus de ataques). |
| ¿Lo ve ahora? | **Sí: 1,000** en los cuatro pasos lentos, con **0,0 FA/disp-día** sobre la variación benigna de E3B. |
| ¿A qué tasa el ARP se vuelve invisible para el supervisado? | A **paso ≥ 5 s** entre tramas (el tamaño de la ventana): ninguna ventana alcanza K=2, el recall supervisado cae de **1,000** (nativo) a **0,000**. |
| ¿Qué canal lo sigue viendo? | El **vigilante IP→MAC** (1,000) y el perfil de identidad (1,000); el supervisado, no. |

## 1. El vigilante ve el ARP (bloque 1)

`VigilanteIP.observar` alimenta el mapa `ip → MAC` con dos fuentes del mismo criterio: el emisor IP
de capa 3 (`ip_src → mac_src`, como antes) y el vínculo que declara cada ARP local
(`arp_psrc → arp_hwsrc`, `arp_op` 1 y 2). Una suplantación ARP reclama una IP ya vinculada a otra
MAC y dispara conflicto o reasignación con la lógica existente, **sin umbrales nuevos**. La señal
`arp_hwsrc != mac_src` (el ARP declara un emisor que no es el `Ether.src` real) se emite como alerta
propia; en este corpus queda latente (el atacante rellena `hwsrc == Ether.src`), y así se reporta.

No se tocó la gracia de 600 s, `MIN_VENTANAS_CRUCE` ni `no_confiable`. Tres pruebas nuevas en
`tests/test_identidad.py`: ARP falso de una trama dispara; GARP legítimo del mismo equipo no;
conflicto (dos MAC a la vez) frente a reasignación (secuencial, dentro de la gracia).

## 2. El re-temporizador (bloque 2)

`scripts/lab/retemporizar.py` no es un generador: lee una sesión existente y solo cambia `pkt.time`
de las tramas de un episodio ARP/DNS ya etiquetado. Verifica y falla si se rompen: (i) multiconjunto
de bytes idéntico; (ii) número de tramas igual; (iii) timestamps no decrecientes; (iv) orden
relativo de las tramas movidas y quietas conservado. Reescribe los sidecars para que
`pcap_to_features` siga etiquetando. Rechaza tipos ≠ ARP/DNS y escrituras fuera de `data/pcap/`.
Semilla fija ⇒ pcap byte a byte. Seis pruebas en `tests/test_retemporizar.py`.

## 3. El régimen invisible, medido (bloque 3)

XGBoost entrenado sobre el corpus congelado al punto de operación de E2 (umbral 0,9086, 1 FA/disp-día),
aplicado a los pcaps retemporizados. Dos episodios ARP (variantes de una trama por evento:
`respuesta`/`gratuito`/`peticion`) y dos DNS. **Duración controlada**: para cada paso se dejan
`m = 300/paso + 1` refrescos, de modo que todos los pasos cubren el mismo horizonte (~305 s) — la
lección de E4R es que sin controlar la duración la curva no dice nada.

### ARP: recall por canal frente al paso entre tramas

| Paso | Ventanas etiquetadas (media) | Invisibles | Supervisado | Identidad | Vigilante | OR | Horizonte (s) |
|---|---|---|---|---|---|---|---|
| nativo (rápido) | 11,0 | 0 | **1,000** | 0,500 | 1,000 | 1,000 | 60 |
| 5 s | 0,0 | 2/2 | **0,000** | 1,000 | **1,000** | 1,000 | 305 |
| 15 s | 0,0 | 2/2 | 0,000 | 1,000 | 1,000 | 1,000 | 310 |
| 30 s | 0,0 | 2/2 | 0,000 | 1,000 | 1,000 | 1,000 | 308 |
| 60 s | 0,0 | 2/2 | 0,000 | 1,000 | 1,000 | 1,000 | 305 |

Latencia del vigilante: 5 s (primera ventana) en los cuatro pasos.

### DNS spoofing (tiempo nativo, la carrera)

Supervisado 1,000 · identidad 0,500 · vigilante 0,500 · OR 1,000 (n=2, 0 invisibles). El suelo de
efecto del DNS es la carrera con la respuesta legítima, no la tasa agregada, así que no se barre un
paso: se mide en su tiempo nativo.

### Veredicto de las predicciones registradas

- **P1** (con paso ≥ 30 s el ARP es invisible para el supervisado): **se cumple**. De hecho el
  supervisado queda ciego ya a **paso 5 s**: en cuanto las tramas se separan el tamaño de la ventana,
  ninguna ventana alcanza K=2 y el episodio no se puede ni etiquetar. No es un fallo del modelo; es
  el límite del etiquetado por ventana.
- **P2** (el vigilante con el bloque 1 ve el ARP lento): **se cumple**, 1,000 en los cuatro pasos.

### Falsas alarmas del vigilante

Sobre las 20 sesiones de variación benigna de E3B (78000–78019, sin clones): **0,0/disp-día** (0
alertas en 2,71 disp-día), dentro del presupuesto de E2. **Sesgo declarado**: el generador de
variación no tiene DHCP ni failover de gateway, así que un cambio legítimo de IP→MAC no está
representado y esta cifra es optimista. El ARP gratuito legítimo y las dos interfaces del mismo
equipo (presentes en la variación) no alarman, como debe ser.

## Invariantes de efecto (citados, no medidos)

| Ataque | `suave` del generador | Invariante de efecto | Suelo | Lectura |
|---|---|---|---|---|
| `arp_spoofing` | 0,25–0,8 ARP/s | refrescar antes del `gc_stale` (≈60 s Linux, ≈30 s Windows) | ≥ 1/60 s ≈ 0,017 ARP/s | el ARP lento conserva el efecto hasta paso 60 s; por encima deja de envenenar y la medida ya no vale |
| `dns_spoofing` | 0,3–0,7 resp/s | la forjada llega antes que la legítima (ventana de RTT) | 1 respuesta por consulta dentro del RTT | el efecto lo pone la carrera por consulta, no la tasa |

El rango medido (5–60 s) queda **por debajo** del suelo de efecto del ARP (60 s): todos los pasos
probados siguen siendo un ataque real, no un ataque que desapareció. A paso > 60 s el refresco llega
después del `gc_stale` y el envenenamiento ya no se mantiene; ahí la medida dejaría de valer.

## Frase para el artículo

> El ARP spoofing se detecta con el clasificador por ventana solo mientras es rápido (recall 1,000 a
> su ritmo nativo). Separando sus tramas apenas **5 segundos** —el tamaño de la ventana, muy por
> encima del suelo de efecto de 60 s que lo mantiene envenenando— el ataque deja de alcanzar el
> umbral de etiquetado y se vuelve **invisible por construcción** para el supervisado (recall 0,000),
> sin dejar de ser un ataque. El **vigilante IP→MAC**, una vez que lee el ARP, lo detecta en el
> 100 % de los casos a cualquiera de esos pasos, con **0 falsas alarmas** sobre tráfico benigno con
> variación. La defensa contra el ataque lento no es un mejor clasificador de volumen: es una señal
> de identidad que no depende de la tasa.

## Límites no resueltos / para E5

- La FA del vigilante (0,0) es optimista: el laboratorio no tiene DHCP ni failover de gateway, que
  son las fuentes reales de cambios legítimos de IP→MAC. Hace falta medirla con DHCP real.
- El supuesto de detección por solape temporal acredita como detección cualquier alerta del
  vigilante dentro de la ventana del episodio; se mitiga reportando las FA fuera de episodio aparte
  (0 aquí).
- El modelo supervisado se entrena sobre el corpus que incluye las sesiones de origen; no afecta la
  conclusión (con 0 ventanas etiquetadas el recall es 0 sea cual sea el modelo), pero se declara.
- La reducción a `m` refrescos descarta frames de ataque sobrantes (sub-muestreo); modela un
  atacante de baja tasa, no al del corpus. La conclusión de visibilidad depende solo de
  tramas-por-ventana, que es invariante a ese detalle.

## Aceptación (salida real)

```text
$ .venv/bin/python -m pytest -o addopts="" -q tests/test_identidad.py tests/test_retemporizar.py tests/test_evaluar_robustez.py
....................................................                     [100%]
52 passed in 2.59s

$ .venv/bin/python scripts/evaluar_robustez.py --config configs/robustez_e4c.json
Escrito reports/robustez_e4c.json y reports/robustez_e4c.md

$ .venv/bin/python -c "import json;d=json.load(open('reports/robustez_e4c.json'));print(d['resumen'])"
{"recall_arp_por_paso": {"nativo": {"supervisado": 1.0, "identidad": 0.5, "vigilante": 1.0, "or": 1.0, "invisibles": 0, "n": 2}, "5s": {"supervisado": 0.0, "identidad": 1.0, "vigilante": 1.0, "or": 1.0, "invisibles": 2, "n": 2}, "15s": {"supervisado": 0.0, "identidad": 1.0, "vigilante": 1.0, "or": 1.0, "invisibles": 2, "n": 2}, "30s": {"supervisado": 0.0, "identidad": 1.0, "vigilante": 1.0, "or": 1.0, "invisibles": 2, "n": 2}, "60s": {"supervisado": 0.0, "identidad": 1.0, "vigilante": 1.0, "or": 1.0, "invisibles": 2, "n": 2}}, "paso_supervisado_ciego_s": "5s", "dns_nativo": {"supervisado": 1.0, "identidad": 0.5, "vigilante": 0.5, "or": 1.0}, "fa_vigilante_variacion_por_dispositivo_dia": 0.0, "P1_arp_invisible_supervisado_paso_30": true, "P2_vigilante_detecta_arp_lento": true}
```

Las rachas de `INFO` del re-temporizador confirman el mecanismo: a paso nativo el episodio deja 8 y
14 ventanas etiquetadas (`sup=True`); a paso 5/15/30/60 s deja 0 (`invis=True`, `sup=False`), y el
vigilante marca `True` en todos.
