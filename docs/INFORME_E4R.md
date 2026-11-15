# Informe E4R — robustez del detector frente a la intensidad del ataque

PEDIDO-E4R-1 · rama `main` · cuatro commits (`dc3c808`, `c8bbe92`, `cbcea22`, + cierre). Cifras de
`reports/robustez_e4.json` (y su `.md`), IC al 95 % por bootstrap (1000 réplicas, semilla 42) sobre
el **corpus de ataques ya congelado** de E1/E2 (`data/pcap/sesion_000..019`, sha256 `7f06d099…a945`).
No se generó ningún ataque ni evasión nuevos. El registro de decisiones previo a medir está en
`PROGRESO-E4R-1.md`.

## Qué es esta fase

Prueba de robustez (testing adversarial **defensivo**) del IDS: medir cuánto se le escapan los
ataques al detector al bajar de intensidad, y cuál es el suelo que ningún detector por ventana puede
cruzar. Sustituye la "evasión" ficticia de `src/attack_simulator.py` (que copiaba agregados de
ventana, cosa que un atacante no puede escribir en un paquete) por la medida honesta: el pcap
congelado pasa por `src/ventanas.py` y el modelo ve lo que vería en vivo. La etiqueta sigue siendo 1.

## Resumen

| Pregunta | Respuesta, con su cifra |
|---|---|
| ¿A qué intensidad cae el recall del supervisado por debajo de 0,5? | **A ninguna** de las que el corpus congelado produce. La más baja es `rafaga`: **0,824 [0,676, 0,941]**. |
| ¿La curva recall vs intensidad es monótona? | **No.** `media` 0,935 > `suave` 0,891 > `rafaga` 0,824: el generador acopla intensidad baja con duración larga (ver abajo). |
| ¿Cuántos episodios son invisibles por construcción? | **0.** Todo episodio alcanza K=2 en alguna ventana; en `suave` el mínimo es 3 tramas/ventana. |
| ¿Cuánto recall extra aporta el OR de canales, y a qué costo? | **+0,053** (0,894 → 0,947), a cambio de **+122 FA/disp-día** del canal de identidad. |
| ¿Se cumplieron las predicciones sobre identidad y vigilante? | **No, y se reporta.** Identidad detecta 0,388 (no ≈ 0); el vigilante IP→MAC detecta 0,000 el ARP (es ciego a la capa 2). |

El recall supervisado de cabecera (**0,894**, FA **0,89/disp-día**) **reproduce exactamente E2**:
es la prueba de que el camino honesto pcap → `src/ventanas.py` → modelo da lo mismo que la
evaluación tabular de E2, al mismo punto de operación.

## 1. Recall vs intensidad (canal supervisado)

| Intensidad | Recall etiquetable (IC) | Episodios | Invisibles | Recall sobre todos |
|---|---|---|---|---|
| media | 0,935 [0,871, 0,984] | 62 | 0 | 0,935 |
| suave | 0,891 [0,826, 0,957] | 92 | 0 | 0,891 |
| rafaga | 0,824 [0,676, 0,941] | 34 | 0 | 0,824 |

**La curva no es monótona, y es un resultado, no un defecto.** En el generador congelado la
intensidad va atada a la duración: `suave` dura 120–400 s y `rafaga` solo 4–30 s. Un ataque suave,
aunque emita pocas tramas por segundo, deja **muchas ventanas etiquetadas** a lo largo de minutos, y
basta que una dé alarma para detectar el episodio; una ráfaga concentra todo en pocas ventanas y, si
el modelo falla en ellas, el episodio se pierde. Por eso la intensidad más silenciosa (`suave`) **no**
es la de peor recall. Bajar la intensidad en este banco no abre un régimen de evasión del supervisado.

Por tipo, el más difícil es `port_scan` (0,786) y el más fácil `mac_flooding` (1,000); el detalle
por tipo está en `reports/robustez_e4.md`.

## 2. Invisibles por construcción

Un episodio es invisible si ninguna de sus ventanas de 5 s alcanza `K=2` tramas de ataque: entonces
no se etiqueta y el canal supervisado **no puede verlo por diseño** (límite del etiquetado por
ventana, no evasión del modelo). Hoy `src/evaluacion.tabla_episodios` solo agrupa `etiqueta==1`, de
modo que esos episodios desaparecían del denominador sin contarse; aquí se cuentan aparte.

**Resultado: 0 de 188 episodios son invisibles.** En `suave`, el mínimo de `n_tramas_ataque` por
episodio es 3 (por encima de K=2). Es decir: la intensidad más baja que los generadores congelados
producen **todavía deja huella etiquetable** en toda sesión. Un régimen invisible por construcción
exigiría estirar los ataques por debajo de lo que el generador congelado hace —lo que corresponde a
una captura real o a un generador de evasión, fuera del alcance de esta fase y no generado aquí—.

## 3. Los canales por separado, y el OR con su precio

| Tipo | Supervisado(42) | Identidad | Vigilante | OR |
|---|---|---|---|---|
| arp_spoofing | 0,912 | 0,324 | 0,000 | 0,971 |
| dns_spoofing | 0,867 | 0,333 | 0,000 | 0,867 |
| icmp_flood | 0,806 | 0,452 | 0,000 | 0,903 |
| mac_flooding | 1,000 | 0,000 | 0,000 | 1,000 |
| port_scan | 0,786 | 0,714 | 0,000 | 0,929 |
| syn_flood | 0,968 | 0,581 | 0,000 | 1,000 |
| **global** | **0,894** | **0,388** | **0,000** | **0,947** |

FA/disp-día sobre estas sesiones: supervisado **0,89**, vigilante **0,0**, identidad **122,06**
(referencia E3B con variación benigna: **826,24**). OR total **122,95**.

**Las dos predicciones registradas antes de medir fallaron, y así se reporta:**

- **Identidad NO es ≈ 0 en floods/escaneos: detecta 0,388.** El 35 % de los episodios del generador
  usan un origen "clon" (`_origen_ataque`: la MAC de una víctima con la IP del host atacante), así
  que el perfil de pila de esa MAC ve una pila ajena y alarma. Es detección genuina de suplantación
  de MAC. Pero su recall **viene con 122 FA/disp-día**: sin esa cifra al lado, el 0,388 engaña.
- **El vigilante IP→MAC NO dispara en `arp_spoofing`: 0,000.** `VigilanteIP` inspecciona la IP de
  origen de capa 3; las tramas ARP no llevan capa IP, así que el envenenamiento ARP le es invisible.
  Es un límite real del vigilante: detectaría a un suplantador que **emita tráfico IP** con la IP
  ajena, no el ARP en sí.

**La lectura para el artículo:** encender identidad y vigilante como un OR sube el recall de 0,894 a
0,947 (**+0,053**), pero a cambio de **+122 FA/disp-día** (y hasta 826 con variación benigna real,
E3B). Sobre floods y escaneos ese canje no sale a cuenta: el detector supervisado ya los ve, y el
precio del OR es un diluvio de falsas alarmas. Los canales de identidad sirven para lo suyo —clones
de pila (E3)—, no como refuerzo del supervisado contra el volumen.

## 4. Invariantes de efecto (el suelo lo pone la física)

Tasa `suave` real del generador (`RANGOS_ATAQUE`) frente al suelo teórico que conserva el efecto del
ataque, y el recall del supervisado medido en `suave`:

| Ataque | `suave` | Invariante | Suelo de efecto | Recall `suave` |
|---|---|---|---|---|
| syn_flood | 0,4–2,5 SYN/s | agotar el backlog antes del RTO | ≈ 64/3 ≈ 21 medios-abiertos/s | 1,000 |
| arp_spoofing | 0,25–0,8 ARP/s | refrescar antes del gc_stale (≈60 s) | ≈ 0,017 ARP/s | 1,000 |
| mac_flooding | 1–6 MAC/s | inserciones ≥ CAM/envejecimiento | ≈ 8192/300 ≈ 27 MAC/s | 1,000 |
| port_scan | 0,3–0,6 sondas/s | puertos/hora para cubrir el rango | top-puertos lento | 0,882 |
| dns_spoofing | 0,3–0,7 resp/s | forjada antes que la legítima (RTT) | 1 por consulta en ventana RTT | 0,778 |
| icmp_flood | 0,5–2 ICMP/s | saturar enlace/CPU | muy por encima de pocas/s | 0,714 |

Matiz honesto que deja esta tabla: en `suave`, varios "floods" ya caen **por debajo de su suelo de
efecto** (el syn_flood a 0,4–2,5/s no agota un backlog de 64 con RTO de 3 s ≈ 21/s; el mac_flooding a
1–6/s no desborda una CAM de 8192 que envejece en 300 s ≈ 27/s). Es decir: a esa intensidad el
ataque **conserva su firma pero pierde su efecto**, y el detector lo marca igual (recall alto). El
ARP y el DNS son la excepción: su efecto depende de la carrera o del refresco, no de la tasa
agregada, y `suave` los conserva. Ningún ataque queda «invisible por construcción» en este corpus.

## Frase para el artículo

> Sobre el corpus congelado del laboratorio, el detector supervisado **no baja de 0,5 de recall a
> ninguna intensidad** (la más baja, ráfaga, es 0,824 [0,676, 0,941]) y **ningún episodio es
> invisible por construcción** (todos alcanzan el umbral de etiquetado de 2 tramas por ventana). La
> curva recall vs intensidad **no es monótona**: la intensidad más silenciosa (suave, 0,891) supera
> a la ráfaga porque dura más y deja más ventanas etiquetables. El refuerzo por OR de los canales de
> identidad sube el recall solo **+0,053** y a cambio de **+122 falsas alarmas por dispositivo-día**,
> así que no compensa frente a floods y escaneos. El régimen donde el supervisado fallaría —ataques
> estirados por debajo del umbral de etiquetado— **no existe en este corpus** y requeriría una
> captura real o un generador de evasión, fuera del alcance de esta fase.

## Límites declarados

- **Corpus sintético y sin régimen de evasión generado.** No se construyó ningún ataque estirado por
  debajo del umbral de etiquetado ni ninguna imitación de huella a nivel de paquete; la robustez se
  mide contra la distribución de este laboratorio, no contra tráfico real ni contra un adversario que
  optimice la evasión.
- **Detección por canal (identidad/vigilante) por solape temporal:** una alarma benigna que caiga en
  una ventana de episodio se acredita como detección. Mitigado reportando la FA de cada canal aparte.
- **El vigilante es ciego al ARP** (capa 2); mide conflictos IP→MAC de capa 3.
- **La quietud del corpus tiene suelo:** incluso en `suave`, cada episodio deja ≥ 3 tramas en alguna
  ventana. Un atacante real más paciente no está representado.

## Qué queda para E5

- Para medir evasión **de verdad** (ataques por debajo del umbral de etiquetado, o imitación de
  huella a nivel de paquete) hace falta una **captura propia del laboratorio real** o un generador de
  evasión; sin eso, cualquier cifra de evasión es optimista.
- Conectar el camino en vivo (streaming: captura → ventanas → modelo → alerta) y la mitigación en
  `dry-run`, que siguen sin implementarse.
- El pronóstico de alertas (parte de OE3) sigue pendiente.

## Aceptación (salida real)

```text
$ .venv/bin/python -m pytest -o addopts="" -q tests/test_evaluar_robustez.py
..........                                                               [100%]
10 passed in 1.69s

$ .venv/bin/python scripts/evaluar_robustez.py --config configs/robustez.json
Escrito /home/nikka/Documentos/FRED/IDS/reports/robustez_e4.json y /home/nikka/Documentos/FRED/IDS/reports/robustez_e4.md
{"recall_episodio": 0.894, "recall_por_intensidad": {"media": 0.935, "rafaga": 0.824, "suave": 0.891}, "fa_dispositivo_dia": 0.89, "invisibles_total": 0, "recall_suave_etiquetable": 0.891, "recall_suave_todos": 0.891, "invisibles_por_tipo": {}, "_suave_tipo_debug": {"suave": 0.891}, "canales": {"recall_supervisado_42": 0.894, "recall_or": 0.947, "extra_recall_or": 0.053, "recall_identidad": 0.3882978723404255, "recall_vigilante": 0.0, "fa_por_dispositivo_dia": {"supervisado": 0.89, "identidad_en_estas_sesiones": 122.06, "identidad_referencia_e3b_con_variacion": 826.24, "vigilante": 0.0, "or_total_en_estas_sesiones": 122.95}}}

$ .venv/bin/python -c "import json;d=json.load(open('reports/robustez_e4.json'));print(d['resumen'])"
{'recall_episodio': 0.894, 'recall_por_intensidad': {'media': 0.935, 'rafaga': 0.824, 'suave': 0.891}, 'fa_dispositivo_dia': 0.89, 'invisibles_total': 0, 'recall_suave_etiquetable': 0.891, 'recall_suave_todos': 0.891, 'invisibles_por_tipo': {}, '_suave_tipo_debug': {'suave': 0.891}, 'canales': {'recall_supervisado_42': 0.894, 'recall_or': 0.947, 'extra_recall_or': 0.053, 'recall_identidad': 0.3882978723404255, 'recall_vigilante': 0.0, 'fa_por_dispositivo_dia': {'supervisado': 0.89, 'identidad_en_estas_sesiones': 122.06, 'identidad_referencia_e3b_con_variacion': 826.24, 'vigilante': 0.0, 'or_total_en_estas_sesiones': 122.95}}}
```

