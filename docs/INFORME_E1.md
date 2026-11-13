# Informe E1 — El generador deja de ser separable y el dataset queda reproducible

> Etapa E1 de `docs/PLAN_IMPLEMENTACION.md`. Trabajo del 2026-11-12/13 sobre `0026bc3`.
> No incluye E2–E6. `docs/INFORME_FASE_1.md` no se modificó; su §4.3 se enmienda en
> `docs/ADDENDUM_SECCION_4_3.md`.

## Resumen

| bloque | resultado |
|---|---|
| 1. Reproducibilidad | `requirements-dev.txt`, ficha versionada del dataset con `sha256`; el dataset se regenera **byte a byte** |
| 2. Holdout de E2 | sesiones 20–29 protegidas por código en generación, carga y reparto |
| 3. Solapamiento | generador con intensidad y variante por episodio y benigno ensanchado. **La puerta de 0,85 solo la cumple `icmp_flood`** (0,837); port_scan queda en 0,891 y los otros cuatro entre 0,977 y 0,996 |
| 4. Puerta automática | `tests/test_separabilidad.py`; los cinco ataques que no cumplen figuran como xfail estricto con su cifra |
| 5. Addendum §4.3 | agrupar por `grupo` = no agrupar; por sesión, la exactitud balanceada del RF baja 0,041 y su recall 0,081 |

**Desviación principal:** el 0,85 no se alcanzó en 5 de 6 ataques. Las cifras y la causa
están en el §3.4. No se relajó el umbral.

## 1. Estado de partida verificado

- HEAD `0026bc3` («testeo y pdf», 2026-11-12 22:27), árbol limpio, 7 commits. ✔
- Suite: **56 passed, 0 skipped**, no 54 + 2 como decía el pedido. En este equipo
  `data/dataset_lab.csv` sí existía (generado el 2026-10-31 15:59), así que las dos
  pruebas de `tests/test_data.py:36,48` no se saltaban. Ese CSV sirvió como «antes»
  medido: reproduce exactamente el `reports/baseline_reglas.json` anterior.
- `.venv/bin/activate` apunta a la ruta antigua del proyecto
  (`ids-proyecto/ids_project/.venv`). Hay que invocar `.venv/bin/python` directamente;
  `source .venv/bin/activate` deja `python` en `/usr/bin/python`, sin pytest.

## 2. Bloques 1 y 2 — reproducibilidad y holdout

**Dependencias.** `requirements-dev.txt` (`-r requirements.txt` + `pytest`). El README
indica `pip install -r requirements.txt -r requirements-dev.txt` y `python -m pytest -q`.

**Ficha.** `scripts/lab/ficha_dataset.py <csv>` escribe `reports/dataset_lab_<fecha>.json`,
con la fecha de generación del CSV. Contiene filas, columnas, distribución por sesión,
etiqueta, tipo, capa, variante e intensidad, semillas, comando, K, commit, `sha256` y
fechas. El orquestador deja el sidecar `data/dataset_lab.csv.meta.json` (ignorado por git)
con comando, semillas y commit. La correspondencia `sesion_NNN` ↔ semilla
`42000 + NNN` vive en `src/data.py`.

**Prueba de reproducibilidad.** El dataset se generó dos veces con el mismo código (una
en el scratchpad y otra en `data/`) y dio el mismo `sha256`:
`3f4d28bcd1d2fee5cd5aeab0ae31d5213262a097f7a051fe87b6e63f9e04eced`.

**Holdout.** `src/data.py` define `SESIONES_RESERVADAS = range(20, 30)`, y se comprueba
en tres puntos:

- `generar_dataset_lab.py` se niega a generar un índice reservado sin `--romper-holdout`:
  sale con código 2 antes de crear nada. `--inicio` permite construir el holdout cuando
  toque.
- `cargar_dataset()` lanza `HoldoutError` si el CSV trae una sesión reservada, salvo con
  `permitir_holdout=True`.
- `dividir()`, la puerta de todo entrenamiento y del baseline, lanza `HoldoutError`
  siempre.

`tests/test_holdout.py` cubre los tres caminos y comprueba que el dataset en disco no
contiene sesiones reservadas.

## 3. Bloque 3 — el generador

### 3.1 Qué cambió (rangos antes → después)

Cada episodio sortea una **intensidad** (ráfaga 25 %, media 30 %, suave 45 %) y una
**variante**. Las tablas completas están en el docstring de `scripts/lab/generar_trafico.py`
(`RANGOS_ATAQUE`, `VARIANTES`).

| ataque | antes | después: ráfaga / media / suave (tasa, duración) | variantes nuevas |
|---|---|---|---|
| mac_flooding | 100–1500 /s, 4–25 s | 100–1500 /s 4–25 s · 10–60 /s 20–90 s · 1–6 /s 60–300 s | `rafaga_por_mac` (2–4 tramas por MAC falsa, solo suave) |
| arp_spoofing | ráfaga 20–200 /s o ~1 /s durante 60–200 s | 20–200 /s 4–20 s · 1–4 /s 20–90 s · 0,25–0,8 /s 120–400 s | método respuesta / carrera / petición / gratuito × objetivo gateway / host |
| dns_spoofing | 0,4–2 consultas/s, 15–60 s | 50–400 /s 4–15 s · 0,5–2 /s 15–60 s · 0,3–0,7 /s 120–400 s | MITM (sin respuesta real), Kaminsky |
| syn_flood | 50–1200 /s, 4–30 s | 50–1200 /s 4–30 s · 8–40 /s 20–90 s · 0,4–2,5 /s 120–400 s | `ip_propia` |
| port_scan | 20–300 /s o 0,3–1,5 /s | 20–300 /s (200–2000 p) · 0,3–1,5 /s (60–300 p) · 0,3–0,6 /s (40–120 puertos comunes) | connect, UDP, FIN/Xmas/Null |
| icmp_flood | 50–1000 /s, 4–25 s | 50–1000 /s 4–25 s · 5–30 /s 20–90 s · 0,5–2 /s 60–300 s | echo_reply, unreachable (BlackNurse) |

Benigno nuevo que se parece a los ataques suaves:

- auditoría de un equipo (30–300 puertos, estilo connect);
- monitorización ICMP del NMS y ping continuo de diagnóstico;
- actualización de software (5–30 flujos en 2–20 s);
- gateway en alta disponibilidad, con conmutación en la que el respaldo reclama la IP del
  gateway con su MAC física;
- sondas ARP NUD;
- DNS externo y reenviador del gateway, retransmisiones DNS con dos respuestas por txid;
- RPC con puertos dinámicos, Delivery Optimization (TCP 7680), QUIC bloqueado con ICMP;
- IoT que reintenta TCP contra su nube abandonada;
- servidor web expuesto con escaneo de fondo desde Internet;
- rotación de MACs con reutilización de IP y reinicio de punto de acceso.

El manifiesto suma la columna `intensidad` (episodios y tramas), y las filas del dataset
heredan `variante` e `intensidad` como columnas de **traza** aditivas (`COLUMNAS_TRAZA`).
No entran al modelo, y el contrato de características no cambió.

### 3.2 Dataset antes / después

| | antes (2026-10-31) | después (2026-11-12) |
|---|---|---|
| sha256 | `3d60dfff…d84a` | `3f4d28bc…eced` |
| ventanas | 62 424 | 78 988 |
| ventanas por sesión (media; mín–máx) | 3 121; 2 762–3 675 | 3 949; 3 136–4 446 |
| benignas / maliciosas | 61 140 / 1 284 | 73 273 / 5 715 |
| proporción maliciosa | 2,06 % | 7,24 % |
| atacantes distintos por sesión | 4,9 | 4,85 |
| episodios (por sesión) | 154 (7,7) | 188 (9,4) |

Ventanas maliciosas por ataque e intensidad:

| ataque | antes | después: ráfaga | media | suave | total |
|---|---|---|---|---|---|
| arp_spoofing | 355 | 26 | 175 | 255 | 456 |
| dns_spoofing | 186 | 16 | 42 | 563 | 621 |
| icmp_flood | 85 | 16 | 161 | 443 | 620 |
| mac_flooding | 103 | 19 | 113 | 2 811 | 2 943 |
| port_scan | 447 | 16 | 165 | 241 | 422 |
| syn_flood | 108 | 14 | 148 | 491 | 653 |

Episodios por variante (antes → después):

- **arp:** ráfaga 15 / unicast lento 12 → respuesta 10, carrera 7, petición 9, gratuito 8.
- **dns:** clona resolver 6 / MAC propia 19 → carrera propia 9, carrera clona 2,
  MITM propia 6, MITM clona 10, Kaminsky 3.
- **icmp:** eco 24 → eco 10, respuesta de eco 10, inalcanzable 11.
- **mac:** aleatorio 28 → aleatorio 20, por MAC 14.
- **port_scan:** lento 11 / rápido 14 → syn 7, connect 8, UDP 8, FIN/Xmas/Null 5.
- **syn:** MAC fija 18 / rotatoria 7 → MAC fija 10, rotatoria 8, IP propia 13.

Reparto completo por tipo/variante/intensidad en `reports/dataset_lab_2026-11-12.json`
(`por_tipo_variante_intensidad`).

**Ojo con mac_flooding:** 2 688 de sus 2 943 ventanas vienen de `rafaga_por_mac` suave,
porque cada MAC falsa con 2–4 tramas es una fila. Las métricas por ventana de E2 deben
leerse junto con las métricas por episodio.

### 3.3 Separabilidad: tabla vieja frente a nueva

Métrica: **exactitud balanceada** (EB) = (recall + 1 − FPR) / 2, máxima entre stump y
árbol de profundidad 2.

- **Por qué no la exactitud simple:** con 93–98 % de ventanas benignas, un clasificador
  que siempre dice «benigno» ya daría 0,93–0,98, y la puerta no significaría nada. Esta
  interpretación del «0,85 de exactitud» es mía.
- **Por qué el máximo de 4 folds:** la puerta toma el máximo sobre los 4 repartos por
  sesión, no un solo reparto. Con 8 sesiones, dns_spoofing dio 0,816 en un reparto y 0,98
  en los otros tres: un solo reparto pasa o falla por suerte.
- **Continuidad:** el fold 0 es el reparto que usaba la versión anterior del script.

| ataque | EB vieja (fold 0) | EB vieja (máx. 4 folds) | regla vieja | EB nueva (fold 0) | EB nueva (media) | **EB nueva (máx.)** | recall / FPR | regla nueva | ¿≤ 0,85? |
|---|---|---|---|---|---|---|---|---|---|
| arp_spoofing | 1,000 | 1,000 | `arp_replies_no_solicitadas` | 0,977 | 0,959 | **0,977** | 1,000 / 0,047 | `arp_cambios_vinculo_60s` | no |
| dns_spoofing | 0,999 | 0,999 | `dns_multiples_respuestas_txid` | 0,976 | 0,978 | **0,979** | 1,000 / 0,042 | `dns_respuestas` | no |
| icmp_flood | 0,982 | 1,000 | `n_icmp_echo` | 0,837 | 0,794 | **0,837** | 0,776 / 0,102 | `longitud_trama_std` | **sí** |
| mac_flooding | 1,000 | 1,000 | `macs_destino_distintas` | 0,996 | 0,984 | **0,996** | 1,000 / 0,007 | `n_tramas_60s` | no |
| port_scan | 0,990 | 0,990 | `syn_medio_abiertos_60s` | 0,864 | 0,874 | **0,891** | 0,878 / 0,097 | `entropia_puertos_destino` | no |
| syn_flood | 0,981 | 1,000 | `ips_origen_distintas` | 0,975 | 0,977 | **0,990** | 0,993 / 0,012 | `syn_medio_abiertos_60s` | no |

Archivos: `reports/baseline_reglas.json` (nuevo) y
`reports/baseline_reglas_dataset_2026-10-31.json` (dataset viejo medido con el método
nuevo). El `reports/baseline_reglas.json` original está en `0026bc3`.

Lo que sí cambió: ningún ataque queda en 1,000 con FPR 0. Las reglas ya no son un umbral
sobre un contador que en benigno vale siempre 0: los FPR van de 0,7 % a 10 %.
`arp_spoofing` y `mac_flooding` salen de 1,000 / 0,000, aunque siguen muy por encima del
listón.

### 3.4 Desviación: por qué 0,85 no se alcanza, con la cifra delante

**Cumple 1 de 6:** icmp_flood con 0,837. No cumplen port_scan (0,891), arp_spoofing
(0,977), dns_spoofing (0,979), syn_flood (0,990) ni mac_flooding (0,996).

La causa es estructural, no de ajuste fino:

- **Recall − FPR ≤ 0,70.** EB ≤ 0,85 equivale a que ninguna regla de profundidad 2
  cumpla recall − FPR > 0,70.
- **El FPR lo diluyen las filas tranquilas.** Se calcula sobre todas las ventanas
  benignas, y la mayoría son de equipos tranquilos. Los gemelos benignos de un ataque (la
  fila del resolver para DNS, la del gateway o los equipos que rotan IP para ARP, los
  reintentos fallidos para SYN) son como mucho una de las ~20 filas de cada ventana.
  Aunque sean indistinguibles del ataque, cuestan pocos puntos de FPR.
- **Lo que haría falta.** Para bajar de 0,85, al menos un 30 % de las ventanas de cada
  ataque tendrían que no llevar su firma semántica. Esa firma es inherente al ataque:
  todo envenenamiento ARP cambia un vínculo IP→MAC conocido, toda suplantación DNS emite
  respuestas desde un equipo que no es servidor y todo SYN flood deja conexiones medio
  abiertas.
- **Por qué icmp sí cumple.** El extractor no tiene un contador para ICMP distinto del
  eco, así que las variantes `echo_reply` y `unreachable` suaves caen dentro del
  benigno.
- **Riesgo de sesgo del autor.** Seguir moviendo pesos y rangos hasta pasar la puerta
  convertiría el generador en un ajuste a la métrica, que es justo el riesgo que declara
  el plan. Paré después de tres iteraciones con criterio documentado. Los cambios hechos
  con el baseline a la vista son exactamente los de §3.1, y el docstring del generador lo
  declara.

Opciones para decidir (no las tomé):

- **Aceptar las cifras como resultado de E1.** El dataset ya no es trivial en el sentido
  del pedido: no hay recall 1 con FPR 0.
- **Cambiar la unidad de la puerta.** Por ejemplo, FPR por dispositivo o por episodio en
  lugar de por ventana, que es lo que E2 va a medir.
- **Endurecer más el generador** con ataques que en su mayoría no lleven firma, sabiendo
  que entonces el recall de E2 medirá sobre todo la proporción que se haya elegido.

## 4. Bloque 4 — la puerta automática

`tests/test_separabilidad.py`:

- **Sin datos.** La maquinaria detecta un dataset trivial (EB > 0,99) y deja pasar uno
  con etiquetas sin señal.
- **Con `data/dataset_lab.csv`.** La puerta corre sobre una muestra: todo el ataque y el
  25 % del benigno de cada sesión. La EB no depende de la proporción de clases, y la
  muestra da el mismo veredicto que el dataset completo en unos 3 s (icmp 0,847 frente a
  0,837 completo). Falla si un ataque supera 0,85 en algún fold. Sin el CSV, se salta con
  el motivo «data/dataset_lab.csv no generado todavía».
- **Desviaciones declaradas.** Los cinco ataques que no cumplen están en
  `DESVIACIONES_DECLARADAS` como `xfail(strict=True)`, con su cifra y causa. Si alguno
  empieza a cumplir, la prueba falla y obliga a retirar la declaración; si icmp_flood
  vuelve a ser trivial, la suite se pone roja. Para que la puerta bloquee también a los
  otros cinco basta con vaciar ese diccionario.

Con el dataset viejo, la puerta falla en los seis ataques (EB 0,998–1,000). Es la
comprobación de que el test detecta lo que tiene que detectar.

## 5. Bloque 5 — §4.3

Detalle en `docs/ADDENDUM_SECCION_4_3.md` (medición reproducible con
`scripts/medir_agrupacion.py` → `reports/agrupacion_4_3.json`). Exactitud balanceada,
media de 4 folds:

| reparto | RF | XGBoost |
|---|---|---|
| sin agrupar | 0,9747 | 0,9866 |
| `grupo` (`mac#ventana`) | 0,9745 | 0,9874 |
| dispositivo | 0,9087 | 0,9370 |
| sesión | 0,9338 | 0,9589 |

`grupo` es único por fila dentro de cada sesión (78 341 valores para 78 988 filas; solo
se repite `__efimeras__#ventana` entre sesiones), así que agruparlo no agrupa nada. La
importancia de `iat_media_ms`, el equivalente actual de `tiempo_entre_tramas_ms`, es
≈ 0,05 (puesto 5–6), no 0,54. `oui_frecuente` ya no existe en el contrato.

## 6. Otras desviaciones y decisiones

1. **Métrica de la puerta.** La puerta usa exactitud balanceada y no exactitud simple
   (§3.3). Es mi interpretación del pedido.
2. **Cuántos repartos mira la puerta.** Toma el máximo de los 4 folds por sesión, no un
   solo reparto. Es más estricto que la versión anterior del baseline.
3. **Baja intensidad.** Interpreté «los ataques de baja intensidad se quedan como
   legítimos» como la regla K existente: una ventana con menos de `K_TRAMAS_ATAQUE = 2`
   tramas de ataque es benigna. K no cambió. Las filas bajo K conservan atacante,
   episodio, variante e intensidad, para que E2 pueda recalcular K.
4. **`feature_schema.py`.** Se tocó solo para añadir dos columnas de traza aditivas
   (`variante`, `intensidad`). Ninguna característica del modelo cambió de nombre ni de
   semántica, y `VERSION_ESQUEMA` sigue en 2.0.
5. **Tests adaptados (no borrados), con el motivo en el propio test:**
   - `test_dns_y_arp_responden_tras_la_peticion` omite las tramas de ataque: Kaminsky
     envía respuestas sin consulta a propósito.
   - `test_manifiestos_y_ataques` comprueba la unicidad de MAC solo para
     `ether_aleatorio`.
   - `test_vector_icmp_presente` comprueba el tipo ICMP según la variante.
6. **Dos commits en el bloque 3.** Primero el código (`70cd3e6`) y después la ficha y el
   baseline (`8ff7fef`), para que el sidecar del dataset apunte al commit del generador
   que lo produjo.
7. **`reports/dataset_lab_2026-10-31.json`.** Es una ficha escrita a posteriori del CSV
   viejo, con `commit: null`: el commit de aquella generación no quedó registrado.
8. **`ruff check src/data.py`** marca un orden de imports que ya estaba en `0026bc3`. No
   lo toqué.

## 7. Criterio de aceptación — salida real

```text
$ python -m pytest -q | tail -3
tests/test_ventanas.py ............                                      [100%]

================== 72 passed, 5 xfailed in 171.71s (0:02:51) ===================
$ python scripts/lab/generar_dataset_lab.py --sesiones 20      # 2026-11-12 23:53, 12 min
[INFO] Dataset: 78988 filas, 62 columnas -> data/dataset_lab.csv
[INFO] Clases: {0: 73273, 1: 5715}
[INFO] Tipos: {'normal': 73273, 'mac_flooding': 2943, 'syn_flood': 653, 'dns_spoofing': 621, 'icmp_flood': 620, 'arp_spoofing': 456, 'port_scan': 422}
$ python scripts/lab/ficha_dataset.py data/dataset_lab.csv
reports/dataset_lab_2026-11-12.json: 78988 filas, sha256 3f4d28bcd1d2fee5cd5aeab0ae31d5213262a097f7a051fe87b6e63f9e04eced
Etiquetas: {'0': 73273, '1': 5715}
$ python scripts/baseline_reglas.py | tail -10                 # sale con código 1: hay ataques que no cumplen
Puerta (exactitud balanceada máxima en 4 folds <= 0.85):
  ataque          fold0  media    máx recall    FPR
  arp_spoofing    0.977  0.959  0.977  1.000  0.047  NO CUMPLE  (arp_cambios_vinculo_60s <= 0.50)
  dns_spoofing    0.976  0.978  0.979  1.000  0.042  NO CUMPLE  (dns_respuestas <= 1.50)
  icmp_flood      0.837  0.794  0.837  0.776  0.102  cumple  (longitud_trama_std <= 19.23)
  mac_flooding    0.996  0.984  0.996  1.000  0.007  NO CUMPLE  (n_tramas_60s <= 4.50)
  port_scan       0.864  0.874  0.891  0.878  0.097  NO CUMPLE  (entropia_puertos_destino <= 1.00)
  syn_flood       0.975  0.977  0.990  0.993  0.012  NO CUMPLE  (syn_medio_abiertos_60s <= 5.50)

Positivos totales: 5715. Reporte: reports/baseline_reglas.json
$ git status --short
(vacío tras el commit de este informe; el CSV, los pcap y el sidecar están en .gitignore)
```

```text
$ git log --oneline -7
4aa3418 IDS E1: bloque 5 — addendum del §4.3 con la diferencia medida
10fba6d IDS E1: bloque 4 — puerta automática de separabilidad
8ff7fef IDS E1: bloque 3 — ficha y puerta del dataset regenerado
70cd3e6 IDS E1: bloque 3 — solapamiento medible y dataset regenerado
ac1d032 IDS E1: bloque 2 — holdout protegido por código
271571a IDS E1: bloque 1 — ficha del dataset y dependencias de prueba
0026bc3 testeo y pdf
```

(Más el commit de este informe.)
