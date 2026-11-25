# INFORME-ENTREGA: cierre del repo IDS_IA (2026-11-25)

Ejecución de `docs/historial/PEDIDO-ENTREGA.md` (antes en la raíz como `PEDIDO-ENTREGA.md`), bloque
por bloque y en orden, desde el commit `31431f8`. Entorno: Linux 6.8, 4 CPU, Python 3.14.9 en `.venv`
(creado con `uv`), xgboost 3.4.1, scikit-learn 1.9.1, scapy 2.8.0. Todo lo que va entre bloques de
código es salida real copiada de la terminal; los recortes se marcan con `[…]`.

Notas de entorno que no cambian resultados:

- La caché por defecto de `uv` (`/opt/data/.cache/uv`) es de root y no se puede escribir. Usé
  `UV_CACHE_DIR=/tmp/uv-cache-ids`.
- El repo no tiene identidad de git configurada y `~/.config/git` no se puede leer. Los commits se
  hicieron con la identidad de los commits previos del repo (`nikkaoyy`), pasada por variables de
  entorno, sin tocar la configuración.

| Bloque | Commit | Asunto |
|---|---|---|
| 0 | `bff16d0` | bloque 0: línea base de pruebas |
| 1 | `ce41da8` | bloque 1: contexto académico correcto |
| 2 | `655ad24` | bloque 2: cuaderno de cierre E7 |
| 3 | `8fb7514` | bloque 3: pcap de demostración |
| 4 | `bf9c839` | bloque 4: figuras y reproducción |
| 5 | (el commit que contiene este archivo) | bloque 5: limpieza del repo y documento de entrega |

---

## Bloque 0: línea base medida (`bff16d0`)

```
$ export UV_CACHE_DIR=/tmp/uv-cache-ids; uv venv && uv pip install -e ".[dev]"
Using CPython 3.14.9 interpreter at: /usr/local/bin/python3
Creating virtual environment at: .venv
[…]
 + scikit-learn==1.9.1
 + scipy==1.18.1
 + statsmodels==0.15.0
 [...]
 + xgboost==3.4.1
$ .venv/bin/python --version
Python 3.14.9

$ time timeout 900 .venv/bin/python -m pytest -o addopts="" -q
.........x................ss............................................ [ 34%]
.....................s.................................................. [ 68%]
.................................ssssss...........................       [100%]
200 passed, 9 skipped, 1 xfailed in 290.92s (0:04:50)

real	4m58.327s
```

Motivos (segunda corrida con `-rsx`, mismo conteo):

```
SKIPPED [1] tests/test_data.py:36: data/dataset_lab.csv no generado todavía (Fase 1 pendiente)
SKIPPED [1] tests/test_data.py:48: data/dataset_lab.csv no generado todavía (Fase 1 pendiente)
SKIPPED [1] tests/test_holdout.py:68: data/dataset_lab.csv no generado todavía
SKIPPED [6] tests/test_separabilidad.py:90: data/dataset_lab.csv no generado todavía: la puerta de separabilidad no se puede evaluar
XFAIL tests/test_anomalias.py::test_una_anomalia_evidente_da_alarma[isolation_forest_pca] - IF sobre PCA satura fuera del rango del primer componente
200 passed, 9 skipped, 1 xfailed in 291.94s (0:04:51)
exit=0
```

**Línea base: 200 passed, 1 xfailed, 9 skipped**, código 0. Ningún archivo se colgó. Quedó escrita en
`docs/ESTADO.md`, sección «Línea base 2026-11-25».

## Bloque 1: contexto académico correcto (`ce41da8`)

`README.md` («Contexto académico») ahora dice: asignatura **Fundamentos de redes de comunicaciones**,
docente **Octavio José Salcedo Parra**, Universidad Distrital Francisco José de Caldas. La
descripción técnica no se tocó.

`CLAUDE.md` **no mencionaba curso ni docente** (contra lo que decía el pedido), así que no hubo nada
que corregir ahí. Búsqueda de criterio sobre el árbol final, después del `git mv` del bloque 5:

```
$ grep -rn -i "modelos de programaci\|daza" --include='*.md' .
docs/historial/PEDIDO-ENTREGA.md:17:- `README.md:107-114` y `CLAUDE.md` dicen que el trabajo es del curso **Modelos de Programación** con el
docs/historial/PEDIDO-ENTREGA.md:18:  docente **Daza**. **Está mal**: el proyecto es de **Fundamentos de redes de comunicaciones**, docente
docs/historial/PEDIDO-ENTREGA.md:61:3. Busca en todo el repo cualquier otra mención a «Modelos de Programación» o «Daza»
docs/historial/PEDIDO-ENTREGA.md:62:   (`grep -rn -i "modelos de programaci\|daza" --include='*.md' --include='*.py' .`) y corrígelas. Las
docs/historial/PEDIDO-ENTREGA.md:66:**Criterio:** `grep -rn -i "modelos de programaci\|daza" --include='*.md' .` sin resultados fuera de
```

Solo quedan menciones en el propio pedido, que es registro y se deja. No había ninguna en
`docs/INFORME_*.md`, en los `.py` ni en los `.ipynb`.

## Bloque 2: cuaderno de cierre E7 (`655ad24`)

Hallazgo: `notebooks/cierre_e7.ipynb` sí existió. El commit `b0a9418` («EA Cerrado (Reporte)») lo
**renombró** a `notebooks/final_report.ipynb` (hoy en `docs/historial/`), con el contenido idéntico:

```
$ git diff -M --stat 750fbb2 b0a9418 -- notebooks
 notebooks/{cierre_e7.ipynb => final_report.ipynb} | 0
```

Como pedía el pedido, regeneré el cuaderno en lugar de editar el README. `final_report.ipynb` (archivado en `docs/historial/` en el pedido 2) se deja
como está. El nuevo `notebooks/cierre_e7.ipynb` tiene 25 celdas, sigue las seis fases CRISP-DM, cita
en cada celda la etapa E1–E6 y el JSON de `reports/` del que sale cada cifra, y solo lee JSON
congelados. Al final trae una tabla que compara cada cifra del texto con el JSON. Añadí a
`pyproject.toml` el extra `notebook` (nbconvert, nbformat, ipykernel), porque jupyter no estaba
entre las dependencias.

```
$ time .venv/bin/jupyter nbconvert --to notebook --execute --inplace notebooks/cierre_e7.ipynb
[NbConvertApp] Converting notebook notebooks/cierre_e7.ipynb to notebook
[IPKernelApp] WARNING | Kernel is running over TCP without encryption. […]
[NbConvertApp] Writing 60472 bytes to notebooks/cierre_e7.ipynb

real	0m6.237s
exit=0
```

Salidas del cuaderno (stdout de las celdas):

```
celdas de código: 12 | con outputs no vacías: 12 | errores: 0
[celda 5] sha256:  7f06d099477a474b12db73001f3ee56a8e14e93bb41501c8b49ee94e4032a945  (abreviado 7f06d099…a945)
filas: 78988  columnas: 65  sesiones: 20  proporción maliciosa: 0,072
[celda 7] Esquema 3.0: 52 columnas de modelo
[celda 9] (tabla) xgboost  0,894  [0,856, 0,936]  188 episodios  FA/disp-día 0,89  PR-AUC 0,989
                  random_forest  0,878  [0,834, 0,922]  188  1,19  0,986
[celda 11] LOAO sin capa 2 · xgboost      : 0,228 [0,168, 0,286]
LOAO sin capa 2 · random_forest: 0,068 [0,032, 0,105]
Isolation Forest solo-benigno, sin capa 2: 0,185
[celda 13] IP-ID por flujo: FA 16,19 → 0,38 FA/disp-día
Con variación benigna: 826,24 FA/disp-día (no_confiable 0,128)
[celda 15] recall supervisado · media  : 0,935
recall supervisado · suave  : 0,891
recall supervisado · rafaga : 0,824
invisibles por construcción: 0
OR con canales de identidad: +0,053 de recall a 122,06 FA/disp-día de identidad
[celda 17] FA del vigilante con variación benigna: 0.0 FA/disp-día
           (tabla ARP por paso) nativo: supervisado 1.0, vigilante 1.0, n 2 · 5s/15s/30s/60s: supervisado 0.0, vigilante 1.0, n 2
[celda 19] FA con variación: apariciones 826,2 → persistencia 381,5 FA/disp-día (IC95 [326,2, 442,0])
[celda 21] E5: cifra no encontrada en reports/, ver informe docs/INFORME_E5.md
E6: cifra no encontrada en reports/, ver informe docs/INFORME_E6.md
mitigación · modo: dry_run | último nivel: BLOQUEO | acciones: ['alerta', 'bloqueo']
pronóstico Holt (serie de juguete) · tendencia: creciente | aviso: {'aviso': True, 'tendencia': 'creciente', 'pronostico': [8.264, 9.514, 10.763, 12.012, 13.262], 'umbral': 10}
[celda 23] 23 de 23 cifras coinciden con reports/; tiempo total del cuaderno: 0.15 s
```

Todas las cifras que pedía el pedido están en `reports/`: 0,894 [0,856, 0,936]; 0,89 FA/disp-día;
LOAO 0,228; 0,38 FA/disp-día en identidad; ARP lento 1,000 → 0,000 frente al vigilante 1,000. Ver
abajo cuáles **no** están (E5/E6) y el redondeo de «382».

(Esta corrida de nbconvert es la final de comprobación. Solo cambiaba las marcas de tiempo de
ejecución del `.ipynb`, así que restauré la versión commiteada, que tiene las mismas salidas.)

## Bloque 3: pcap de demostración (`8fb7514`)

Hallazgo previo: **el generador congelado `generar_trafico.py` no fija el IP-ID** (Scapy deja `id=1`
en todas las tramas) **ni pone opciones TCP**. Un pcap hecho solo con él no pasa el criterio del
verificador (TCP con opciones y cambios de IP-ID). Esas señales solo existen en `generar_clones.py`.
Por eso el pcap junta dos recortes: la sesión 0 de `generar_trafico.py` (semilla 42000, segundos
236–386, **un** episodio `arp_spoofing`) y la sesión 1 de `generar_clones.py` (semilla 77001, un clon
de MAC de nivel `ritmo`), cada uno en su subred. `scripts/generar_demo_pcap.py` no sintetiza nada:
llama a `generar_sesion`/`escribir_pcap` de los generadores y recorta.

```
$ time .venv/bin/python scripts/generar_demo_pcap.py
[INFO] /opt/data/projects/ids_ia/data/pcap/demo/sesion_demo.pcap: 9827 tramas (8853 lab + 974 clones), 4.29 MB, sha256 3db1b93782256f7fab3cee27462129ec62ee8523983d81967fbc056454ec989b
real	0m44.015s

# determinismo: segunda generación en otro directorio
3db1b93782256f7fab3cee27462129ec62ee8523983d81967fbc056454ec989b  /tmp/demo2/sesion_demo.pcap
3db1b93782256f7fab3cee27462129ec62ee8523983d81967fbc056454ec989b  data/pcap/demo/sesion_demo.pcap
tramas.csv idéntico / episodios.csv idéntico / config.json idéntico / clones.json idéntico

$ ls -l data/pcap/demo/
-rw-r--r-- 1 hermes hermes    2662 Nov 25 14:22 sesion_demo.clones.json
-rw-r--r-- 1 hermes hermes     127 Nov 25 14:22 sesion_demo.config.json
-rw-r--r-- 1 hermes hermes     162 Nov 25 14:22 sesion_demo.episodios.csv
-rw-r--r-- 1 hermes hermes    1721 Nov 25 14:22 sesion_demo.meta.json
-rw-r--r-- 1 hermes hermes 4293057 Nov 25 14:22 sesion_demo.pcap
-rw-r--r-- 1 hermes hermes   19180 Nov 25 14:22 sesion_demo.tramas.csv

$ git ls-files data/pcap/demo/
data/pcap/demo/sesion_demo.clones.json
data/pcap/demo/sesion_demo.config.json
data/pcap/demo/sesion_demo.episodios.csv
data/pcap/demo/sesion_demo.meta.json
data/pcap/demo/sesion_demo.pcap
data/pcap/demo/sesion_demo.tramas.csv

$ git check-ignore -v data/pcap/demo/sesion_demo.pcap data/pcap/sesion_000.pcap data/pcap/otra/x.pcap
.gitignore:20:data/pcap/*	data/pcap/sesion_000.pcap
.gitignore:20:data/pcap/*	data/pcap/otra/x.pcap
```

En `.gitignore` cambié `data/pcap/` por `data/pcap/*` + `!data/pcap/demo/`. Con `data/pcap/`, git
no deja reincluir nada de dentro. Se versionan el pcap y sus manifiestos, porque
`pcap_to_features.py` necesita `.tramas.csv`/`.config.json` para etiquetar.

Verificador (`scripts/verificar_demo_pcap.py`):

```
$ time .venv/bin/python scripts/verificar_demo_pcap.py
== Ejemplos por tipo de trama (3 de cada uno) ==
[LLC/STP] #1 t=1000236.050000 | mac a4:83:e7:03:b0:72 -> 01:80:c2:00:00:00 | oui a4:83:e7 | ethertype longitud 38 (802.3/LLC) | llc dsap=0x42 ssap=0x42 | stp raiz=00:00:00:00:00:00 puente=00:00:00:00:00:00
[TCP] #2 t=1000236.169746 | mac b8:27:eb:6b:ca:89 -> 00:0c:29:46:6e:05 | oui b8:27:eb | ethertype 0x0800 (IPv4) | ip 10.0.0.31 -> 10.0.0.34 id=1 ttl=64 proto=6 flags= | tcp 58136 -> 7680 flags=S window=8192 opciones=[]
[ARP] #4 t=1000236.301620 | mac 00:1b:21:20:fb:ad -> b8:27:eb:f7:50:f9 | oui 00:1b:21 | ethertype 0x0806 (ARP) | arp op=1 (who-has) hwsrc=00:1b:21:20:fb:ad psrc=10.0.0.20 hwdst=00:00:00:00:00:00 pdst=10.0.0.1
[ARP] #5 t=1000236.304442 | mac b8:27:eb:f7:50:f9 -> 00:1b:21:20:fb:ad | oui b8:27:eb | ethertype 0x0806 (ARP) | arp op=2 (is-at) hwsrc=b8:27:eb:f7:50:f9 psrc=10.0.0.1 hwdst=00:1b:21:20:fb:ad pdst=10.0.0.20
[DNS] #6 t=1000236.369016 | mac 00:50:56:de:5c:24 -> b8:27:eb:2a:4f:6d | oui 00:50:56 | ethertype 0x8100 (802.1Q) -> 0x0800 (IPv4) | vlan 100 | ip 10.0.0.24 -> 10.0.0.2 id=1 ttl=64 proto=17 flags= | udp 60730 -> 53 | dns txid=0x2ff0 qr=0 qname=srv36.ejemplo.lab.
[DNS] #7 t=1000236.402668 | mac b8:27:eb:2a:4f:6d -> 00:50:56:de:5c:24 | oui b8:27:eb | ethertype 0x0800 (IPv4) | ip 10.0.0.2 -> 10.0.0.24 id=1 ttl=64 proto=17 flags= | udp 53 -> 60730 | dns txid=0x2ff0 qr=1 qname=srv36.ejemplo.lab.
[ICMP] #68 t=1000236.934612 | mac dc:a6:32:a4:02:9e -> dc:a6:32:dc:30:61 | oui dc:a6:32 | ethertype 0x0800 (IPv4) | ip 10.0.0.36 -> 10.0.0.4 id=1 ttl=128 proto=1 flags=
[TCP+opciones] #88 t=1000237.218024 | mac 02:d2:a4:c6:21:75 -> 02:00:00:00:00:01 | oui 02:d2:a4 | ethertype 0x0800 (IPv4) | ip 10.20.0.20 -> 93.184.216.34 id=29605 ttl=128 proto=6 flags=DF | tcp 43176 -> 22 flags=S window=64240 opciones=[('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')]
[UDP] #95 t=1000237.268130 | mac 00:50:56:19:2b:05 -> b8:27:eb:f7:50:f9 | oui 00:50:56 | ethertype 0x0800 (IPv4) | ip 10.0.0.37 -> 10.0.0.1 id=1 ttl=128 proto=17 flags= | udp 60687 -> 123
[TCP+opciones] #117 t=1000240.057561 | mac 02:68:f9:e8:cb:7f -> 02:00:00:00:00:01 | oui 02:68:f9 | ethertype 0x0800 (IPv4) | ip 10.20.0.25 -> 93.184.216.34 id=0 ttl=64 proto=6 flags=DF | tcp 47321 -> 443 flags=S window=65535 opciones=[('MSS', 1460), ('SAckOK', b''), ('Timestamp', (0, 0)), ('NOP', None), ('WScale', 9)]
[LLDP] #167 t=1000241.000000 | mac a4:83:e7:03:b0:72 -> 01:80:c2:00:00:0e | oui a4:83:e7 | ethertype 0x88cc (LLDP)
[…] (24 líneas de ejemplo en total)

== Campos agregados ==
MACs de origen distintas: 40  |  OUIs: ['00:0c:29', '00:1b:21', '00:50:56', '02:00:00', '02:24:db', '02:2d:25', '02:5f:0f', '02:60:29', '02:68:f9', '02:93:81', '02:a6:c4', '02:ca:e6', '02:cd:76', '02:d2:a4', '02:d9:1a', '02:fe:d5', '3c:52:82', 'a4:83:e7', 'b8:27:eb', 'dc:a6:32', 'f4:8e:38']
ethertypes: {'0x0800 (IPv4)': 8812, '0x0806 (ARP)': 794, '0x8100 (802.1Q) -> 0x0800 (IPv4)': 114, 'longitud 38 (802.3/LLC)': 75, '0x8100 (802.1Q) -> 0x0806 (ARP)': 27, '0x88cc (LLDP)': 5}
VLAN 802.1Q: {100: 141}
ARP por op (1=who-has, 2=is-at): {1: 315, 2: 506}
TTL: {64: 6837, 128: 1712, 255: 233, 58: 144}
ventana TCP (top 8): {29200: 5632, 64240: 1424, 502: 579, 8192: 288, 65160: 144, 65535: 91, 5840: 27}
TCP con opciones: 288  |  firmas: {'MSS': 171, 'MSS,SAckOK,Timestamp,NOP,WScale': 101, 'MSS,NOP,WScale,NOP,NOP,SAckOK': 8, 'MSS,NOP,WScale,NOP,NOP,Timestamp,SAckOK,EOL': 8}
IP-ID: 340 cambios entre tramas consecutivas del mismo emisor (MAC, IP); 38 de 44 emisores IPv4 con IP-ID constante
  primer cambio: trama #93 emisor 02:d2:a4:c6:21:75 / 10.20.0.20 id 29605 -> 29606

== Episodio de ataque del catálogo (197 tramas en .tramas.csv); primeras ==
#2486 t=1000276.409916 | mac a4:83:e7:99:34:f4 -> 00:1b:21:20:fb:ad | oui a4:83:e7 | ethertype 0x0806 (ARP) | arp op=2 (is-at) hwsrc=a4:83:e7:99:34:f4 psrc=10.0.0.3 hwdst=00:1b:21:20:fb:ad pdst=10.0.0.20
#2489 t=1000276.452769 | mac a4:83:e7:99:34:f4 -> f4:8e:38:c7:17:4c | oui a4:83:e7 | ethertype 0x0806 (ARP) | arp op=2 (is-at) hwsrc=a4:83:e7:99:34:f4 psrc=10.0.0.3 hwdst=f4:8e:38:c7:17:4c pdst=10.0.0.32
#2492 t=1000276.515100 | mac a4:83:e7:99:34:f4 -> f4:8e:38:c7:17:4c | oui a4:83:e7 | ethertype 0x0806 (ARP) | arp op=2 (is-at) hwsrc=a4:83:e7:99:34:f4 psrc=10.0.0.3 hwdst=f4:8e:38:c7:17:4c pdst=10.0.0.32

== Clon de MAC (ritmo, víctima 02:2d:25:a4:7d:30, pila iot -> clon android, 306.0-378.5 s): SYN bajo esa MAC ==
  antes del episodio: {'ip=10.20.0.24 ttl=255 window=5840 opciones=MSS': 6}
  durante el episodio: {'ip=10.20.0.24 ttl=255 window=5840 opciones=MSS': 7, 'ip=10.20.0.24 ttl=64 window=65535 opciones=MSS,SAckOK,Timestamp,NOP,WScale': 4}

9827 tramas, 1640 flujos, tipos: TCP 8185, ARP 821, DNS 469, ICMP 179, UDP 93, LLC/STP 75, LLDP 5
OK: el pcap trae ARP, TCP con opciones y cambios de IP-ID

real	0m5.072s
exit=0
```

Durante el desarrollo del verificador encontré y corregí dos fallos propios. (1) Scapy disecciona las
tramas IEEE 802.3 con campo longitud como `Dot3`, no como `Ether`, y la primera versión se saltaba
las 75 BPDU STP. (2) Los dos generadores usan la misma IP externa, 93.184.216.34, así que agrupar el
IP-ID solo por IP fabricaba un «cambio» falso. Ahora se agrupa por emisor (MAC, IP).

El pipeline lo consume (interfaz real del script: `--pcap`, `--salida`):

```
$ time .venv/bin/python scripts/pcap_to_features.py --pcap data/pcap/demo/sesion_demo.pcap --salida /tmp/demo_ventanas.csv
2026-11-25 14:23:10,408 [INFO] Dataset guardado en /tmp/demo_ventanas.csv: 708 filas
real	0m5.856s
exit=0

filas (ventanas MAC×5 s): 708 | columnas: 65 | ventanas de 5 s distintas: 30 | MACs: 41
etiqueta: {0: 697, 1: 11}
tipo_ataque: {'normal': 697, 'arp_spoofing': 11}

Primeras 5 filas:
                 grupo  n_tramas  bytes_totales  longitud_trama_media  iat_media_ms  tasa_broadcast tipo_ataque  etiqueta
0  a4:83:e7:03:b0:72#0         4            240             60.000000   1650.000000        0.000000      normal         0
1  b8:27:eb:6b:ca:89#0         2            120             60.000000   1742.420000        0.000000      normal         0
2  00:0c:29:46:6e:05#0        14           1276             91.142857    262.601846        0.071429      normal         0
3  00:1b:21:20:fb:ad#0        25           1917             76.680000     50.506875        0.000000      normal         0
4  b8:27:eb:f7:50:f9#0        36          28561            793.361111    135.397829        0.027778      normal         0

Filas maliciosas (primeras 5):
                    grupo  n_tramas  bytes_totales  longitud_trama_media  iat_media_ms  tasa_broadcast   tipo_ataque  etiqueta  n_tramas_ataque
171   a4:83:e7:99:34:f4#8        16            960                 60.00    607.275688        0.062500  arp_spoofing         1               15
193   a4:83:e7:99:34:f4#9        60           4173                 69.55     78.384017        0.000000  arp_spoofing         1               15
226  a4:83:e7:99:34:f4#10        30           1800                 60.00    183.249433        0.100000  arp_spoofing         1               27
249  a4:83:e7:99:34:f4#11        21           1260                 60.00    233.264476        0.000000  arp_spoofing         1               21
282  a4:83:e7:99:34:f4#12        12            720                 60.00    443.618833        0.083333  arp_spoofing         1               11
```

**708 ventanas** (fila = MAC × ventana de 5 s; 30 ventanas de 5 s), 11 etiquetadas `arp_spoofing`.
`docs/PCAP_DEMO.md` empieza con la frase obligatoria («tráfico sintético de laboratorio, generado por
`scripts/lab/generar_trafico.py` con semilla fija; no es una captura de red real») y trae los filtros
de Wireshark (`arp`, `tcp.flags.syn==1`, `ip.id`, `tcp.options`, `dns`, `vlan`, `stp`, `lldp`) y la
tabla campo → columna del esquema 3.0. La misma frase acompaña al pcap en el README.

## Bloque 4: figuras y reproducción (`bf9c839`)

```
$ rm -rf docs/figuras && MPLCONFIGDIR=/tmp/mplcfg .venv/bin/python scripts/figuras.py
docs/figuras/recall_por_intensidad.png: 57614 bytes
docs/figuras/fa_disp_dia.png: 57986 bytes
exit=0
$ ls -l docs/figuras/*.png
-rw-r--r-- 1 hermes hermes 57986 Nov 25 14:27 docs/figuras/fa_disp_dia.png
-rw-r--r-- 1 hermes hermes 57614 Nov 25 14:27 docs/figuras/recall_por_intensidad.png
# segunda regeneración: mismos bytes
6c719766913c18663b41082d1c07f8fb  docs/figuras/fa_disp_dia.png
d7a5e7ed366bc0cc8cd05ca8ed35e7cc  docs/figuras/recall_por_intensidad.png
6c719766913c18663b41082d1c07f8fb  docs/figuras/fa_disp_dia.png
d7a5e7ed366bc0cc8cd05ca8ed35e7cc  docs/figuras/recall_por_intensidad.png
```

`recall_por_intensidad.png` muestra media 0,935 / suave 0,891 / ráfaga 0,824 con IC95 y n de
episodios. `fa_disp_dia.png` muestra 826,2 → 381,5 FA/disp-día con IC95 en escala logarítmica,
porque una escala lineal aplastaría la línea de presupuesto de 1 FA/disp-día. Los títulos citan el
JSON de origen y «laboratorio sintético».

«Reproducir desde cero» (README), comando por comando:

| # | Comando | Estado | Salida real |
|---|---|---|---|
| 1 | `uv venv` · `uv pip install -e ".[dev]"` | **ejecutado** | ver bloque 0; `uv pip install -e ".[dev,notebook]"` también, exit 0 en 2,8 s |
| 2 | `.venv/bin/python scripts/lab/generar_dataset_lab.py --salida data/dataset_lab.csv` | **ejecutado** | `Dataset: 78988 filas, 65 columnas` · `Clases: {0: 73273, 1: 5715}` · real 6m41s · exit 0 |
| 2b | `sha256sum data/dataset_lab.csv` | **ejecutado** | `7f06d099477a474b12db73001f3ee56a8e14e93bb41501c8b49ee94e4032a945`: **coincide** con `7f06d099…a945` |
| 3 | `generar_clones.py --inicio 0 --sesiones 40 --dir-pcap data/pcap_clones` | **ejecutado** | 40 pcaps (`clones_000.pcap: 6803 tramas, 4 episodios`, …) · real 2m32s · exit 0 |
| 3 | `generar_variacion.py --inicio 0 --sesiones 20 --dir-pcap data/pcap_variacion` | **ejecutado** | 20 pcaps · real 1m18s · exit 0 |
| 3 | `generar_suplantacion.py --inicio 0 --sesiones 40 --dir-pcap data/pcap_e3b` | **ejecutado** | 40 pcaps · real 2m26s · exit 0 |
| 3 | `generar_contaminacion.py --inicio 0 --sesiones 20 --dir-pcap data/pcap_e3b` | **ejecutado** | 20 pcaps · real 1m18s · exit 0 |
| 4 | `evaluar.py --config configs/e2.json` (E2) | **no ejecutado** | escribe `reports/evaluacion_e2.json` (congelado; reentrenar está fuera del alcance) |
| 4 | `evaluar_identidad.py --config configs/identidad.json --partes a,b` (E3) | **no ejecutado** | escribe `reports/identidad_e3a.json` y `identidad_e3b.json` |
| 4 | `evaluar_robustez.py --config configs/robustez.json` (E4R) | **no ejecutado** | escribe `reports/robustez_e4.json` |
| 4 | `evaluar_robustez.py --config configs/robustez_e4c.json` (E4C) | **no ejecutado** | escribe `reports/robustez_e4c.json` |
| 4 | `evaluar_adopcion.py --config configs/adopcion_e5c.json` (E5C) | **no ejecutado** | escribe `reports/adopcion_e5c.json` |
| 5 | `captura_en_vivo.py --pcap data/pcap/demo/sesion_demo.pcap --dataset data/dataset_lab.csv --red-local 10.0.0.0/24` | **ejecutado** | `Modelo entrenado; umbral de operación 0.9086 (1.0 FA/disp-día)` · `Offline hecho en 3.8 s · {'tramas': 9827, 'ventanas': 708, 'alarmas_supervisado': 51, 'alarmas_identidad': 5, 'alertas_vigilante': 12, 'latencia_ms_media': 4.063, 'latencia_ms_max': 6.992}` · exit 0 |
| 6 | `timeout 900 .venv/bin/python -m pytest -o addopts="" -q` | **ejecutado** | ver bloque 5 |
| 7 | `jupyter nbconvert … cierre_e7.ipynb` · `figuras.py` · `generar_demo_pcap.py` · `verificar_demo_pcap.py` · `pcap_to_features.py` | **ejecutado** | ver bloques 2, 3 y 4 |

Hay un sha256 de referencia para el corpus, y coincide. No lo hay para los pcaps de E3: `reports/`
guarda semillas, no hashes. Esos generadores corrieron sin error, pero su identidad byte a byte con
los pcaps usados en E3 **no se pudo verificar**.

## Bloque 5: limpieza y entrega (este commit)

```
$ sha256sum IDS_IA_NicolasMartinez_20241020098.pdf doc_proyecto/IDS_IA_NicolasMartinez_20241020098.pdf
208ba06da7875e88def9bdcd5f305911cb47f5517c8c52ca67721410d9f5c8a2  IDS_IA_NicolasMartinez_20241020098.pdf
208ba06da7875e88def9bdcd5f305911cb47f5517c8c52ca67721410d9f5c8a2  doc_proyecto/IDS_IA_NicolasMartinez_20241020098.pdf
$ cmp … && echo idénticos
idénticos
```

- `git rm IDS_IA_NicolasMartinez_20241020098.pdf` (copia de la raíz). Queda solo la de
  `doc_proyecto/`.
- `git mv` a `docs/historial/` de 15 archivos versionados: `CONTEXT_UPGRADE.md`, 8 `PEDIDO-*.md`
  (incluye `PEDIDO-ANOMALIAS-1.md`) y 6 `PROGRESO-*.md`. `PEDIDO-ENTREGA.md` no estaba versionado,
  así que se movió con `mv` + `git add`. No se borró ninguno. Añadí `docs/historial/README.md`
  explicando que son registro.
- `LICENSE`: MIT, «Copyright (c) 2026 Nicolás Martínez Pineda».
- `.github/workflows/tests.yml`: Python 3.11, `uv venv` + `uv pip install -e ".[dev]"`,
  `timeout 900 .venv/bin/python -m pytest -o addopts="" -q`, `timeout-minutes` en el job y en el
  paso, `permissions: contents: read`, sin secretos. Validación de sintaxis (la primera versión
  tenía un «:» sin comillas en un `name`, ya corregido):

  ```
  YAML válido; jobs: ['pytest'] | python: 3.11 | timeout job: 30
  ['python -m pip install uv', 'uv venv\nuv pip install -e ".[dev]"\n', 'timeout 900 .venv/bin/python -m pytest -o addopts="" -q']
  ```
- `CLAUDE.md`: la sección «Estado del proyecto y problemas conocidos» pasa a ser «Arquitectura y
  comandos» + «Decisiones tomadas» (incluye el dataset sintético en vez de CICIDS2017, con su
  motivo) + «Extensiones conocidas». El aviso apunta a `docs/historial/CONTEXT_UPGRADE.md`.
  También actualicé la estructura y los comandos, que estaban obsoletos.
- `README.md`: tabla de módulos actualizada; «Uso rápido» con `uv` (antes `pip install`, que en este
  entorno no existe); «Pendientes» reducidos a los cuatro abiertos de verdad (captura real,
  DHCP/failover, RST del clon en switch, sesiones largas ≥ 30); árbol nuevo con `scripts/`, `tests/`,
  `configs/`, `docs/`, `notebooks/cierre_e7.ipynb`, `docs/figuras/`, `data/pcap/demo/`; sección
  «Licencia».
- `docs/ESTADO.md`: fuera «Sin `git push` desde estas ventanas» y «Pendiente para Nico». Entran
  «Pendientes abiertos (laboratorio físico)» y «Extensiones conocidas».

Suite de cierre, en las mismas condiciones que la línea base (sin `data/dataset_lab.csv`, apartado
temporalmente) y sobre el árbol final:

```
$ time timeout 900 .venv/bin/python -m pytest -o addopts="" -q
[…]
.................................ssssss...........................       [100%]
200 passed, 9 skipped, 1 xfailed in 289.73s (0:04:49)
real	4m55.118s
exit=0
```

Corrida adicional con el corpus regenerado presente (los 9 skips pasan a ejecutarse):

```
$ time timeout 900 .venv/bin/python -m pytest -o addopts="" -q -rsx
XFAIL tests/test_anomalias.py::test_una_anomalia_evidente_da_alarma[isolation_forest_pca] - IF sobre PCA satura fuera del rango del primer componente
XFAIL tests/test_separabilidad.py::test_clasificador_trivial_no_supera_la_puerta[arp_spoofing] - desviación declarada E1: 0.977: arp_cambios_vinculo_60s > 0 delata todo envenenamiento (FPR 0.047)
XFAIL tests/test_separabilidad.py::test_clasificador_trivial_no_supera_la_puerta[dns_spoofing] - desviación declarada E1: 0.979: dns_respuestas >= 2 desde una fila que no es servidor (FPR 0.042)
XFAIL tests/test_separabilidad.py::test_clasificador_trivial_no_supera_la_puerta[icmp_flood] - desviación declarada E1: 0.974: respuestas_no_solicitadas > 1, echo reply y errores ICMP sin petición (FPR 0.052)
XFAIL tests/test_separabilidad.py::test_clasificador_trivial_no_supera_la_puerta[mac_flooding] - desviación declarada E1: 0.996: MAC falsa con <= 4 tramas en su ventana de 60 s (FPR 0.007)
XFAIL tests/test_separabilidad.py::test_clasificador_trivial_no_supera_la_puerta[port_scan] - desviación declarada E1: 0.891: entropía de puertos baja con varios puertos distintos (FPR 0.097)
XFAIL tests/test_separabilidad.py::test_clasificador_trivial_no_supera_la_puerta[syn_flood] - desviación declarada E1: 0.990: SYN medio abiertos acumulados en 60 s (FPR 0.012)
203 passed, 7 xfailed in 301.82s (0:05:01)
exit=0
```

| | passed | xfailed | skipped |
|---|---|---|---|
| Línea base (bloque 0, sin datos) | 200 | 1 | 9 |
| Cierre (bloque 5, sin datos) | 200 | 1 | 9 |
| Cierre con corpus regenerado | 203 | 7 | 0 |

Ningún rojo en ninguna corrida.

---

## Desviaciones y lo que no se pudo verificar

1. **`CLAUDE.md` no mencionaba curso ni docente** (el pedido decía que sí). El error solo estaba en
   `README.md`. El texto «de Ingeniería de Sistemas» que acompaña a la asignatura se conservó (el
   pedido mandaba corregir solo materia y docente). Pero entró en el mismo commit erróneo `31431f8` y
   **no lo pude verificar** con ningún documento del repo: conviene que el autor lo confirme.
2. **`cierre_e7.ipynb` no se perdió: se renombró.** `b0a9418` lo movió a
   `notebooks/final_report.ipynb` sin cambios (pedido 2: archivado en `docs/historial/`). Se regeneró
   uno nuevo como pedía el pedido y el antiguo se dejó intacto, así que había dos cuadernos de cierre.
3. **Cifras de E5 y E6 sin respaldo en `reports/`.** `docs/INFORME_E7.md` cita para E5 «1014
   ventanas, 62 alarmas de identidad, latencia 0,011 ms» y para E6 la escalada a BLOQUEO y el
   pronóstico Holt. Ningún JSON de `reports/` las contiene. El cuaderno lo dice explícitamente
   («cifra no encontrada en reports/, ver informe docs/INFORME_E5.md / E6.md»). No las recalculé:
   la demo de E5 del cuaderno viejo necesitaba `data/pcap_clones/clones_000.pcap` y en la entrega no
   se reentrena.
4. **«382» es un doble redondeo.** El valor completo de E5C es 381,456 FA/disp-día
   (`reports/adopcion_e5c.json`, `por_modo/persistencia/…/fa_ventanas_por_dispositivo_dia`).
   `resumen` lo guarda como 381,5, y los informes lo citan como 382. Redondeado directamente sale 381
   (el commit `2a6cfd0` lo cita como 381). La figura rotula 381,5 y el cuaderno explica el redondeo.
   No cambié ningún informe.
5. **El pcap demo no sale solo de `generar_trafico.py`.** Ese generador no pone opciones TCP y deja
   IP-ID = 1 en todas las tramas, así que el criterio del verificador era imposible con él solo. Se
   añadió un episodio de clon de `generar_clones.py`, que el pedido permitía «si tu pcap necesita un
   clon de MAC». Por eso el pcap tiene **dos** episodios (ARP spoofing del catálogo + clon de MAC),
   no uno, y dos subredes en un mismo archivo. Además dura 150 s (pedido: ≈ 2–3 min). Escribí
   `scripts/generar_demo_pcap.py`: es un recorte que llama a los generadores congelados, no un
   generador nuevo.
6. **Se versiona el directorio demo entero, no solo el `.pcap`.** Los manifiestos (`.tramas.csv`,
   `.config.json`, `.episodios.csv`, `.clones.json`, `.meta.json`, 24 KB en total) son necesarios
   para que `pcap_to_features.py` etiquete. El `.meta.json` guarda como `commit_partida` el HEAD
   anterior al commit que versiona el script (`655ad24`).
7. **El replay del pcap demo en el motor de streaming no mide falsas alarmas.** Da 39 alarmas del
   supervisado fuera del atacante, en 150 s. Mezclar dos segmentos altera las columnas de nivel de
   segmento, y los perfiles de identidad no tienen tiempo de salir de `no_confiable`. Queda
   documentado en `docs/PCAP_DEMO.md` como demostración, no como cifra.
8. **Evaluaciones E2/E3/E4R/E4C/E5C no ejecutadas.** Sus `configs/` escriben en `reports/`,
   congelado, y reentrenar está fuera del alcance. Están marcadas «no ejecutado» en el README.
9. **Generadores de E3 ejecutados sin verificación byte a byte.** No hay sha256 de referencia en
   `reports/`. El del corpus E1–E2 sí se verificó y coincide.
10. **CI no ejecutado.** El workflow no ha corrido en GitHub (no hay push, por instrucción). Solo se
    validó su sintaxis YAML. La suite local corrió en Python 3.14.9, no en 3.11: el 3.11 no está
    instalado y bajarlo no era necesario. En CI, sin `data/`, se esperan los mismos 9 skips.
11. **Lint preexistente.** `ruff check src/ tests/ scripts/` da 60 hallazgos (N806, N803, I001,
    F401), todos en `src/` y `tests/`, anteriores a la entrega. No los toqué (fuera del alcance). Los
    scripts nuevos (`generar_demo_pcap.py`, `verificar_demo_pcap.py`, `figuras.py`) pasan ruff sin
    hallazgos.
12. **Conteo de archivos de trabajo.** El pedido hablaba de 17 `.md` de trabajo en la raíz. Había 16
    (15 versionados + `PEDIDO-ENTREGA.md` sin versionar); con `README.md` y `CLAUDE.md`, 18 `.md` en
    total.
13. **Referencias por nombre a archivos movidos.** Los informes de `docs/`, `src/attack_simulator.py`,
    `scripts/extractor_final.py`, `tests/test_separabilidad.py` y `.claude/skills/` citan
    `CONTEXT_UPGRADE.md`/`PEDIDO-*`/`PROGRESO-*` por su nombre, sin ruta y sin enlace. No los cambié:
    son menciones de texto, ningún código abre esos archivos, y `.claude/skills/` está vetado.
    `docs/historial/README.md` lo explica.
14. **`pyproject.toml` cambió** (extra `notebook`). El pedido no lo prohibía, pero tampoco lo pedía.
15. **No se tocaron** `reports/`, `configs/`, `scripts/lab/generar_trafico.py`,
    `scripts/lab/generar_dataset_lab.py` ni `.claude/skills/`. No hubo `git push` ni se reescribió la
    historia.

## Nota de publicación (2026-11-25)

El PAT del clon no tiene el permiso `workflow`, así que GitHub rechaza el push que crea
`.github/workflows/tests.yml`. Para no bloquear la entrega, el archivo se excluye del commit y queda
como copia revisable en `/opt/data/entregas/ids_ci_tests.yml`: se añade desde la interfaz de GitHub o
con un token que tenga «Workflows: Read and write». El resto del bloque 5 va tal cual.
