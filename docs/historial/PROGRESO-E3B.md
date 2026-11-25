PARAR — PEDIDO-E3B-1 cerrado: cuatro bloques y cierre (docs/INFORME_E3B.md, docs/ESTADO.md).

# Progreso — PEDIDO-E3B-1

Primera línea: semáforo (`SEGUIR` con el siguiente paso, o `PARAR` con el motivo).

## Bloque 1 — IP-ID por flujo (registrado antes de medir)

- `ipid_continuidad` e `ipid_salto_log2` se calculan **por flujo**: destino, protocolo y
  puertos, con flujos de al menos 3 tramas (2 saltos). Cada flujo aporta su valor y la
  desviación se juzga flujo a flujo (máximo de los z), igual que TTL y ventana se juzgan por
  valor: un clon minoritario no queda escondido en una mediana. El perfil hace la mediana y
  la MAD sobre los valores de todos los flujos.
- La versión por equipo queda **descartada** y accesible con `IPID_MODO = "equipo"`, solo
  para reproducir la cifra de E3A en el mismo informe.
- Se mide sobre las mismas 20 sesiones de E3A (semillas 77000–77019, pcap sin regenerar).
- Exigencia del pedido: la detección no baja de 0,975 / 1,000, y FA ≤ 1/disp-día.

Resultado del bloque 1 (`reports/identidad_e3b.json`, sección `ipid`):

| Medida | Por equipo (E3A, descartada) | Por flujo |
|---|---|---|
| FA/disp-día | 16,19 [9,41, 23,67] | **0,38 [0,00, 1,13]** (1 FA en 2,66 disp-día) |
| Dispositivos con alguna FA | 0,092 | 0,004 |
| Detección ingenuo / ritmo | 0,975 / 1,000 | **0,975 / 1,000** |
| Latencia mediana ingenuo / ritmo (s) | 4,2 / 10,0 | 3,7 / 10,0 |

Cumple las dos exigencias: la detección no baja y las FA quedan dentro del presupuesto de
E2. La causa de las 16,2 era el IP-ID medido entre flujos.

## Bloque 2 — benigno con variación real (registrado antes de medir)

- Generador nuevo `scripts/lab/generar_variacion.py` (semillas 78000–78019), mismas pilas y
  primitivas que `generar_clones.py` (refactor verificado byte a byte sobre clones_000 y
  clones_007). Doce equipos por sesión: dos por variación (actualización, VPN, dos pilas,
  descubrimiento con IP-ID 0 y SSDP con TTL 4, deriva lenta de la ventana cada 10 ventanas)
  y dos de control. **No hay clones**: toda alarma es falsa.
- Defensa añadida antes de medir, con su prueba: **reperfilado** tras 24 ventanas seguidas en
  alarma (2 min). Un cambio persistente (actualización) no puede quedar acusado para siempre;
  el equipo vuelve a `no_confiable` y reaprende. Las alarmas intercaladas no reperfilan.
  El clon de E3A dura 60–180 s, así que 24 ventanas no le alcanzan para reperfilar en el
  episodio típico; si en el bloque 3 o 4 se ve que sí, se reporta.
- Se mide con las defensas por defecto (`MIN_VENTANAS_PERFIL` 12, congelar en alerta, tope
  96/día, reperfilar 24). FA en dos unidades: ventanas en alarma por disp-día y **eventos**
  (rachas de alarma) por disp-día, **siempre junto** a la fracción de ventanas en
  `no_confiable`, los dispositivos que nunca llegan a confiable y los reperfilados.
- Grupos: con variación (los cinco tipos), sin variación (control + gateway de la misma
  sesión), y por tipo. No se reajusta ningún umbral después de ver la tabla.
- Lo que espero (para contrastar, no para ajustar): la actualización alarma hasta reperfilar;
  la VPN (TTL −1) pasa casi en silencio salvo por la ventana; el SSDP con TTL 4 puede dar FA
  intermitentes si no se vio dos veces en el aprendizaje; la deriva lenta pasa en silencio.

Resultado del bloque 2 (`reports/identidad_e3b.json`, sección `con_variacion`; 20 sesiones,
200 equipos con variación, 60 sin ella; defensas por defecto):

| Grupo | FA ventanas/disp-día | FA eventos/disp-día | Disp. con FA | Ventanas no_confiable | Señal que dispara |
|---|---|---|---|---|---|
| **con variación (todas)** | **824 [725, 918]** | **361 [299, 417]** | 0,43 | **0,128** | ventana TCP, TTL, IP-ID |
| sin variación (control + gateway) | 1,6 [0,0, 4,9] | 1,6 | 0,02 | 0,101 | — |
| actualización | 2393 | 564 | 0,97 | 0,157 | TTL, ventana |
| dos pilas | 1328 | 1020 | 0,80 | 0,126 | IP-ID salto, ventana |
| VPN | 252 | 88 | 0,23 | 0,156 | ventana |
| descubrimiento | 145 | 125 | 0,10 | 0,084 | TTL (SSDP con TTL 4) |
| deriva lenta | 4,9 | 4,9 | 0,05 | 0,159 | — |

**El bloque hunde el resultado, como el pedido advertía.** Con variación legítima, las falsas
alarmas suben de 1,6 a 824 ventanas (361 eventos) por disp-día, y no es porque el detector
se calle en `no_confiable`: esa fracción apenas se mueve (0,101 → 0,128). El detector no
está apagado; grita.

Mecanismo: un valor legítimo que aparece **después** de que el perfil es confiable dispara,
la congelación en alerta impide aprenderlo, y como nunca se aprende nunca llega a las dos
apariciones que lo eximirían. La actualización queda acusada hasta el final de la sesión
(97 % de los equipos). La segunda pila (30 % del tráfico) casi nunca se vio dos veces en las
12 ventanas de aprendizaje, y su IP-ID, con otra política de contador, sigue disparando aunque
se juzgue por flujo. La VPN dispara por la ventana en 1 de cada 4 equipos. El SSDP con TTL 4
dispara en 1 de cada 10. La deriva lenta pasa en silencio en 15 minutos: el perfil la sigue
porque aprende en las ventanas limpias.

**Reperfilado (registrado como defensa por defecto, descartado al medir):** con 24 ventanas
solo rescata 7 de 40 actualizaciones (las ventanas en las que el valor nuevo no aparece cortan
la racha) y baja las FA con variación de 824 a 775. En cambio, en las sesiones con clon de E3A
**lava el clon**: si el episodio dura más de dos minutos, el perfil se rehace con el clon
dentro y la víctima acumula alarmas cuando se va (FA 0,38 → 12,05/disp-día; prueba
`test_reperfilar_con_el_clon_presente_lo_lava`). Decisión, tomada **después** de medir y
declarada así: queda apagado por defecto (`REPERFILAR_TRAS_ALARMAS = inf`) y entra en la
ablación del bloque 4. No se ajusta ningún otro parámetro a la vista de esta tabla; el
arreglo de fondo (cómo aprender un cambio legítimo sin aprender un clon) queda abierto.

## Bloque 3 — pila completa, víctima apagada, conflicto de sesión (registrado antes de medir)

Generador nuevo `scripts/lab/generar_suplantacion.py` (semillas 79000–79019; usa las
primitivas de `generar_clones.py`, que no cambia). Doce equipos y seis episodios por sesión,
dos de cada nivel, víctimas distintas:

- `pila_completa`: misma MAC, misma IP, misma familia de pila (TTL, ventana, opciones, política
  de IP-ID) y mismo ritmo y tamaños que la víctima, que sigue emitiendo. El clon lleva **su
  propio** contador de IP-ID (no puede compartir el de la víctima sin producir IDs
  duplicados). No se modelan los RST que la víctima enviaría a los SYN-ACK del clon si el
  switch se los entregara: dependen de la topología y se dejan para el laboratorio de E4.
  Sin ellos, la cifra es una cota inferior de lo que vería una red real.
- `victima_apagada`: la víctima calla desde 5–60 s antes del episodio hasta 10–60 s después;
  el atacante usa la IP de la víctima con **su** MAC y su propia pila.
- `suplantacion_ip`: el atacante usa la IP de la víctima con su MAC **mientras ella emite**.

Señales nuevas, fijadas antes de medir:

1. `ipid_contadores` (en `src/identidad.py`). En cada ventana se encadenan los IP-ID del equipo
   (sin los 0) en orden temporal: un ID se une a la cadena cuyo último ID queda entre 1 y 2048
   por detrás. El perfil marca el equipo como de **contador global** si, en al menos 3 ventanas
   con IP-ID de dos o más flujos y en el 80 % de ellas, una sola cadena cruza flujos y no hay
   cadenas extra. Solo en esos equipos, una ventana con una segunda cadena de ≥ 2 tramas puntúa
   `Z_FIRMA_NUEVA` (10). En Linux (contador por flujo), macOS (aleatorio) y Android (cero)
   la puerta queda cerrada: ahí la señal no existe.
2. `VigilanteIP` (en `src/identidad.py`), sobre las IP de la red local (10.20.0.0/16):
   - **conflicto**: la misma IP con dos MAC en la misma ventana de 5 s. En una red sana es
     imposible (salvo failover de gateway, que aquí no hay).
   - **reasignación**: una IP vinculada a una MAC (vínculo tras 12 ventanas, como el perfil)
     aparece con otra MAC mientras la anterior lleva **menos de 600 s** callada. Pasados los
     600 s el vínculo se traspasa en silencio (como un DHCP); no se acusa. Esto es un límite
     declarado: un atacante que espere más de diez minutos después de que la víctima calle
     pasa.

Medida por nivel: detección (cualquier alarma de identidad sobre la MAC víctima o del
vigilante sobre la IP víctima dentro del episodio), por canal (identidad / vigilante),
latencia y FA (identidad + vigilante, fuera de episodios). Los niveles ingenuo y ritmo se
remiden con la señal nueva sobre las sesiones de E3A, y las FA con variación (bloque 2) se
remiden con ella, con la cifra de antes al lado.

Lo que espero: pila completa detectada solo en víctimas de contador global (Windows e IoT,
≈ 2 de cada 5), y nada en el resto; víctima apagada ≈ 1,0 por reasignación; suplantación de IP
≈ 1,0 por conflicto. Las FA del vigilante serán 0 en estos datos porque el generador no tiene
DHCP ni failover: es una cifra optimista y se dirá así.

Corrección de diseño antes de medir (la detectó la prueba del generador, no una cifra): con el
ritmo propio del atacante, un episodio corto podía quedar sin ninguna trama suya (0 tramas en un
episodio de 148 s de la sesión 79000). En los tres niveles el atacante abre ahora una conexión
en los 2 s siguientes al inicio y después sigue su ritmo.

### Bloque 3 — primera medida (señal registrada) y corrección post hoc declarada

Con la señal **tal como se registró** (cadenas en orden temporal):

| Nivel | Detección | Identidad / vigilante | FA/disp-día (sesiones del nivel) |
|---|---|---|---|
| ingenuo / ritmo (E3A) | 0,975 / 1,000 | igual / 0 | **21,08** (era 0,38) |
| pila completa | **0,25** (10/40: IoT 6/7, Windows 4/6; Linux, macOS, Android 0/27) | 0,25 / 0 | 20,30 |
| víctima apagada | 1,00 | 0 / 1,00 (reasignación) | |
| suplantación de IP | 0,95 | 0,05 / 0,95 (conflicto 37, reasignación 36) | |

Sin la señal, la pila completa es **0/40** y las FA vuelven a 0,38. La señal registrada rompe el
presupuesto: 55 de 56 FA en E3A son `ipid_contadores` en equipos Windows e IoT **solos**. Causa
vista en las tramas: dos conexiones del mismo equipo que se solapan en el tiempo llevan IDs
intercalados (34195, 34200, 34196, 34201…). El encadenado en orden temporal ve un retroceso y abre
una segunda cadena, aunque los IDs formen un único bloque contiguo. En el generador pasa porque
cada conexión toma sus IDs al crearse; en una red real, el reordenamiento en la captura produce lo
mismo. El defecto está en la señal, no en un umbral.

**Corrección post hoc (decidida después de ver la cifra, declarada así, sin parámetros nuevos):**
los contadores se cuentan como **grupos de IDs separados por más de 2048** (el mismo
`SALTO_IPID_CONTINUO`), sin importar el orden: los IDs de la ventana se ordenan por valor
(circular, módulo 65536) y cada hueco mayor que 2048 separa dos grupos. Un contador global da un
grupo; dos contadores independientes dan dos, salvo que caigan a menos de 2048 el uno del otro
(≈ 6 % de las veces con inicio aleatorio). La puerta (`ipid_global`) y la puntuación no cambian.
La señal registrada queda accesible (`IPID_CONTADORES_MODO = "cadenas"`) y su cifra se publica
junto a la corregida. Como la corrección se diseñó mirando estas sesiones, se **confirma en
sesiones nuevas**: 20 de clones de E3A (semillas 77020–77039; no tienen nada que ver con el holdout
20–29 del dataset de E2) y 20 de suplantación (79020–79039).

### Bloque 3 — resultado (señal por grupos; `reports/identidad_e3b.json`, sección `niveles`)

| Nivel | Detección | Canal | Latencia mediana (s) | Confirmación (sesiones nuevas) |
|---|---|---|---|---|
| ingenuo | 0,975 [0,925, 1,000] | identidad | 3,7 | 1,000 |
| ritmo y tamaños | 1,000 [1,000, 1,000] | identidad | 10,0 | 0,975 |
| **pila completa** | **0,200 [0,075, 0,325]** | identidad (contadores de IP-ID) | 8,6 | **0,325 [0,175, 0,475]** |
| víctima apagada | 1,000 [1,000, 1,000] | vigilante (reasignación) | 4,6 | 1,000 |
| suplantación de IP | 0,950 [0,875, 1,000] | vigilante (conflicto) | 3,9 | 0,975 |

FA/disp-día: 0,38 [0,00, 1,13] en las sesiones de E3A y 0,38 en las de suplantación (0,75 y 0,75
en las de confirmación). Dentro del presupuesto. La única alerta del vigilante fuera de episodio
es la cola de uno: las tramas del atacante 0,03 s después de `fin_s` caen en la ventana siguiente.
Se cuenta como FA igual, sin corregir la ventana del episodio.

**Pila completa, por familia de la víctima (las 80 sesiones):** IoT 15/20 y Windows 6/13 (las dos
con contador global); Linux 0/15, macOS 0/17 y Android 0/15. Sin la señal de contadores, 0/40.
Por qué se escapan los globales: en 31 de 33 episodios con víctima global la puerta estaba
abierta. De los 12 no detectados, en 10 los dos contadores existen a lo largo del episodio pero
**nunca coinciden en la misma ventana de 5 s** (ritmos de ~4 conexiones/min), y en 2 caen a menos
de 2048 uno del otro. El conflicto de sesión (misma IP, dos MAC) no lo ve: la MAC también es la
misma. El SEQ tampoco: el ISN es aleatorio por conexión en todas las familias.

**Frase para el artículo:** el sistema se rompe en el tercer nivel. El clon de pila completa se
detecta en el **20 % de los episodios (32,5 % en sesiones nuevas)**, y solo cuando la víctima
usa un contador de IP-ID global (IoT, Windows). Con víctima Linux, macOS o Android, la
detección es **0 de 47**. Se declara **límite no resuelto**. La víctima apagada (1,00) y la
suplantación de IP con la víctima activa (0,95) se detectan por el vínculo IP→MAC, no por la pila.

**Contadores en los benignos con variación:** la señal añade 4 FA en dos pilas y 5 en un control
macOS cuya puerta se abrió por azar. Con IP-ID aleatorio y pocas ventanas multiflujo en el
aprendizaje, tres ventanas cumplen el criterio por casualidad. Las FA sin variación (control y
gateway) suben de 1,6 a 9,7/disp-día, con IC que se solapan. Queda registrado como debilidad de la
puerta (`MIN_VENTANAS_CRUCE = 3`), sin reajustar.

Pendiente para E4: juzgar los contadores **entre ventanas** (un contador global que retrocede de
una ventana a otra delata a un segundo emisor aunque no coincidan en la misma ventana), los RST de
la víctima en un switch real, y FA del vigilante con DHCP real.

## Bloque 4 — contaminación y ablación de defensas (registrado antes de medir)

Generador nuevo `scripts/lab/generar_contaminacion.py` (semillas 80000–80019). Doce equipos y
ocho víctimas por sesión, dos por condición. Cada víctima recibe un episodio principal de nivel
**ritmo** (MAC e IP de la víctima, su ritmo y tamaños, pila de otra familia), igual que en E3A
y en el mismo hueco temporal (desde los 300 s). El clon de ritmo es el que el perfil podría
absorber: la pila completa no tiene nada que absorber. Antes del episodio, según la condición:

- `limpio`: nada.
- `contaminado_5` / `contaminado_20`: el clon abre una conexión en el 5 % o el 20 % de las
  ventanas de 5 s entre los 60 s y los 300 s, elegidas al azar. El perfil inicial ya tuvo tiempo
  de formarse, y es donde actúan la congelación y el tope.
- `continuo_20`: una conexión en el 20 % de las ventanas desde los 0 s hasta los 300 s, primer
  minuto incluido. El perfil **nace** con el clon dentro.

Cada ráfaga figura en el manifiesto como episodio `rafaga_<condición>`: no cuenta como FA y su
detección se reporta aparte. Medidas por condición:

- detección del episodio principal;
- **cobertura**: fracción de ventanas del episodio con alarma;
- **absorción**: al empezar el episodio, el perfil de la víctima ya exime el TTL o la ventana del
  clon (≥ 2 apariciones) o ya contiene su firma de opciones;
- FA.

Ablación: `todas` (por defecto), `sin_congelar`, `sin_tope` (∞), `sin_no_confiable`
(`min_ventanas = 1`) y `con_reperfilado` (24). Cada una sobre las sesiones de contaminación y
sobre las de variación del bloque 2 (FA y `no_confiable`).

**Regla para quedarse, fijada ahora:** una defensa se queda si apagarla empeora, en alguna
condición, la detección o la cobertura del episodio principal en ≥ 0,05, la absorción en ≥ 0,05,
o las FA en ≥ 1/disp-día. Si no cambia ninguna cifra, se declara sin efecto y se apaga por
defecto, aunque la razón sea que el banco no la puede ejercitar (el tope de 96 al día casi no
puede actuar en sesiones de 15 minutos). Eso se dirá.

Lo que espero: `contaminado_5/20` no absorbe con la congelación puesta y sí sin ella;
`continuo_20` absorbe a menudo (en las 12 ventanas que forman el perfil no hay congelación
posible) y la detección cae; sin `no_confiable`, las FA se disparan; el tope no cambia nada.

### Bloque 4 — resultado (`reports/identidad_e3b.json`, sección `contaminacion`)

| Condición | Detección | Cobertura | Absorción | FA de la víctima (dueña) /disp-día |
|---|---|---|---|---|
| limpio | 0,950 [0,875, 1,000] | 0,558 | 0,000 | 2,5 (1 FA) |
| contaminado 5 % | 0,975 [0,925, 1,000] | 0,576 | **0,225** | 0,0 |
| contaminado 20 % | **0,825** [0,700, 0,925] | 0,462 | **0,800** | **146** (60 FA) |
| continuo 20 % | **0,850** [0,750, 0,950] | 0,441 | **1,000** | **583** (238 FA) |

Equipos que no son víctima: 0 FA en todas las condiciones.

**El perfil absorbe el clon, y la congelación no lo impide cuando la contaminación llega antes de
que el perfil sea confiable.** La regla de no aprender en alerta solo actúa una vez confiable.
Las ráfagas que caen en la fase `no_confiable` se aprenden enteras, y dos bastan para eximir el
TTL y la ventana del clon. Al 5 %, la absorción es de 0,225 (sin congelar sería 1,000); al 20 %,
de 0,80; con el clon desde el primer minuto, de 1,00. Aun así, la detección solo cae de 0,95 a
0,83–0,85. Lo que sigue delatando al clon son las señales que el perfil no eximió (IP-ID, firma
de opciones cuando no se absorbió). La cobertura baja de 0,56 a 0,44.

**Envenenamiento:** cuando el perfil nace contaminado, la acusada pasa a ser **la dueña
legítima**. Con el 20 % continuo, su perfil de IP-ID es a veces el del clon (mediana 1,0 y
MAD 0 en víctimas macOS, cuyo IP-ID es aleatorio). Desde ahí, su propio tráfico dispara: 583
FA/disp-día sobre las víctimas, 0 sobre el resto. La congelación lo vuelve permanente, porque
la dueña nunca puede reaprenderse.

**Ablación (regla registrada: se queda si apagarla empeora una cifra en ≥ 0,05 o ≥ 1 FA/disp-día):**

| Defensa | Al apagarla | Veredicto |
|---|---|---|
| sin aprendizaje en alerta | absorción al 5 %: 0,225 → 1,000; detección al 5 %: 0,975 → 0,825; cobertura −0,09 a −0,18. **Pero** FA con variación: 826 → 265, y de víctimas contaminadas: 583 → 135 | **queda**; es un compromiso, no una defensa gratis |
| `no_confiable` | FA: 112 → 1354 (contaminación), 826 → 3756 (variación), 9,7 → 853 (sin variación) | **queda** |
| tope diario (96/día) | no cambia ninguna cifra (medido primero con el tope puesto; al reponerlo, cifras idénticas) | **se apaga** (`TOPE_ACTUALIZACIONES_DIA = inf`); en sesiones de 15 min casi no puede actuar, y en días habría que remedirlo |
| reperfilado (24) | contaminación: nada; variación: 826 → 777; clones de E3A: FA 0,38 → 12,05 (bloque 2) | sigue **apagado** |
