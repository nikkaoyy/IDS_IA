SEGUIR — bloque 2 hecho; sigue el bloque 3 (pila completa, víctima apagada, conflicto de sesión).

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
