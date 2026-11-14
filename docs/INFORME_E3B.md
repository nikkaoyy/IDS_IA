# Informe E3B — pila completa, víctima apagada, variación benigna y contaminación

PEDIDO-E3B-1 · rama `main` · cuatro bloques, un commit cada uno (`2b48096`, `211d2b6`, `8c433ce`,
`0d8061e`). Cifras de `reports/identidad_e3b.json` (y su `.md`), IC al 95 % por bootstrap
(1000 réplicas, semilla 42). El diario de decisiones, con lo que se registró antes de cada medida,
está en `PROGRESO-E3B.md`.

## Resumen

| Pregunta | Respuesta, con su cifra |
|---|---|
| ¿Arregla las FA el IP-ID por flujo? | Sí: **16,19 → 0,38 FA/disp-día**, sin perder detección (0,975 / 1,000). |
| ¿Aguanta el perfil la variación benigna real? | **No.** Con variación legítima de pila: **826 FA/disp-día** en ventanas (363 en eventos), con `no_confiable` en **0,128** de las ventanas. Sin variación: 9,7 (0,101). |
| ¿Qué nivel de clon rompe el sistema? | **El tercero.** Pila completa: **0,20 [0,075, 0,325]** (0,325 en sesiones nuevas), y solo con víctimas de contador de IP-ID global. Con Linux, macOS o Android: **0 de 47**. |
| ¿Víctima apagada y conflicto de IP? | 1,00 y 0,95, por el vínculo IP→MAC, no por la pila. |
| ¿Absorbe el perfil un clon presente al aprender? | **Sí.** Absorción 0,225 / 0,80 / 1,00 (5 % / 20 % / 20 % continuo); la detección cae de 0,95 a 0,83–0,85 y la dueña legítima queda acusada (583 FA/disp-día con el 20 % continuo). |
| ¿Qué defensas se quedan? | Congelar en alerta y `no_confiable`, sí; el tope diario, no (no cambió ninguna cifra); el reperfilado sigue apagado (lava el clon). |

## 1. IP-ID por flujo (bloque 1)

| Medida | Por equipo (E3A, **descartada**) | Por flujo |
|---|---|---|
| FA/disp-día | 16,19 [9,41, 23,67] | **0,38 [0,00, 1,13]** (1 FA en 2,66 disp-día) |
| Dispositivos con alguna FA | 0,092 | 0,004 |
| Detección ingenuo / ritmo | 0,975 / 1,000 | 0,975 / 1,000 |
| Latencia mediana ingenuo / ritmo (s) | 4,2 / 10,0 | 3,7 / 10,0 |

La señal por equipo medía el salto entre tramas consecutivas del equipo. Cuando una ventana mezcla
dos conexiones Linux, cada una con su contador, ese salto es aleatorio. Queda en el código
(`IPID_MODO = "equipo"`) solo para reproducir la cifra.

## 2. Falsas alarmas con y sin variación benigna (bloque 2)

`scripts/lab/generar_variacion.py` (semillas 78000–78019, prueba byte a byte): 20 sesiones,
200 equipos con variación y 60 sin ella, **sin clones**. Toda alarma es falsa. Defensas por
defecto.

| Grupo | FA ventanas/disp-día | FA eventos/disp-día | Disp. con FA | Ventanas `no_confiable` | Señal que dispara |
|---|---|---|---|---|---|
| **con variación** | **826 [730, 920]** | **363** | 0,43 | **0,128** | ventana TCP, TTL, IP-ID |
| sin variación (control + gateway) | 9,7 [0,0, 27,5] | 4,9 | 0,02 | 0,101 | contadores de IP-ID |
| actualización | 2393 | 564 | 0,97 | 0,157 | TTL, ventana |
| dos pilas | 1337 | 1020 | 0,80 | 0,126 | IP-ID (salto), ventana |
| VPN | 252 | 88 | 0,23 | 0,156 | ventana |
| descubrimiento (mDNS/SSDP) | 145 | 125 | 0,10 | 0,084 | TTL (SSDP con TTL 4) |
| deriva lenta | 4,9 | 4,9 | 0,05 | 0,159 | — |

(La fila «sin variación» era 1,6 antes de la señal de contadores del bloque 3; la sube a 9,7 un
control macOS cuya puerta de contador global se abrió por azar.)

Las dos cifras juntas, como pide el pedido: **el detector no se calla marcando todo como no
confiable** (0,101 → 0,128). Grita, y se equivoca. El mecanismo es estructural: un valor
legítimo que aparece después de que el perfil es confiable dispara, la congelación impide
aprenderlo, y como nunca se aprende nunca llega a las dos apariciones que lo eximirían. La deriva
lenta pasa en silencio porque cada paso es pequeño y se aprende en las ventanas limpias.

**Con variación real, cualquier cifra de FA de E3 es optimista en un factor de ~100 o más.** Esta
es la limitación principal del perfil de pila tal como está.

## 3. Tabla por nivel de clon (bloque 3)

Ingenuo y ritmo sobre las 20 sesiones de E3A; los otros tres sobre las 20 de
`scripts/lab/generar_suplantacion.py` (semillas 79000–79019). La detección es cualquier alarma
de identidad sobre la MAC víctima o del vigilante IP→MAC sobre la IP víctima dentro del episodio.

| Nivel | Detección | Canal | Latencia mediana (s) | FA/disp-día | Confirmación (40 sesiones nuevas) |
|---|---|---|---|---|---|
| 1 ingenuo | 0,975 [0,925, 1,000] | identidad | 3,7 | 0,38 | 1,000 |
| 2 ritmo y tamaños | 1,000 [1,000, 1,000] | identidad | 10,0 | 0,38 | 0,975 |
| **3 pila completa** | **0,200 [0,075, 0,325]** | identidad (contadores de IP-ID) | 8,6 | 0,38 | **0,325 [0,175, 0,475]** |
| víctima apagada | 1,000 [1,000, 1,000] | vigilante (reasignación) | 4,6 | 0,38 | 1,000 |
| suplantación de IP | 0,950 [0,875, 1,000] | vigilante (conflicto) | 3,9 | 0,38 | 0,975 |

FA en las sesiones de confirmación: 0,75 [0,00, 1,88]. La única alerta del vigilante fuera de
episodio es la cola de uno: tramas del atacante 0,03 s después de `fin_s`. Se cuenta como FA.

**Pila completa por familia de la víctima (80 sesiones):** IoT 15/20, Windows 6/13, Linux 0/15,
macOS 0/17, Android 0/15. Sin la señal de contadores, 0/40.

Por qué se detecta cuando se detecta, y por qué no el resto:

- MAC, IP, TTL, ventana, opciones y ritmo son los de la víctima. Ninguna señal de pila los
  distingue, y el conflicto IP→MAC tampoco (la MAC es la misma).
- El SEQ tampoco: el ISN es aleatorio por conexión en todas las familias.
- Lo único que queda es el **contador de IP-ID**. Si la víctima usa uno global, el clon trae el
  suyo y en una ventana aparecen dos bloques de IDs separados. Si la víctima usa contador por
  flujo, aleatorio o cero, esa diferencia no existe.
- De los 12 episodios no detectados con víctima global, en 10 los dos contadores existen a lo
  largo del episodio pero **nunca coinciden en la misma ventana de 5 s**. En 2 caen a menos de
  2048 uno del otro.

Sobre la señal de contadores: la versión **registrada** (encadenar IDs en orden temporal) dio
0,25 de detección pero **21 FA/disp-día**. Dos conexiones solapadas del mismo contador llevan
IDs intercalados, y la cadena se rompe. La **corrección post hoc** (grupos de IDs separados por
más de 2048, sin importar el orden, sin parámetros nuevos) se declaró antes de medirla y se
confirmó en 40 sesiones nuevas. Las dos cifras están en el JSON (`e3b_cadenas_registradas`).

No se modelan los RST que la víctima enviaría a los SYN-ACK del clon si el switch se los
entregara. Es una vía de detección real que depende de la topología, así que esta cifra es una
cota inferior.

## 4. Contaminación 0 / 5 / 20 % (bloque 4)

`scripts/lab/generar_contaminacion.py` (semillas 80000–80019): clon de nivel ritmo y dos
víctimas por condición. Las ráfagas de contaminación son una conexión del clon en el 5 % o el
20 % de las ventanas entre 60 y 300 s; en «continuo», en el 20 % de las ventanas entre 0 y 300 s.

| Condición | Detección | Cobertura | Absorción | FA de la víctima /disp-día |
|---|---|---|---|---|
| limpio (0 %) | 0,950 [0,875, 1,000] | 0,558 [0,487, 0,624] | 0,000 | 2,5 |
| 5 % | 0,975 [0,925, 1,000] | 0,576 [0,508, 0,635] | **0,225** [0,100, 0,375] | 0,0 |
| 20 % | **0,825** [0,700, 0,925] | 0,462 [0,380, 0,544] | **0,800** [0,675, 0,900] | **146** |
| 20 % continuo | **0,850** [0,750, 0,950] | 0,441 [0,352, 0,528] | **1,000** | **583** |

Equipos que no son víctima: 0 FA en todas las condiciones.

**El perfil absorbe el clon.** La congelación en alerta solo actúa una vez el perfil es
confiable. Las ráfagas que caen antes se aprenden, y dos bastan para eximir el TTL y la ventana
del clon. La detección cae menos que la absorción (0,95 → 0,83–0,85) porque el IP-ID y, cuando no
se absorbió, la firma de opciones siguen delatando al clon.

**Envenenamiento:** cuando el perfil nace con el clon dentro, la dueña legítima pasa a ser la
anomalía. Con el 20 % continuo, el perfil de IP-ID de algunas víctimas es el del clon, y el
tráfico propio de la víctima dispara: 583 FA/disp-día sobre las víctimas. La congelación lo hace
permanente.

## 5. Ablación de defensas (bloque 4)

Regla registrada antes de medir: una defensa se queda si apagarla empeora la detección, la
cobertura o la absorción en ≥ 0,05, o las FA en ≥ 1/disp-día.

| Defensa | Efecto de apagarla | Veredicto |
|---|---|---|
| Sin aprendizaje en alerta | absorción al 5 %: 0,225 → 1,000; detección al 5 %: 0,975 → 0,825; cobertura −0,09 a −0,18. Pero las FA **bajan**: con variación, 826 → 265; víctimas contaminadas, 583 → 135. | **Se queda.** Es un compromiso: protege contra la absorción y a la vez es la causa de las FA persistentes con variación. |
| `no_confiable` | FA: 112 → 1354 (contaminación), 826 → 3756 (variación), 9,7 → 853 (sin variación) | **Se queda.** |
| Tope diario (96/día) | Ninguna cifra cambia. Se midió primero con el tope puesto; al reponerlo, las cifras son idénticas. | **Se apaga** (`TOPE_ACTUALIZACIONES_DIA = inf`, `TOPE_REGISTRADO = 96`). En sesiones de 15 minutos casi no puede actuar; en un despliegue de días habría que remedirlo. |
| Reperfilado (24 ventanas) | Encenderlo no cambia la contaminación, baja las FA con variación de 826 a 777 y **lava el clon** en E3A (FA 0,38 → 12,05). | **Sigue apagado** (decisión del bloque 2, tomada después de medir y declarada así). |

## 6. Decisiones tomadas después de medir (todas declaradas)

1. **Reperfilado:** registrado como defensa por defecto; apagado tras ver que lava el clon.
2. **Contadores de IP-ID:** se registraron por cadenas y se corrigieron a grupos, con
   confirmación en sesiones nuevas. Se publican las dos cifras.
3. **Generador de suplantación:** se garantizó una conexión del atacante al empezar cada
   episodio. La prueba del generador encontró un episodio con 0 tramas del atacante. Fue antes
   de medir.
4. **Tope diario:** se apagó por la regla registrada. No se reajustó ningún umbral
   (`UMBRAL_DESVIACION`, `MIN_VENTANAS_PERFIL`, `MIN_VENTANAS_CRUCE`, la gracia de 600 s).

## 7. Límites no resueltos

- **Clon de pila completa:** pasa desapercibido salvo con víctimas de contador global, y aun con
  ellas se escapa un tercio (12 de 33).
- **Variación benigna:** 826 FA/disp-día. Falta un mecanismo que aprenda un cambio legítimo sin
  aprender un clon. Congelar y no congelar fallan en sentidos opuestos (ablación).
- **Contaminación al aprender:** la fase `no_confiable` no tiene defensa.
- **Vigilante:** 0 FA aquí porque el generador no tiene DHCP ni failover; es una cifra optimista.
  Un atacante que espere más de 600 s después de que la víctima calle no se acusa.
- **Puerta de contador global:** con IP-ID aleatorio y pocas ventanas multiflujo, se abre por
  azar (un control macOS).
- **Sesiones cortas:** todo está medido en sesiones sintéticas de 15 minutos.

## Frase para el artículo

> El perfil de pila detecta los clones que cambian la pila (ingenuo 0,975, ritmo 1,000, a 0,38
> FA/disp-día), y el vínculo IP→MAC detecta la víctima apagada (1,00) y la suplantación de IP
> (0,95). **El sistema se rompe en el tercer nivel:** el clon de pila completa se detecta en el
> **20 %** de los episodios (32,5 % en sesiones nuevas), solo cuando la víctima usa un contador de
> IP-ID global, y en **0 de 47** con víctimas Linux, macOS o Android. Además, con variación benigna
> realista las falsas alarmas suben a **826 por dispositivo-día**, y un clon presente durante el
> aprendizaje es absorbido por el perfil (80 % al 20 % de contaminación). Ambos quedan como
> límites no resueltos.

## Aceptación (salida real)

```text
$ .venv/bin/python -m pytest -o addopts="" -q tests/test_identidad.py tests/test_evaluar_identidad.py tests/test_generar_clones.py
...........................................                              [100%]
43 passed in 59.02s
$ .venv/bin/python scripts/evaluar_identidad.py --config configs/identidad.json --partes b
Escrito /home/nikka/Documentos/FRED/IDS/reports/identidad_e3b.json y /home/nikka/Documentos/FRED/IDS/reports/identidad_e3b.md
{"ipid": {"fa_antes": 16.19, "fa_despues": 0.38, "fa_despues_con_reperfilado_24": 12.05, "deteccion_despues": {"ingenuo": 0.975, "ritmo": 1.0}}, "con_variacion": {"con_variacion": {"fa_ventanas_dia": 826.24, "fa_eventos_dia": 362.94, "no_confiable_ventanas": 0.128}, "sin_variacion": {"fa_ventanas_dia": 9.73, "fa_eventos_dia": 4.86, "no_confiable_ventanas": 0.101}}, "niveles": {"ingenuo": {"deteccion": 0.975, "latencia_s": 3.7}, "ritmo": {"deteccion": 1.0, "latencia_s": 10.0}, "pila_completa": {"deteccion": 0.2, "latencia_s": 8.6}, "suplantacion_ip": {"deteccion": 0.95, "latencia_s": 3.9}, "victima_apagada": {"deteccion": 1.0, "latencia_s": 4.6}, "fa_dia": {"e3a": 0.38, "e3b": 0.38}, "confirmacion_pila_completa": 0.325}, "contaminacion": {"limpio": {"deteccion": 0.95, "cobertura": 0.558, "absorcion": 0.0}, "contaminado_5": {"deteccion": 0.975, "cobertura": 0.576, "absorcion": 0.225}, "contaminado_20": {"deteccion": 0.825, "cobertura": 0.462, "absorcion": 0.8}, "continuo_20": {"deteccion": 0.85, "cobertura": 0.441, "absorcion": 1.0}}, "defensas": {"sin aprendizaje en alerta": true, "no_confiable": true, "tope diario (apagado tras la ablación)": "apagada", "reperfilado (apagado en el bloque 2)": "apagada"}}
$ .venv/bin/python -c "import json;d=json.load(open('reports/identidad_e3b.json'));print(d['resumen'])"
{'ipid': {'fa_antes': 16.19, 'fa_despues': 0.38, 'fa_despues_con_reperfilado_24': 12.05, 'deteccion_despues': {'ingenuo': 0.975, 'ritmo': 1.0}}, 'con_variacion': {'con_variacion': {'fa_ventanas_dia': 826.24, 'fa_eventos_dia': 362.94, 'no_confiable_ventanas': 0.128}, 'sin_variacion': {'fa_ventanas_dia': 9.73, 'fa_eventos_dia': 4.86, 'no_confiable_ventanas': 0.101}}, 'niveles': {'ingenuo': {'deteccion': 0.975, 'latencia_s': 3.7}, 'ritmo': {'deteccion': 1.0, 'latencia_s': 10.0}, 'pila_completa': {'deteccion': 0.2, 'latencia_s': 8.6}, 'suplantacion_ip': {'deteccion': 0.95, 'latencia_s': 3.9}, 'victima_apagada': {'deteccion': 1.0, 'latencia_s': 4.6}, 'fa_dia': {'e3a': 0.38, 'e3b': 0.38}, 'confirmacion_pila_completa': 0.325}, 'contaminacion': {'limpio': {'deteccion': 0.95, 'cobertura': 0.558, 'absorcion': 0.0}, 'contaminado_5': {'deteccion': 0.975, 'cobertura': 0.576, 'absorcion': 0.225}, 'contaminado_20': {'deteccion': 0.825, 'cobertura': 0.462, 'absorcion': 0.8}, 'continuo_20': {'deteccion': 0.85, 'cobertura': 0.441, 'absorcion': 1.0}}, 'defensas': {'sin aprendizaje en alerta': True, 'no_confiable': True, 'tope diario (apagado tras la ablación)': 'apagada', 'reperfilado (apagado en el bloque 2)': 'apagada'}}
```

El JSON se generó sobre el commit `0d8061e`; la marca «árbol con cambios» se debe a que este
informe y `docs/ESTADO.md` se estaban escribiendo durante la corrida (no tocan código ni
configuración).
