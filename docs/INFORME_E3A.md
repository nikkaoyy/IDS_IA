# Informe E3A — identidad del dispositivo: perfil de pila y los dos primeros niveles de clon

> PEDIDO-E3A-1 sobre la base `fe7a165` (después de PEDIDO-ANOMALIAS-1). Trabajo del
> 2026-11-14. Bitácora: `PROGRESO-ANOMALIAS.md` (sección E3A). Cifras:
> `reports/identidad_e3a.json` / `.md`. No se tocó `feature_schema.py`, ni `COLUMNAS_MODELO`,
> ni `VERSION_ESQUEMA` (3.0), ni la salida agregada de `src/ventanas.py`, ni
> `generar_trafico.py` / `generar_dataset_lab.py`, ni el holdout, ni `src/anomalias.py`. Sin
> `git push`.

## La frase para el artículo

**Ninguno de los dos primeros niveles de clon rompe el perfil de pila.** El clon ingenuo se
detecta en el **0,975 [0,925, 1,000]** de los episodios y el clon que imita ritmo y tamaños,
en el **1,000 [1,000, 1,000]** (40 episodios por nivel). Imitar el ritmo no esconde al clon:
solo lo retrasa. Latencia mediana de 4,2 s [3,0, 5,1] frente a 10,0 s [6,6, 17,0], y p90 de
6,7 s frente a 33,3 s. Lo que sí rompe la configuración registrada son las **falsas alarmas:
16,2 [9,4, 23,7] por dispositivo-día**, 16 veces el presupuesto de E2. El 98 % viene de una
sola señal mal diseñada, el salto de IP-ID medido entre flujos (§4).

El pedido esperaba que el ingenuo se detectara casi siempre y el de ritmo bastante menos.
No sale así, y era previsible: el detector solo mira la pila, y en los dos niveles el clon
tiene una pila distinta de la de la víctima. El nivel que debería romperlo es el clon de
pila completa (parte B).

## 1. Qué se construyó

| Bloque | Qué | Criterio | Commit |
|---|---|---|---|
| 1 | `Trama` captura `ip_ttl`, `ip_id`, `ip_df`, `tcp_window`, `tcp_options`, `tcp_seq` y `tcp_ack`; el agregado no los lee | Dataset regenerado con el parser extendido: **sha256 `7f06d099…a945`, idéntico**; `test_ventanas.py` + `test_identidad.py`: 36 passed | `5946c11` |
| 2 | `src/identidad.py`: perfil por mediana/MAD, `no_confiable` por debajo de 12 ventanas, sin aprendizaje durante alertas, tope diario | `tests/test_identidad.py`: 16 passed | `a496f2e` |
| 3 | `scripts/lab/generar_clones.py` (nuevo), `scripts/evaluar_identidad.py`, `configs/identidad.json` | este informe; `tests/test_evaluar_identidad.py`: 3 passed | (este) |

**`MIN_VENTANAS_PERFIL = 12`:** doce ventanas de 5 s con señal de pila, un minuto de
actividad. Con n = 12 la mediana aguanta hasta 5 ventanas raras (punto de ruptura del 50 %)
y la MAD no sale 0 por azar con pocas muestras. Coincide con la ventana larga de 60 s del
extractor.

**Un cambio de diseño hecho antes de medir:** TTL y ventana TCP se juzgan *por valor
distinto* en la ventana, no por su mediana. El clon emite con la MAC de la víctima y sus
tramas comparten ventana con las de ella, así que una mediana escondería a un clon
minoritario. Un valor visto en ≥ 2 ventanas del perfil no cuenta, y así se aprende, por
ejemplo, el TTL 255 del mDNS legítimo.

## 2. Resultados por nivel (salida real)

20 sesiones propias de 15 min (semillas 77000–77019, sin relación con el dataset de E2 ni
con su holdout), 12 equipos por sesión de cinco familias de pila, 4 episodios por sesión.
**Split temporal por dispositivo:** cada MAC lleva su perfil en orden temporal y solo juzga
ventanas posteriores a las que lo construyeron. Ningún clon empieza antes de los 300 s.

| Nivel | Episodios | Detección | Detección (víctima acusable) | No acusables | Latencia mediana (s) | Latencia p90 (s) |
|---|---|---|---|---|---|---|
| ingenuo | 40 | **0,975 [0,925, 1,000]** | 1,000 (n = 39) | 1 | **4,2 [3,0, 5,1]** | 6,7 [5,7, 21,8] |
| ritmo | 40 | **1,000 [1,000, 1,000]** | 1,000 (n = 39) | 1 | **10,0 [6,6, 17,0]** | 33,3 [22,2, 51,6] |

- **El único ingenuo no detectado** (`clones_005`, windows → iot) empezó con la víctima aún
  `no_confiable`: no se le puede acusar, y no hubo alarma.
- **El ritmo no acusable** (`clones_018`) sí acabó detectado, a los 28 s, cuando el perfil
  llegó a confiable a mitad del episodio. El aprendizaje durante `no_confiable` absorbió
  parte del clon, aunque no tanto como para ocultarlo.
- **Detección por par de pilas:** 79 de 80, incluidos los pares que comparten TTL
  (linux→android, android→macos…). Los delatan la ventana del SYN o la firma de opciones.

## 3. Legítimos

| Medida | Valor |
|---|---|
| **Falsas alarmas por dispositivo-día** | **16,19 [9,41, 23,67]** (43 en 2,66 dispositivo-días, 260 dispositivos) |
| Dispositivos con alguna falsa alarma | 0,092 [0,062, 0,123] |
| Dispositivos que nunca llegan a `confiable` | 0,004 [0,000, 0,012] (1 de 260) |
| Ventanas en `no_confiable` (el arranque de cada perfil) | 0,139 [0,135, 0,144] |

## 4. De dónde salen las falsas alarmas (diagnóstico después de las cifras)

- **42 de las 43 las dispara `ipid_salto_log2` y 1 `ipid_continuidad`.** 35 son de equipos
  Linux, 7 de IoT y 1 de macOS.
- La causa en Linux: el IP-ID va por flujo, con una base aleatoria por conexión. La señal
  mide el salto entre tramas consecutivas *del equipo*, no del flujo. Cuando una ventana
  mezcla dos conexiones, el salto es aleatorio (log2 ≈ 15). El perfil se construye casi
  siempre con ventanas de un solo flujo (mediana 0, MAD 0), así que una ventana con dos
  conexiones da z ≈ 13. En IoT, el mDNS con IP-ID 0 rompe la continuidad del contador
  global de la misma forma.
- **Es un defecto de diseño de la señal, no del umbral.** No se corrige aquí: se registró
  antes de medir, y cambiarla ahora sería ajustar a las cifras.

**Análisis exploratorio, no es la cifra del pedido:** con las mismas sesiones y sin las dos
señales de IP-ID, la detección queda igual (0,975 y 1,000) y la latencia también (4,2 s y
10,0 s), con **0 falsas alarmas**. Ese 0 es optimista por construcción: en el generador, el
TTL, la ventana del SYN y las opciones son **constantes por equipo**, sin la variación que
tendría un equipo real (actualizaciones del sistema operativo, VPN, varias interfaces,
contenedores). Es la misma clase de trivialidad que la puerta de E1 vigilaba en E2.

## 5. Límites que el artículo debe declarar

1. **Los clones de los niveles 1 y 2 tienen siempre una pila distinta de la de la víctima.**
   Por eso los detecta un perfil de pila. La pregunta difícil, un clon con la misma pila, es
   el nivel 3 (parte B).
2. **Generador propio y simplificado.** Cinco familias de pila con valores habituales,
   aproximados; sin variación legítima dentro de un equipo; y el mismo catálogo para
   víctimas y clones.
3. **El dataset de E2 no sirve para E3:** su pcap tiene IP-ID = 1 en todas las tramas, sin
   opciones TCP. Solo TTL y ventana llevan información.
4. **El arranque es una ventana ciega:** el 14 % de las ventanas de cada equipo transcurre en
   `no_confiable`, y un clon presente desde el principio contamina el perfil. El caso de
   contaminación (5 % y 20 %) es parte B.
5. Episodios por sesión con víctimas distintas y siempre con la víctima emitiendo; víctima
   apagada es parte B.

## 6. Qué queda para la parte B

- **Clon de pila completa** (mismo TTL, ventana, opciones y comportamiento de IP-ID): es
  donde se espera que el perfil se rompa, y la cifra que el artículo necesita.
- **Rediseñar la señal de IP-ID por flujo o por destino** antes de medir la parte B, para
  que no dispare con dos conexiones en la misma ventana. Con la variación registrada, cada
  cambio va antes de medir.
- Contaminación del perfil (5 % y 20 % de ventanas del clon durante la construcción),
  víctima apagada y deriva lenta (actualización del sistema operativo de un equipo
  legítimo).
- Variación legítima de pila dentro de un equipo en el generador, para que las falsas
  alarmas tengan un valor creíble.

## 7. Criterio de aceptación — salida real

```
$ .venv/bin/python -m pytest -o addopts="" -q tests/test_ventanas.py tests/test_identidad.py
36 passed in 92.91s (0:01:32)

$ .venv/bin/python scripts/lab/generar_dataset_lab.py --salida $CLAUDE_JOB_DIR/tmp/ds_check.csv \
      --dir-pcap $CLAUDE_JOB_DIR/tmp/pcap_check && \
  .venv/bin/python scripts/lab/ficha_dataset.py $CLAUDE_JOB_DIR/tmp/ds_check.csv --salida $CLAUDE_JOB_DIR/tmp
…/dataset_lab_2026-11-14.json: 78988 filas, sha256 7f06d099477a474b12db73001f3ee56a8e14e93bb41501c8b49ee94e4032a945
Etiquetas: {'0': 73273, '1': 5715}

$ .venv/bin/python scripts/evaluar_identidad.py --config configs/identidad.json
Escrito /home/nikka/Documentos/FRED/IDS/reports/identidad_e3a.json y /home/nikka/Documentos/FRED/IDS/reports/identidad_e3a.md
ingenuo: detección 0.975 [0.925, 1.000] · latencia mediana 4.2 [3.0, 5.1] s
ritmo: detección 1.000 [1.000, 1.000] · latencia mediana 10.0 [6.6, 17.0] s
legítimos: FA/disp-día 16.19 [9.41, 23.67] · nunca confiables 0.004 [0.000, 0.012]
```

La regeneración de comprobación se escribió en el directorio temporal del trabajo en vez de
`/tmp`, que comparten varios procesos en paralelo. Mismo comando y mismo resultado. La
ficha no se actualizó.
