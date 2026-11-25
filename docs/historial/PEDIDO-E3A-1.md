# PEDIDO-E3A-1 — identidad del dispositivo: perfil de pila y los dos primeros niveles de clon

Repo: `/home/nikka/Documentos/FRED/IDS`, rama `main`. Se ejecuta **después** de `PEDIDO-ANOMALIAS-1.md`
(y después de su commit; si ese pedido se cortó por ventana, este espera y arranca con su árbol limpio).

## Qué es E3 y por qué se parte

E3 responde otra pregunta que la de E2: no «¿esto es un ataque?» sino «**¿este equipo es el que dice ser?**».
La parte B (clon de pila completa, contaminación del 5 % y 20 %, deriva lenta) queda para otro pedido. Esta parte A
construye lo que todo lo demás necesita: **la captura de las señales de pila, el perfil robusto por dispositivo y los
dos primeros niveles de clon**.

## Estado verificado (2026-11-13, sobre `72f5f8f`)

- `src/ventanas.py:56` → `Trama` **no captura TTL, IP-ID, ventana TCP, opciones TCP ni SEQ**. Sin eso no hay E3: el
  perfil de pila no se puede construir con lo que hay hoy.
- `trama_desde_paquete` (`src/ventanas.py:84`) es el único punto que toca Scapy. Es donde se añaden los campos.
- El contrato de características del modelo de ataques es **52 columnas, esquema 3.0** y está cerrado por el pedido
  del extractor: no cambia.
- Dataset 3.0: 78 988 ventanas, sha256 `7f06d099477a474b12db73001f3ee56a8e14e93bb41501c8b49ee94e4032a945`.
- Holdout 20–29 gastado. `.venv/bin/python`. Suite completa ~4 min.

## Regla dura: identidad fuera del contrato de ataques

Las señales de pila describen un equipo, no una violación. **No entran en `feature_schema.py`** ni en
`COLUMNAS_MODELO`: viven en `src/identidad.py` con su propio perfil. Si se meten en el contrato, se contamina el
marcador de E2 y se repite el error que costó el `longitud_trama_std`.

La prueba de que no se contaminó es binaria: **regenerar el dataset con el parser extendido tiene que dar el mismo
sha256**. Si cambia, el cambio tocó la agregación y hay que sacarlo.

## Bloque 1 — Captura de señales (aditivo, sin cambiar la salida)

1. `Trama` gana campos con valor por defecto: `ip_ttl`, `ip_id`, `ip_df`, `tcp_window`, `tcp_options` (tupla de
   nombres: MSS, SACK, Timestamps, NOP, WS…), `tcp_seq`, `tcp_ack`. Todo `None`/0 por defecto, así el resto del
   código no se entera.
2. `trama_desde_paquete` los rellena cuando hay IP/TCP.
3. `ventanas.py` **sigue produciendo las mismas 52 columnas con los mismos valores**: nada de estas señales entra al
   agregado.

Criterio (los dos comandos):

```bash
.venv/bin/python -m pytest -o addopts="" -q tests/test_ventanas.py tests/test_identidad.py
.venv/bin/python scripts/lab/generar_dataset_lab.py --salida /tmp/ds_check.csv --dir-pcap /tmp/pcap_check && \
  .venv/bin/python scripts/lab/ficha_dataset.py /tmp/ds_check.csv
```

`sha256` de `/tmp/ds_check.csv` debe ser `7f06d099…a945`. Si no coincide, el bloque está mal: se corrige, no se
actualiza la ficha.

## Bloque 2 — `src/identidad.py`: perfil robusto por dispositivo

1. `perfil_dispositivo(tramas) -> dict` con **mediana y MAD** por señal (TTL, ventana TCP, conjunto de opciones,
   IP-ID: continuidad y salto medio, SEQ: continuidad), más el mínimo y el máximo vistos. Sin promedios: el perfil
   tiene que aguantar un pico sin moverse.
2. **Ventana mínima para ser confiable** (`MIN_VENTANAS_PERFIL`, elige el número y justifícalo): por debajo, el
   dispositivo queda en estado `no_confiable` y **no se le puede acusar**.
3. **Sin aprendizaje durante alertas**: si el dispositivo está marcado como sospechoso, sus tramas no actualizan el
   perfil. Sin eso, el clon se vuelve «normal» en tres ventanas.
4. **Actualización limitada**: como mucho una actualización por ventana y un tope por día; el perfil deriva despacio
   a propósito.
5. `desviacion(perfil, tramas) -> puntaje` normalizado por MAD, con las señales que estén disponibles; el puntaje
   de las que falten no inventa valores.

Criterio: `tests/test_identidad.py` con casos sintéticos — un dispositivo estable no dispara; uno con TTL distinto
dispara; con ventana TCP distinta dispara; con las mismas señales y solo la MAC cambiada **no** dispara (eso es un
clon, no un equipo nuevo— ver bloque 3); un dispositivo con dos ventanas queda `no_confiable`.

## Bloque 3 — Los dos primeros niveles de clon

1. `scripts/lab/generar_clones.py`: generador **nuevo y propio**, semillas fijas, que produce pcaps con:
   - **clon ingenuo**: MAC copiada, todo lo demás del atacante distinto;
   - **clon de ritmo y tamaños**: MAC copiada, ritmo y longitudes imitando a la víctima, pila distinta.
   El tercer nivel (clon de pila completa) es parte B. **No se toca `generar_trafico.py`**.
2. La víctima sigue emitiendo durante el episodio (el caso de víctima apagada es parte B).
3. `scripts/evaluar_identidad.py --config configs/identidad.json` mide, por nivel: **tasa de detección**, **latencia
   hasta la alarma** (segundos desde el inicio del clon), **falsos positivos sobre dispositivos legítimos** y
   **proporción de dispositivos en `no_confiable`**.
4. **Split temporal por dispositivo**: el perfil se construye con las primeras ventanas de cada equipo y se prueba
   con las posteriores. Nunca al revés; un perfil entrenado con el futuro miente.

Criterio: `reports/identidad_e3a.json` con la tabla por nivel y los IC por bootstrap de episodios, más
`docs/INFORME_E3A.md` con la frase que el artículo necesita: **qué nivel de clon rompe el sistema, con la cifra**
(se espera que el ingenuo se detecte casi siempre y el de ritmo bastante menos; si sale otra cosa, se reporta igual).

## Lo que NO se toca

- `src/feature_schema.py`, `COLUMNAS_MODELO`, `VERSION_ESQUEMA` (3.0), `src/ventanas.py` en su salida agregada.
- `scripts/lab/generar_trafico.py` y `generar_dataset_lab.py`.
- El holdout 20–29 y `scripts/evaluar_holdout.py`.
- `src/anomalias.py` y sus reportes, aunque el pedido anterior los acabe de crear.
- `docs/INFORME_*.md` anteriores: addendum si hace falta, no reescritura.
- E4, E5, E6. `data/*.csv`, `data/*.pcap`: fuera de git. Sin `git push`.

## Cierre

Un commit por bloque, `git status` limpio, `docs/ESTADO.md` actualizado (este pedido es el dueño del archivo en esta
ventana), y un reporte de cinco líneas: detección por nivel de clon, latencia, falsos positivos, y qué queda para la
parte B.
