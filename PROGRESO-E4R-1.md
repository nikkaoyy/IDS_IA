SEGUIR — bloque 1 en curso (canal supervisado + invisibles por construcción).

# Progreso — PEDIDO-E4R-1

Primera línea: semáforo (`SEGUIR` con el siguiente paso, o `PARAR` con el motivo).

## Registro previo a medir (fijado antes de correr nada)

Fase de prueba de robustez del detector sobre el **corpus de ataques ya congelado**
(`data/pcap/sesion_000..019`, generador `generar_trafico.py` intacto). No se genera ningún
ataque ni evasión nuevos. Se mide cuánto se le escapan los ataques al detector al bajar de
intensidad, y cuántos episodios son invisibles por construcción.

Recortes declarados **antes** de ver cifras:

- **Solo XGBoost** (no RF): es el modelo ganador de E2; correr RF duplicaría el coste sin aportar.
- **5 semillas (42–46), 1000 réplicas bootstrap**: idénticas a `configs/e2.json`. Si el coste total
  supera ~20 min, se corta a 3 semillas y se escribe aquí antes de mirar cifras.
- Punto de operación: umbral de validación anidada a **1 FA/disp-día** (el de E2). No se reajusta.

Expectativas registradas (para contrastar, no para ajustar):

- El canal de **identidad** detecta ≈ 0 de los floods y escaneos: vigila la suplantación de pila,
  no el volumen ni los puertos.
- El **vigilante IP→MAC** SÍ puede disparar en `arp_spoofing` (las variantes que reclaman una IP con
  la MAC del atacante son un conflicto IP↔MAC) y también puede dar FA por el gateway en alta
  disponibilidad y la rotación de MAC del fondo benigno. Se mide, no se asume 0.
- El OR de los tres canales añadirá poco o ningún recall sobre floods/escaneos y arrastrará las
  826 FA/disp-día de identidad de E3B. Si es así, se escribe así.

## Decisiones de método fijadas

- **Invisibles por construcción**: un episodio es invisible si el máximo de `n_tramas_ataque` sobre
  todas sus ventanas es < `K=2`. Esos episodios nunca se etiquetan, así que el canal supervisado no
  puede verlos por diseño (es un límite del etiquetado por ventana, no evasión del modelo).
  `src/evaluacion.tabla_episodios` solo agrupa `etiqueta==1`, de modo que hoy desaparecen del
  denominador sin contarse: se cuentan aparte desde el `df` crudo.
- Recall reportado con las dos cifras juntas: sobre episodios **etiquetables** (con IC bootstrap, el
  de `ev.resumir`) y sobre **todos** (etiquetables + invisibles, los invisibles como no detectados).
  El IC mostrado es el de los etiquetables.
- **OR por episodio**: para un OR booleano limpio, el canal supervisado entra con la detección por
  episodio de la **semilla de referencia 42**; el recall supervisado de cabecera sigue siendo la
  media de las 5 semillas. Se declara en el informe.
- **Detección por canal (identidad/vigilante)**: por solape temporal. El rango de ventanas de cada
  episodio se toma de los `ts_us` de sus tramas de ataque en `.tramas.csv` (mismo índice absoluto
  `ts_us // (5·10⁶)` que usan `seguir_sesion`/`vigilar_sesion`). Limitación declarada: una alerta
  benigna que caiga en una ventana del episodio se acredita como detección; por eso las FA del
  vigilante se cuentan aparte (alertas fuera de todo rango de episodio, por disp-día).
