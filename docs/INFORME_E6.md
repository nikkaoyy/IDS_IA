# Informe E6 — Mitigación y pronóstico (OE3)

> **Procedencia de las cifras** (añadido en la entrega, pedido 2)
>
> - Las cifras de E6 que citan `docs/INFORME_E7.md` y `doc_proyecto/culminacion_doc.md` —la
>   mitigación **escala a BLOQUEO** en dry-run (comando `ebtables` registrado, no ejecutado) y el
>   pronóstico **Holt marca tendencia creciente y da aviso temprano**, con backtesting **MAE < 1**
>   sobre una recta— salían de las demos de las celdas 15–16 del cuaderno de cierre anterior (commit
>   `750fbb2`, 2026-11-15, guardado sin salidas) y de `tests/test_pronostico.py`.
> - **Ahora están persistidas** en `reports/mitigacion_pronostico_e6.json`, escrito por
>   `python scripts/demo_e6.py` (determinista, < 1 s, sin red ni corpus): último nivel `BLOQUEO`,
>   acciones `alerta → bloqueo`, modo `dry_run`; Holt sobre la serie `[0, 0, 1, 1, 2, 3, 4, 6, 8]`:
>   tendencia `creciente`, pronóstico a 3 pasos 8,264 / 9,514 / 10,763, aviso temprano `True` con
>   umbral 10; backtesting en la recta 0..29: MAE 0,0 (n_test = 6).
> - Son **demostraciones del módulo con entradas de juguete**, no mediciones sobre tráfico del
>   laboratorio. No hay cifra de E6 medida sobre tráfico.

Fase E6 del plan: cerrar los dos mecanismos de OE3 que faltaban —responder a la amenaza y
anticiparla—.

## Mitigación (`src/mitigacion.py`)

Política de respuesta **escalable** que convierte las alertas del detector en acciones:

`REGISTRO → ALERTA → BLOQUEO de la MAC → CUARENTENA (VLAN)`

`GestorMitigacion.procesar_alerta(mac, ts, score)` cuenta las alertas de cada MAC en una ventana
deslizante (`PoliticaMitigacion.ventana_s`): `umbral_bloqueo` alertas llevan a bloqueo; si persiste,
`umbral_cuarentena` más, a cuarentena.

**Dry-run por defecto, por diseño.** Sin un `ejecutor` explícito, el gestor **no toca la red**:
imprime y registra el comando que ejecutaría (`ebtables -A FORWARD -s <mac> -j DROP`, o la marca de
VLAN de cuarentena). Es imposible inyectar en una interfaz por accidente desde estas ventanas. En el
laboratorio se pasa `ejecutor=` (una función que corre el comando) y entonces, y solo entonces, se
ejecuta. `desbloquear(mac)` revierte con el comando inverso.

Pruebas (`tests/test_mitigacion.py`, 7): una alerta es solo alerta; tres bloquean; la persistencia
lleva a cuarentena; dry-run registra el comando y no ejecuta; con `ejecutor` sí ejecuta; la ventana
deslizante olvida alertas viejas; el desbloqueo revierte.

## Pronóstico (`src/pronostico.py`)

`RegistroTemporalAlertas` mantiene la serie de la tasa de alertas por ventana.
`PronosticadorAnomalias` la pronostica para **anticipar** un ataque sostenido o un escalamiento:

- Método por defecto **Holt** (suavizado exponencial doble) a mano: determinista, sin dependencias,
  bueno para una tasa con tendencia. `metodo="holt_winters"` usa `statsmodels` (0.15.0, disponible)
  si se quiere estacionalidad.
- `pronosticar(pasos)` da la tasa prevista (no negativa: son conteos). `tendencia` la clasifica
  (creciente/estable/decreciente). `aviso_temprano(umbral)` es la señal de OE3: avisa si la tasa
  prevista supera el umbral o la tendencia es claramente creciente, **antes** de que el detector
  acumule las alertas.
- `backtesting(serie, train_ratio)` evalúa el pronóstico (MAE, MAPE) entrenando con el inicio y
  midiendo sobre la cola.

Pruebas (`tests/test_pronostico.py`, 8): la serie en orden; Holt sigue una tendencia creciente; una
serie plana es estable; el pronóstico no es negativo; el aviso temprano salta con tendencia
creciente; el backtesting da MAE < 1 en una recta; una serie corta falla explícito; el camino de
`statsmodels` funciona.

## Cómo se conectan al streaming (E5)

En vivo, cada ventana cerrada por `MotorStreaming` produce alertas por MAC: se pasan a
`GestorMitigacion.procesar_alerta` (que decide el nivel de respuesta) y su conteo alimenta
`RegistroTemporalAlertas` para el pronóstico. El aviso temprano puede disparar una respuesta
preventiva antes de que se acumulen las alertas que la justificarían por sí solas.

## Límite

La ejecución real de `ebtables`/VLAN (`ejecutor=`) necesita root y un puente real; aquí todo se
validó en **dry-run** (el comando correcto, sin ejecutarlo). La prueba en el laboratorio físico
queda declarada.
