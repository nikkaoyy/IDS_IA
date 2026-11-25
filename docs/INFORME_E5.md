# Informe E5 — Captura en streaming (tiempo real)

> **Procedencia de las cifras** (añadido en la entrega, pedido 2)
>
> - **1014 ventanas, 62 alarmas de identidad, latencia media 0,011 ms por ventana** (citadas en
>   `docs/INFORME_E7.md` y `doc_proyecto/culminacion_doc.md`, no en este informe): salen de la demo
>   offline de la celda 11 del cuaderno de cierre anterior (commit `750fbb2`, 2026-11-15; hoy
>   archivado en `docs/historial/`), que reproduce
>   `data/pcap_clones/clones_000.pcap` con `MotorStreaming(modelo=None, con_identidad=True)`. El
>   cuaderno se guardó **sin salidas**, así que la cifra solo consta en el texto de los informes.
> - **No está persistida en `reports/`.** No se recalculó: necesita `data/pcap_clones/clones_000.pcap`,
>   que no está en la copia de trabajo (solo queda `clones_000.clones.json`), y regenerar el corpus de
>   clones queda fuera de este pedido. La latencia, además, depende de la máquina.
> - Lo que sí está respaldado: la **paridad** con el lote y el comportamiento del motor, por las 7
>   pruebas de `tests/test_streaming.py`.

Fase E5 del plan: conectar el camino que era por lotes en vivo —captura → ventanas → modelo +
identidad → alerta— sin cambiar las features ni el contrato.

## Qué se implementó

- **`src/streaming.py` · `MotorStreaming`**: consume tramas una a una y, al cerrar cada ventana de
  5 s, evalúa dos canales:
  - **supervisado**: la fila de 52 columnas la produce el **mismo `AgregadorVentanas`** que la
    evaluación por lotes, así que las features en vivo son **idénticas** a las de `extraer_ventanas`
    (paridad garantizada por construcción, probada). Se pasa al modelo al umbral de operación de E2.
  - **identidad**: las tramas crudas de la ventana alimentan un `SeguidorIdentidad` por MAC y un
    `VigilanteIP` global (los de E3B/E4C), con la red local del segmento.
- **`scripts/captura_en_vivo.py`**: `AsyncSniffer(iface)` → `MotorStreaming` en vivo (requiere
  root), con filtro BPF, volcado periódico de estadísticas y parada limpia con Ctrl+C. Entrena el
  XGB al arrancar si se le da el dataset, o corre solo identidad. Tiene un modo **offline** que
  reproduce un pcap ya capturado, para validar sin root.

## Paridad con el lote (lo que garantiza que el streaming es correcto)

`tests/test_streaming.py::test_streaming_reproduce_las_filas_del_lote` alimenta las mismas tramas al
motor y a `extraer_ventanas`, y comprueba que **cada ventana produce la misma fila de 52 columnas**
(con un modelo determinista, la misma feature da la misma predicción). El streaming no es un segundo
extractor: es el mismo `AgregadorVentanas`, consumido incrementalmente.

## Validación offline (sin root)

```
python scripts/captura_en_vivo.py --pcap data/pcap_clones/clones_000.pcap --red-local 10.20.0.0/16
```

Reproduce una sesión del laboratorio y emite las alertas de identidad en el mismo orden temporal que
el análisis por lotes (detecta el clon desde su ventana de inicio). El canal supervisado se activa
añadiendo `--dataset data/dataset_lab.csv` (entrena el XGB al arrancar).

## Métricas de rendimiento

`MotorStreaming.resumen_metricas()` reporta, por ventana: latencia de inferencia (ms, media y
máximo), ventanas procesadas, tramas y alertas por canal. La latencia se mide desde el cierre de la
ventana hasta la predicción.

## Pruebas (`tests/test_streaming.py`, 7)

Paridad con el lote; alarma supervisada al pasar el umbral; el canal de identidad detecta un cambio
de TTL en streaming; sin modelo corre solo identidad; el vigilante ve un conflicto de IP en vivo;
las métricas se poblan; las 52 columnas están en las filas.

## Límite

La captura en vivo (`--iface`) necesita root y una interfaz real; aquí se validó el camino completo
**offline** (reproduciendo pcaps), que ejercita el mismo motor. La prueba en vivo sobre `eth0` queda
para el laboratorio físico.
