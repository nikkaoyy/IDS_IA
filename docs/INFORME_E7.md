# Informe E7 — Cierre

Fase E7 del plan: atar el proyecto de punta a punta y dejarlo reproducible.

## Entregables

- **`notebooks/cierre_e7.ipynb`**: cuaderno CRISP-DM que recorre OE1–OE3. Carga los reportes
  congelados de cada etapa (`reports/`) y corre demos en vivo (streaming offline, mitigación en
  dry-run, pronóstico). Todas sus celdas de código se ejecutan sin error y reproducen las cifras del
  proyecto (validado celda a celda).
- **`README.md`**: sección «Etapas E1–E7 y cómo reproducir» con los comandos de cada etapa, el
  cuaderno, la captura en vivo y las pruebas.
- **`requirements.txt`**: `statsmodels` añadido como dependencia **opcional** (el pronóstico tiene
  fallback sin ella).
- **`docs/ESTADO.md`**: tabla de etapas, ocho conclusiones vigentes para el artículo y los límites
  para el laboratorio real.

## Lo que el cuaderno muestra (cifras reales)

- OE1: vectores por capa con su invariante de efecto.
- OE2: XGB recall/episodio 0,894 (FA/disp-día 0,89, PR-AUC 0,989); RF 0,878.
- E3: detección por nivel (ingenuo 0,975, ritmo 1,000, pila completa 0,20, víctima apagada 1,000,
  suplantación 0,950); IP-ID por flujo baja la FA de 16,19 a 0,38/disp-día.
- E4: recall por intensidad (media 0,935 / suave 0,891 / ráfaga 0,824), 0 invisibles sin
  retemporizar; ARP lento supervisado 1,000 → 0,000, vigilante 1,000 con 0,0 FA.
- E5: el motor de streaming reproduce una sesión (1014 ventanas, 62 alarmas de identidad, latencia
  media 0,011 ms) con paridad respecto al lote.
- E5C: FA con variación 826 → 382/disp-día sin perder detección (ritmo 1,000 → 0,975).
- E6: mitigación escala a BLOQUEO en dry-run (comando `ebtables` registrado, no ejecutado); el
  pronóstico Holt marca tendencia creciente y da aviso temprano.

## Qué queda fuera (laboratorio real)

La captura en vivo sobre una interfaz, la ejecución real de la mitigación, la FA del vigilante con
DHCP/failover, la imitación de huella a nivel de paquete y los RST de la víctima frente al clon de
pila completa necesitan el laboratorio físico. Están declarados en `docs/ESTADO.md`.

Con esto se cierran E4, E5, E6 y E7; el núcleo software del IDS (OE1–OE3) queda implementado,
medido y reproducible.
