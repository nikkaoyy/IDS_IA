PARAR — PEDIDO-E4C-1 cerrado: cuatro bloques, informe, ESTADO y aceptación.

# Progreso — PEDIDO-E4C-1

Primera línea: semáforo (`SEGUIR` con el siguiente paso, o `PARAR` con el motivo).

## Línea base (sobre `9b42040`)

- `git status` limpio; `git log` en `9b42040` (E4R cerrado).
- Suite completa: se corre antes de tocar nada (en segundo plano) para fijar que arranca en verde.

## Bloque 1 — el vigilante ve el ARP (registrado antes de medir)

- `VigilanteIP.observar` alimenta el mapa `ip → MAC` con **dos fuentes**: la de siempre
  (`ip_src → mac_src`, capa 3) y el vínculo que declara cada ARP local (`arp_psrc → arp_hwsrc`,
  `arp_op` 1 o 2). Un ARP que reclama una IP ya vinculada a otra MAC dispara conflicto o
  reasignación con la lógica existente; **no se añade ningún umbral**.
- Señal de contradicción propia: `arp_hwsrc != mac_src` (el ARP declara un emisor que no es el
  `Ether.src` real) se emite como alerta `arp_ether_discrepante`, deduplicada por IP y por ventana.
  Nota honesta: en el corpus congelado el atacante rellena `hwsrc == Ether.src`, así que esta
  señal queda latente aquí (0 detecciones y 0 FA sobre estos datos); es defensa en profundidad
  para otra forma de suplantación y así se reportará.
- No se toca: gracia de 600 s, `MIN_VENTANAS_CRUCE`, `no_confiable`, ni ningún umbral.
- **Lectura del criterio (c)** del pedido: dice «después de que la anterior calló **más** de la
  gracia se acusa como reasignación». Eso contradice el comportamiento congelado (pasada la
  gracia el vínculo se traspasa **sin** alerta, `test_pasada_la_gracia_...`, E3B) y el pedido
  prohíbe tocar la gracia. Se implementa la versión consistente y se declara: **dentro** de la
  gracia, un cambio secuencial de MAC (una sola MAC en la ventana) es `reasignacion`, frente al
  `conflicto` (dos MAC a la vez). Pasada la gracia sigue siendo traspaso silencioso.
- Tres pruebas nuevas en `tests/test_identidad.py`: (a) ARP falso de una sola trama dispara;
  (b) GARP legítimo del mismo equipo con la misma MAC no dispara; (c) conflicto vs reasignación.

### Expectativas registradas (se contrastan, no se ajustan)

- La FA del vigilante sobre las 20 sesiones de variación benigna de E3B (78000–78019, sin clones)
  no debe pasar de 1/disp-día. Sesgo declarado: ese generador no tiene DHCP ni failover de
  gateway, así que un cambio legítimo de IP→MAC no está representado; la cifra es optimista.
- P1 (bloque 3): con paso ≥ 30 s, el ARP deja 0 ventanas con ≥ 2 tramas de ataque → invisible
  para el supervisado por el etiquetado K=2, no por el modelo.
- P2 (bloque 3): el vigilante con el bloque 1 sí detecta el ARP lento, latencia ≈ la ventana de
  cruce. Si falla cualquiera de las dos, se reporta que falló y por qué.

## Bloque 2 — retemporizador (hecho)

- `scripts/lab/retemporizar.py`: lee una sesión existente y solo cambia `pkt.time` de las tramas
  de un episodio ARP/DNS. Verifica cuatro invariantes y falla si se rompen: (i) multiconjunto de
  bytes idéntico; (ii) nº de tramas igual; (iii) timestamps no decrecientes; (iv) orden relativo
  de movidas y quietas conservado. Reescribe los sidecars (`.tramas.csv`/`.episodios.csv` con los
  `ts_us` nuevos) para que `pcap_to_features` siga etiquetando. Rechaza tipos ≠ ARP/DNS, pcaps
  fuera de `data/pcap/` y escrituras fuera de ahí. Semilla fija ⇒ pcap byte a byte.
- `tests/test_retemporizar.py` (6): determinismo, bytes invariantes, rechazo de tipo, rechazo de
  ruta, y la integración con `pcap_to_features`: a paso 30 s el episodio queda por debajo de K
  (0 ventanas etiquetadas, invisible); a paso 0,5 s sí se etiqueta.

## Bloque 3 — régimen invisible medido (hecho)

- `scripts/evaluar_robustez.py` gana la fase `e4c` (dispatch por `cfg["fase"]`, sin tocar la ruta
  de E4R): entrena XGB sobre el corpus congelado al umbral de E2 (0,9086) y mide, por episodio y
  canal, el ARP retemporizado a pasos {5,15,30,60} s y el DNS en tiempo nativo.
- Dos correcciones de diseño registradas y necesarias:
  1. **Red del corpus**: el vigilante nace con la red del lab de identidad (10.20.0.0/16), pero el
     corpus de ataques usa 10.0.0.0/24. Se le pasa `red=10.0.0.0/24` a `vigilar_sesion`. Sin esto
     el vigilante no ve ninguna IP local (era parte de por qué E4R midió 0,000 en ARP).
  2. **Duración controlada** (lección de E4R): para cada paso se dejan `m = horizonte/paso + 1`
     refrescos (horizonte 300 s), descartando los frames de ataque sobrantes del episodio
     (sub-muestreo, no fabricación; modela un atacante de baja tasa). Así todos los pasos cubren
     el mismo horizonte (~305 s) y la curva compara peras con peras.

Resultado (`reports/robustez_e4c.json`):

| Paso | Ventanas etiq. | Invisibles | Supervisado | Identidad | Vigilante | OR |
|---|---|---|---|---|---|---|
| nativo (rápido) | 11,0 | 0 | **1,000** | 0,500 | 1,000 | 1,000 |
| 5 s | 0,0 | 2/2 | **0,000** | 1,000 | **1,000** | 1,000 |
| 15 s | 0,0 | 2/2 | 0,000 | 1,000 | 1,000 | 1,000 |
| 30 s | 0,0 | 2/2 | 0,000 | 1,000 | 1,000 | 1,000 |
| 60 s | 0,0 | 2/2 | 0,000 | 1,000 | 1,000 | 1,000 |

- **P1 se cumple**: a paso ≥ 5 s ninguna ventana alcanza K=2, el ARP es invisible para el
  supervisado (recall 0). El supervisado queda ciego a partir de 5 s (el tamaño de la ventana).
- **P2 se cumple**: el vigilante con el bloque 1 detecta el ARP lento en los cuatro pasos (1,000),
  latencia 5 s (primera ventana).
- **FA del vigilante** sobre las 20 sesiones de variación benigna de E3B: **0,0/disp-día** (0
  alertas en 2,71 disp-día), dentro del presupuesto de E2. Sesgo declarado: sin DHCP ni failover.
- DNS nativo: supervisado 1,000, vigilante 0,500, OR 1,000 (la carrera, no la tasa).
