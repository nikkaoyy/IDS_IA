SEGUIR — bloque 1 hecho (vigilante ARP); sigue el bloque 2 (retemporizador).

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
