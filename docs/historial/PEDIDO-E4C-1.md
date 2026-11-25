# PEDIDO-E4C-1 — el vigilante que sí ve el ARP, y el régimen invisible medido sobre el corpus ya congelado

Repo: `~/Documentos/FRED/IDS`, rama `main`, base `9b42040` (E4R cerrado).

**La verdad es el repositorio.** El «estado verificado» de abajo se comprobó sobre `9b42040`; si algo contradice el
código, manda el código y se reporta como desviación antes de seguir.

## Qué es esta fase, y qué no es

Es una **prueba de robustez defensiva del propio IDS**, la que E4R dejó declarada como pendiente:
llevar los ataques al régimen donde el detector por ventana no puede verlos y medir qué se pierde.
No se construye ninguna herramienta ofensiva y **no se fabrica ni una sola trama**:

- La única pieza nueva que toca pcaps es un **re-temporizador** (`scripts/lab/retemporizar.py`) que
  lee una sesión **ya existente** del corpus (`data/pcap/sesion_XXX.pcap` + `.tramas.csv`, del
  generador congelado de E1) y **solo cambia `pkt.time`** de las tramas de un episodio etiquetado.
  Bytes, orden por flujo, número y etiqueta quedan idénticos y se verifican con asserts.
- No hay inyección, ni interfaz, ni root, ni payload nuevo.
- El CLI **rechaza** cualquier episodio que no sea `arp_spoofing` o `dns_spoofing`.

## Bloque 1 — El vigilante ve el ARP (`src/identidad.py`)

1. Segunda fuente del mismo mapa: además de `ip_src → mac_src`, el vínculo ARP `arp_psrc → arp_hwsrc`
   (solo IPs locales, `arp_op` 1 y 2). Dos fuentes, un mapa; sin umbrales nuevos.
2. Señal de contradicción: `arp_hwsrc != mac_src` como evidencia propia.
3. No cambia: gracia de 600 s, `MIN_VENTANAS_CRUCE`, `no_confiable`.
4. FA medida con las 20 sesiones de variación benigna de E3B (sin clones): no puede pasar de
   1/disp-día. Sesgo declarado: sin DHCP ni failover, cifra optimista.
5. ARP gratuito legítimo y dos interfaces del mismo equipo no deben alarmar.

Criterio: `tests/test_identidad.py` con tres casos — (a) ARP spoofing a 1 trama/60 s alarma; (b) ARP
gratuito del mismo equipo con la misma MAC no alarma; (c) IP que cambia de MAC pasada la gracia se
acusa como reasignación, no como conflicto.

## Bloque 2 — `scripts/lab/retemporizar.py` (transformador, no generador)

1. Selecciona las tramas del episodio (`episodio` + `tipo`) y les asigna nuevo horario `--paso-s`,
   con `--jitter` y `--semilla`. El resto conserva su tiempo.
2. Invariantes verificadas en código: (i) multiconjunto de bytes idéntico; (ii) nº de tramas igual;
   (iii) timestamps no decrecientes; (iv) orden relativo por flujo TCP conservado.
3. Rechaza tipos ≠ `arp_spoofing`/`dns_spoofing`, pcaps que no sean del lab, y escrituras fuera de
   `data/pcap/`.
4. Semilla fija ⇒ mismo pcap byte a byte.

Criterio: `tests/test_retemporizar.py` con (a) determinismo; (b) hashes de trama invariantes; (c)
rechazo de tipo no permitido; (d) el episodio se sigue etiquetando pero con ventanas bajo K si el paso
es grande.

## Bloque 3 — El régimen invisible, medido (predicciones registradas antes de medir)

Rejilla: `arp_spoofing` paso `{5, 15, 30, 60}` s; `dns_spoofing` una respuesta por consulta. Dos
episodios por tipo, sesiones reservadas. Sobre cada pcap retemporizado: `pcap_to_features.py` → 52
columnas → XGB al umbral de E2; en paralelo identidad y vigilante (bloque 1), y el OR con su FA.

1. **Invisible por construcción**: episodios donde ninguna ventana alcanza K=2.
2. **P1 (antes de medir)**: con paso ≥ 30 s, el ARP tiene 0 ventanas con ≥ 2 tramas: invisible para el
   supervisado por el etiquetado, no por el modelo. Si P1 falla, se reporta.
3. **P2**: el vigilante con el bloque 1 sí lo detecta, latencia ≈ ventana de cruce. Si no, hueco
   abierto declarado.
4. Suelo de efecto: 1 ARP/60 s refresca antes del `gc_stale`; a paso > 60 s el ataque ya no conserva
   el efecto y la medida deja de valer. DNS: la forjada antes que la legítima.
5. Recall y FA de los cuatro canales por paso, curva recall vs paso **con la duración controlada**.

## Bloque 4 — Informe y cierre

`reports/robustez_e4c.json` (+ `.md`) y `docs/INFORME_E4C.md`: vigilante antes/después (ARP 0,000 →
cifra), FA del vigilante con variación benigna, recall vs paso por canal, invisibles y en qué paso
aparecen, veredicto de P1 y P2, y la frase: **a qué tasa de ARP el sistema deja de poder verlo y qué
canal lo sigue viendo**. Un commit por bloque, `docs/ESTADO.md` actualizado, `git status` limpio.

## Criterio de aceptación (pega la salida real)

```bash
cd ~/Documentos/FRED/IDS
.venv/bin/python -m pytest -o addopts="" -q tests/test_identidad.py tests/test_retemporizar.py tests/test_evaluar_robustez.py
.venv/bin/python scripts/evaluar_robustez.py --config configs/robustez_e4c.json
.venv/bin/python -c "import json;d=json.load(open('reports/robustez_e4c.json'));print(d['resumen'])"
```

## Lo que NO se toca

- El contrato de 52 columnas, `VERSION_ESQUEMA` 3.0, `COLUMNAS_MODELO`, el dataset (`7f06d099…a945`),
  `models/`.
- Los generadores congelados (se leen, no se editan). El retemporizador opera sobre su salida.
- Los umbrales de identidad (`UMBRAL_DESVIACION`, `MIN_VENTANAS_PERFIL`, `MIN_VENTANAS_CRUCE`, gracia
  600 s) y la ablación de E3B. El único cambio en `src/identidad.py` es el bloque 1.
- El holdout 20–29, E5, E6, E7. Interfaces reales: nada. Sin `git push`.

## Cierre

Reporte de cinco líneas: detección del ARP lento por el vigilante antes/después, FA del vigilante con
variación benigna, el paso en que el ARP se vuelve invisible para el supervisado, qué canal lo sigue
viendo, y qué queda para E5.
