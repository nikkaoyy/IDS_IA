# PEDIDO-2-DESVIACIONES — correcciones de la entrega (2026-11-25)

Segundo encargo sobre el mismo repo, tras `15d286d` («bloque 5: limpieza del repo y documento de
entrega»). Trabajas sobre `main` limpio. **No hagas `git push`** (lo hace el orquestador).

## Regla cero

La verdad es el repositorio y los JSON de `reports/`. No recalculas una cifra que no puedas recalcular
de verdad: en ese caso la declaras con su procedencia. **Prohibido** tocar `reports/*.json`,
`configs/`, `scripts/lab/generar_trafico.py`, `generar_dataset_lab.py` y `.claude/`.

Se corrigen **cuatro desviaciones** que tú mismo reportaste en `INFORME-ENTREGA.md`. Un commit por
bloque, mensaje en español.

### Bloque 1 — El 382 es un doble redondeo (commit «bloque 1: precisión del 382 de E5C»)

El valor real de E5C es **381,456 FA/dispositivo-día** (`reports/adopcion_e5c.json`, ruta
`por_modo/persistencia/…/fa_ventanas_por_dispositivo_dia`). Los informes lo citan como 382 y un commit
antiguo como 381.

1. Localiza todas las menciones: `grep -rn "382" --include='*.md' . | grep -v docs/historial`.
2. En la **primera mención de cada documento**, escribe `382 (381,5 exacto)`; en las siguientes deja
   `382` para no ensuciar la prosa. No cambies el número por 381 en ningún sitio: redondear 381,456 da
   381 y los informes dicen 382 desde antes; la salida honesta es mostrar el valor y el redondeo.
3. En `docs/ESTADO.md`, añade una nota de una línea en la tabla o debajo de ella: «E5C: 381,456
   exacto; los informes citan 382 por redondeo».
4. La figura (`docs/figuras/fa_disp_dia.png`) ya rotula 381,5: compruébalo y no la regeneres si es así.

**Criterio:** `grep -rn "381,5" --include='*.md' .` devuelve al menos una línea por documento que cita
382, y ningún informe dice 381.

### Bloque 2 — Cifras de E5 y E6 sin respaldo en reports/ (commit «bloque 2: procedencia de E5 y E6»)

`docs/INFORME_E7.md` cita para E5 «1014 ventanas, 62 alarmas de identidad, latencia 0,011 ms» y para
E6 la escalada a bloqueo y el pronóstico Holt, y **ningún JSON de `reports/` las contiene**.

1. No las borres ni las inventes. En `docs/INFORME_E5.md` y `docs/INFORME_E6.md`, añade al principio
   un recuadro «Procedencia de las cifras» que diga, para cada cifra sin respaldo: en qué corrida se
   midió (si consta en el propio informe o en el commit), y que **no está persistida en `reports/`**.
2. Intenta el camino barato de persistirlas: si algún script (`scripts/captura_en_vivo.py`,
   `src/streaming.py`, `src/pronostico.py`) puede reproducir la cifra **sin el corpus de clones** y en
   menos de dos minutos, córrelo y escribe el JSON en `reports/`. Si necesita `data/pcap_clones/`, **no
   lo hagas**: no hay corpus y regenerarlo no es de este pedido. Dilo en el informe.
3. `docs/ESTADO.md`: marca esas cifras con un asterisco y una nota al pie que remita al recuadro.

**Criterio:** cada cifra citada de E5/E6 en `docs/` tiene, o su JSON en `reports/`, o una línea de
procedencia explícita que dice que no está persistida. Cero cifras huérfanas.

### Bloque 3 — El pcap viene de dos generadores (commit «bloque 3: origen del pcap demo en el README»)

`docs/PCAP_DEMO.md` ya lo explica; el README no. En la sección donde enlazas el pcap demo, añade una
línea: que el archivo combina un episodio de `scripts/lab/generar_trafico.py` con uno de
`generar_clones.py` (ese generador no escribe opciones TCP y deja el IP-ID fijo), y que es **tráfico
sintético de laboratorio**. Nada más.

**Criterio:** la frase está en `README.md` y `docs/PCAP_DEMO.md` dice lo mismo (misma lista de
generadores).

### Bloque 4 — Un solo cuaderno de cierre (commit «bloque 4: cuaderno de cierre único»)

Hoy hay dos: `notebooks/cierre_e7.ipynb` (el nuevo, el que cita el README) y
`notebooks/final_report.ipynb` (el antiguo, renombrado en `b0a9418`).

1. `git mv notebooks/final_report.ipynb docs/historial/final_report_cierre_anterior.ipynb`.
2. En `docs/historial/`, un `README.md` de tres líneas que explique qué es ese cuaderno y por qué está
   ahí (el cierre anterior, sustituido por `notebooks/cierre_e7.ipynb`).
3. Verifica que ningún documento enlaza a `notebooks/final_report.ipynb`.
   `grep -rn "final_report" --include='*.md' . | grep -v docs/historial` debe salir vacío.

**Criterio:** `ls notebooks/` deja `cierre_e7.ipynb` y `IDS_IA_Ciberseguridad_proyecto.ipynb`, el
`grep` sale vacío y `cierre_e7.ipynb` sigue ejecutado (no lo reabras a mano).

### Cierre

1. Actualiza `INFORME-ENTREGA.md` con una sección «Pedido 2» (los cuatro commits, los comandos y sus
   salidas reales).
2. Corre la suite una vez con el corpus que ya regeneraste:
   `timeout 900 .venv/bin/python -m pytest -o addopts="" -q | tail -3` y pega el conteo. Si baja de
   **203 passed**, di qué prueba cambió de estado: este pedido no toca código de `src/` y no debería
   moverse ninguna.
3. `git status --porcelain` vacío al cerrar.

## Fuera del alcance

- El CI (`.github/workflows/`): el token del orquestador no tiene permiso `workflow`; se queda fuera a
  propósito y lo publica el dueño desde la interfaz de GitHub. **No lo reintentes.**
- Reentrenar, rehacer informes, tocar `reports/`, `configs/` o los generadores congelados.
- `git push`, abrir servicios o capturar tráfico en vivo.

## Al terminar

Responde con los cuatro commits, el conteo de pruebas y cualquier cifra de E5/E6 que hayas podido
persistir de verdad. Y di explícitamente qué desviación sigue abierta, si alguna.
