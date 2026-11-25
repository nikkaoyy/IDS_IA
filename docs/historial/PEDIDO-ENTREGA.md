# PEDIDO-ENTREGA — cierre del repo IDS_IA para la entrega del 2026-11-26

Fecha: 2026-11-25. Autor del pedido: Hermes (agente de Nico). Ejecuta: Claude Code.

## Regla cero

**La verdad es el repositorio.** Si algo de este pedido contradice el código, los tests o los informes,
manda el repositorio: no recodifiques datos para cuadrar el pedido y reporta cada desviación con su
evidencia (archivo:línea, comando y salida). Este pedido se escribió leyendo el repo en el commit
`31431f8`, con `docs/ESTADO.md` como estado, pero **no se ha ejecutado la suite**: la línea base de
pruebas la estableces tú en el bloque 0 y la reportas tal cual.

Se entrega mañana (2026-11-26). Prioridad: que el repo sea coherente y reproducible de punta a punta.

## Estado verificado al escribir el pedido (compruébalo, no lo asumas)

- `README.md:107-114` y `CLAUDE.md` dicen que el trabajo es del curso **Modelos de Programación** con el
  docente **Daza**. **Está mal**: el proyecto es de **Fundamentos de redes de comunicaciones**, docente
  **Octavio José Salcedo Parra** (Universidad Distrital Francisco José de Caldas). El error entró en el
  commit `31431f8` («contexto academico: materia y docente») hace un día.
- `README.md:78` y `docs/ESTADO.md:22` citan `notebooks/cierre_e7.ipynb` como entregable de E7. **Ese
  archivo no existe**: en `notebooks/` solo hay `IDS_IA_Ciberseguridad_proyecto.ipynb` y
  `final_report.ipynb`.
- `CLAUDE.md:66-78` sigue listando como «problemas críticos» cosas ya resueltas (features desconectadas,
  resultados tautológicos, «sin tests, sin pyproject.toml»). Se contradice con el árbol actual.
- `README.md:45-50` («Pendientes (trazabilidad)») y `docs/ESTADO.md:84` («Sin `git push` desde estas
  ventanas») están obsoletos.
- `data/` y `models/` están vacíos (solo `.gitkeep`); ningún pcap está versionado. Sin datos, ninguna
  cifra del repo se reproduce.
- Hay 17 `.md` de trabajo en la raíz (`PEDIDO-*.md`, `PROGRESO-*.md`, `CONTEXT_UPGRADE.md`) y el PDF del
  anteproyecto está duplicado (raíz y `doc_proyecto/`). No hay `LICENSE` ni CI.

## Entorno

- Python con `uv` (`/opt/data/local/bin/uv`). Crea `.venv` con `uv venv && uv pip install -e ".[dev]"`;
  **no uses `pip` global** (no existe). Dependencias en `pyproject.toml`.
- Repo de trabajo: este directorio. Rama `main` local. **No hagas `git push`** (lo hace el orquestador).
  Un commit por bloque, mensaje en español, sin enmendar commits anteriores.
- No toques `.claude/skills/` ni `reports/` (las cifras congeladas son la evidencia del informe).

## Bloques

### Bloque 0 — Línea base medida (commit «bloque 0: línea base de pruebas»)

1. Crear `.venv` e instalar dependencias.
2. Correr la suite completa con plazo: `timeout 900 .venv/bin/python -m pytest -o addopts="" -q`.
3. Escribir en `docs/ESTADO.md` una sección «Línea base 2026-11-25» con el conteo exacto (`N passed, M
   xfailed, K skipped`) y la versión de Python. Si algún archivo se cuelga, identifícalo por nombre y
   repórtalo; no lo borres.

**Criterio:** la salida real pegada en el informe. Si hay rojos, se reportan y se sigue: este pedido no
es para arreglar la suite, salvo que un rojo lo cause un archivo que tú toques.

### Bloque 1 — Contexto académico correcto (commit «bloque 1: contexto académico correcto»)

1. `README.md`: la sección «Contexto académico» pasa a decir **Fundamentos de redes de comunicaciones**,
   docente **Octavio José Salcedo Parra**, Universidad Distrital Francisco José de Caldas. Mantén la
   descripción técnica que ya está (captura, ventanas, XGBoost, capa de identidad); corrige solo
   materia y docente.
2. `CLAUDE.md`: si menciona curso o docente, igualarlo al mismo dato.
3. Busca en todo el repo cualquier otra mención a «Modelos de Programación» o «Daza»
   (`grep -rn -i "modelos de programaci\|daza" --include='*.md' --include='*.py' .`) y corrígelas. Las
   que aparezcan en `docs/INFORME_*.md` o `PEDIDO-*.md` históricos **se dejan** (son registro) y se
   listan en el informe.

**Criterio:** `grep -rn -i "modelos de programaci\|daza" --include='*.md' .` sin resultados fuera de
`PEDIDO-*.md` y `docs/historial/`.

### Bloque 2 — Cuaderno de cierre E7 (commit «bloque 2: cuaderno de cierre E7»)

El README promete `notebooks/cierre_e7.ipynb` y no existe. **Regenerarlo de verdad**, no cambiar el
README para tapar el hueco:

1. Crear `notebooks/cierre_e7.ipynb` con estructura CRISP-DM de punta a punta (comprensión del negocio,
   comprensión de los datos, preparación, modelado, evaluación, despliegue), citando en cada celda la
   etapa E1–E6 y el archivo de `reports/` de donde sale la cifra.
2. Las celdas de datos deben **leer los JSON ya congelados de `reports/`** (no reentrenar): el cuaderno
   tiene que ejecutarse en menos de un minuto de punta a punta y mostrar las cifras reales
   (0,894 [0,856, 0,936]; 0,89 FA/disp-día; LOAO 0,228; 0,38 FA/disp-día en identidad; 1,000 → 0,000
   del ARP lento contra vigilante 1,000). Si un JSON no trae la cifra que el texto afirma, no la
   inventes: anota en la celda «cifra no encontrada en reports/, ver informe X».
3. Ejecutarlo completo (`jupyter nbconvert --to notebook --execute --inplace`) y commitear el `.ipynb`
   **con las salidas**.
4. Si al ejecutarlo aparece que alguna cifra del informe no existe en `reports/`, repórtalo: es más
   grave que el cuaderno.

**Criterio:** `.venv/bin/jupyter nbconvert --to notebook --execute --inplace notebooks/cierre_e7.ipynb`
termina sin error y el archivo tiene `outputs` no vacías en las celdas de resultados.

### Bloque 3 — pcap de demostración con los campos que ve Wireshark (commit «bloque 3: pcap de demostración»)

Objetivo: que el repo traiga **un pcap pequeño y real** (legible en Wireshark y en Scapy) con las
tramas que sostienen la huella IEEE 802.3 y el canal de identidad, para que la entrega no dependa de
regenerar el corpus en vivo.

1. Usa **los generadores congelados que ya están en `scripts/lab/generar_trafico.py`** (y
   `generar_clones.py` si tu pcap necesita un clon de MAC). No escribas un generador nuevo.
2. Genera **una sesión corta** (≈2–3 minutos de tráfico, objetivo < 8 MB) con fondo benigno y **un
   episodio** de ataque, semilla fija, y guárdala en `data/pcap/demo/sesion_demo.pcap`
   (+ su manifiesto `.meta.json` si el generador lo produce).
3. `.gitignore`: añade la excepción que permita versionar **solo** ese archivo
   (`!data/pcap/demo/`), dejando el resto de `data/pcap/` ignorado.
4. Verifica leyendo el pcap con Scapy (script corto en `scripts/verificar_demo_pcap.py`, commitéalo) e
   imprime, con su valor real, cada campo que Wireshark muestra y que el proyecto usa:
   MAC origen y destino, OUI, ethertype, VLAN/LLC si los hay, IP origen/destino, **IP-ID**, **TTL**,
   protocolo, puertos, **ventana TCP** y **opciones TCP**, y las tramas ARP (op, hwsrc/psrc) y DNS
   (txid, qname). El script termina con un resumen `N tramas, M flujos, tipos: ...` y **falla** si el
   pcap no trae ARP, TCP con opciones y al menos un cambio de IP-ID.
5. `docs/PCAP_DEMO.md`: qué contiene el archivo, cómo abrirlo en Wireshark, los filtros de display que
   muestran la evidencia (`arp`, `tcp.flags.syn==1`, `ip.id`, `tcp.options`, `dns`), y la tabla de qué
   columna del esquema 3.0 sale de cada campo. Encabeza con: **«tráfico sintético de laboratorio,
   generado por `scripts/lab/generar_trafico.py` con semilla fija; no es una captura de red real»**.
   Esta frase es obligatoria: el pcap no se presenta como real en ningún documento.
6. Comprueba que el pipeline lo consume: `python3 scripts/pcap_to_features.py --pcap
   data/pcap/demo/sesion_demo.pcap …` (usa la interfaz real del script, lee su `--help`) y pega en el
   informe las primeras filas generadas y el número de ventanas.

**Criterio:** `ls -l data/pcap/demo/` muestra el pcap versionado (`git ls-files data/pcap/demo/`), el
verificador imprime los campos con sus valores y termina 0, y `pcap_to_features.py` produce ventanas a
partir de ese archivo. **No metas tráfico de ataque real contra ninguna red**: todo se genera en archivo.

### Bloque 4 — Figuras para la exposición (commit «bloque 4: figuras y reproducción»)

1. `scripts/figuras.py`: lee `reports/*.json` y escribe **dos PNG** en `docs/figuras/`:
   `recall_por_intensidad.png` (media 0,935 / suave 0,891 / ráfaga 0,824) y
   `fa_disp_dia.png` (826 con variación benigna → 382 con E5C, con la línea de presupuesto 1 FA/disp-día).
   Matplotlib, sin estilo exótico, ejes rotulados en español, título con la fuente («datos de
   `reports/…json`, laboratorio sintético»).
2. `README.md`: sección «Reproducir desde cero» con los comandos exactos (`uv venv`, instalación,
   generación del corpus con los generadores congelados y sus rangos de sesión ya usados —clones 0–39,
   variación 0–19, suplantación 0–39, contaminación 0–19—, verificación del sha256 del dataset
   `7f06d099…a945`, cómo correr las evaluaciones E2/E3/E4/E5C y la suite). Nada de comandos supuestos:
   cada uno lo ejecutas o lo marcas como no ejecutado y dices por qué.
3. Enlazar las figuras y el pcap demo desde el README.

**Criterio:** los dos PNG existen (`ls -l docs/figuras/*.png`), los genera el script desde cero
(borra y reejecuta), y cada comando de «Reproducir desde cero» está marcado como **ejecutado** o
**no ejecutado** en el informe.

### Bloque 5 — Limpieza y entrega (commit «bloque 5: limpieza del repo y documento de entrega»)

1. `git mv` de `PEDIDO-*.md`, `PROGRESO-*.md`, `CONTEXT_UPGRADE.md` y `PEDIDO-ANOMALIAS-1.md` a
   `docs/historial/`. **No borres ninguno.**
2. Un solo PDF del anteproyecto: deja `doc_proyecto/IDS_IA_NicolasMartinez_20241020098.pdf` y elimina
   la **copia duplicada de la raíz** (`git rm` del duplicado; son idénticos, compruébalo con `sha256sum`
   antes y pega el hash en el informe).
3. `LICENSE`: MIT con «Nicolás Martínez Pineda» y el año 2026.
4. `.github/workflows/tests.yml`: Python 3.11, `uv pip install -e ".[dev]"` y `pytest -o addopts="" -q`,
   con plazo. Sin secretos.
5. `CLAUDE.md`: reescribir la sección «Estado del proyecto y problemas conocidos». Los seis problemas de
   la lista están resueltos o son decisiones tomadas (el dataset sintético en vez de CICIDS2017 con su
   motivo). Conviértela en «Arquitectura y comandos» + «Decisiones tomadas» + «Extensiones conocidas»,
   sin narrar el diagnóstico viejo. Mantén el aviso de leer `CONTEXT_UPGRADE.md` apuntando a la ruta
   nueva en `docs/historial/`.
6. `README.md` y `docs/ESTADO.md`: quitar los pendientes obsoletos y dejar los que siguen abiertos de
   verdad (laboratorio físico: captura real, DHCP/failover, RST del clon en switch, sesiones largas ≥30).
7. `README.md`: árbol de archivos actualizado (incluye `scripts/`, `tests/`, `configs/`, `docs/`,
   `notebooks/cierre_e7.ipynb`, `docs/figuras/`, `data/pcap/demo/`).
8. `INFORME-ENTREGA.md` en la raíz: por bloque, el commit, los comandos corridos y **su salida real**
   (conteos de pruebas, cifras del pcap, tamaño de los PNG). Al final, una sección **«Desviaciones y lo
   que no se pudo verificar»**: todo lo que el pedido ordenaba y no se hizo, con el motivo.

**Criterio:** `git log --oneline -7` con los seis commits; `git status --porcelain` vacío al cerrar;
`INFORME-ENTREGA.md` existe con la salida real pegada.

## Fuera del alcance

- Reentrenar modelos o rehacer informes: las cifras de E1–E7 están congeladas y así se quedan.
- Cambiar `reports/`, `configs/` o `scripts/lab/generar_trafico.py` / `generar_dataset_lab.py`.
- Instalar servicios, abrir puertos, o ejecutar captura en vivo con root.
- `git push`, publicar, o tocar cualquier repo que no sea este.
- Reescribir la historia de git.

## Al terminar

Responde con: los commits (hash y asunto), el conteo de pruebas de la línea base y del cierre, el
tamaño y la ruta del pcap demo, y **la lista de desviaciones**. Nada de «todo listo» sin las cifras.
