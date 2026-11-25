# IDS basado en IA — Huella Digital IEEE 802.3

Prototipo del sistema de detección de intrusiones descrito en el artículo
*"Detección de Intrusiones en Redes TCP/IP mediante Huella Digital de
Dispositivos en el Protocolo IEEE 802.3 usando Inteligencia Artificial"*.

Todos los datos del proyecto son **tráfico sintético de laboratorio** (generadores con semilla
fija en `scripts/lab/`); no hay capturas de una red real. Licencia: MIT (`LICENSE`).

## Arquitectura

```
Captura (Scapy) -> Huella IEEE 802.3 por ventana de 5 s -> Preprocesado
   -> Clasificación (Random Forest / XGBoost)  +  Identidad del dispositivo
   -> Mitigación (dry-run) / Alerta  +  Pronóstico de alertas
                     ^
     Evasión a nivel de pcap (E4) · suplantación de MAC/IP/pila (E3)
```

| Módulo | Responsabilidad |
|---|---|
| `src/capture.py` | Captura de tráfico en vivo con Scapy (requiere permisos de red) |
| `src/streaming.py` | Motor de streaming: AsyncSniffer o replay → ventanas → modelo → alerta (E5) |
| `src/ventanas.py` | Extractor de la huella por ventana, común al lote y al streaming |
| `src/feature_schema.py` | Contrato de características: esquema 3.0, 52 columnas |
| `src/fingerprint.py` | Huella IEEE 802.3 por trama (MAC, OUI, longitud, timing) |
| `src/data.py` | Carga del dataset del laboratorio, semillas y holdout reservado |
| `src/preprocess.py` | División y escalado |
| `src/models.py` | Entrenamiento, evaluación y persistencia de Random Forest y XGBoost |
| `src/evaluacion.py` | Evaluación por episodio con IC bootstrap y FA/disp-día (E2) |
| `src/anomalias.py` | Detector entrenado solo con benigno (contraste) |
| `src/identidad.py` | Perfil de pila por dispositivo y vigilante IP→MAC (E3) |
| `src/mitigacion.py` | Respuesta escalable log → alerta → bloqueo → cuarentena, dry-run por defecto (E6) |
| `src/pronostico.py` | Pronóstico Holt de la tasa de alertas (E6) |
| `src/attack_simulator.py` | Simulador original por columnas (se conserva; no es representativo, ver E4) |
| `src/pipeline.py` | Orquestador (Algoritmo 1 del artículo) |

## Uso rápido

```bash
uv venv && uv pip install -e ".[dev]"
timeout 900 .venv/bin/python -m pytest -o addopts="" -q
.venv/bin/python scripts/verificar_demo_pcap.py      # el pcap de demostración, campo por campo
```

Para regenerar los datos y reproducir cada etapa, ver «Reproducir desde cero» más abajo.

## Pendientes (abiertos de verdad)

Todos necesitan el laboratorio físico o sesiones nuevas; el núcleo software (OE1–OE3) está
implementado y medido en el laboratorio sintético.

- [ ] Captura real sobre una interfaz del laboratorio (y ejecución real de la mitigación).
- [ ] FA del vigilante IP→MAC con DHCP y failover reales (su 0,0 FA/disp-día es optimista).
- [ ] RST de la víctima frente a un clon de pila completa en un switch.
- [ ] Sesiones largas y nuevas (≥ 30; el holdout 20–29 está gastado) para cualquier cifra final.

## Estructura

```
.
├── src/                    # módulos del IDS (tabla de arriba)
├── scripts/                # evaluaciones por etapa, pcap -> ventanas, figuras, pcap demo
│   ├── lab/                # generadores sintéticos (generar_trafico.py y generar_dataset_lab.py congelados)
│   ├── evaluar*.py         # E2, E3, E4R/E4C, E5C, anomalías, holdout
│   ├── pcap_to_features.py
│   ├── captura_en_vivo.py  # E5: en vivo (root) o replay offline
│   ├── figuras.py          # docs/figuras/ desde reports/
│   ├── generar_demo_pcap.py
│   └── verificar_demo_pcap.py
├── tests/                  # pytest
├── configs/                # configuración de cada evaluación (salida en reports/)
├── reports/                # cifras congeladas de E1–E6 (JSON/MD)
├── docs/
│   ├── ESTADO.md           # estado y conclusiones vigentes
│   ├── INFORME_*.md        # un informe por etapa
│   ├── PCAP_DEMO.md
│   ├── figuras/            # recall_por_intensidad.png, fa_disp_dia.png
│   └── historial/          # pedidos y bitácoras de trabajo (registro)
├── notebooks/
│   ├── cierre_e7.ipynb     # cierre CRISP-DM, lee reports/
│   ├── final_report.ipynb
│   └── IDS_IA_Ciberseguridad_proyecto.ipynb
├── doc_proyecto/           # anteproyecto (PDF) y culminacion_doc.md
├── data/                   # datos regenerables (no versionados)...
│   └── pcap/demo/          # ...salvo el pcap de demostración y sus manifiestos
├── models/                 # modelos .joblib (no versionados)
├── .github/workflows/tests.yml
├── pyproject.toml
└── LICENSE
```

## Etapas E1–E7 y cómo reproducir

El proyecto avanzó por etapas, cada una con su informe en `docs/` y sus cifras congeladas en
`reports/`. El cuaderno de cierre las recorre de punta a punta:

```bash
# Cuaderno de cierre (CRISP-DM, OE1–OE3): abrir en Jupyter y ejecutar en orden
jupyter notebook notebooks/cierre_e7.ipynb

# Evaluación supervisada (E2) y de identidad (E3)
.venv/bin/python scripts/evaluar.py --config configs/e2.json
.venv/bin/python scripts/evaluar_identidad.py --config configs/identidad.json --partes b

# Robustez / evasión a nivel de pcap (E4)
.venv/bin/python scripts/evaluar_robustez.py --config configs/robustez.json      # E4R
.venv/bin/python scripts/evaluar_robustez.py --config configs/robustez_e4c.json  # E4C (ARP lento)

# Menos falsas alarmas sin absorber el clon (E5C)
.venv/bin/python scripts/evaluar_adopcion.py --config configs/adopcion_e5c.json

# Captura en streaming (E5): offline (sin root) o en vivo
.venv/bin/python scripts/captura_en_vivo.py --pcap data/pcap/sesion_000.pcap --dataset data/dataset_lab.csv
sudo .venv/bin/python scripts/captura_en_vivo.py --iface eth0 --red-local 10.0.0.0/24 --dataset data/dataset_lab.csv

# Pruebas
.venv/bin/python -m pytest -o addopts="" -q
```

| Etapa | Qué resuelve | Informe |
|---|---|---|
| E1–E2 | Dataset del laboratorio y clasificador por episodio (OE2) | `docs/INFORME_E1.md`, `docs/INFORME_E2.md` |
| E3 | Identidad del dispositivo: perfil de pila y vínculo IP→MAC | `docs/INFORME_E3A.md`, `docs/INFORME_E3B.md` |
| E4 | Evasión a nivel de pcap (OE3): robustez y régimen invisible | `docs/INFORME_E4.md` (+ E4R, E4C) |
| E5 | Captura en streaming en vivo (`src/streaming.py`) | `docs/INFORME_E5.md` |
| E5C | Tercera vía: menos FA con variación benigna sin absorber clones | `docs/INFORME_E5C.md` |
| E6 | Mitigación (dry-run) y pronóstico de alertas (OE3) | `docs/INFORME_E6.md` |
| E7 | Cierre: cuaderno CRISP-DM de punta a punta | `notebooks/cierre_e7.ipynb` |

Estado y conclusiones vigentes: `docs/ESTADO.md`.

## Reproducir desde cero

Comandos exactos, en orden. Cada uno se ejecutó el 2026-11-25 (Python 3.14.9, 4 CPU) salvo los
marcados **no ejecutado**; los tiempos son los medidos. Todo el tráfico es sintético y se escribe a
archivo: nada se emite por ninguna interfaz.

```bash
# 1. Entorno (ejecutado). `uv` en vez de pip global.
uv venv
uv pip install -e ".[dev]"            # ".[dev,notebook]" añade nbconvert/ipykernel para el cuaderno

# 2. Corpus de desarrollo E1–E2: 20 sesiones de 15 min con el generador congelado (ejecutado, 6 min 41 s)
.venv/bin/python scripts/lab/generar_dataset_lab.py --salida data/dataset_lab.csv
sha256sum data/dataset_lab.csv
# esperado y obtenido: 7f06d099477a474b12db73001f3ee56a8e14e93bb41501c8b49ee94e4032a945

# 3. Sesiones de identidad E3 con los rangos ya usados (ejecutado; 1–2,5 min cada uno)
.venv/bin/python scripts/lab/generar_clones.py       --inicio 0 --sesiones 40 --dir-pcap data/pcap_clones
.venv/bin/python scripts/lab/generar_variacion.py    --inicio 0 --sesiones 20 --dir-pcap data/pcap_variacion
.venv/bin/python scripts/lab/generar_suplantacion.py --inicio 0 --sesiones 40 --dir-pcap data/pcap_e3b
.venv/bin/python scripts/lab/generar_contaminacion.py --inicio 0 --sesiones 20 --dir-pcap data/pcap_e3b

# 4. Evaluaciones (NO EJECUTADAS: escriben en reports/, cuyas cifras están congeladas; ver abajo)
.venv/bin/python scripts/evaluar.py --config configs/e2.json                                 # E2
.venv/bin/python scripts/evaluar_identidad.py --config configs/identidad.json --partes a,b   # E3A + E3B
.venv/bin/python scripts/evaluar_robustez.py --config configs/robustez.json                  # E4R
.venv/bin/python scripts/evaluar_robustez.py --config configs/robustez_e4c.json              # E4C
.venv/bin/python scripts/evaluar_adopcion.py --config configs/adopcion_e5c.json              # E5C

# 5. Streaming offline E5 sobre el pcap de demostración (ejecutado, 12 s; entrena el supervisado al arrancar)
.venv/bin/python scripts/captura_en_vivo.py --pcap data/pcap/demo/sesion_demo.pcap \
    --dataset data/dataset_lab.csv --red-local 10.0.0.0/24

# 6. Suite de pruebas (ejecutado, ~5 min)
timeout 900 .venv/bin/python -m pytest -o addopts="" -q

# 7. Cuaderno de cierre, figuras y pcap de demostración (ejecutado; segundos cada uno)
.venv/bin/jupyter nbconvert --to notebook --execute --inplace notebooks/cierre_e7.ipynb
.venv/bin/python scripts/figuras.py
.venv/bin/python scripts/generar_demo_pcap.py      # regenera data/pcap/demo/ (mismo sha256)
.venv/bin/python scripts/verificar_demo_pcap.py
.venv/bin/python scripts/pcap_to_features.py --pcap data/pcap/demo/sesion_demo.pcap --salida /tmp/demo_ventanas.csv
```

Por qué no se ejecutaron las evaluaciones del paso 4: sus `configs/` fijan la salida en
`reports/*.json`, y `reports/` es la evidencia congelada del informe (ninguna se reentrena en la
entrega). Para rehacer una, copia su config cambiando `salida` a otra ruta. Los generadores del
paso 3 corrieron sin error, pero `reports/` no guarda un sha256 de esos pcaps, así que su identidad
byte a byte con los de E3 no se pudo comprobar. El corpus del paso 2 sí: el sha256 coincide.

## Figuras y pcap de demostración

- `docs/figuras/recall_por_intensidad.png`: recall del supervisado por intensidad (media 0,935 /
  suave 0,891 / ráfaga 0,824, con IC95). Datos: `reports/robustez_e4.json`.
- `docs/figuras/fa_disp_dia.png`: FA/disp-día del canal de identidad con variación benigna, 826 →
  382 (381,5 exacto) con E5C, frente al presupuesto de 1 FA/disp-día (escala log). Datos: `reports/adopcion_e5c.json`.
- Las dos se regeneran desde cero con `scripts/figuras.py`, que solo lee `reports/`.
- `data/pcap/demo/sesion_demo.pcap` (4,29 MB, 150 s): **tráfico sintético de laboratorio, generado
  por `scripts/lab/generar_trafico.py` con semilla fija; no es una captura de red real**. Trae un
  episodio de ARP spoofing y un clon de MAC (este último de `generar_clones.py`). Qué contiene, cómo
  abrirlo en Wireshark y qué columna sale de cada campo: [`docs/PCAP_DEMO.md`](docs/PCAP_DEMO.md).

![Recall por intensidad](docs/figuras/recall_por_intensidad.png)
![FA por dispositivo-día](docs/figuras/fa_disp_dia.png)

## Contexto académico

Detección de intrusiones en red con aprendizaje automático: captura de tráfico, ventanas de tiempo, modelo XGBoost y una capa de identidad por dispositivo. Trabajo de la asignatura **Fundamentos de redes de comunicaciones** de Ingeniería de Sistemas (Universidad Distrital Francisco José de Caldas),
con el docente **Octavio José Salcedo Parra**.

## Licencia

MIT, © 2026 Nicolás Martínez Pineda. Ver `LICENSE`.
