# IDS basado en IA — Huella Digital IEEE 802.3

Prototipo del sistema de detección de intrusiones descrito en el artículo
*"Detección de Intrusiones en Redes TCP/IP mediante Huella Digital de
Dispositivos en el Protocolo IEEE 802.3 usando Inteligencia Artificial"*.

## Arquitectura

```
Captura (Scapy) -> Extracción de huella IEEE 802.3 -> Preprocesamiento
      -> Clasificación (Random Forest / XGBoost) -> Mitigación / Alerta
                              ^
                              |
                    Simulador de ataque de suplantación
```

Cada bloque corresponde a un módulo en `src/`:

| Módulo | Responsabilidad |
|---|---|
| `src/capture.py` | Captura de tráfico en vivo con Scapy (requiere permisos de red) |
| `src/fingerprint.py` | Extracción de la huella digital IEEE 802.3 (MAC, OUI, longitud, timing) |
| `src/data.py` | Carga del dataset real (CICIDS2017/2018) o generación sintética de respaldo |
| `src/preprocess.py` | División train/test y escalado de variables |
| `src/models.py` | Entrenamiento, evaluación y persistencia de Random Forest y XGBoost |
| `src/attack_simulator.py` | Simulación del ataque de suplantación de huella digital |
| `src/pipeline.py` | Orquestador (Algoritmo 1 del artículo): inferencia por trama y experimento completo |

## Uso rápido

```bash
pip install -r requirements.txt
python3 -m src.pipeline
```

Pruebas: `pip install -r requirements.txt -r requirements-dev.txt` y luego `python -m pytest -q`.

Esto ejecuta las Fases 2-4 de la metodología (datos, entrenamiento, evaluación
comparativa y simulación de ataque) y guarda los modelos entrenados en `models/`.

Mientras no se cuente con el dataset real, `src/data.py` genera datos sintéticos
con la misma estructura de columnas, para que el pipeline sea ejecutable de
punta a punta desde ya.

## Pendientes (trazabilidad)

- [ ] Sustituir `data/cicids2017_procesado.csv` (placeholder) por CICIDS2017/2018 real.
- [ ] Ejecutar `src/capture.py` en el laboratorio de la asignatura para obtener huellas digitales reales.
- [ ] Ajuste de hiperparámetros (`GridSearchCV`/`RandomizedSearchCV`).
- [ ] Integrar `src/pipeline.py:inferir` en un bucle de captura en vivo (modo streaming).

## Estructura

```
.
├── src/
│   ├── capture.py
│   ├── fingerprint.py
│   ├── data.py
│   ├── preprocess.py
│   ├── models.py
│   ├── attack_simulator.py
│   └── pipeline.py
├── notebooks/
│   └── IDS_IA_Ciberseguridad_proyecto.ipynb
├── data/              # datasets (no versionados)
├── models/             # modelos entrenados (.joblib, no versionados)
└── requirements.txt
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

## Contexto académico

Detección de intrusiones en red con aprendizaje automático: captura de tráfico, ventanas de tiempo, modelo XGBoost y una capa de identidad por dispositivo. Trabajo de la asignatura **Fundamentos de redes de comunicaciones** de Ingeniería de Sistemas (Universidad Distrital Francisco José de Caldas),
con el docente **Octavio José Salcedo Parra**.
