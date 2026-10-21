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
