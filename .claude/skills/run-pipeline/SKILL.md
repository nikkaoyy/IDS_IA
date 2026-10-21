---
name: run-pipeline
description: >-
  Ejecuta el pipeline completo del IDS (datos → entrenamiento → evaluación → simulación de ataque)
  y muestra los resultados comparativos RF vs XGBoost.
when_to_use: >-
  Use when the user asks to run the experiment, train models, execute the pipeline, 
  or test that everything works end-to-end.
allowed-tools: Bash
---

# Ejecutar Pipeline IDS

## Pasos

1. Verificar que las dependencias estén instaladas:
   ```bash
   cd /home/nikka/Documentos/FRED/ids-proyecto/ids_project
   pip install -r requirements.txt 2>/dev/null
   ```

2. Ejecutar el pipeline completo:
   ```bash
   cd /home/nikka/Documentos/FRED/ids-proyecto/ids_project
   python3 -m src.pipeline
   ```

3. Interpretar los resultados:
   - Si accuracy/precision/recall/f1 = 1.0 con FPR = 0.0 → **resultados tautológicos** (dataset sintético, ver CONTEXT_UPGRADE.md §3.2)
   - Los resultados solo serán significativos cuando se use un dataset real
   - La "tasa de detección bajo ataque" actual (~0.15) no tiene interpretación válida (§3.3)

4. Verificar que los modelos se guardaron:
   ```bash
   ls -la /home/nikka/Documentos/FRED/ids-proyecto/ids_project/models/
   ```

## Notas
- El pipeline usa datos **sintéticos** si no encuentra `data/cicids2017_procesado.csv`
- Los modelos se guardan en `models/` como `.joblib`
- El scaler NO se persiste actualmente (bug conocido)
