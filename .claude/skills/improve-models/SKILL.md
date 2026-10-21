---
name: improve-models
description: >-
  Mejora los modelos RF y XGBoost: agrega class_weight/scale_pos_weight para desbalance,
  validación cruzada, tuning de hiperparámetros, métricas adicionales (ROC-AUC, PR-AUC),
  importancia de features, y persistencia completa (scaler + columnas + metadata).
when_to_use: >-
  Use when the user asks to improve models, add cross-validation, tune hyperparameters,
  add ROC curves, fix class imbalance, or improve evaluation metrics.
allowed-tools: Bash, Read, Write, Edit
---

# Mejorar Modelos del IDS

## Mejoras por prioridad

### 1. Manejo de desbalance de clases (CRÍTICO)

En `src/models.py`:
- RF: agregar `class_weight="balanced"` o `class_weight="balanced_subsample"`
- XGBoost: calcular `scale_pos_weight = n_negativos / n_positivos`

### 2. Métricas adicionales (CRÍTICO)

En `src/models.py`, función `evaluar()`:
- Agregar `roc_auc_score(y_test, y_prob)` usando `modelo.predict_proba()[:, 1]`
- Agregar `average_precision_score(y_test, y_prob)` (PR-AUC)
- Pasar `labels=[0, 1]` a `confusion_matrix()` para evitar error con una sola clase
- Guardar curvas ROC y PR como figuras en `docs/figuras/`

### 3. Validación cruzada

En `src/models.py`, agregar función:
```python
def validacion_cruzada(modelo, X, y, cv=5, semillas=[42, 123, 456, 789, 1024]):
    """StratifiedKFold con múltiples semillas para intervalos de confianza."""
```
- Usar `StratifiedKFold` (o `StratifiedGroupKFold` si hay grupos por dispositivo/sesión)
- Reportar media ± IC 95% de cada métrica
- Múltiples semillas para robustez

### 4. Tuning de hiperparámetros

```python
def buscar_hiperparametros(X_train, y_train, modelo_tipo="rf"):
    """RandomizedSearchCV con grid razonable."""
```

Grids sugeridos:
- RF: `n_estimators=[100,200,500]`, `max_depth=[None,10,20,30]`, `min_samples_split=[2,5,10]`
- XGB: `n_estimators=[100,200,500]`, `max_depth=[3,6,9]`, `learning_rate=[0.01,0.1,0.3]`, `subsample=[0.8,1.0]`

### 5. Importancia de features

```python
def analizar_importancia(modelo, X_test, y_test, nombres_features):
    """Importancia por permutación + importancia nativa del modelo."""
```

- Comparar importancia nativa (Gini/gain) vs. permutación
- Ablación: entrenar con vs. sin features de capa 2 para demostrar aporte de huella 802.3
- Guardar tabla de importancias y gráfico de barras

### 6. Persistencia completa

En `src/models.py`, función `guardar_modelo()`:
```python
def guardar_artefacto_completo(modelo, scaler, columnas, nombre, metadata=None):
    """Guarda modelo + scaler + columnas + metadata como un solo artefacto."""
    artefacto = {
        "modelo": modelo,
        "scaler": scaler,
        "columnas": columnas,
        "metadata": metadata or {},
        "timestamp": datetime.now().isoformat(),
        "version": "0.1.0",
    }
    joblib.dump(artefacto, MODELOS_DIR / f"{nombre}_artefacto.joblib")
```

### 7. Validación

```bash
cd /home/nikka/Documentos/FRED/ids-proyecto/ids_project
python3 -m src.pipeline
```

- Accuracy ya no debe ser 1.0 (si se corrigió el dataset)
- ROC-AUC y PR-AUC deben reportarse
- Importancias de features deben estar en la salida
- Modelos guardados deben incluir scaler y columnas
