SEGUIR — bloque 1 hecho; sigue el bloque 2 (evaluación completa con configs/anomalias.json).

# Progreso — PEDIDO-ANOMALIAS-1 y después PEDIDO-E3A-1

Bitácora del bucle (`/loop` autodirigido). La primera línea es el semáforo: `SEGUIR` con el
siguiente paso, o `PARAR` con el motivo. Orden: anomalías bloques 1→3, después E3A bloques 1→3.

## Decisiones registradas antes de ver ninguna cifra (anomalías)

- Ajuste solo con `benignas_limpias` de las sesiones de train; la etiqueta no llega al
  modelo (`EtiquetaEnAjusteError` si se pasa la columna).
- Umbral: `umbral_para_objetivo` sobre los puntajes benignos limpios fuera de fold de 3 folds
  internos por sesión. Se calcula con un DataFrame que solo contiene filas benignas limpias,
  así que el dispositivo-día interno se mide sobre el lapso benigno de cada (sesión, MAC).
- Hiperparámetros por defecto o fijados a priori: IF de 200 árboles; LOF con 20 vecinos,
  `novelty=True` y una submuestra de 20 000 filas benignas (por coste); PCA del 95 % de la
  varianza benigna + el mismo IF. NaN → 0 tras escalar.
- Semillas 42–46 y 5 folds, las mismas que E2, para que la comparación con 0,894 sea con el
  mismo reparto.
- Autoencoder: fuera (sin `torch` en el entorno; el pedido lo deja como opcional).
- **Limitación declarada antes de medir:** IF sobre PCA no ve una anomalía que solo se sale
  del rango por el primer componente. El IF satura fuera del rango de entrenamiento y en el
  resto de componentes el punto cae en el centro benigno (caso sintético: 0,46 frente a un
  máximo benigno de 0,62). Figura como xfail estricto en `tests/test_anomalias.py`.
- **Desviación de forma:** la configuración lleva `conjuntos: [sin_capa2, completo]` (lista)
  en vez de un solo `conjunto`, para que una corrida deje los dos en `reports/anomalias.json`
  con claves `modelo/conjunto`. `sin_capa2` es el principal.

## Registro

| Paso | Qué | Commit |
|---|---|---|
| A1 | `src/anomalias.py`, `scripts/evaluar_anomalias.py`, `configs/anomalias.json`, `tests/test_anomalias.py` (12 passed + 1 xfail). Ensayo de tiempos: ≈ 25 s por semilla y modelo | ver `git log` |
