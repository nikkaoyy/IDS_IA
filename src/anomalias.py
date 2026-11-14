"""
Detector de anomalías entrenado solo con benigno (PEDIDO-ANOMALIAS-1; contraste de OE2/OE3).

Responde a la pregunta que el supervisado no puede contestar: ¿se detecta un ataque sin
haberlo visto nunca? El detector aprende el comportamiento de las ventanas benignas y el
umbral sale del cuantil de sus propios puntajes benignos fuera de fold, con el mismo objetivo
de falsas alarmas por dispositivo-día que E2. **Ningún dato malicioso toca el ajuste ni la
calibración**: el malicioso solo se puntúa en el test para medir.

Decisiones fijadas antes de ver ninguna cifra (no se reajustan después):

- Filas de ajuste: `benignas_limpias` (etiqueta 0 y ninguna trama de ataque) de las sesiones
  de entrenamiento. Las ambiguas y las maliciosas no entran.
- Preprocesado: el escalador de `src/preprocess.py` ajustado con esas filas; los NaN («sin
  dato») pasan a 0 tras escalar, es decir, a la media benigna de entrenamiento.
- Modelos con hiperparámetros por defecto o fijados a priori (sin etiquetas no hay con qué
  elegirlos sin hacer trampa):
  * `isolation_forest` (principal): 200 árboles, `max_samples` por defecto (256).
  * `lof`: `LocalOutlierFactor(n_neighbors=20, novelty=True)` sobre una submuestra benigna de
    como mucho `MAX_FILAS_LOF` filas, por coste (el kNN crece con n²).
  * `isolation_forest_pca`: PCA que retiene el 95 % de la varianza benigna + el mismo IF.
- Puntaje: `-score_samples`, mayor = más anómalo.
- Umbral: `umbral_para_objetivo` de `src/evaluacion.py` sobre los puntajes fuera de fold de
  folds internos por sesión, calculado solo con filas benignas limpias.
- Autoencoder: fuera. El entorno no tiene un framework de redes (no hay `torch` en
  `requirements.txt`) y el pedido lo deja como opcional.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

from .evaluacion import (
    PrediccionesFueraDeFold,
    benignas_limpias,
    falsas_alarmas_por_dispositivo_dia,
    repartos_por_sesion,
    umbral_para_objetivo,
)
from .feature_schema import COLUMNAS_MODELO, ETIQUETA, FEATURES_CAPA2
from .preprocess import ajustar_escalador, preprocesar

MAX_FILAS_LOF: int = 20_000
N_ARBOLES_IF: int = 200
VARIANZA_PCA: float = 0.95
VECINOS_LOF: int = 20

CONJUNTOS: dict[str, list[str]] = {
    "sin_capa2": [c for c in COLUMNAS_MODELO if c not in set(FEATURES_CAPA2)],
    "completo": list(COLUMNAS_MODELO),
}
MODELOS: tuple[str, ...] = ("isolation_forest", "lof", "isolation_forest_pca")


class EtiquetaEnAjusteError(ValueError):
    """Se intentó ajustar el detector con la etiqueta o con filas maliciosas."""


@dataclass
class Detector:
    """Escalador + modelo ajustados solo con benigno; `puntuar(X)` da mayor = más anómalo."""

    nombre: str
    columnas: list[str]
    _escalador: object
    _transformar: Callable[[np.ndarray], np.ndarray]
    _modelo: object

    def puntuar(self, X: pd.DataFrame) -> np.ndarray:  # noqa: N803
        """Puntaje de anomalía por ventana."""
        Z = self._transformar(_escalar(X[self.columnas], self._escalador))  # noqa: N806
        return -self._modelo.score_samples(Z)


def _escalar(X: pd.DataFrame, escalador) -> np.ndarray:  # noqa: N803
    Z = np.asarray(preprocesar(X, escalador), dtype=float)  # noqa: N806
    return np.where(np.isfinite(Z), Z, 0.0)


def ajustar_detector(nombre: str, X_benigno: pd.DataFrame, semilla: int,  # noqa: N803
                     columnas: Sequence[str] | None = None) -> Detector:
    """Ajusta el detector `nombre` con ventanas benignas.

    `X_benigno` solo puede traer características: si trae la columna de etiqueta (aunque
    valga 0) se rechaza, porque la selección de filas benignas corresponde al llamador
    (`filas_de_ajuste`) y la etiqueta no debe llegar al modelo.

    Raises:
        EtiquetaEnAjusteError: Si `X_benigno` contiene la columna de etiqueta.
        KeyError: Si `nombre` no es un modelo conocido.
    """
    if ETIQUETA in X_benigno.columns:
        raise EtiquetaEnAjusteError(
            f"El ajuste del detector no recibe la columna '{ETIQUETA}': pasa solo características "
            "de filas benignas (ver filas_de_ajuste)."
        )
    columnas = list(columnas) if columnas is not None else [c for c in X_benigno.columns]
    X = X_benigno[columnas]  # noqa: N806
    escalador = ajustar_escalador(X)
    Z = _escalar(X, escalador)  # noqa: N806
    transformar: Callable[[np.ndarray], np.ndarray] = lambda z: z  # noqa: E731
    if nombre == "isolation_forest":
        modelo = IsolationForest(n_estimators=N_ARBOLES_IF, random_state=semilla, n_jobs=-1).fit(Z)
    elif nombre == "isolation_forest_pca":
        pca = PCA(n_components=VARIANZA_PCA, svd_solver="full", random_state=semilla).fit(Z)
        transformar = pca.transform
        modelo = IsolationForest(n_estimators=N_ARBOLES_IF, random_state=semilla, n_jobs=-1).fit(pca.transform(Z))
    elif nombre == "lof":
        if len(Z) > MAX_FILAS_LOF:
            Z = Z[np.random.default_rng(semilla).choice(len(Z), MAX_FILAS_LOF, replace=False)]  # noqa: N806
        modelo = LocalOutlierFactor(n_neighbors=VECINOS_LOF, novelty=True, n_jobs=-1).fit(Z)
    else:
        raise KeyError(f"Modelo de anomalías desconocido: {nombre!r}; opciones {MODELOS}")
    return Detector(nombre, columnas, escalador, transformar, modelo)


def filas_de_ajuste(df: pd.DataFrame) -> np.ndarray:
    """Máscara de las únicas filas que pueden entrar al ajuste y al umbral: benignas limpias."""
    return benignas_limpias(df).to_numpy()


def _ajustar_con_benigno(df: pd.DataFrame, idx: np.ndarray, nombre: str, columnas: list[str],
                         semilla: int) -> Detector:
    """Ajusta con las filas benignas limpias de `idx` (posiciones); el resto se descarta aquí."""
    parte = df.iloc[idx]
    return ajustar_detector(nombre, parte.loc[filas_de_ajuste(parte), columnas], semilla, columnas)


def predecir_fuera_de_fold(
    df: pd.DataFrame,
    nombre_modelo: str,
    semilla: int,
    n_folds: int,
    n_folds_internos: int,
    objetivo_por_dispositivo_dia: float,
    columnas: Sequence[str],
) -> PrediccionesFueraDeFold:
    """Puntaje y alarma de cada fila, desde el fold externo que la dejó fuera.

    En cada fold externo: (1) los folds internos por sesión dan puntajes benignos fuera de
    fold, y con ellos `umbral_para_objetivo` fija el umbral, usando solo filas benignas
    limpias; (2) el detector final se ajusta con el benigno limpio de todo el train; (3) se
    puntúa todo el test, benigno y malicioso.
    """
    columnas = list(columnas)
    puntaje = np.full(len(df), np.nan)
    alarma = np.zeros(len(df), dtype=bool)
    folds: list[dict] = []
    for k, (idx_tr, idx_te) in enumerate(repartos_por_sesion(df, n_folds, semilla)):
        interno = df.iloc[idx_tr]
        benigno_interno = filas_de_ajuste(interno)
        puntaje_interno = np.full(len(idx_tr), np.nan)
        for jdx_tr, jdx_te in repartos_por_sesion(interno, n_folds_internos, semilla):
            det = _ajustar_con_benigno(df, idx_tr[jdx_tr], nombre_modelo, columnas, semilla)
            jdx_te_b = jdx_te[benigno_interno[jdx_te]]
            puntaje_interno[jdx_te_b] = det.puntuar(df.iloc[idx_tr[jdx_te_b]])
        solo_benigno = interno[benigno_interno]
        umbral = umbral_para_objetivo(solo_benigno, puntaje_interno[benigno_interno], objetivo_por_dispositivo_dia)
        det = _ajustar_con_benigno(df, idx_tr, nombre_modelo, columnas, semilla)
        puntaje[idx_te] = det.puntuar(df.iloc[idx_te])
        alarma[idx_te] = puntaje[idx_te] > umbral
        test = df.iloc[idx_te]
        folds.append({
            "fold": k,
            "umbral": float(umbral),
            "filas_ajuste": int(filas_de_ajuste(interno).sum()),
            "falsas_alarmas_dispositivo_dia_interna": falsas_alarmas_por_dispositivo_dia(
                solo_benigno, puntaje_interno[benigno_interno] > umbral),
            "falsas_alarmas_dispositivo_dia_test": falsas_alarmas_por_dispositivo_dia(test, alarma[idx_te]),
            "sesiones_train": sorted(interno["sesion"].astype(str).unique()),
            "sesiones_test": sorted(test["sesion"].astype(str).unique()),
        })
    return PrediccionesFueraDeFold(puntaje, alarma, folds, {float(objetivo_por_dispositivo_dia): alarma})
