"""
Evaluación honesta del clasificador (etapa E2 del plan; OE2 y OE3, Fase 3 de la metodología).

La unidad que decide no es la ventana: un episodio de ataque perdido y una ventana benigna de
más no pesan igual, y el generador reparte las ventanas de forma muy desigual entre ataques
(`mac_flooding` aporta casi la mitad de las ventanas maliciosas en una sola variante). Por eso:

- el **ataque** se agrega por episodio (`sesion`, `episodio`) y por atacante (`sesion`,
  `atacante`): un episodio está detectado si alguna de sus ventanas etiquetadas da alarma;
- el **benigno** se agrega por dispositivo (`sesion`, `mac`) y se mide en falsas alarmas por
  dispositivo-día observado;
- la vista por ventana (PR-AUC, recall y FPR por ventana) se conserva solo como referencia.

Las ventanas «ambiguas» (con 1..K-1 tramas de ataque, etiquetadas benignas por la regla K de
`scripts/pcap_to_features.py`) no cuentan ni como acierto ni como falsa alarma.

Reparto: `StratifiedGroupKFold` por sesión, estratificado por `tipo_ataque`, siempre después de
`verificar_holdout`. Umbral: validación anidada, se elige en las predicciones fuera de fold de
los pliegues internos (también por sesión) para no superar un objetivo de falsas alarmas por
dispositivo-día. Intervalos: bootstrap percentil al 95 % remuestreando sesiones (métricas por
ventana y por dispositivo) o episodios (recall), con semilla fija.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score
from sklearn.model_selection import StratifiedGroupKFold

from .data import RANDOM_STATE, verificar_holdout
from .feature_schema import COLUMNAS_MODELO, ETIQUETA
from .models import entrenar_random_forest, entrenar_xgboost
from .preprocess import ajustar_escalador, preprocesar
from .ventanas import MAC_EFIMERAS, VENTANA_CORTA_S

SEGUNDOS_POR_DIA = 86_400.0
N_REPLICAS_BOOTSTRAP = 1000
NIVEL_CONFIANZA = 0.95

ENTRENADORES: dict[str, Callable] = {
    "random_forest": entrenar_random_forest,
    "xgboost": entrenar_xgboost,
}


# --------------------------------------------------------------------------- reparto
def repartos_por_sesion(df: pd.DataFrame, n_folds: int, semilla: int) -> list[tuple[np.ndarray, np.ndarray]]:
    """Índices posicionales (train, test) agrupados por sesión y estratificados por tipo.

    Raises:
        HoldoutError: Si `df` contiene sesiones reservadas para el holdout.
    """
    verificar_holdout(df)
    divisor = StratifiedGroupKFold(n_splits=n_folds, shuffle=True, random_state=semilla)
    return list(divisor.split(np.zeros(len(df)), df["tipo_ataque"].astype(str), df["sesion"].astype(str)))


def filas_ambiguas(df: pd.DataFrame) -> pd.Series:
    """Ventanas benignas por la regla K que contienen alguna trama de ataque."""
    return (df["n_tramas_ataque"] > 0) & (df[ETIQUETA] == 0)


def benignas_limpias(df: pd.DataFrame) -> pd.Series:
    """Ventanas benignas sin ninguna trama de ataque: las únicas que generan falsas alarmas."""
    return (df[ETIQUETA] == 0) & (df["n_tramas_ataque"] == 0)


# --------------------------------------------------------------------------- vistas
def tabla_dispositivos(df: pd.DataFrame, alarma: np.ndarray) -> pd.DataFrame:
    """Por dispositivo (`sesion`, `mac`) con ventanas benignas limpias: tiempo observado y alarmas.

    El tiempo observado va de la primera a la última ventana del dispositivo en la sesión, de
    modo que un equipo que aparece una sola vez aporta 5 s y no la sesión entera. La fila de
    MACs efímeras cuenta como un dispositivo más (sus alarmas son del segmento).
    """
    limpias = benignas_limpias(df).to_numpy()
    base = df.loc[:, ["sesion", "mac", "idx_ventana"]].assign(alarma=np.asarray(alarma, dtype=bool))
    span = base.groupby(["sesion", "mac"])["idx_ventana"].agg(["min", "max"])
    lim = base[limpias].groupby(["sesion", "mac"]).agg(ventanas=("alarma", "size"), alarmas=("alarma", "sum"))
    tabla = lim.join(span)
    tabla["segundos"] = (tabla["max"] - tabla["min"] + 1) * VENTANA_CORTA_S
    tabla["efimeras"] = tabla.index.get_level_values("mac") == MAC_EFIMERAS
    return tabla.drop(columns=["min", "max"]).reset_index()


def _moda(serie: pd.Series) -> str:
    valores = serie.astype(str)
    valores = valores[valores != ""]
    return str(valores.mode().iloc[0]) if len(valores) else ""


def tabla_episodios(df: pd.DataFrame, alarma: np.ndarray) -> pd.DataFrame:
    """Por episodio (`sesion`, `episodio`) con ventanas etiquetadas: detección y tiempo.

    El inicio del episodio es la primera ventana con alguna de sus tramas (aunque quede por
    debajo de K); la detección ocurre al cierre de la primera ventana etiquetada con alarma,
    así que `t_deteccion_s` = (ventana de alarma - ventana de inicio + 1) * 5 s.
    """
    base = df.loc[:, ["sesion", "episodio", "idx_ventana", ETIQUETA, "tipo_ataque", "atacante",
                      "intensidad", "variante"]].assign(alarma=np.asarray(alarma, dtype=bool))
    base = base[base["episodio"] >= 0]
    inicio = base.groupby(["sesion", "episodio"])["idx_ventana"].min().rename("idx_inicio")
    etiquetadas = base[base[ETIQUETA] == 1]
    primera = etiquetadas[etiquetadas["alarma"]].groupby(["sesion", "episodio"])["idx_ventana"].min()
    tabla = etiquetadas.groupby(["sesion", "episodio"]).agg(
        tipo=("tipo_ataque", _moda), intensidad=("intensidad", _moda), variante=("variante", _moda),
        atacante=("atacante", _moda), ventanas=("alarma", "size"), alarmas=("alarma", "sum"),
    ).join(inicio).join(primera.rename("idx_deteccion"))
    tabla["detectado"] = tabla["alarmas"] > 0
    tabla["t_deteccion_s"] = (tabla["idx_deteccion"] - tabla["idx_inicio"] + 1) * VENTANA_CORTA_S
    return tabla.drop(columns=["idx_inicio", "idx_deteccion"]).reset_index()


def tabla_atacantes(df: pd.DataFrame, alarma: np.ndarray) -> pd.DataFrame:
    """Por atacante (`sesion`, `atacante`) con ventanas etiquetadas: ¿alguna dio alarma?"""
    base = df.loc[:, ["sesion", "atacante", ETIQUETA]].assign(alarma=np.asarray(alarma, dtype=bool))
    base = base[base[ETIQUETA] == 1]
    tabla = base.groupby(["sesion", "atacante"]).agg(ventanas=("alarma", "size"), alarmas=("alarma", "sum"))
    tabla["detectado"] = tabla["alarmas"] > 0
    return tabla.reset_index()


# --------------------------------------------------------------------------- umbral
def falsas_alarmas_por_dispositivo_dia(df: pd.DataFrame, alarma: np.ndarray) -> float:
    """Alarmas en ventanas benignas limpias por dispositivo-día observado."""
    t = tabla_dispositivos(df, alarma)
    dias = t["segundos"].sum() / SEGUNDOS_POR_DIA
    return float(t["alarmas"].sum() / dias) if dias > 0 else math.nan


def umbral_para_objetivo(df: pd.DataFrame, prob: np.ndarray, objetivo_por_dispositivo_dia: float) -> float:
    """Umbral más bajo que deja como mucho `objetivo × dispositivo-días` falsas alarmas.

    La alarma es `prob > umbral`. Con k alarmas permitidas, el umbral es la probabilidad
    benigna limpia en la posición k (orden descendente): como mucho k quedan por encima.
    """
    limpias = benignas_limpias(df).to_numpy()
    dias = tabla_dispositivos(df, np.zeros(len(df), dtype=bool))["segundos"].sum() / SEGUNDOS_POR_DIA
    permitidas = int(math.floor(objetivo_por_dispositivo_dia * dias))
    benignas = np.sort(np.asarray(prob)[limpias])[::-1]
    if permitidas >= len(benignas):
        return 0.0
    return float(benignas[permitidas])


# --------------------------------------------------------------------------- modelos
def ajustar_modelo(nombre: str, X_tr: pd.DataFrame, y_tr: np.ndarray,  # noqa: N803
                   semilla: int) -> Callable[[pd.DataFrame], np.ndarray]:
    """Pipeline de `src/preprocess.py` (escalador) + modelo; devuelve la función X -> P(malicioso)."""
    escalador = ajustar_escalador(X_tr)
    modelo = ENTRENADORES[nombre](preprocesar(X_tr, escalador), y_tr, semilla=semilla)
    return lambda X: modelo.predict_proba(preprocesar(X, escalador))[:, 1]  # noqa: N803


def _ajustar_y_predecir(nombre: str, X_tr: pd.DataFrame, y_tr: np.ndarray, X_te: pd.DataFrame,  # noqa: N803
                        semilla: int) -> np.ndarray:
    """Ajusta en train y devuelve P(malicioso) en test."""
    return ajustar_modelo(nombre, X_tr, y_tr, semilla)(X_te)


@dataclass
class PrediccionesFueraDeFold:
    """Probabilidad y alarma de cada fila, predichas por el fold que la dejó fuera.

    `alarma` corresponde al objetivo principal (el primero); `alarmas_por_objetivo` guarda
    la alarma de cada objetivo de falsas alarmas evaluado, con umbrales elegidos igual.
    """

    prob: np.ndarray
    alarma: np.ndarray
    folds: list[dict] = field(default_factory=list)
    alarmas_por_objetivo: dict[float, np.ndarray] = field(default_factory=dict)


def predecir_fuera_de_fold(
    df: pd.DataFrame,
    nombre_modelo: str,
    semilla: int,
    n_folds: int,
    n_folds_internos: int,
    objetivo_por_dispositivo_dia: float | Sequence[float],
    columnas: Sequence[str] = COLUMNAS_MODELO,
    excluir_de_entrenamiento: pd.Series | None = None,
) -> PrediccionesFueraDeFold:
    """Validación anidada: umbral elegido dentro de cada fold externo, aplicado a su test.

    Con varios objetivos de falsas alarmas, cada uno recibe su propio umbral a partir de las
    mismas predicciones internas; el primero es el principal. `excluir_de_entrenamiento`
    (máscara booleana) quita filas del entrenamiento sin quitarlas del test: es lo que usa
    leave-one-attack-out.
    """
    objetivos = [float(o) for o in np.atleast_1d(objetivo_por_dispositivo_dia)]
    X = df[list(columnas)]  # noqa: N806
    y = df[ETIQUETA].to_numpy()
    excluir = np.zeros(len(df), dtype=bool) if excluir_de_entrenamiento is None else excluir_de_entrenamiento.to_numpy()
    prob = np.full(len(df), np.nan)
    alarmas = {o: np.zeros(len(df), dtype=bool) for o in objetivos}
    folds: list[dict] = []
    for k, (idx_tr, idx_te) in enumerate(repartos_por_sesion(df, n_folds, semilla)):
        idx_tr = idx_tr[~excluir[idx_tr]]
        interno = df.iloc[idx_tr]
        prob_interna = np.full(len(idx_tr), np.nan)
        for jdx_tr, jdx_te in repartos_por_sesion(interno, n_folds_internos, semilla):
            prob_interna[jdx_te] = _ajustar_y_predecir(
                nombre_modelo, X.iloc[idx_tr[jdx_tr]], y[idx_tr[jdx_tr]], X.iloc[idx_tr[jdx_te]], semilla)
        umbrales = {o: umbral_para_objetivo(interno, prob_interna, o) for o in objetivos}
        prob[idx_te] = _ajustar_y_predecir(nombre_modelo, X.iloc[idx_tr], y[idx_tr], X.iloc[idx_te], semilla)
        for o, umbral in umbrales.items():
            alarmas[o][idx_te] = prob[idx_te] > umbral
        folds.append({
            "fold": k,
            "umbral": umbrales[objetivos[0]],
            "umbrales_por_objetivo": {str(o): u for o, u in umbrales.items()},
            "falsas_alarmas_dispositivo_dia_interna": falsas_alarmas_por_dispositivo_dia(
                interno, prob_interna > umbrales[objetivos[0]]),
            "sesiones_train": sorted(interno["sesion"].astype(str).unique()),
            "sesiones_test": sorted(df["sesion"].iloc[idx_te].astype(str).unique()),
        })
    return PrediccionesFueraDeFold(prob, alarmas[objetivos[0]], folds, alarmas)


# --------------------------------------------------------------------------- bootstrap
def _percentiles(muestras: np.ndarray) -> list[float]:
    alfa = (1 - NIVEL_CONFIANZA) / 2
    validas = muestras[~np.isnan(muestras)]
    if not len(validas):
        return [math.nan, math.nan]
    return [float(np.quantile(validas, alfa)), float(np.quantile(validas, 1 - alfa))]


def pesos_bootstrap(n: int, n_replicas: int, semilla: int) -> np.ndarray:
    """Matriz (réplicas × unidades) con cuántas veces entra cada unidad en cada réplica."""
    rng = np.random.default_rng(semilla)
    return rng.multinomial(n, np.full(n, 1 / n), size=n_replicas)


def ic_razon_por_sesion(numerador: np.ndarray, denominador: np.ndarray, n_replicas: int = N_REPLICAS_BOOTSTRAP,
                        semilla: int = RANDOM_STATE) -> dict:
    """Razón Σnum/Σden con IC remuestreando sesiones; admite varias semillas de modelo.

    `numerador` y `denominador` son (semillas × sesiones); la estimación es la media entre
    semillas de la razón, y cada réplica remuestrea las mismas sesiones en todas las semillas.
    """
    num, den = np.atleast_2d(numerador).astype(float), np.atleast_2d(denominador).astype(float)
    with np.errstate(invalid="ignore", divide="ignore"):
        punto = float(np.mean(num.sum(axis=1) / den.sum(axis=1)))
        w = pesos_bootstrap(num.shape[1], n_replicas, semilla)
        replicas = np.mean((w @ num.T) / (w @ den.T), axis=1)
    return {"valor": punto, "ic95": _percentiles(replicas)}


def ic_media_por_unidad(valores: np.ndarray, n_replicas: int = N_REPLICAS_BOOTSTRAP,
                        semilla: int = RANDOM_STATE) -> dict:
    """Media de una cantidad por unidad (episodio, atacante) con IC remuestreando unidades."""
    v = np.asarray(valores, dtype=float)
    if not len(v):
        return {"valor": math.nan, "ic95": [math.nan, math.nan], "n": 0}
    w = pesos_bootstrap(len(v), n_replicas, semilla)
    return {"valor": float(v.mean()), "ic95": _percentiles(w @ v / len(v)), "n": int(len(v))}


def ic_mediana_por_unidad(valores_por_unidad: list[np.ndarray], n_replicas: int = N_REPLICAS_BOOTSTRAP,
                          semilla: int = RANDOM_STATE, cuantil: float = 0.5) -> dict:
    """Cuantil de valores agrupados por unidad (p. ej. tiempos por episodio y semilla)."""
    unidades = [np.asarray(v, dtype=float) for v in valores_por_unidad if len(v)]
    if not unidades:
        return {"valor": math.nan, "ic95": [math.nan, math.nan], "n": 0}
    rng = np.random.default_rng(semilla)
    punto = float(np.quantile(np.concatenate(unidades), cuantil))
    replicas = np.array([
        np.quantile(np.concatenate([unidades[i] for i in rng.integers(0, len(unidades), len(unidades))]), cuantil)
        for _ in range(n_replicas)
    ])
    return {"valor": punto, "ic95": _percentiles(replicas), "n": len(unidades)}


def ic_pr_auc_por_sesion(df: pd.DataFrame, probs: list[np.ndarray], n_replicas: int = N_REPLICAS_BOOTSTRAP,
                         semilla: int = RANDOM_STATE) -> dict:
    """PR-AUC por ventana (sin ambiguas) con IC remuestreando sesiones mediante pesos."""
    validas = ~filas_ambiguas(df).to_numpy()
    y = df[ETIQUETA].to_numpy()[validas]
    sesiones = df["sesion"].astype(str).to_numpy()[validas]
    codigos, unicas = pd.factorize(sesiones)
    punto = float(np.mean([average_precision_score(y, p[validas]) for p in probs]))
    w = pesos_bootstrap(len(unicas), n_replicas, semilla)
    ordenes = [_orden_pr(p[validas]) for p in probs]
    replicas = []
    for fila in w:
        peso = fila[codigos]
        if peso[y == 1].sum() == 0:
            replicas.append(math.nan)
            continue
        replicas.append(np.mean([_pr_auc_ponderada(y, peso, *o) for o in ordenes]))
    return {"valor": punto, "ic95": _percentiles(np.array(replicas))}


def _orden_pr(prob: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Orden descendente y último índice de cada valor distinto (umbrales de la curva PR)."""
    orden = np.argsort(prob, kind="mergesort")[::-1]
    p = prob[orden]
    return orden, np.r_[np.flatnonzero(np.diff(p)), len(p) - 1]


def _pr_auc_ponderada(y: np.ndarray, peso: np.ndarray, orden: np.ndarray, cortes: np.ndarray) -> float:
    """`average_precision_score(y, prob, sample_weight=peso)` con el orden ya calculado.

    Misma definición que sklearn (suma escalonada de precisión × Δrecall sobre los umbrales
    distintos); evita reordenar en cada réplica del bootstrap.
    """
    w, yo = peso[orden].astype(float), y[orden]
    tp = np.cumsum(w * yo)[cortes]
    fp = np.cumsum(w * (1 - yo))[cortes]
    precision = np.divide(tp, tp + fp, out=np.zeros_like(tp), where=(tp + fp) > 0)
    recall = tp / tp[-1]
    return float(np.sum(np.diff(np.r_[0.0, recall]) * precision))


# --------------------------------------------------------------------------- resumen
def _por_sesion(df: pd.DataFrame, valores: np.ndarray, sesiones: list[str]) -> np.ndarray:
    return pd.Series(valores).groupby(df["sesion"].astype(str).to_numpy()).sum().reindex(sesiones, fill_value=0).to_numpy()


def resumir(df: pd.DataFrame, predicciones: list[PrediccionesFueraDeFold], n_replicas: int = N_REPLICAS_BOOTSTRAP,
            semilla: int = RANDOM_STATE) -> dict:
    """Métricas con IC al 95 % a partir de las predicciones fuera de fold de varias semillas."""
    sesiones = sorted(df["sesion"].astype(str).unique())
    y = df[ETIQUETA].to_numpy()
    limpias = benignas_limpias(df).to_numpy()
    alarmas = [p.alarma for p in predicciones]

    # Vista por dispositivo (decide para el benigno).
    disp = [tabla_dispositivos(df, a) for a in alarmas]
    num_fa = np.array([t.groupby("sesion")["alarmas"].sum().reindex(sesiones, fill_value=0) for t in disp])
    dias = np.array([t.groupby("sesion")["segundos"].sum().reindex(sesiones, fill_value=0) / SEGUNDOS_POR_DIA for t in disp])
    con_alarma = np.array([(t.assign(a=t["alarmas"] > 0).groupby("sesion")["a"].sum()).reindex(sesiones, fill_value=0) for t in disp])
    n_disp = np.array([t.groupby("sesion").size().reindex(sesiones, fill_value=0) for t in disp])

    # Vista por episodio y por atacante (decide para el ataque).
    epis = [tabla_episodios(df, a) for a in alarmas]
    base = epis[0][["sesion", "episodio", "tipo", "intensidad", "variante"]]
    detectado = np.mean([e["detectado"].to_numpy() for e in epis], axis=0)
    tiempos = [np.array([e.loc[i, "t_deteccion_s"] for e in epis if e.loc[i, "detectado"]]) for i in range(len(base))]
    atac = [tabla_atacantes(df, a) for a in alarmas]
    det_atac = np.mean([t["detectado"].to_numpy() for t in atac], axis=0)

    def recall_episodios(mascara: np.ndarray) -> dict:
        return ic_media_por_unidad(detectado[mascara], n_replicas, semilla)

    resumen: dict = {
        "episodios": {
            "recall": recall_episodios(np.ones(len(base), dtype=bool)),
            "por_tipo": {t: recall_episodios((base["tipo"] == t).to_numpy()) for t in sorted(base["tipo"].unique())},
            "por_intensidad": {i: recall_episodios((base["intensidad"] == i).to_numpy())
                               for i in sorted(base["intensidad"].unique())},
            "por_tipo_e_intensidad": {
                f"{t}/{i}": recall_episodios(((base["tipo"] == t) & (base["intensidad"] == i)).to_numpy())
                for t, i in sorted(set(zip(base["tipo"], base["intensidad"])))
            },
            "tiempo_deteccion_s_mediana": ic_mediana_por_unidad(tiempos, n_replicas, semilla),
            "tiempo_deteccion_s_p90": ic_mediana_por_unidad(tiempos, n_replicas, semilla, cuantil=0.9),
            "tiempo_deteccion_s_mediana_por_tipo": {
                t: ic_mediana_por_unidad([tiempos[i] for i in np.flatnonzero(base["tipo"] == t)], n_replicas, semilla)
                for t in sorted(base["tipo"].unique())
            },
        },
        "atacantes": {"recall": ic_media_por_unidad(det_atac, n_replicas, semilla)},
        "dispositivos": {
            "falsas_alarmas_por_dispositivo_dia": ic_razon_por_sesion(num_fa, dias, n_replicas, semilla),
            "fraccion_con_alguna_alarma": ic_razon_por_sesion(con_alarma, n_disp, n_replicas, semilla),
            "dispositivos": int(n_disp[0].sum()),
            "dispositivo_dias": float(dias[0].sum()),
        },
        "ventanas_referencia": {
            "pr_auc": ic_pr_auc_por_sesion(df, [p.prob for p in predicciones], n_replicas, semilla),
            "recall": ic_razon_por_sesion(
                np.array([_por_sesion(df, a & (y == 1), sesiones) for a in alarmas]),
                np.array([_por_sesion(df, y == 1, sesiones)] * len(alarmas)), n_replicas, semilla),
            "fpr": ic_razon_por_sesion(
                np.array([_por_sesion(df, a & limpias, sesiones) for a in alarmas]),
                np.array([_por_sesion(df, limpias, sesiones)] * len(alarmas)), n_replicas, semilla),
            "recall_por_tipo": {
                t: float(np.mean([a[(df["tipo_ataque"] == t).to_numpy()].mean() for a in alarmas]))
                for t in sorted(df.loc[df[ETIQUETA] == 1, "tipo_ataque"].unique())
            },
        },
        "conteos": {
            "sesiones": len(sesiones),
            "episodios": int(len(base)),
            "atacantes": int(len(atac[0])),
            "ventanas": int(len(df)),
            "ventanas_maliciosas": int((y == 1).sum()),
            "ventanas_benignas_limpias": int(limpias.sum()),
            "ventanas_ambiguas": int(filas_ambiguas(df).sum()),
        },
    }
    return resumen
