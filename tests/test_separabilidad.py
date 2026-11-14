"""Puerta automática de separabilidad (etapa E1, bloque 4).

Si un stump o un árbol de profundidad 2 separa un ataque con exactitud balanceada mayor
que `UMBRAL_PUERTA` en algún fold por sesión, el generador volvió a ser trivial y la
prueba falla. Corre sobre una muestra (todo el ataque y el 25 % del benigno por sesión;
mismo veredicto que el dataset completo, unos 3 s). Sin `data/dataset_lab.csv` la parte
que lo usa se salta con su motivo. Los ataques de `DESVIACIONES_DECLARADAS` no alcanzan
la puerta y figuran como xfail estricto.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from scripts.baseline_reglas import (
    UMBRAL_PUERTA,
    calcular_baseline,
    muestra_para_puerta,
    resumen_puerta,
)
from src.data import RUTA_DATASET_LAB, generar_dataset_sintetico
from src.feature_schema import ETIQUETA

ATAQUES = ["arp_spoofing", "dns_spoofing", "icmp_flood", "mac_flooding", "port_scan", "syn_flood"]

# Desviaciones declaradas en docs/INFORME_E1.md (dataset sha256 3f4d28bc…eced, exactitud
# balanceada máxima en 4 folds sobre el dataset completo). Son fallos conocidos, no
# aceptados: `strict=True` hace que la prueba falle en cuanto el ataque cumpla, para que
# la declaración se retire. Un ataque que no está aquí tiene que cumplir la puerta.
DESVIACIONES_DECLARADAS: dict[str, str] = {
    "arp_spoofing": "0.977: arp_cambios_vinculo_60s > 0 delata todo envenenamiento (FPR 0.047)",
    "dns_spoofing": "0.979: dns_respuestas >= 2 desde una fila que no es servidor (FPR 0.042)",
    # Esquema 3.0 (PEDIDO-EXTRACTOR-1, it. 1; dataset sha256 7f06d099…a945): la causa es el
    # extractor, no el generador, que sigue congelado. Ver PROGRESO-EXTRACTOR.md.
    "icmp_flood": "0.974: respuestas_no_solicitadas > 1, echo reply y errores ICMP sin petición (FPR 0.052)",
    "mac_flooding": "0.996: MAC falsa con <= 4 tramas en su ventana de 60 s (FPR 0.007)",
    "port_scan": "0.891: entropía de puertos baja con varios puertos distintos (FPR 0.097)",
    "syn_flood": "0.990: SYN medio abiertos acumulados en 60 s (FPR 0.012)",
}


def _con_desviaciones(ataques: list[str]) -> list:
    return [
        pytest.param(a, marks=pytest.mark.xfail(strict=True, reason=f"desviación declarada E1: {DESVIACIONES_DECLARADAS[a]}"))
        if a in DESVIACIONES_DECLARADAS else a
        for a in ataques
    ]


def _sesiones_sinteticas(etiqueta_separable: bool) -> pd.DataFrame:
    """12 sesiones de 120 ventanas; con `etiqueta_separable`, `n_syn` revela la etiqueta."""
    rng = np.random.default_rng(0)
    df = generar_dataset_sintetico(n=1440, seed=3)
    df[ETIQUETA] = (rng.random(len(df)) < 0.1).astype(int)
    if etiqueta_separable:
        df["n_syn"] = df[ETIQUETA] * 50.0
    return df.assign(
        sesion=[f"sesion_{i % 12:03d}" for i in range(len(df))],
        tipo_ataque=np.where(df[ETIQUETA] == 1, "syn_flood", "normal"),
    )


def test_la_puerta_detecta_un_dataset_trivial():
    resumen = resumen_puerta(calcular_baseline(_sesiones_sinteticas(etiqueta_separable=True)))
    assert resumen["syn_flood"]["exactitud_balanceada_max"] > 0.99
    assert not resumen["syn_flood"]["cumple"]


def test_la_puerta_deja_pasar_etiquetas_sin_senal():
    resumen = resumen_puerta(calcular_baseline(_sesiones_sinteticas(etiqueta_separable=False)))
    assert resumen["syn_flood"]["cumple"]


def test_la_muestra_conserva_todos_los_ataques():
    df = _sesiones_sinteticas(etiqueta_separable=False)
    muestra = muestra_para_puerta(df, 0.25)
    assert muestra[ETIQUETA].sum() == df[ETIQUETA].sum()
    assert (muestra[ETIQUETA] == 0).sum() == pytest.approx(0.25 * (df[ETIQUETA] == 0).sum(), abs=12)


@pytest.fixture(scope="module")
def puerta_dataset() -> dict:
    if not RUTA_DATASET_LAB.exists():
        pytest.skip("data/dataset_lab.csv no generado todavía: la puerta de separabilidad no se puede evaluar")
    df = pd.read_csv(RUTA_DATASET_LAB, low_memory=False)
    return resumen_puerta(calcular_baseline(muestra_para_puerta(df)))


@pytest.mark.parametrize("ataque", _con_desviaciones(ATAQUES))
def test_clasificador_trivial_no_supera_la_puerta(puerta_dataset, ataque):
    assert ataque in puerta_dataset, f"{ataque} no aparece en el dataset"
    v = puerta_dataset[ataque]
    assert v["exactitud_balanceada_max"] <= UMBRAL_PUERTA, (
        f"{ataque}: exactitud balanceada {v['exactitud_balanceada_max']:.3f} > {UMBRAL_PUERTA} "
        f"(profundidad {v['profundidad']}, fold {v['fold']}, regla {v['regla']!r})"
    )
