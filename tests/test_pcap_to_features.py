"""Pruebas de etiquetado por manifiesto (scripts/pcap_to_features.py)."""
from __future__ import annotations

import pandas as pd
import pytest

pytest.importorskip("scapy.all")

from scripts import pcap_to_features as p2f  # noqa: E402
from src.feature_schema import COLUMNAS_MODELO, ETIQUETA  # noqa: E402
from src.ventanas import MAC_EFIMERAS  # noqa: E402


def _manifiesto(filas: list[tuple[int, str]]) -> pd.DataFrame:
    return pd.DataFrame([
        {"ts_us": ts, "mac_src": mac, "atacante": "x", "episodio": 3, "tipo": "syn_flood", "capa": "transporte"}
        for ts, mac in filas
    ])


def _filas() -> pd.DataFrame:
    return pd.DataFrame({"mac": ["a", "b", MAC_EFIMERAS], "idx_ventana": [0, 0, 1], "t0_us": 0})


def test_k_separa_ventanas_y_conserva_el_conteo():
    df = p2f.etiquetar_ventanas(_filas(), _manifiesto([(1, "a"), (2, "a"), (3, "b")]), k=2)
    assert df[ETIQUETA].tolist() == [1, 0, 0]
    assert df["tipo_ataque"].tolist() == ["syn_flood", "normal", "normal"]
    assert df["n_tramas_ataque"].tolist() == [2, 1, 0]


def test_tramas_de_macs_efimeras_van_a_su_fila():
    df = p2f.etiquetar_ventanas(_filas(), _manifiesto([(5_000_001, "z"), (5_000_002, "y")]), k=2)
    assert df[ETIQUETA].tolist() == [0, 0, 1]


def test_variante_e_intensidad_son_aditivas():
    """E1: las filas heredan variante e intensidad del episodio; sin ellas, quedan vacías."""
    viejo = p2f.etiquetar_ventanas(_filas(), _manifiesto([(1, "a"), (2, "a")]), k=2)
    assert viejo["variante"].tolist() == ["", "", ""] and viejo["intensidad"].tolist() == ["", "", ""]
    m = _manifiesto([(1, "a"), (2, "a"), (3, "b")]).assign(variante="ip_propia", intensidad="suave")
    df = p2f.etiquetar_ventanas(_filas(), m, k=2)
    assert df.loc[0, ["variante", "intensidad"]].tolist() == ["ip_propia", "suave"]
    # Por debajo de K la fila es benigna, pero conserva el episodio para recalcular K.
    assert df.loc[1, "tipo_ataque"] == "normal" and df.loc[1, "intensidad"] == "suave"


def test_trama_de_ataque_sin_fila_es_error():
    with pytest.raises(ValueError, match="sin fila"):
        p2f.etiquetar_ventanas(_filas(), _manifiesto([(99_000_000, "a")]))


def test_procesar_sesion_cumple_contrato(sesion_corta):
    sesion, ruta = sesion_corta
    df = p2f.procesar_sesion(ruta, "s")
    assert set(COLUMNAS_MODELO + [ETIQUETA, "sesion", "n_tramas_ataque", "variante", "intensidad"]) <= set(df.columns)
    assert (df.loc[df[ETIQUETA] == 1, "intensidad"] != "").all()
    assert df[ETIQUETA].nunique() == 2
    ataque = sum(m is not None for _, _, m in sesion.tramas)
    assert df["n_tramas_ataque"].sum() == ataque
    assert (df.loc[df[ETIQUETA] == 1, "n_tramas_ataque"] >= p2f.K_TRAMAS_ATAQUE).all()


def test_pcap_inexistente_lanza_error():
    with pytest.raises(FileNotFoundError):
        p2f.procesar_sesion("no_existe.pcap", "s")
