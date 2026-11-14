"""Prueba de humo de `scripts/ablaciones.py` (etapa E2, bloque 3)."""
from __future__ import annotations

import json

import numpy as np

from scripts import ablaciones
from tests.test_evaluacion import _dataset


def test_ablaciones_escribe_las_cuatro_partes(tmp_path):
    df = _dataset(n_sesiones=8, senal=True)
    df["capa"] = df["tipo_ataque"].map({"arp_spoofing": "enlace", "syn_flood": "transporte",
                                        "icmp_flood": "red"}).fillna("ninguna")
    ruta_csv = tmp_path / "mini.csv"
    df.to_csv(ruta_csv, index=False)
    salida = tmp_path / "abl.json"
    cfg = {"dataset": str(ruta_csv), "n_folds": 4, "n_folds_internos": 2,
           "objetivo_falsas_alarmas_dispositivo_dia": 1.0, "n_bootstrap": 50, "semilla_bootstrap": 0,
           "ablaciones": {"modelos": ["random_forest"], "semillas": [1], "repeticiones_permutacion": 1,
                          "salida": str(salida)}}
    (tmp_path / "cfg.json").write_text(json.dumps(cfg))
    assert ablaciones.main(["--config", str(tmp_path / "cfg.json")]) == 0
    inf = json.loads(salida.read_text())
    rf = inf["ablacion"]["random_forest"]
    assert set(rf) == {"capa2", "capas3_4", "completo"}
    # La señal está en n_syn (capas 3-4): sin ella, la capa 2 no detecta nada útil.
    assert rf["completo"]["recall_episodios"]["valor"] == 1.0
    assert rf["capas3_4"]["recall_episodios"]["valor"] == 1.0
    loao = inf["loao"]["random_forest"]
    assert set(loao) == {"arp_spoofing", "syn_flood", "icmp_flood"}
    media = inf["loao"]["media_seis"]["random_forest"]["recall_episodios_excluido"]
    assert media["valor"] == 1.0 and media["tipos"] == 3
    # La señal sintética es la misma para todos los tipos: excluir uno no lo vuelve invisible.
    assert all(v["recall_episodios_excluido"]["valor"] == 1.0 for v in loao.values())
    assert inf["multiclase"]["tipo_ataque"]["clases"][-1] == "syn_flood"
    perm = inf["permutacion"]["random_forest"]
    assert next(iter(perm["familias"])) == "tcp"
    assert next(iter(perm["caracteristicas"])) == "n_syn"
    assert "Leave-one-attack-out" in salida.with_suffix(".md").read_text()


def test_tipo_de_episodio_cubre_las_ventanas_ambiguas():
    df = _dataset(n_sesiones=1)
    tipos = ablaciones.tipo_de_episodio(df)
    ambiguas = (df["n_tramas_ataque"] > 0) & (df["etiqueta"] == 0)
    assert (tipos[ambiguas] != "").all() and (df.loc[ambiguas, "tipo_ataque"] == "normal").all()
    assert (tipos[df["episodio"] < 0] == "").all()


def test_media_de_tipos_promedia_tipos_y_no_episodios():
    det = {"a": np.ones(30), "b": np.zeros(2)}
    m = ablaciones.media_de_tipos(det, n_replicas=200, semilla=0)
    assert m["valor"] == 0.5 and m["ic95"] == [0.5, 0.5]
    m = ablaciones.media_de_tipos({"a": np.array([0.0, 1.0] * 10)}, n_replicas=500, semilla=0)
    assert m["ic95"][0] < 0.5 < m["ic95"][1]


def test_el_conjunto_sin_capa2_no_tiene_capa2():
    from src.feature_schema import COLUMNAS_MODELO, FEATURES_CAPA2
    cols = ablaciones.CONJUNTOS_LOAO["sin_capa2"]
    assert not set(cols) & set(FEATURES_CAPA2) and len(cols) == len(COLUMNAS_MODELO) - len(FEATURES_CAPA2)
