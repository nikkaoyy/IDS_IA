"""Pruebas de la ficha versionable del dataset (etapa E1, reproducibilidad)."""
from __future__ import annotations

import hashlib
import json

import pandas as pd

from scripts.lab import ficha_dataset as fd
from src.data import SEMILLA_BASE_LAB, indice_sesion, nombre_sesion
from src.feature_schema import ETIQUETA


def _csv_minimo(tmp_path):
    df = pd.DataFrame({
        "n_tramas": [3, 5, 8, 2],
        ETIQUETA: [0, 1, 0, 1],
        "sesion": ["sesion_000", "sesion_000", "sesion_001", "sesion_001"],
        "tipo_ataque": ["normal", "arp_spoofing", "normal", "syn_flood"],
        "atacante": ["", "aa", "", "bb"],
        "variante": ["", "respuesta_gateway", "", "mac_fija"],
        "intensidad": ["", "suave", "", "rafaga"],
    })
    ruta = tmp_path / "d.csv"
    df.to_csv(ruta, index=False)
    return ruta


def test_nombre_e_indice_de_sesion_son_inversos():
    assert nombre_sesion(7) == "sesion_007"
    assert indice_sesion(nombre_sesion(123)) == 123
    assert indice_sesion("otra_cosa") is None


def test_ficha_describe_el_csv_y_su_huella(tmp_path):
    ruta = _csv_minimo(tmp_path)
    ficha = fd.construir_ficha(ruta)
    assert ficha["sha256"] == hashlib.sha256(ruta.read_bytes()).hexdigest()
    assert ficha["filas"] == 4 and ficha["sesiones"] == 2
    assert ficha["por_sesion"] == {"sesion_000": 2, "sesion_001": 2}
    assert ficha["por_etiqueta"] == {"0": 2, "1": 2}
    assert ficha["por_tipo_ataque"]["normal"] == 2
    assert ficha["por_intensidad"] == {"rafaga": 1, "suave": 1}
    # Sin sidecar las semillas se deducen del nombre de la sesión.
    assert ficha["semillas"] == {"sesion_000": SEMILLA_BASE_LAB, "sesion_001": SEMILLA_BASE_LAB + 1}
    assert "desconocido" in ficha["comando"]


def test_ficha_usa_el_sidecar_y_escribe_el_json_fechado(tmp_path):
    ruta = _csv_minimo(tmp_path)
    fd.ruta_meta(ruta).write_text(json.dumps({
        "comando": "python scripts/lab/generar_dataset_lab.py --sesiones 2",
        "semillas": {"sesion_000": 1, "sesion_001": 2},
    }))
    assert fd.main([str(ruta), "--salida", str(tmp_path / "rep"), "--fecha", "2026-11-12"]) == 0
    ficha = json.loads((tmp_path / "rep" / "dataset_lab_2026-11-12.json").read_text())
    assert ficha["comando"].endswith("--sesiones 2")
    assert ficha["semillas"] == {"sesion_000": 1, "sesion_001": 2}
