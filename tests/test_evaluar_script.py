"""Prueba de humo de `scripts/evaluar.py` sobre un dataset sintético pequeño (etapa E2, bloque 2)."""
from __future__ import annotations

import json

from scripts import evaluar
from tests.test_evaluacion import _dataset


def test_evaluar_escribe_json_y_markdown(tmp_path):
    ruta_csv = tmp_path / "mini.csv"
    _dataset(n_sesiones=8, senal=True).to_csv(ruta_csv, index=False)
    cfg = {
        "dataset": str(ruta_csv), "modelos": ["random_forest", "xgboost"], "n_folds": 4, "semillas": [1, 2],
        "n_folds_internos": 2, "objetivo_falsas_alarmas_dispositivo_dia": 1.0,
        "objetivos_sensibilidad": [1.0, 100.0], "n_bootstrap": 100, "semilla_bootstrap": 0,
        "salida": str(tmp_path / "eval.json"),
    }
    ruta_cfg = tmp_path / "cfg.json"
    ruta_cfg.write_text(json.dumps(cfg))
    assert evaluar.main(["--config", str(ruta_cfg)]) == 0
    informe = json.loads((tmp_path / "eval.json").read_text())
    assert set(informe["modelos"]) == {"random_forest", "xgboost"}
    for datos in informe["modelos"].values():
        r = datos["resumen"]
        assert r["episodios"]["recall"]["valor"] == 1.0
        assert {"pr_auc", "recall", "fpr", "recall_por_tipo"} <= set(r["ventanas_referencia"])
        assert set(r["sensibilidad_al_objetivo"]) == {"1.0", "100.0"}
        # Semilla y partición registradas.
        assert [c["semilla"] for c in datos["corridas"]] == [1, 2]
        assert all(len(c["folds"]) == 4 and c["folds"][0]["sesiones_test"] for c in datos["corridas"])
    assert informe["dataset"]["sha256"] and len(informe["dataset"]["sha256"]) == 64
    md = (tmp_path / "eval.md").read_text()
    assert "Recall por episodio" in md and "xgboost" in md
