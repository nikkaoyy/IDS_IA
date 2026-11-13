"""El holdout se abre una sola vez (etapa E2, bloque 4); pruebas con rutas temporales."""
from __future__ import annotations

import json

from scripts import evaluar_holdout as eh
from src.data import nombre_sesion
from tests.test_evaluacion import _dataset


def _preparar(tmp_path):
    dev = _dataset(n_sesiones=6, senal=True, semilla=1)
    hold = _dataset(n_sesiones=4, senal=True, semilla=2)
    hold["sesion"] = hold["sesion"].map({nombre_sesion(i): nombre_sesion(20 + i) for i in range(4)})
    dev.to_csv(tmp_path / "dev.csv", index=False)
    hold.to_csv(tmp_path / "hold.csv", index=False)
    cfg = {"dataset": str(tmp_path / "dev.csv"), "modelos": ["random_forest"], "n_folds": 3, "semillas": [1],
           "objetivo_falsas_alarmas_dispositivo_dia": 1.0, "n_bootstrap": 50, "semilla_bootstrap": 0,
           "salida": str(tmp_path / "no_existe.json"),
           "holdout": {"dataset": str(tmp_path / "hold.csv"), "salida": str(tmp_path / "holdout.json"),
                       "sello": str(tmp_path / ".holdout_abierto")}}
    (tmp_path / "cfg.json").write_text(json.dumps(cfg))
    return ["--config", str(tmp_path / "cfg.json")]


def test_segunda_corrida_se_niega_y_no_toca_el_json(tmp_path, capsys):
    args = _preparar(tmp_path)
    assert eh.main(args) == 0
    salida = tmp_path / "holdout.json"
    inf = json.loads(salida.read_text())
    assert inf["dataset_holdout"]["sesiones"] == [nombre_sesion(20 + i) for i in range(4)]
    assert inf["modelos"]["random_forest"]["resumen"]["episodios"]["recall"]["valor"] == 1.0
    assert inf["reapertura"] is None and inf["sello"]["commit"] == json.loads(
        (tmp_path / ".holdout_abierto").read_text())["commit"]
    antes = salida.read_bytes()
    assert eh.main(args) == eh.CODIGO_SELLADO
    assert "NEGADO" in capsys.readouterr().err
    assert salida.read_bytes() == antes
    # La reapertura exige motivo, queda registrada y no se repite.
    assert eh.main(args + ["--romper-holdout-una-vez"]) == eh.CODIGO_SELLADO
    assert eh.main(args + ["--romper-holdout-una-vez", "--motivo", "bug de prueba"]) == 0
    inf = json.loads(salida.read_text())
    assert inf["reapertura"]["motivo"] == "bug de prueba"
    assert json.loads((tmp_path / ".holdout_abierto").read_text())["reaperturas"][0]["motivo"] == "bug de prueba"
    assert eh.main(args + ["--romper-holdout-una-vez", "--motivo", "otra vez"]) == eh.CODIGO_SELLADO


def test_el_holdout_no_admite_sesiones_de_desarrollo(tmp_path):
    args = _preparar(tmp_path)
    hold = _dataset(n_sesiones=2, senal=True)  # sesiones 0 y 1: no reservadas
    hold.to_csv(tmp_path / "hold.csv", index=False)
    try:
        eh.main(args)
    except SystemExit as e:
        assert "no reservadas" in str(e)
    else:
        raise AssertionError("debió rechazar un holdout con sesiones de desarrollo")
