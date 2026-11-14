"""Pruebas de la prueba de robustez del detector (PEDIDO-E4R-1, E4)."""
from __future__ import annotations

import pandas as pd
import pytest

from scripts import evaluar_robustez as er


def _fila(sesion: str, episodio: int, tipo: str, intensidad: str, n_tramas: int, etiqueta: int) -> dict:
    return {"sesion": sesion, "episodio": episodio, "tipo_ataque": tipo, "intensidad": intensidad,
            "n_tramas_ataque": n_tramas, "etiqueta": etiqueta}


# --- Bloque 1: invisibles por construcción ----------------------------------------------

def test_episodio_bajo_k_es_invisible():
    """Todas las ventanas con 1 trama (< K=2): el episodio nunca se etiqueta -> invisible."""
    df = pd.DataFrame([_fila("s0", 0, "normal", "suave", 1, 0), _fila("s0", 0, "normal", "suave", 1, 0)])
    inv = er.episodios_invisibles(df, k=2, tipos={("s0", 0): "arp_spoofing"})
    assert len(inv) == 1 and bool(inv.loc[0, "invisible"])
    assert inv.loc[0, "tipo"] == "arp_spoofing" and inv.loc[0, "max_tramas"] == 1


def test_episodio_con_una_ventana_sobre_k_no_es_invisible():
    df = pd.DataFrame([_fila("s0", 0, "syn_flood", "media", 1, 0), _fila("s0", 0, "syn_flood", "media", 3, 1)])
    inv = er.episodios_invisibles(df, k=2)
    assert len(inv) == 1 and not bool(inv.loc[0, "invisible"]) and inv.loc[0, "max_tramas"] == 3


def test_sin_episodios_de_ataque_tabla_vacia():
    df = pd.DataFrame([_fila("s0", -1, "normal", "", 0, 0)])
    assert er.episodios_invisibles(df, k=2).empty


def test_recall_con_invisibles_baja():
    """1 etiquetable detectado y 1 invisible -> recall etiquetable 1.0, sobre todos 0.5."""
    r = er._recall_con_invisibles(valor=1.0, n_etiquetables=1, n_invisibles=1)
    assert r["recall_etiquetables"] == 1.0 and r["recall_todos"] == 0.5


def test_recall_sin_invisibles_coincide():
    r = er._recall_con_invisibles(valor=0.8, n_etiquetables=10, n_invisibles=0)
    assert r["recall_todos"] == pytest.approx(0.8)


def test_resumen_invisibles_junta_las_dos_cifras():
    resumen_sup = {"episodios": {
        "recall": {"valor": 1.0, "n": 2},
        "por_tipo": {"syn_flood": {"valor": 1.0, "n": 2}},
        "por_intensidad": {"media": {"valor": 1.0, "n": 2}},
    }}
    inv = pd.DataFrame([
        {"sesion": "s0", "episodio": 5, "tipo": "syn_flood", "intensidad": "suave",
         "max_tramas": 1, "ventanas_tocadas": 3, "invisible": True},
    ])
    out = er.resumen_invisibles(resumen_sup, inv)
    assert out["total"]["n_etiquetables"] == 2 and out["total"]["n_invisibles"] == 1
    assert out["total"]["recall_todos"] == pytest.approx(2 / 3)
    assert out["por_tipo"]["syn_flood"]["n_invisibles"] == 1
    # La intensidad suave solo aparece como invisible (0 etiquetables): recall sobre todos = 0.
    assert out["por_intensidad"]["suave"]["recall_todos"] == 0.0


def test_verificar_dataset_rechaza_sha_distinto(monkeypatch, tmp_path):
    ruta = tmp_path / "d.csv"
    ruta.write_text("x\n1\n")
    monkeypatch.setattr(er, "cargar_dataset_estricto", lambda _: pd.DataFrame({"x": [1]}))
    monkeypatch.setattr(er, "sha256_archivo", lambda _: "deadbeef")
    monkeypatch.setattr(er, "ruta_proyecto", lambda p: ruta)
    with pytest.raises(ValueError, match="sha256"):
        er.verificar_dataset({"dataset": str(ruta), "sha256_esperado": "otro"})
