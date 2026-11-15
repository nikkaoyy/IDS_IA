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


# --- Bloque 2: canales y OR -------------------------------------------------------------

def test_canal_or_combina_los_tres_por_episodio():
    tabla = pd.DataFrame([
        {"sesion": "s0", "episodio": 0, "tipo": "syn_flood", "detectado": True},
        {"sesion": "s0", "episodio": 1, "tipo": "arp_spoofing", "detectado": False},
        {"sesion": "s0", "episodio": 2, "tipo": "arp_spoofing", "detectado": False},
    ])
    canales = {
        "por_episodio": {
            "s0#1": {"tipo": "arp_spoofing", "det_identidad": False, "det_vigilante": True},
            "s0#2": {"tipo": "arp_spoofing", "det_identidad": False, "det_vigilante": False},
        },
        "identidad": {"fa_por_dispositivo_dia": 10.0},
        "vigilante": {"fa_por_dispositivo_dia": 2.0},
    }
    sup = {"dispositivos": {"falsas_alarmas_por_dispositivo_dia": {"valor": 0.9}}}
    o = er.canal_or(tabla, canales, {"fa_identidad_e3b_variacion": 826.24}, sup)
    # Supervisado detecta 1/3; el vigilante rescata el episodio 1 -> OR 2/3.
    assert o["recall_supervisado_42"] == pytest.approx(1 / 3)
    assert o["recall_or"] == pytest.approx(2 / 3)
    assert o["extra_recall_or"] == pytest.approx(1 / 3)
    assert o["recall_or_por_tipo"]["arp_spoofing"] == pytest.approx(0.5)
    fa = o["fa_por_dispositivo_dia"]
    assert fa["supervisado"] == 0.9 and fa["vigilante"] == 2.0
    assert fa["or_total_en_estas_sesiones"] == pytest.approx(0.9 + 10.0 + 2.0)


def test_episodios_sesion_mapea_ventanas_y_macs(tmp_path, monkeypatch):
    """El rango de ventanas del episodio sale de ts_us // (5e6), igual que seguir/vigilar."""
    d = tmp_path
    (d / "sesion_000.tramas.csv").write_text(
        "n_trama,ts_us,mac_src,atacante,episodio,tipo,variante,intensidad,capa\n"
        "1,1000000000000,aa:bb,aa:bb,0,syn_flood,x,media,transporte\n"
        "2,1000005000000,aa:bb,aa:bb,0,syn_flood,x,media,transporte\n")
    epis = er._episodios_sesion(d, "sesion_000", 5.0)
    assert set(epis) == {0} and epis[0]["macs"] == {"aa:bb"} and epis[0]["tipo"] == "syn_flood"
    assert epis[0]["idx"] == {200000, 200001}  # 1e12//5e6 y (1e12+5e6·10³)//5e6
