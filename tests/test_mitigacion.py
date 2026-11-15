"""Pruebas de la mitigación (E6, OE3): escalado, dry-run y ejecución explícita."""
from __future__ import annotations

from src.mitigacion import GestorMitigacion, NivelRespuesta, PoliticaMitigacion

MAC = "02:ff:00:00:00:99"


def _gestor(**kw) -> GestorMitigacion:
    return GestorMitigacion(politica=PoliticaMitigacion(umbral_bloqueo=3, umbral_cuarentena=6, ventana_s=60), **kw)


def test_una_alerta_es_solo_alerta():
    g = _gestor()
    assert g.procesar_alerta(MAC, ts_s=0.0) == NivelRespuesta.ALERTA
    assert not g.bloqueados


def test_tres_alertas_bloquean():
    g = _gestor()
    niveles = [g.procesar_alerta(MAC, ts_s=float(i)) for i in range(3)]
    assert niveles[-1] == NivelRespuesta.BLOQUEO and MAC in g.bloqueados


def test_persistir_tras_el_bloqueo_lleva_a_cuarentena():
    g = _gestor()
    for i in range(6):
        g.procesar_alerta(MAC, ts_s=float(i))
    assert MAC in g.cuarentena and g.procesar_alerta(MAC, ts_s=7.0) == NivelRespuesta.CUARENTENA


def test_dry_run_no_ejecuta_y_registra_el_comando():
    g = _gestor()  # sin ejecutor -> dry-run
    for i in range(3):
        g.procesar_alerta(MAC, ts_s=float(i))
    assert g.modo == "dry_run"
    bloqueo = [a for a in g.acciones if a["accion"] == "bloqueo"][0]
    assert bloqueo["comando"] == ["ebtables", "-A", "FORWARD", "-s", MAC, "-j", "DROP"]


def test_modo_laboratorio_ejecuta_el_comando():
    ejecutados = []
    g = _gestor(ejecutor=ejecutados.append)
    for i in range(3):
        g.procesar_alerta(MAC, ts_s=float(i))
    assert g.modo == "laboratorio" and ejecutados[0][0] == "ebtables"


def test_ventana_deslizante_olvida_alertas_viejas():
    g = _gestor()
    g.procesar_alerta(MAC, ts_s=0.0)
    g.procesar_alerta(MAC, ts_s=1.0)
    # la tercera llega 200 s después: las dos primeras ya no cuentan
    assert g.procesar_alerta(MAC, ts_s=200.0) == NivelRespuesta.ALERTA and not g.bloqueados


def test_desbloquear_revierte():
    g = _gestor()
    for i in range(3):
        g.procesar_alerta(MAC, ts_s=float(i))
    g.desbloquear(MAC)
    assert MAC not in g.bloqueados and MAC not in g.cuarentena
    assert any(a["accion"] == "desbloqueo" for a in g.acciones)
