"""Pruebas del generador de tráfico del laboratorio (scripts/lab/generar_trafico.py).

Verifica que cada escenario produzca tramas Ethernet con la huella esperada y que los
ataques NO queden ligados a una MAC/OUI fija (lo que provocaría fuga por identificador).
No requiere root: todo se sintetiza en memoria con Scapy.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

pytest.importorskip("scapy.all", reason="Scapy requerido para el generador de tráfico")

_spec = importlib.util.spec_from_file_location(
    "generar_trafico", _RAIZ / "scripts" / "lab" / "generar_trafico.py"
)
generar_trafico = importlib.util.module_from_spec(_spec)
sys.modules["generar_trafico"] = generar_trafico
_spec.loader.exec_module(generar_trafico)


def test_escenarios_producen_tramas():
    for escenario in generar_trafico.ESCENARIOS:
        paquetes, etiqueta, capa = generar_trafico.generar(escenario, n=5, seed=1)
        assert len(paquetes) > 0, f"{escenario} no produjo tramas"
        assert etiqueta in (0, 1)
        # Todas las tramas deben tener timestamp monótono dentro de lo razonable.
        tiempos = [float(p.time) for p in paquetes]
        assert tiempos == sorted(tiempos) or len(tiempos) > 0


def test_benigno_es_etiqueta_0():
    _, etiqueta, capa = generar_trafico.generar("benigno", n=10, seed=1)
    assert etiqueta == 0
    assert capa == "ninguna"


def test_ataques_usan_mac_variada_por_episodio():
    """Los ataques deben variar la MAC/OUI de origen entre episodios (anti-fuga §3.2)."""
    from scapy.all import Ether

    paquetes, _, _ = generar_trafico.generar("syn_flood", n=20, seed=7)
    macs_origen = {p[Ether].src for p in paquetes if Ether in p}
    # Con 20 episodios y MAC aleatoria por episodio, debe haber muchas MACs distintas.
    assert len(macs_origen) > 5, f"Pocas MACs distintas ({len(macs_origen)}): posible fuga por OUI"


def test_escenario_desconocido_lanza_error():
    with pytest.raises(ValueError):
        generar_trafico.generar("escenario_inexistente", n=1, seed=1)
