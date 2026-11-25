#!/usr/bin/env python3
"""
Persistencia de las cifras de E6 (OE3: mitigación y pronóstico; Fig. 1, bloques de respuesta).

`docs/INFORME_E7.md` cita para E6 que la mitigación escala a BLOQUEO en dry-run y que el
pronóstico Holt marca tendencia creciente y da aviso temprano (y `doc_proyecto/` añade el
backtesting MAE < 1 sobre una recta). Esas salidas salían de las demos del cuaderno de cierre y
no estaban en `reports/`. Este script repite **exactamente** esas demos, sin red, sin datos y sin
corpus (deterministas), y las escribe en JSON.

No es una medición sobre tráfico: son demostraciones del módulo con entradas de juguete
(cuatro alertas de una MAC; la serie [0, 0, 1, 1, 2, 3, 4, 6, 8]; la recta 0..29).

Uso:
    python scripts/demo_e6.py [--salida reports/mitigacion_pronostico_e6.json]
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np

_RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_RAIZ))

from src.mitigacion import GestorMitigacion, PoliticaMitigacion  # noqa: E402
from src.pronostico import PronosticadorAnomalias  # noqa: E402

MAC_DEMO = "02:ff:00:00:00:99"
SERIE_DEMO = [0, 0, 1, 1, 2, 3, 4, 6, 8]
UMBRAL_AVISO = 10.0


def demo_mitigacion() -> dict:
    """Cuatro alertas seguidas de una MAC con umbral de bloqueo 3 (celda del cuaderno de cierre)."""
    gestor = GestorMitigacion(politica=PoliticaMitigacion(umbral_bloqueo=3, ventana_s=60))
    nivel = None
    for i in range(4):
        nivel = gestor.procesar_alerta(MAC_DEMO, ts_s=float(i), score=0.9)
    return {
        "entrada": {"mac": MAC_DEMO, "n_alertas": 4, "umbral_bloqueo": 3, "ventana_s": 60},
        "modo": gestor.modo,
        "ultimo_nivel": nivel.name,
        "acciones": [a["accion"] for a in gestor.acciones],
        "comandos": [" ".join(a["comando"]) if a["comando"] else None for a in gestor.acciones],
        "ejecutado": False,
        "resumen": gestor.resumen(),
    }


def demo_pronostico() -> dict:
    """Holt sobre la serie de juguete creciente y backtesting sobre una recta."""
    pron = PronosticadorAnomalias(metodo="holt").entrenar(np.array(SERIE_DEMO, dtype=float))
    aviso = pron.aviso_temprano(umbral=UMBRAL_AVISO)
    back = PronosticadorAnomalias(metodo="holt").backtesting(np.arange(0, 30, dtype=float), 0.8)
    return {
        "serie": SERIE_DEMO,
        "metodo": "holt",
        "tendencia": pron.tendencia,
        "pronostico_3_pasos": [round(float(x), 3) for x in pron.pronosticar(3)],
        "aviso_temprano": aviso,
        "backtesting_recta_0_29": back,
    }


def main() -> None:
    """Corre las dos demos y escribe el JSON."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--salida", type=Path, default=_RAIZ / "reports" / "mitigacion_pronostico_e6.json")
    args = ap.parse_args()
    logging.basicConfig(level=logging.ERROR)
    resultado = {
        "etapa": "E6",
        "procedencia": ("scripts/demo_e6.py; demostración determinista del módulo con entradas de "
                        "juguete, sin red ni datos; no es una medición sobre tráfico"),
        "mitigacion": demo_mitigacion(),
        "pronostico": demo_pronostico(),
    }
    args.salida.parent.mkdir(parents=True, exist_ok=True)
    args.salida.write_text(json.dumps(resultado, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(resultado, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
