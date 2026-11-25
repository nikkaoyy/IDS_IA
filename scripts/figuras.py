#!/usr/bin/env python3
"""
Figuras para la exposición (entrega, bloque 4; OE3: evaluación E4R y E5C).

Lee solo los JSON congelados de `reports/` (no reentrena ni genera datos) y escribe dos PNG
en `docs/figuras/`:

- `recall_por_intensidad.png`: recall por episodio del supervisado (XGBoost) por intensidad
  del ataque, con su IC95 (`reports/robustez_e4.json`, E4R).
- `fa_disp_dia.png`: falsas alarmas por dispositivo-día del canal de identidad con variación
  benigna, antes (apariciones) y después de E5C (persistencia exclusiva), con IC95 y la línea
  de presupuesto de 1 FA/disp-día (`reports/adopcion_e5c.json`, E5C).

Uso:
    python scripts/figuras.py [--dir-salida docs/figuras]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

_RAIZ = Path(__file__).resolve().parent.parent
REPORTS: Path = _RAIZ / "reports"
COLOR_SERIE: str = "#2a78d6"   # un solo tono: una sola serie por figura
COLOR_TEXTO: str = "#52514e"
COLOR_PRESUPUESTO: str = "#0b0b0b"
PRESUPUESTO_FA: float = 1.0    # FA/disp-día: el umbral de operación de E2
ETIQUETAS_INTENSIDAD: dict[str, str] = {"media": "media", "suave": "suave", "rafaga": "ráfaga"}
DPI: int = 150


def _coma(x: float, dec: int = 3) -> str:
    return f"{x:.{dec}f}".replace(".", ",")


def _ejes(ax) -> None:
    """Ejes sobrios: sin marco superior/derecho, rejilla horizontal tenue."""
    for lado in ("top", "right"):
        ax.spines[lado].set_visible(False)
    ax.grid(axis="y", color="#e4e3df", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(colors=COLOR_TEXTO)


def figura_recall(dir_salida: Path) -> Path:
    """Barras de recall por intensidad con IC95, desde reports/robustez_e4.json."""
    d = json.loads((REPORTS / "robustez_e4.json").read_text(encoding="utf-8"))
    por_int = d["supervisado"]["resumen"]["episodios"]["por_intensidad"]
    orden = ["media", "suave", "rafaga"]
    valores = [d["resumen"]["recall_por_intensidad"][k] for k in orden]
    ic = [por_int[k]["ic95"] for k in orden]
    n = [por_int[k]["n"] for k in orden]
    err = [[v - lo for v, (lo, _) in zip(valores, ic)], [hi - v for v, (_, hi) in zip(valores, ic)]]

    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    x = range(len(orden))
    ax.bar(x, valores, width=0.55, color=COLOR_SERIE, yerr=err, capsize=4,
           error_kw={"ecolor": COLOR_TEXTO, "elinewidth": 1})
    for xi, v, (_, hi) in zip(x, valores, ic):
        ax.text(xi, hi + 0.02, _coma(v), ha="center", va="bottom", color=COLOR_PRESUPUESTO, fontsize=10)
    ax.set_xticks(list(x), [f"{ETIQUETAS_INTENSIDAD[k]}\n(n = {m} episodios)" for k, m in zip(orden, n)])
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Recall por episodio (XGBoost)")
    ax.set_xlabel("Intensidad del ataque")
    ax.axhline(0.5, color=COLOR_TEXTO, linestyle=":", linewidth=1)
    ax.text(2.42, 0.51, "0,5", color=COLOR_TEXTO, fontsize=8, va="bottom", ha="right")
    _ejes(ax)
    ax.set_title("Recall del supervisado por intensidad (E4R), con IC95\n"
                 "datos de reports/robustez_e4.json, laboratorio sintético", fontsize=10)
    fig.tight_layout()
    ruta = dir_salida / "recall_por_intensidad.png"
    fig.savefig(ruta, dpi=DPI, metadata={"Software": None})
    plt.close(fig)
    return ruta


def figura_fa(dir_salida: Path) -> Path:
    """FA/disp-día con variación benigna antes y después de E5C, desde reports/adopcion_e5c.json."""
    d = json.loads((REPORTS / "adopcion_e5c.json").read_text(encoding="utf-8"))
    modos = [("apariciones", "Con variación benigna\n(antes de E5C)"),
             ("persistencia", "Con E5C\n(persistencia exclusiva)")]
    valores, ic = [], []
    for modo, _ in modos:
        fa = d["por_modo"][modo]["fa"]["con_variacion"]["fa_ventanas_por_dispositivo_dia"]
        if round(fa["valor"], 1) != d["resumen"]["fa_con_variacion"][modo]:
            raise ValueError(f"reports/adopcion_e5c.json incoherente en {modo}")
        valores.append(fa["valor"])
        ic.append(fa["ic95"])
    err = [[v - lo for v, (lo, _) in zip(valores, ic)], [hi - v for v, (_, hi) in zip(valores, ic)]]

    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    x = range(len(modos))
    ax.bar(x, valores, width=0.5, color=COLOR_SERIE, yerr=err, capsize=4,
           error_kw={"ecolor": COLOR_TEXTO, "elinewidth": 1})
    for xi, v, (_, hi) in zip(x, valores, ic):
        # Un decimal, como `resumen` del JSON (826,2 y 381,5); el valor completo de E5C es 381,46.
        ax.text(xi, hi * 1.12, _coma(v, 1), ha="center", va="bottom", color=COLOR_PRESUPUESTO, fontsize=11)
    ax.set_yscale("log")
    ax.set_ylim(0.5, 3000)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda y, _: f"{y:g}"))
    ax.axhline(PRESUPUESTO_FA, color=COLOR_PRESUPUESTO, linestyle="--", linewidth=1.2,
               label="presupuesto: 1 FA/disp-día")
    ax.legend(loc="upper right", frameon=False, fontsize=9)
    ax.set_xticks(list(x), [etiqueta for _, etiqueta in modos])
    ax.set_xlim(-0.6, 1.6)
    ax.set_ylabel("Falsas alarmas por dispositivo-día (escala log)")
    _ejes(ax)
    ax.set_title("Canal de identidad con variación benigna: FA/disp-día (E5C), con IC95\n"
                 "datos de reports/adopcion_e5c.json, laboratorio sintético", fontsize=10)
    fig.tight_layout()
    ruta = dir_salida / "fa_disp_dia.png"
    fig.savefig(ruta, dpi=DPI, metadata={"Software": None})
    plt.close(fig)
    return ruta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Genera las figuras de la exposición desde reports/.")
    p.add_argument("--dir-salida", type=Path, default=_RAIZ / "docs" / "figuras")
    args = p.parse_args(argv)
    args.dir_salida.mkdir(parents=True, exist_ok=True)
    for ruta in (figura_recall(args.dir_salida), figura_fa(args.dir_salida)):
        print(f"{ruta.relative_to(_RAIZ) if ruta.is_relative_to(_RAIZ) else ruta}: {ruta.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
