"""Consolida el marcador de PEDIDO-EXTRACTOR-1 en `reports/extractor_final.json`.

Lee los informes LOAO de `reports/extractor/` (salida de `scripts/ablaciones.py --partes
loao`) y, para cada familia de contadores compartidos, compara el recall por episodio de
los tipos que declaró cubrir al quedar excluidos, antes y después, con el IC bootstrap de
cada informe. Evalúa el criterio de parada del pedido v2 (OE2, OE3: transferencia a
ataques no vistos).

Uso:
    .venv/bin/python scripts/extractor_final.py [--salida reports/extractor_final.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_RAIZ))

MODELOS: list[str] = ["random_forest", "xgboost"]
TIPOS: list[str] = ["arp_spoofing", "dns_spoofing", "icmp_flood", "mac_flooding", "port_scan", "syn_flood"]
LINEA_BASE: str = "reports/extractor/loao_it0_sin_capa2.json"
MEJORA_MEDIA_PARADA: float = 0.15
UMBRAL_TIPO_PARADA: float = 0.25
TIPOS_PARADA: int = 3

# Registro de familias, en el orden en que se midieron. La predicción se copia de
# PROGRESO-EXTRACTOR.md, donde quedó escrita antes de medir.
FAMILIAS: list[dict] = [
    {
        "iteracion": 1,
        "familia": "respuestas sin petición previa",
        "features": [
            "respuestas_no_solicitadas",
            "tasa_respuestas_no_solicitadas",
            "respuestas_no_solicitadas_60s",
        ],
        "viola": "Un equipo legítimo no contesta lo que nadie preguntó.",
        "fuente_pcap": (
            "ARP reply sin request (psrc, pdst) previo; respuesta DNS sin consulta (ip, puerto, "
            "txid); ICMP echo reply sin echo request (ips, id, seq); error ICMP 3/11 que cita "
            "un datagrama que su destinatario no envió; ventana de 5 s"
        ),
        "cubre": ["icmp_flood", "arp_spoofing", "dns_spoofing"],
        "prediccion": {
            "icmp_flood": 0.15,
            "arp_spoofing": 0.10,
            "dns_spoofing": None,  # sube como mucho +0,10 (solo la variante kaminsky)
        },
        "regla_decision": (
            "Se queda si el LOAO medio sube en al menos un modelo y icmp_flood o arp_spoofing "
            "sube >= 0,10 al quedar excluido."
        ),
        "informe": "reports/extractor/loao_it1_respuestas.json",
    },
]


def _leer(ruta: str) -> dict:
    return json.loads((_RAIZ / ruta).read_text())["loao"]


def _cifra(bloque: dict) -> dict:
    return {"valor": round(bloque["valor"], 3), "ic95": [round(x, 3) for x in bloque["ic95"]]}


def resumen_loao(loao: dict) -> dict:
    """Media de los seis y recall por tipo excluido, por modelo."""
    return {
        m: {
            "media": _cifra(loao["media_seis"][m]["recall_episodios_excluido"]),
            "por_tipo": {t: _cifra(loao[m][t]["recall_episodios_excluido"]) for t in TIPOS},
        }
        for m in MODELOS
    }


def evaluar_familia(familia: dict, antes: dict, despues: dict) -> dict:
    """Transferencia de los tipos declarados y aplicación de la regla de decisión."""
    transferencia = {}
    for tipo in familia["cubre"]:
        transferencia[tipo] = {}
        for m in MODELOS:
            a, d = antes[m]["por_tipo"][tipo], despues[m]["por_tipo"][tipo]
            transferencia[tipo][m] = {"antes": a, "despues": d, "delta": round(d["valor"] - a["valor"], 3)}
    sube_media = any(despues[m]["media"]["valor"] > antes[m]["media"]["valor"] for m in MODELOS)
    sube_clave = any(
        transferencia[t][m]["delta"] >= 0.10 for t in ("icmp_flood", "arp_spoofing") if t in transferencia
        for m in MODELOS
    )
    prediccion = {
        t: {
            "minimo_declarado": umbral,
            "cumplida": (
                any(transferencia[t][m]["delta"] >= umbral for m in MODELOS) if umbral is not None
                else all(transferencia[t][m]["delta"] <= 0.10 for m in MODELOS)
            ),
        }
        for t, umbral in familia["prediccion"].items()
    }
    return {
        "transferencia": transferencia,
        "prediccion": prediccion,
        "se_queda": bool(sube_media and sube_clave),
    }


def criterio_parada(base: dict, actual: dict) -> dict:
    """Pedido v2: media >= línea base + 0,15 en un modelo, o 3 de 6 tipos >= 0,25."""
    por_modelo = {}
    for m in MODELOS:
        objetivo = round(base[m]["media"]["valor"] + MEJORA_MEDIA_PARADA, 3)
        tipos = [t for t in TIPOS if actual[m]["por_tipo"][t]["valor"] >= UMBRAL_TIPO_PARADA]
        por_modelo[m] = {
            "media": actual[m]["media"]["valor"],
            "objetivo_media": objetivo,
            "media_cumple": actual[m]["media"]["valor"] >= objetivo,
            "tipos_sobre_umbral": tipos,
            "tipos_cumple": len(tipos) >= TIPOS_PARADA,
        }
    return {
        "por_modelo": por_modelo,
        "transferencia_lograda": any(v["media_cumple"] or v["tipos_cumple"] for v in por_modelo.values()),
    }


def construir() -> dict:
    """Arma el informe con la línea base y la cadena de familias medidas."""
    base = resumen_loao(_leer(LINEA_BASE))
    vigente, iteraciones = base, []
    for familia in FAMILIAS:
        despues = resumen_loao(_leer(familia["informe"]))
        evaluacion = evaluar_familia(familia, vigente, despues)
        iteraciones.append({**familia, "loao": despues, **evaluacion})
        if evaluacion["se_queda"]:
            vigente = despues
    return {
        "pedido": "PEDIDO-EXTRACTOR-1 (v2)",
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "marcador": "Recall por episodio del tipo excluido (LOAO), conjunto sin_capa2, IC 95 % bootstrap",
        "linea_base_semantica": {"informe": LINEA_BASE, "loao": base},
        "iteraciones": iteraciones,
        "vigente": vigente,
        "criterio_parada": criterio_parada(base, vigente),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--salida", type=Path, default=_RAIZ / "reports" / "extractor_final.json")
    args = p.parse_args(argv)
    informe = construir()
    args.salida.write_text(json.dumps(informe, indent=2, ensure_ascii=False) + "\n")
    print(f"Escrito {args.salida}; transferencia lograda: {informe['criterio_parada']['transferencia_lograda']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
