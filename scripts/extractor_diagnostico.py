#!/usr/bin/env python3
"""
Diagnóstico del extractor (PEDIDO-EXTRACTOR-1, iteración 0).

1. Separación univariada de cada característica actual: AUC de las ventanas de cada tipo de
   ataque frente a las benignas limpias del dataset de desarrollo, y las 3 que más separan.
2. Evidencia en el pcap (solo `data/pcap/`, sesiones de desarrollo; nunca el holdout): para
   cada clase de protocolo (ARP por operación, TCP por flags, DNS consulta/respuesta, ICMP por
   tipo…), longitud de trama, TTL, longitud de cabecera TCP y ventana TCP de las tramas de
   ataque frente a las benignas de la misma clase. Si una trama de ataque difiere del benigno
   *de su misma clase* en un campo que el protocolo no fija, ese campo mide la herramienta.
3. Para las 3 características de cada ataque, `depende_de_herramienta` (sí/no/mixta) con el
   motivo en una línea, apoyado en la evidencia del punto 2 (`JUICIOS`).

Uso:
    python scripts/extractor_diagnostico.py [--salida reports/extractor_diagnostico.json]
"""
from __future__ import annotations

import argparse
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

_RAIZ = Path(__file__).resolve().parent.parent
if str(_RAIZ) not in sys.path:
    sys.path.insert(0, str(_RAIZ))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scapy.utils import RawPcapReader  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402

from scripts.evaluar import cargar_dataset_estricto, commit_actual, escribir_json  # noqa: E402
from scripts.lab.ficha_dataset import sha256_archivo  # noqa: E402
from src import evaluacion as ev  # noqa: E402
from src.data import SESIONES_RESERVADAS, indice_sesion  # noqa: E402
from src.feature_schema import COLUMNAS_MODELO, ETIQUETA  # noqa: E402

DIR_PCAP = _RAIZ / "data" / "pcap"
TOP = 3

# ------------------------------------------------------------------------------------------
# 1. Separación univariada
# ------------------------------------------------------------------------------------------


def separacion(df: pd.DataFrame) -> dict:
    """AUC de cada característica: ventanas del tipo frente a benignas limpias."""
    limpias = ev.benignas_limpias(df).to_numpy()
    salida = {}
    for tipo in sorted(df.loc[df[ETIQUETA] == 1, "tipo_ataque"].unique()):
        ataque = ((df["tipo_ataque"] == tipo) & (df[ETIQUETA] == 1)).to_numpy()
        sub = df[ataque | limpias]
        y = ataque[ataque | limpias].astype(int)
        filas = []
        for c in COLUMNAS_MODELO:
            bruto = sub[c].to_numpy(dtype=float)
            nan = np.isnan(bruto)
            # NaN = «no hay tramas suficientes para calcularla»: se ordena por debajo de todo.
            v = np.where(nan, np.nanmin(bruto) - 1 if (~nan).any() else 0.0, bruto)
            auc = float(roc_auc_score(y, v)) if v.std() > 0 else 0.5
            a, b = bruto[(y == 1) & ~nan], bruto[(y == 0) & ~nan]
            filas.append({
                "caracteristica": c, "auc": auc, "separacion": abs(auc - 0.5) * 2,
                "fraccion_nan_ataque": float(nan[y == 1].mean()), "fraccion_nan_benigno": float(nan[y == 0].mean()),
                "mediana_ataque": float(np.median(a)) if len(a) else None,
                "mediana_benigno": float(np.median(b)) if len(b) else None,
                "p90_benigno": float(np.percentile(b, 90)) if len(b) else None,
                "p10_ataque": float(np.percentile(a, 10)) if len(a) else None,
                "p90_ataque": float(np.percentile(a, 90)) if len(a) else None,
            })
        filas.sort(key=lambda f: -f["separacion"])
        salida[tipo] = {"ventanas": int(ataque.sum()), "caracteristicas": filas}
    return salida


# ------------------------------------------------------------------------------------------
# 2. Evidencia en el pcap
# ------------------------------------------------------------------------------------------

_FLAGS = "FSRPAUEC"


def _flags(b: int) -> str:
    return "".join(n for i, n in enumerate(_FLAGS) if b >> i & 1) or "nulo"


def clasificar(raw: bytes) -> tuple[str, int | None, int | None, int | None]:
    """(clase de protocolo, TTL, longitud de cabecera TCP, ventana TCP) de una trama Ethernet."""
    if len(raw) < 14:
        return "corta", None, None, None
    tipo, off = struct.unpack_from("!H", raw, 12)[0], 14
    if tipo == 0x8100 and len(raw) >= 18:
        tipo, off = struct.unpack_from("!H", raw, 16)[0], 18
    if tipo < 0x0600:
        return "llc", None, None, None
    if tipo == 0x0806 and len(raw) >= off + 8:
        return f"arp/op{struct.unpack_from('!H', raw, off + 6)[0]}", None, None, None
    if tipo == 0x86DD and len(raw) >= off + 40:
        return f"ipv6/nh{raw[off + 6]}", raw[off + 7], None, None
    if tipo != 0x0800 or len(raw) < off + 20:
        return f"eth/0x{tipo:04x}", None, None, None
    ihl, proto, ttl = (raw[off] & 0xF) * 4, raw[off + 9], raw[off + 8]
    l4 = off + ihl
    if proto == 6 and len(raw) >= l4 + 16:
        return (f"tcp/{_flags(raw[l4 + 13])}", ttl, (raw[l4 + 12] >> 4) * 4,
                struct.unpack_from("!H", raw, l4 + 14)[0])
    if proto == 17 and len(raw) >= l4 + 8:
        sport, dport = struct.unpack_from("!HH", raw, l4)
        if 53 in (sport, dport) and len(raw) >= l4 + 11:
            return ("udp/dns-respuesta" if raw[l4 + 10] & 0x80 else "udp/dns-consulta"), ttl, None, None
        return "udp/otro", ttl, None, None
    if proto == 1 and len(raw) >= l4 + 1:
        return f"icmp/{raw[l4]}", ttl, None, None
    return f"ip/proto{proto}", ttl, None, None


def _resumen_contador(c: Counter, n: int = 4) -> list:
    total = sum(c.values())
    return [[k, round(v / total, 4)] for k, v in c.most_common(n)] if total else []


def evidencia_pcap(directorio: Path = DIR_PCAP) -> dict:
    """Recorre los pcap de desarrollo y agrega por (grupo, clase de protocolo)."""
    acumulado: dict = defaultdict(lambda: {"n": 0, "long": Counter(), "ttl": Counter(),
                                           "tcp_hl": Counter(), "tcp_win": Counter()})
    sesiones = []
    for pcap in sorted(directorio.glob("sesion_*.pcap")):
        nombre = pcap.stem
        if indice_sesion(nombre) in SESIONES_RESERVADAS:
            raise SystemExit(f"{pcap} es del holdout: el diagnóstico no lo lee")
        tramas = pd.read_csv(pcap.with_suffix(".tramas.csv"), usecols=["n_trama", "tipo"])
        tipo_de = dict(zip(tramas["n_trama"], tramas["tipo"]))
        sesiones.append(nombre)
        for i, (raw, _) in enumerate(RawPcapReader(str(pcap))):
            clase, ttl, hl, win = clasificar(raw)
            a = acumulado[(tipo_de.get(i, "benigno"), clase)]
            a["n"] += 1
            a["long"][len(raw)] += 1
            if ttl is not None:
                a["ttl"][ttl] += 1
            if hl is not None:
                a["tcp_hl"][hl] += 1
                a["tcp_win"][win] += 1
    clases: dict = defaultdict(dict)
    for (grupo, clase), a in sorted(acumulado.items()):
        longs = np.repeat(list(a["long"].keys()), list(a["long"].values()))
        clases[grupo][clase] = {
            "tramas": a["n"], "longitudes_distintas": len(a["long"]),
            "longitud_min_mediana_max": [int(longs.min()), float(np.median(longs)), int(longs.max())],
            "longitudes_frecuentes": _resumen_contador(a["long"]),
            "ttl_frecuentes": _resumen_contador(a["ttl"]),
            "tcp_cabecera_frecuentes": _resumen_contador(a["tcp_hl"]),
            "tcp_ventana_frecuentes": _resumen_contador(a["tcp_win"]),
        }
    return {"sesiones": sesiones, "por_grupo": dict(clases)}


# ------------------------------------------------------------------------------------------
# 3. Juicio: ¿la característica mide el ataque o la herramienta?
# ------------------------------------------------------------------------------------------

# Clave: característica (vale para todos los ataques) o (tipo, característica) si el juicio
# cambia con el ataque. Cada motivo cita la evidencia del pcap de `evidencia_pcap`.
# Criterio: «sí» = la trama de ataque difiere de las benignas de su misma clase de protocolo en
# un campo que el protocolo no fija (la herramienta la construye distinta); «mixta» = trama a
# trama no se distingue, la separación sale de la composición o el volumen de la ventana (en el
# laboratorio la MAC atacante solo emite el ataque, al ritmo que fija la herramienta); «no» =
# cuenta un estado o vínculo que el protocolo no admite en un equipo legítimo.
_COMPOSICION = ("mixta", "Trama a trama no difiere del benigno de su clase (pcap: misma longitud); separa "
                         "porque la MAC atacante solo emite el ataque en su ventana.")
JUICIOS: dict = {
    "arp_cambios_vinculo_60s": ("no", "Cuenta IPs cuyo vínculo IP→MAC cambia: es la suplantación misma, "
                                      "vista en el campo ARP sender, no en cómo se construye la trama."),
    "arp_cambios_vinculo": ("no", "Igual que la versión de 60 s, en la ventana de 5 s."),
    ("arp_spoofing", "longitud_trama_media"): (
        "mixta", "ARP de ataque y benigno miden 60 B en el pcap (100 % ambos); la media baja porque la "
                 "ventana atacante solo trae ARP, no por la trama."),
    ("dns_spoofing", "dns_respuestas"): (
        "mixta", "Un equipo que no es el resolver emitiendo respuestas sí es la violación, pero el contador "
                 "no distingue al resolver legítimo y su magnitud es el ritmo de la herramienta."),
    ("dns_spoofing", "entropia_puertos_destino"): (
        "mixta", "Respuestas a muchos puertos efímeros: refleja la estrategia de adivinar puertos de la "
                 "herramienta; un spoofing dirigido a un solo cliente no la tendría."),
    ("dns_spoofing", "puertos_destino_distintos_60s"): (
        "mixta", "Misma causa que la entropía de puertos: estrategia de puertos de la herramienta."),
    ("dns_spoofing", "longitud_trama_media"): (
        "sí", "pcap: respuestas falsas de 128/112 B frente a 110/108 B en las legítimas; la herramienta "
              "arma la respuesta distinta."),
    ("icmp_flood", "conexiones_distintas"): (
        "mixta", "Separa por ausencia de flujos TCP/UDP en la ventana atacante (vale 0), no por nada ICMP: "
                 "ninguna característica actual mira el tipo ICMP."),
    ("icmp_flood", "puertos_destino_distintos"): (
        "mixta", "Como conexiones_distintas: separa por lo que la ventana atacante no tiene."),
    ("icmp_flood", "puertos_destino_distintos_60s"): (
        "mixta", "Como conexiones_distintas, en 60 s."),
    ("mac_flooding", "n_tramas_60s"): (
        "mixta", "Cada MAC falsa emite muy pocas tramas (mediana 3 frente a 131): consecuencia del ataque "
                 "(muchas MAC efímeras), pero la cifra exacta la fija la herramienta."),
    ("mac_flooding", "macs_nuevas_por_s"): (
        "no", "MACs origen nuevas por segundo: es la presión sobre la tabla CAM que define el ataque."),
    ("mac_flooding", "longitud_trama_media"): (
        "sí", "pcap: el UDP del ataque mide 60 B (100 %) frente a 90/75/286 B del UDP benigno; la "
              "herramienta emite tramas mínimas."),
    ("port_scan", "puertos_destino_distintos_60s"): (
        "no", "Tocar muchos puertos de un destino es la definición del barrido."),
    ("port_scan", "entropia_puertos_destino"): ("no", "Abanico de puertos destino: definición del barrido."),
    ("port_scan", "syn_medio_abiertos_60s"): (
        "no", "SYN sin completar el saludo: el barrido no abre conexiones."),
    ("syn_flood", "syn_medio_abiertos"): (
        "no", "Conexiones medio abiertas: el estado que el ataque deja en la víctima."),
    ("syn_flood", "syn_medio_abiertos_60s"): ("no", "Igual, en 60 s."),
    ("syn_flood", "tasa_syn"): (
        "mixta", "Fracción de SYN en la ventana: alta por el ataque, pero vale 1 porque la MAC atacante no "
                 "emite nada más (composición)."),
    "longitud_trama_std": _COMPOSICION,
    "longitud_trama_media": _COMPOSICION,
}

# Huellas de herramienta vistas en el pcap que NO tienen característica y no deben tenerla.
ARTEFACTOS_SIN_CARACTERISTICA = [
    "Ventana TCP 8192 en el 100 % de los TCP de ataque (SYN, nulo, FIN, Xmas) frente a 29200/64240 en el benigno.",
    "TTL 64 en el 100 % del IP de ataque frente a 64/128 (y 48–50 de equipos remotos) en el benigno.",
    "Respuestas DNS falsas de 112–128 B frente a 108–110 B en las legítimas.",
    "UDP de mac_flooding de 60 B (trama mínima) frente a 75–1242 B en el UDP benigno.",
]

# Violaciones vistas en el pcap que ninguna característica cuenta todavía (candidatas).
VIOLACIONES_SIN_CONTADOR = [
    "TCP sin flags (503), FIN suelto (453) y FIN+PSH+URG (466) en port_scan; 0 en el benigno.",
    "ICMP destination unreachable: 10 250 tramas de icmp_flood frente a 1 499 benignas; hoy solo se cuenta echo.",
    "ICMP echo reply: 29 204 tramas de icmp_flood, que ningún contador mira (n_icmp_echo solo cuenta echo request).",
    "UDP a puertos sin servicio en port_scan (883 tramas de 60 B).",
]


def juicio(tipo: str, caracteristica: str) -> dict:
    j = JUICIOS.get((tipo, caracteristica)) or JUICIOS.get(caracteristica)
    if j is None:
        return {"depende_de_herramienta": "sin_juicio", "motivo": ""}
    return {"depende_de_herramienta": j[0], "motivo": j[1]}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Diagnóstico de las características actuales (iteración 0).")
    p.add_argument("--dataset", default="data/dataset_lab.csv")
    p.add_argument("--salida", type=Path, default=_RAIZ / "reports" / "extractor_diagnostico.json")
    p.add_argument("--sin-pcap", action="store_true", help="Omite la lectura de pcap (pruebas).")
    p.add_argument("--dir-pcap", type=Path, default=DIR_PCAP)
    args = p.parse_args(argv)
    df = cargar_dataset_estricto(args.dataset)
    sep = separacion(df)
    informe = {
        "pedido": "PEDIDO-EXTRACTOR-1", "iteracion": 0, **commit_actual(),
        "dataset": {"ruta": args.dataset, "sha256": sha256_archivo(Path(_RAIZ / args.dataset)
                                                                    if not Path(args.dataset).is_absolute()
                                                                    else Path(args.dataset)),
                    "filas": int(len(df))},
        "metodo": "AUC univariada (ventanas etiquetadas del tipo frente a benignas limpias); "
                  "separacion = |AUC − 0,5| × 2. Top 3 por tipo.",
        "top_por_ataque": {
            t: [{**{k: f[k] for k in ("caracteristica", "auc", "mediana_ataque", "mediana_benigno",
                                      "fraccion_nan_ataque", "fraccion_nan_benigno")},
                 **juicio(t, f["caracteristica"])} for f in d["caracteristicas"][:TOP]]
            for t, d in sep.items()
        },
        "criterio_depende_de_herramienta": "sí = difiere del benigno de su misma clase de protocolo en un campo "
                                           "que el protocolo no fija; mixta = separa por composición o volumen "
                                           "de la ventana; no = cuenta una violación de estado o vínculo.",
        "artefactos_sin_caracteristica": ARTEFACTOS_SIN_CARACTERISTICA,
        "violaciones_sin_contador": VIOLACIONES_SIN_CONTADOR,
        "separacion_completa": sep,
    }
    if not args.sin_pcap:
        informe["pcap"] = evidencia_pcap(args.dir_pcap)
    escribir_json(informe, args.salida)
    for t, filas in informe["top_por_ataque"].items():
        print(t, " · ".join(f"{f['caracteristica']} AUC {f['auc']:.3f} [{f['depende_de_herramienta']}]" for f in filas))
    print(f"Escrito {args.salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
