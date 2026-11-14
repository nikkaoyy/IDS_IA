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


# Contrato 3.0, columna por columna: (alcance, qué viola o qué mide, fuente en el pcap).
# Alcance: «compartido» (varios ataques lo violan), «propio:<tipo>» (un solo ataque: es la
# razón estructural de que el LOAO no suba), «contexto» (describe la ventana, no viola nada).
FEATURES_3_0: dict[str, tuple[str, str, str]] = {
    # FEATURES_CAPA2: en el contrato, fuera del marcador LOAO (ver CAPA2_FUERA_DEL_MARCADOR).
    "n_tramas": ("contexto", "volumen emitido por la MAC en 5 s", "tramas con esa MAC origen"),
    "bytes_totales": ("contexto", "volumen en octetos", "longitud de trama en el medio"),
    "longitud_trama_media": ("contexto", "composición de la ventana, no construcción de la trama", "longitud de trama"),
    "longitud_trama_std": ("contexto", "ídem; NaN con una sola trama (22 % del benigno)", "longitud de trama"),
    "iat_media_ms": ("contexto", "ritmo de emisión", "marcas de tiempo"),
    "iat_std_ms": ("contexto", "regularidad del ritmo", "marcas de tiempo"),
    "tasa_unicast": ("contexto", "reparto del destino de enlace", "MAC destino"),
    "tasa_multicast": ("contexto", "ídem", "MAC destino, bit I/G"),
    "tasa_broadcast": ("contexto", "ídem", "MAC destino ff:ff:ff:ff:ff:ff"),
    "macs_destino_distintas": ("contexto", "pares de enlace", "MAC destino"),
    "pct_menor_64": ("contexto", "tramas runt (< 64 B con FCS)", "longitud de trama"),
    "tasa_vlan": ("contexto", "tramas 802.1Q", "EtherType 0x8100"),
    "tasa_llc": ("contexto", "tramas 802.3/LLC", "campo longitud < 0x0600"),
    "entropia_ethertype": ("contexto", "mezcla de protocolos", "EtherType"),
    # FEATURES_ARP
    "arp_requests": ("contexto", "peticiones ARP emitidas", "ARP op 1"),
    "arp_replies": ("contexto", "respuestas ARP emitidas", "ARP op 2"),
    "arp_replies_no_solicitadas": ("propio:arp_spoofing", "respuesta ARP sin petición (psrc, pdst)", "ARP op 2 sin op 1 previo en 5 s"),
    "arp_gratuitos": ("propio:arp_spoofing", "anuncio de vínculo sin petición", "ARP con psrc == pdst"),
    "arp_cambios_vinculo": ("propio:arp_spoofing", "una IP conocida aparece con otra MAC", "tabla IP->MAC de ARP"),
    "arp_ether_distinto_hwsrc": ("propio:arp_spoofing", "la MAC de enlace no coincide con la que declara ARP", "Ether.src frente a ARP.hwsrc"),
    "arp_gateway_reclamado": ("propio:arp_spoofing", "alguien que no es el gateway dice serlo (NaN sin gateway declarado)", "ARP psrc == IP del gateway"),
    # FEATURES_TCP
    "n_syn": ("contexto", "aperturas TCP", "flags SYN sin ACK"),
    "tasa_syn": ("contexto", "proporción de aperturas", "flags SYN / tramas"),
    "syn_medio_abiertos": ("propio:syn_flood", "SYN sin SYN-ACK ni RST tras 1 s", "seguimiento de flujos TCP"),
    "ratio_syn_medio_abiertos": ("propio:syn_flood", "ídem, normalizado por SYN evaluables", "seguimiento de flujos TCP"),
    "n_rst": ("contexto", "reinicios TCP", "flag RST"),
    "ips_origen_distintas": ("contexto", "IP de origen que usa la MAC", "IP.src"),
    "ips_destino_distintas": ("contexto", "abanico de destinos", "IP.dst"),
    "puertos_destino_distintos": ("contexto", "abanico de puertos", "TCP/UDP dport"),
    "entropia_puertos_destino": ("contexto", "reparto de puertos", "TCP/UDP dport"),
    "conexiones_distintas": ("contexto", "pares (ip, puerto) de destino", "IP.dst + dport"),
    "n_icmp_echo": ("contexto", "echo request emitidos", "ICMP tipo 8"),
    # FEATURES_DNS
    "dns_consultas": ("contexto", "consultas DNS", "DNS qr=0"),
    "dns_respuestas": ("contexto", "respuestas DNS emitidas", "DNS qr=1"),
    "dns_respuestas_sin_consulta": ("propio:dns_spoofing", "respuesta DNS sin consulta (ip, puerto, txid)", "DNS qr=1 sin qr=0 previo en 5 s"),
    "dns_multiples_respuestas_txid": ("propio:dns_spoofing", "dos respondedores para el mismo txid", "DNS qr=1 repetido"),
    "dns_resolver_no_autorizado": ("propio:dns_spoofing", "responde quien no es resolver (NaN sin resolvers declarados)", "IP.src de DNS qr=1"),
    # FEATURES_LARGAS (12 ventanas = 60 s)
    "n_tramas_60s": ("contexto", "volumen en 60 s", "tramas"),
    "arp_replies_no_solicitadas_60s": ("propio:arp_spoofing", "ver arp_replies_no_solicitadas", "ídem, 60 s"),
    "arp_cambios_vinculo_60s": ("propio:arp_spoofing", "ver arp_cambios_vinculo", "ídem, 60 s"),
    "syn_medio_abiertos_60s": ("propio:syn_flood", "ver syn_medio_abiertos (también port_scan)", "ídem, 60 s"),
    "dns_respuestas_sin_consulta_60s": ("propio:dns_spoofing", "ver dns_respuestas_sin_consulta", "ídem, 60 s"),
    "puertos_destino_distintos_60s": ("propio:port_scan", "abanico de puertos sostenido", "dport, 60 s"),
    "ips_destino_distintas_60s": ("contexto", "abanico de destinos sostenido", "IP.dst, 60 s"),
    # FEATURES_GLOBALES (segmento)
    "macs_nuevas_por_s": ("propio:mac_flooding", "aparición de MAC nunca vistas", "MAC origen del segmento"),
    "macs_activas": ("propio:mac_flooding", "MAC que emiten en la ventana", "MAC origen del segmento"),
    "ratio_macs_una_trama": ("propio:mac_flooding", "MAC que emiten una sola trama", "MAC origen del segmento"),
    "syn_sin_synack_max_destino": ("propio:syn_flood", "presión de SYN sobre un destino", "flujos TCP por destino"),
    "syn_medio_abiertos_max_destino": ("propio:syn_flood", "conexiones medio abiertas sobre un destino", "flujos TCP por destino"),
    # FEATURES_RESPUESTAS (familia 1, iteración 1)
    "respuestas_no_solicitadas": ("compartido", "respuesta de protocolo que nadie pidió (ARP, DNS, ICMP echo, error ICMP)", FAMILIAS[0]["fuente_pcap"]),
    "tasa_respuestas_no_solicitadas": ("compartido", "ídem, por trama", "ídem"),
    "respuestas_no_solicitadas_60s": ("compartido", "ídem, en 60 s", "ídem"),
}

CAPA2_FUERA_DEL_MARCADOR: str = (
    "FEATURES_CAPA2 sigue en el contrato 3.0 (E2 la usa) pero no en el marcador LOAO: según el "
    "diagnóstico de la iteración 0, mide la composición de la ventana (ARP 60 B y SYN 60 B "
    "iguales en ataque y benigno), longitud_trama_std es NaN en el 22 % del benigno, y "
    "quitarla no cambia el LOAO (RF 0,028 -> 0,044; XGB 0,111 -> 0,116)."
)

NUNCA_ENTRAN: dict[str, str] = {
    "ventana_tcp": "8192 en el 100 % del TCP de ataque (benigno 29200/64240): huella de la herramienta",
    "ttl_ip": "64 en el 100 % del IP de ataque (benigno 64/128/48-50): huella de la herramienta",
}

FAMILIAS_NO_MEDIDAS: dict[int, str] = {
    2: "flujos iniciados que nunca se completan (syn_flood, port_scan)",
    3: "reclamación de rol (arp_spoofing, dns_spoofing)",
    4: "abanico de identidad (mac_flooding, port_scan, syn_flood)",
    5: "tasa de eventos de control por encima de lo humano (los seis)",
}


RESPUESTA_TRANSFERENCIA: str = (
    "Sí, poco y casi todo en un tipo. Con el contador compartido, el LOAO medio de XGB pasa de "
    "0,116 [0,074, 0,156] a 0,228 [0,168, 0,286] (los IC no se solapan); el de RF, de 0,044 a "
    "0,068 (se solapan). La única transferencia atribuible es arp_spoofing (0 -> 0,294 en XGB, "
    "0 -> 0,147 en RF). icmp_flood, el tipo que más usa el contador, no se beneficia al quedar "
    "excluido. Lo que transfiere es la semántica del protocolo (respuestas sin petición), no la "
    "huella de capa 2: quitarla no movió el LOAO en la iteración 0. Con 20 de 38 "
    "características propias de un solo ataque y 3 compartidas, el clasificador supervisado "
    "sigue siendo un detector del catálogo conocido; a <= 1 FA/dispositivo-día no detecta un "
    "ataque nuevo en más de 1 de cada 4 episodios de media."
)


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
        "features_3_0": {
            n: {"alcance": a, "justificacion": j, "fuente_pcap": f, "en_marcador": n not in _capa2()}
            for n, (a, j, f) in FEATURES_3_0.items()
        },
        "capa2_fuera_del_marcador": CAPA2_FUERA_DEL_MARCADOR,
        "retiradas_del_contrato": {},
        "nunca_entran": NUNCA_ENTRAN,
        "familias_no_medidas": FAMILIAS_NO_MEDIDAS,
        "iteraciones_sin_mejora": [i["iteracion"] for i in iteraciones if not i["se_queda"]],
        "respuesta_transferencia": RESPUESTA_TRANSFERENCIA,
    }


def _capa2() -> set[str]:
    from src.feature_schema import FEATURES_CAPA2

    return set(FEATURES_CAPA2)


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
