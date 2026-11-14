"""Pruebas del núcleo de ventanas (src/ventanas.py), incluida la paridad lote/incremental."""
from __future__ import annotations

import math

import pandas as pd
import pytest

pytest.importorskip("scapy.all")
from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether, Padding, rdpcap  # noqa: E402

from scripts import pcap_to_features  # noqa: E402
from src import capture  # noqa: E402
from src.feature_schema import COLUMNAS_MODELO  # noqa: E402
from src.ventanas import (  # noqa: E402
    MAC_EFIMERAS,
    AgregadorVentanas,
    ConfigSegmento,
    Trama,
    extraer_ventanas,
    leer_pcap,
    trama_desde_paquete,
)

A, B, GW = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:01"
CONFIG = ConfigSegmento("10.0.0.1", GW, {"10.0.0.2": "02:00:00:00:00:02"})


def _tabla(filas: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(filas).sort_values(["idx_ventana", "mac"]).reset_index(drop=True)


def _una_fila(tramas: list[Trama], mac: str, config=CONFIG) -> dict:
    return next(f for f in extraer_ventanas(tramas, config) if f["mac"] == mac)


def _base(ts: float, src: str = A, dst: str = B, **kw) -> Trama:
    return Trama(ts_us=round(ts * 1e6), longitud=60, mac_src=src, mac_dst=dst, ethertype=0x0800, **kw)


def _syn(ts, flags=0x02, src=A, ips=("10.0.0.9", "10.0.0.3"), ports=(4000, 80)) -> Trama:
    return _base(ts, src, ip_src=ips[0], ip_dst=ips[1], proto="tcp", sport=ports[0], dport=ports[1],
                 tcp_flags=flags)


def test_paridad_lote_incremental(sesion_corta):
    """Lote lee el pcap y emite al final; incremental emite ventana a ventana desde bytes."""
    sesion, ruta = sesion_corta
    config = pcap_to_features.cargar_config(ruta)
    lote = _tabla(extraer_ventanas(leer_pcap(ruta), config))

    agregador = AgregadorVentanas(config)
    emitidas: list[dict] = []
    tandas = 0
    for ts_us, crudo, _ in sesion.tramas:
        pkt = Ether(crudo)
        pkt.time = ts_us / 1e6
        nuevas = agregador.agregar(trama_desde_paquete(pkt))
        tandas += bool(nuevas)
        emitidas.extend(nuevas)
    emitidas.extend(agregador.cerrar())

    assert tandas > 30, "el agregador no emitió de forma incremental"
    pd.testing.assert_frame_equal(lote, _tabla(emitidas), check_exact=True)


def test_fila_emitida_no_depende_de_tramas_futuras(sesion_corta):
    sesion, ruta = sesion_corta
    config = pcap_to_features.cargar_config(ruta)
    tramas = list(leer_pcap(ruta))
    corte = len(tramas) // 2
    agregador = AgregadorVentanas(config)
    parciales: list[dict] = []
    for t in tramas[:corte]:
        parciales.extend(agregador.agregar(t))
    completas = _tabla(extraer_ventanas(tramas, config))
    parciales_t = _tabla(parciales)
    ultimo = parciales_t["idx_ventana"].max()
    pd.testing.assert_frame_equal(
        parciales_t, completas[completas["idx_ventana"] <= ultimo].reset_index(drop=True)
    )


def test_oraculo_independiente_sobre_el_pcap(sesion_corta):
    """Recalcula columnas con Scapy y pandas, sin pasar por el agregador."""
    _, ruta = sesion_corta
    paquetes = rdpcap(str(ruta))
    t0 = float(paquetes[0].time)
    registros = [{
        "idx": int((float(p.time) - t0) // 5),
        "mac": p.src.lower(),
        "n": len(p),
        "bcast": p.dst == "ff:ff:ff:ff:ff:ff",
        "syn": TCP in p and p[TCP].flags & 0x12 == 0x02,
    } for p in paquetes]
    crudo = pd.DataFrame(registros)
    por_ventana = crudo.groupby("idx").agg(tramas=("n", "size"), bytes=("n", "sum"), syn=("syn", "sum"),
                                           bcast=("bcast", "sum"))
    filas = _tabla(extraer_ventanas(leer_pcap(ruta), pcap_to_features.cargar_config(ruta)))
    filas["bcast"] = filas["tasa_broadcast"] * filas["n_tramas"]
    nuestra = filas.groupby("idx_ventana").agg(tramas=("n_tramas", "sum"), bytes=("bytes_totales", "sum"),
                                               syn=("n_syn", "sum"), bcast=("bcast", "sum"))
    assert (nuestra["tramas"] == por_ventana["tramas"]).all()
    assert (nuestra["bytes"] == por_ventana["bytes"]).all()
    assert (nuestra["syn"] == por_ventana["syn"]).all()
    assert ((nuestra["bcast"] - por_ventana["bcast"]).abs() < 1e-6).all()


def test_todas_las_columnas_del_contrato_presentes():
    fila = _una_fila([_base(0.0), _base(1.0)], A)
    assert set(COLUMNAS_MODELO) <= set(fila)


def test_iat_y_std_son_nan_sin_datos():
    fila = _una_fila([_base(0.0)], MAC_EFIMERAS, None)
    assert math.isnan(fila["iat_media_ms"]) and math.isnan(fila["iat_std_ms"])
    assert math.isnan(fila["arp_gateway_reclamado"])
    assert math.isnan(fila["dns_resolver_no_autorizado"])


def test_macs_efimeras_se_funden_en_una_fila():
    tramas = [_base(i * 0.01, f"02:00:00:00:10:{i:02x}") for i in range(50)] + [_base(0.9), _base(1.0)]
    filas = extraer_ventanas(tramas)
    assert {f["mac"] for f in filas} == {A, MAC_EFIMERAS}
    efimera = next(f for f in filas if f["mac"] == MAC_EFIMERAS)
    assert efimera["n_tramas"] == 50
    assert efimera["macs_activas"] == 51
    assert efimera["macs_nuevas_por_s"] == 51 / 5
    assert efimera["ratio_macs_una_trama"] == 50 / 51


def _arp(ts, op, src, psrc, pdst, hwsrc=None, dst=B) -> Trama:
    return Trama(round(ts * 1e6), 60, src, dst, 0x0806, arp_op=op, arp_psrc=psrc, arp_pdst=pdst,
                 arp_hwsrc=hwsrc or src)


def test_indicadores_arp():
    tramas = [
        _base(0.0, GW),
        _arp(0.0, 1, A, "10.0.0.9", "10.0.0.1"),
        _arp(0.1, 2, GW, "10.0.0.1", "10.0.0.9"),         # solicitada
        _arp(0.2, 2, B, "10.0.0.1", "10.0.0.9"),          # responde a tiempo pero reclama gateway
        _arp(0.3, 2, B, "10.0.0.1", "10.0.0.7"),          # no solicitada
        _arp(0.4, 2, B, "10.0.0.5", "10.0.0.5", "aa:aa:aa:aa:aa:aa"),  # gratuito, hwsrc distinto
    ]
    legit, falso = _una_fila(tramas, GW), _una_fila(tramas, B)
    assert legit["arp_replies_no_solicitadas"] == 0 and legit["arp_gateway_reclamado"] == 0
    assert falso["arp_replies_no_solicitadas"] == 1
    assert falso["arp_gateway_reclamado"] == 2
    assert falso["arp_cambios_vinculo"] == 1
    assert falso["arp_gratuitos"] == 1
    assert falso["arp_ether_distinto_hwsrc"] == 1


def test_medio_abiertos_y_gracia():
    tramas = [
        _syn(0.0), _syn(0.1, 0x12, B, ("10.0.0.3", "10.0.0.9"), (80, 4000)),  # sin ACK final
        _syn(1.0, ports=(4001, 80)), _syn(1.1, 0x12, B, ("10.0.0.3", "10.0.0.9"), (80, 4001)),
        _syn(1.2, 0x10, ports=(4001, 80)),                                    # completa
        _syn(2.0, ports=(4002, 80)),                                          # sin SYN-ACK
        _syn(4.5, ports=(4003, 80)),                                          # dentro de la gracia
    ]
    fila = _una_fila(tramas, A)
    assert fila["n_syn"] == 4
    assert fila["syn_medio_abiertos"] == 2
    assert fila["ratio_syn_medio_abiertos"] == pytest.approx(2 / 3)
    assert fila["syn_sin_synack_max_destino"] == 1
    assert fila["syn_medio_abiertos_max_destino"] == 2


def _dns(ts, qr, src, ip_src, ip_dst, sport, dport, txid=7) -> Trama:
    return _base(ts, src, ip_src=ip_src, ip_dst=ip_dst, proto="udp", sport=sport, dport=dport,
                 dns_qr=qr, dns_id=txid)


def test_indicadores_dns_senalan_a_ambos_respondedores():
    real = "02:00:00:00:00:02"
    tramas = [
        _base(0.0, real),
        _dns(0.0, 0, A, "10.0.0.9", "10.0.0.2", 4000, 53),
        _dns(0.1, 1, B, "10.0.0.2", "10.0.0.9", 53, 4000),   # falsa gana la carrera
        _dns(0.2, 1, real, "10.0.0.2", "10.0.0.9", 53, 4000),
        _dns(0.3, 1, B, "10.0.0.2", "10.0.0.9", 53, 4999),   # sin consulta
    ]
    falso, legit = _una_fila(tramas, B), _una_fila(tramas, real)
    assert falso["dns_multiples_respuestas_txid"] == 1 and legit["dns_multiples_respuestas_txid"] == 1
    assert falso["dns_respuestas_sin_consulta"] == 1
    assert falso["dns_resolver_no_autorizado"] == 2 and legit["dns_resolver_no_autorizado"] == 0


def test_ventana_larga_acumula_y_olvida():
    tramas = [_base(0.0)] + [_base(0.1 + i * 20.0) for i in range(5)]  # cada 20 s
    filas = sorted(extraer_ventanas(tramas), key=lambda f: f["idx_ventana"])
    assert [f["n_tramas_60s"] for f in filas] == [2, 2 + 1, 2 + 2, 3, 3]


def test_parseo_de_paquetes_con_relleno_vlan_y_dot3():
    from scapy.all import LLC, Dot1Q, Dot3

    dns = Ether(bytes(Ether(src=A, dst=B) / Dot1Q(vlan=5) / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(
        sport=1, dport=53) / DNS(id=3, qd=DNSQR(qname="a.b")) / Padding(b"\0" * 30)))
    dns.time = 1.0
    t = trama_desde_paquete(dns)
    assert t.vlan and t.ethertype == 0x0800 and t.dns_id == 3 and t.dns_qr == 0
    llc = Ether(bytes(Dot3(src=A, dst=B) / LLC()))
    llc.time = 1.0
    t = trama_desde_paquete(llc)
    assert t.ethertype is None
    assert trama_desde_paquete(ARP()) is None


def test_capturar_ventanas_usa_el_mismo_nucleo(monkeypatch):
    pkts = [Ether(src=A, dst=B) / IP() / TCP(flags="S") for _ in range(3)]
    for i, p in enumerate(pkts):
        p.time = float(i)
    monkeypatch.setattr(capture, "_obtener_sniff", lambda: lambda iface, prn, count, timeout: [prn(p) for p in pkts])
    filas = capture.capturar_ventanas("lo")
    assert filas[0]["n_syn"] == 3 and set(COLUMNAS_MODELO) <= set(filas[0])


# --- Esquema 3.0, familia «respuestas sin petición previa» (PEDIDO-EXTRACTOR-1) -----------

def _icmp(ts, tipo, src=A, ips=("10.0.0.9", "10.0.0.3"), id_seq=(7, 1), cita=None) -> Trama:
    return _base(ts, src, ip_src=ips[0], ip_dst=ips[1], proto="icmp", icmp_tipo=tipo,
                 icmp_id_seq=id_seq if tipo in (0, 8) else None, icmp_cita=cita)


def _con_a(tramas: list[Trama]) -> list[Trama]:
    """Una trama neutra de A al inicio, para que A no caiga en la fila de efímeras."""
    return [_base(0.01)] + tramas


def test_echo_reply_sin_request_es_respuesta_no_solicitada():
    pedido = [_icmp(0.1, 8, src=B, ips=("10.0.0.3", "10.0.0.9")), _icmp(0.2, 0)]
    assert _una_fila(_con_a(pedido), A)["respuestas_no_solicitadas"] == 0
    otro_seq = [_icmp(0.1, 8, src=B, ips=("10.0.0.3", "10.0.0.9"), id_seq=(7, 2)), _icmp(0.2, 0)]
    assert _una_fila(_con_a(otro_seq), A)["respuestas_no_solicitadas"] == 1
    fila = _una_fila(_con_a([_icmp(0.1, 0), _icmp(0.2, 0)]), A)
    assert fila["respuestas_no_solicitadas"] == 2 and fila["tasa_respuestas_no_solicitadas"] == 2 / 3


def test_error_icmp_que_cita_un_datagrama_no_enviado():
    """El error es una respuesta al datagrama que cita; si su destinatario no lo envió, nadie lo pidió."""
    enviado = _base(0.1, B, ip_src="10.0.0.3", ip_dst="10.0.0.20", proto="udp", sport=5000, dport=161)
    cita = ("10.0.0.3", "10.0.0.20", "udp", 5000, 161)
    error = _icmp(0.2, 3, ips=("10.0.0.20", "10.0.0.3"), cita=cita)
    assert _una_fila(_con_a([enviado, error]), A)["respuestas_no_solicitadas"] == 0
    assert _una_fila(_con_a([error]), A)["respuestas_no_solicitadas"] == 1
    # Cita un datagrama de otro equipo: el destinatario del error no lo envió.
    ajeno = _icmp(0.2, 3, ips=("10.0.0.20", "10.0.0.4"), cita=cita)
    assert _una_fila(_con_a([enviado, ajeno]), A)["respuestas_no_solicitadas"] == 1
    caducado = [_icmp(6.0, 3, ips=("10.0.0.20", "10.0.0.3"), cita=cita), _base(6.1)]
    filas = [f for f in extraer_ventanas(_con_a([enviado, *caducado]), CONFIG) if f["mac"] == A]
    assert filas[-1]["respuestas_no_solicitadas"] == 1


def test_arp_y_dns_no_solicitados_suman_al_contador_compartido():
    arp = Trama(ts_us=100_000, longitud=60, mac_src=A, mac_dst=B, ethertype=0x0806, arp_op=2,
                arp_psrc="10.0.0.1", arp_pdst="10.0.0.3", arp_hwsrc=A)
    dns = _base(0.2, ip_src="10.0.0.2", ip_dst="10.0.0.3", proto="udp", sport=53, dport=4000, dns_qr=1, dns_id=9)
    eco = _icmp(0.3, 0)
    fila = _una_fila([arp, dns, eco], A)
    assert fila["respuestas_no_solicitadas"] == 3
    assert fila["arp_replies_no_solicitadas"] == 1 and fila["dns_respuestas_sin_consulta"] == 1


def test_respuestas_no_solicitadas_60s_acumula_ventanas():
    tramas = _con_a([_icmp(0.1 + 5 * k, 0) for k in range(4)] + [_base(21.0)])
    filas = [f for f in extraer_ventanas(tramas, CONFIG) if f["mac"] == A]
    assert [f["respuestas_no_solicitadas_60s"] for f in filas] == [1, 2, 3, 4, 4]


def test_trama_desde_paquete_lee_echo_y_cita_icmp():
    from scapy.all import ICMP
    eco = Ether(src=A, dst=B) / IP(src="10.0.0.9", dst="10.0.0.3") / ICMP(type=0, id=7, seq=3)
    eco.time = 1.0
    assert trama_desde_paquete(eco).icmp_id_seq == (7, 3)
    err = Ether(bytes(Ether(src=A, dst=B) / IP(src="10.0.0.20", dst="10.0.0.3") / ICMP(type=3, code=3)
                      / IP(src="10.0.0.3", dst="10.0.0.20") / UDP(sport=5000, dport=161)))
    err.time = 1.0
    t = trama_desde_paquete(err)
    assert t.proto == "icmp" and t.icmp_cita == ("10.0.0.3", "10.0.0.20", "udp", 5000, 161)
