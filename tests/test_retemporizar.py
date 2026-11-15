"""Pruebas del re-temporizador (PEDIDO-E4C-1, bloque 2): mismos bytes, otros tiempos."""
from __future__ import annotations

import hashlib

import pandas as pd
import pytest
from scapy.all import ARP, IP, UDP, Ether

from scripts import pcap_to_features
from scripts.lab import retemporizar as rt

ATACANTE = "02:ff:00:00:00:99"
VICTIMA_MAC = "02:aa:00:00:00:01"
VICTIMA_IP, GW_IP = "10.0.0.20", "10.0.0.1"


def _frame(ts_us: int, pkt) -> tuple[int, bytes]:
    crudo = bytes(pkt)
    return ts_us, crudo + b"\x00" * max(0, 60 - len(crudo))


def _sesion_min(dir_pcap, paso_ataque_s: float = 1.0):
    """Mini-sesión: fondo benigno + un episodio ARP spoofing de 6 tramas, en `data/pcap` simulado."""
    dir_pcap.mkdir(parents=True, exist_ok=True)
    frames, filas = [], []
    # Fondo benigno: dos equipos con UDP, repartido en ventanas limpias.
    for k in range(24):
        frames.append(_frame(int((k * 2.0 + 0.1) * 1e6),
                              Ether(src=VICTIMA_MAC, dst="02:00:00:00:00:01") / IP(src=VICTIMA_IP, dst=GW_IP) / UDP()))
    # Episodio ARP: el atacante reclama la IP de la víctima; 6 tramas juntas (paso base).
    t0 = 10.0
    for n in range(6):
        frames.append(_frame(int((t0 + n * paso_ataque_s) * 1e6),
                             Ether(src=ATACANTE, dst="ff:ff:ff:ff:ff:ff") / ARP(
                                 op=2, hwsrc=ATACANTE, psrc=VICTIMA_IP, hwdst="ff:ff:ff:ff:ff:ff", pdst=GW_IP)))
    frames.sort(key=lambda x: x[0])
    ruta = dir_pcap / "sesion_900.pcap"
    rt.escribir_pcap_crudo(ruta, frames)
    for i, (ts, raw) in enumerate(frames):
        if raw[:2] != b"\xff\xff":  # las ARP van a broadcast; marca solo las de ataque
            continue
        filas.append({"n_trama": i, "ts_us": ts, "mac_src": ATACANTE, "atacante": ATACANTE,
                      "episodio": 0, "tipo": "arp_spoofing", "variante": "respuesta_gateway",
                      "intensidad": "suave", "capa": "enlace"})
    pd.DataFrame(filas).to_csv(ruta.with_suffix(".tramas.csv"), index=False)
    pd.DataFrame([{"episodio": 0, "tipo": "arp_spoofing", "variante": "respuesta_gateway",
                   "intensidad": "suave", "capa": "enlace", "atacante": ATACANTE, "origen": "propia",
                   "t_inicio_s": t0, "t_fin_s": t0 + 5 * paso_ataque_s}]).to_csv(
        ruta.with_suffix(".episodios.csv"), index=False)
    return ruta


def _sha(ruta) -> str:
    return hashlib.sha256(ruta.read_bytes()).hexdigest()


@pytest.fixture
def lab(tmp_path, monkeypatch):
    dir_pcap = tmp_path / "data" / "pcap"
    monkeypatch.setattr(rt, "DIR_PERMITIDO", dir_pcap)
    return _sesion_min(dir_pcap)


def test_misma_semilla_mismo_pcap_byte_a_byte(lab):
    a = rt.retemporizar(lab, 0, "arp_spoofing", paso_s=30, jitter=0.1, semilla=81000, salida=lab.with_name("a.pcap"))
    b = rt.retemporizar(lab, 0, "arp_spoofing", paso_s=30, jitter=0.1, semilla=81000, salida=lab.with_name("b.pcap"))
    assert _sha(a) == _sha(b)


def test_los_bytes_de_cada_trama_no_cambian(lab):
    antes = sorted(raw for _, raw in rt.leer_pcap_crudo(lab))
    salida = rt.retemporizar(lab, 0, "arp_spoofing", paso_s=30, jitter=0.0, semilla=1)
    assert sorted(raw for _, raw in rt.leer_pcap_crudo(salida)) == antes


def test_rechaza_tipo_no_permitido(lab):
    with pytest.raises(ValueError, match="no permitido"):
        rt.retemporizar(lab, 0, "syn_flood", paso_s=5, jitter=0.0, semilla=1)


def test_rechaza_pcap_fuera_de_data_pcap(tmp_path, monkeypatch):
    monkeypatch.setattr(rt, "DIR_PERMITIDO", tmp_path / "data" / "pcap")
    fuera = _sesion_min(tmp_path / "otro")  # crea la sesión fuera del directorio permitido
    with pytest.raises(ValueError, match="data/pcap"):
        rt.retemporizar(fuera, 0, "arp_spoofing", paso_s=5, jitter=0.0, semilla=1)


def test_paso_grande_deja_el_episodio_por_debajo_del_umbral(lab):
    """(d): el episodio se sigue etiquetando, pero ninguna ventana alcanza K=2 (invisible)."""
    salida = rt.retemporizar(lab, 0, "arp_spoofing", paso_s=30, jitter=0.0, semilla=1)
    df = pcap_to_features.procesar_sesion(salida, "sesion_900_ret30")
    ataque = df[df["n_tramas_ataque"] > 0]
    assert len(ataque) >= 1  # el episodio sigue presente en el manifiesto
    assert int(ataque["n_tramas_ataque"].max()) < pcap_to_features.K_TRAMAS_ATAQUE
    assert int(df["etiqueta"].sum()) == 0  # ninguna ventana etiquetada maliciosa


def test_paso_pequeno_si_etiqueta(lab):
    """Control: a paso 0,5 s varias tramas caen en una ventana y el episodio sí se etiqueta."""
    salida = rt.retemporizar(lab, 0, "arp_spoofing", paso_s=0.5, jitter=0.0, semilla=1)
    df = pcap_to_features.procesar_sesion(salida, "sesion_900_ret0")
    assert int(df["n_tramas_ataque"].max()) >= pcap_to_features.K_TRAMAS_ATAQUE
    assert int(df["etiqueta"].sum()) >= 1
