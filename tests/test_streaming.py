"""Pruebas del motor en streaming (PEDIDO E5): paridad con el lote, identidad y métricas."""
from __future__ import annotations

import numpy as np

from src.feature_schema import COLUMNAS_MODELO
from src.streaming import MotorStreaming
from src.ventanas import ConfigSegmento, Trama, extraer_ventanas

MAC_A, MAC_B, MAC_DST = "02:aa:00:00:00:01", "02:bb:00:00:00:02", "02:00:00:00:00:fe"


def _trama(ts_us: int, mac: str, ttl: int = 64, window: int = 29200, syn: bool = False, sport: int = 40000) -> Trama:
    return Trama(ts_us=ts_us, longitud=100, mac_src=mac, mac_dst=MAC_DST, ethertype=0x0800,
                 ip_src="10.0.0.20" if mac == MAC_A else "10.0.0.21", ip_dst="93.184.216.34",
                 proto="tcp", sport=sport, dport=443, tcp_flags=0x02 if syn else 0x10,
                 ip_ttl=ttl, ip_id=ts_us % 65536, ip_df=True, tcp_window=window,
                 tcp_options=("MSS", "SAckOK", "Timestamp", "NOP", "WScale") if syn else None,
                 tcp_seq=ts_us % 100000, tcp_ack=1)


def _flujo(n_ventanas: int, mac: str, ttl: int = 64, por_ventana: int = 5) -> list[Trama]:
    tramas = []
    for k in range(n_ventanas):
        for i in range(por_ventana):
            ts = int((5 * k + 0.2 * i + 0.1) * 1_000_000)
            tramas.append(_trama(ts, mac, ttl=ttl, syn=(i == 0), sport=40000 + k))
    return tramas


def _modelo_determinista(x):
    return (x["n_tramas"].to_numpy().astype(float)) / 50.0  # misma X -> misma prob


def test_streaming_reproduce_las_filas_del_lote():
    """La fila de 52 columnas del streaming es idéntica a la del lote (mismo AgregadorVentanas)."""
    tramas = sorted(_flujo(6, MAC_A) + _flujo(6, MAC_B), key=lambda t: t.ts_us)
    cfg = ConfigSegmento()
    batch = {(r["mac"], r["idx_ventana"]): r for r in extraer_ventanas(iter(tramas), cfg)}
    motor = MotorStreaming(config=cfg, modelo=_modelo_determinista, umbral=0.5, con_identidad=False)
    res = motor.reproducir(iter(tramas))
    assert len(res) == len(batch)
    for r in res:
        fila = batch[(r.mac, r.idx_ventana)]
        assert abs(r.probabilidad - fila["n_tramas"] / 50.0) < 1e-9  # misma feature -> misma predicción


def test_alarma_supervisado_al_pasar_el_umbral():
    tramas = _flujo(4, MAC_A, por_ventana=30)  # n_tramas alto -> prob alta
    motor = MotorStreaming(modelo=_modelo_determinista, umbral=0.5, con_identidad=False)
    res = motor.reproducir(iter(tramas))
    assert any(r.alarma_supervisado for r in res)


def test_identidad_en_streaming_detecta_cambio_de_ttl():
    """Un equipo estable y luego un cambio de TTL persistente dispara el canal de identidad."""
    tramas = _flujo(20, MAC_A, ttl=64) + _flujo(10, MAC_A, ttl=128)
    for k, t in enumerate(tramas):  # re-sella los tiempos para que las ventanas avancen
        t.ts_us = int((5 * (k // 5) + 0.2 * (k % 5) + 0.1) * 1_000_000)
    motor = MotorStreaming(modelo=None, con_identidad=True)
    res = motor.reproducir(iter(sorted(tramas, key=lambda t: t.ts_us)))
    assert any(r.alarma_identidad for r in res)


def test_sin_modelo_solo_corre_identidad():
    tramas = _flujo(4, MAC_A)
    motor = MotorStreaming(modelo=None, con_identidad=True)
    res = motor.reproducir(iter(tramas))
    assert res and all(r.probabilidad is None and not r.alarma_supervisado for r in res)


def test_vigilante_en_streaming_ve_conflicto_de_ip():
    """Dos MAC con la misma IP en la red local disparan el vigilante del streaming."""
    base = _flujo(14, MAC_A)
    for t in base:
        t.ip_src = "10.0.0.20"
    intruso = [_trama(int((5 * 14 + 0.3) * 1_000_000), MAC_B)]
    intruso[0].ip_src = "10.0.0.20"  # reclama la IP de A
    motor = MotorStreaming(modelo=None, con_identidad=True, red_local="10.0.0.0/24")
    motor.reproducir(iter(sorted(base + intruso, key=lambda t: t.ts_us)))
    assert motor.metricas["alertas_vigilante"] >= 1


def test_metricas_de_rendimiento():
    tramas = _flujo(5, MAC_A)
    motor = MotorStreaming(modelo=_modelo_determinista, con_identidad=False)
    motor.reproducir(iter(tramas))
    m = motor.resumen_metricas()
    assert m["ventanas"] >= 4 and m["tramas"] == len(tramas) and m["latencia_ms_media"] is not None


def test_columnas_modelo_presentes_en_las_filas():
    tramas = _flujo(3, MAC_A)
    filas = extraer_ventanas(iter(tramas), ConfigSegmento())
    assert set(COLUMNAS_MODELO).issubset(filas[0].keys())
    assert not np.isnan(filas[0]["n_tramas"])
