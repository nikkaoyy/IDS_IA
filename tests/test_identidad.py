"""Pruebas del perfil de pila por dispositivo (PEDIDO-E3A-1, bloque 2)."""
from __future__ import annotations

import math

import pytest

from src import identidad as idn
from src.ventanas import Trama

VICTIMA, CLON = "aa:aa:aa:00:00:01", "aa:aa:aa:00:00:99"
OPC_LINUX = ("MSS", "SAckOK", "Timestamp", "NOP", "WScale")
OPC_WIN = ("MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK")


def _ventana(k: int, mac: str = VICTIMA, ttl: int = 64, window: int = 29200, opciones=OPC_LINUX,
             ipid0: int | None = None, n: int = 4) -> list[Trama]:
    """n tramas TCP de la ventana k: una SYN y el resto del mismo flujo, IP-ID incremental."""
    base = (ipid0 if ipid0 is not None else 1000 + 10 * k) % 65536
    tramas = []
    for i in range(n):
        syn = i == 0
        tramas.append(Trama(
            ts_us=int((5 * k + 0.5 + 0.1 * i) * 1_000_000), longitud=60, mac_src=mac, mac_dst="bb:bb:bb:00:00:01",
            ethertype=0x0800, ip_src="10.0.0.5", ip_dst="10.0.0.80", proto="tcp", sport=40000 + k, dport=443,
            tcp_flags=0x02 if syn else 0x10, ip_ttl=ttl, ip_id=(base + i) % 65536, ip_df=True,
            tcp_window=window if syn else 501, tcp_options=opciones if syn else ("NOP", "NOP", "Timestamp"),
            tcp_seq=10_000 * k + 100 * i, tcp_ack=0 if syn else 1))
    return tramas


def _perfil_estable(n_ventanas: int = 20) -> dict:
    return idn.perfil_dispositivo([t for k in range(n_ventanas) for t in _ventana(k)])


def test_dispositivo_estable_no_dispara():
    perfil = _perfil_estable()
    assert perfil["estado"] == idn.CONFIABLE and perfil["ttl"]["mediana"] == 64
    d = idn.desviacion(perfil, _ventana(30))
    assert d["puntaje"] <= idn.UMBRAL_DESVIACION and d["senales"] >= 4


def test_ttl_distinto_dispara():
    d = idn.desviacion(_perfil_estable(), _ventana(30, ttl=128))
    assert d["puntaje"] > idn.UMBRAL_DESVIACION and d["por_senal"]["ttl"] > idn.UMBRAL_DESVIACION


def test_ventana_tcp_distinta_dispara():
    d = idn.desviacion(_perfil_estable(), _ventana(30, window=64240))
    assert d["puntaje"] > idn.UMBRAL_DESVIACION and d["por_senal"]["tcp_window"] > idn.UMBRAL_DESVIACION


def test_opciones_nuevas_disparan():
    d = idn.desviacion(_perfil_estable(), _ventana(30, opciones=OPC_WIN))
    assert d["por_senal"]["tcp_opciones"] == idn.Z_FIRMA_NUEVA


def test_misma_pila_con_otra_mac_no_dispara():
    """La MAC no es una señal de pila: un equipo con la misma pila y otra MAC no se distingue."""
    d = idn.desviacion(_perfil_estable(), _ventana(30, mac=CLON))
    assert d["puntaje"] <= idn.UMBRAL_DESVIACION


def test_dos_ventanas_es_no_confiable():
    perfil = _perfil_estable(n_ventanas=2)
    assert perfil["estado"] == idn.NO_CONFIABLE and perfil["n_ventanas"] == 2
    seg = idn.SeguidorIdentidad()
    salidas = [seg.observar(_ventana(k, ttl=64 if k == 0 else 128)) for k in range(2)]
    assert not any(s["alarma"] for s in salidas) and seg.estado == idn.NO_CONFIABLE


def test_el_pico_no_mueve_la_mediana():
    tramas = [t for k in range(20) for t in _ventana(k, ttl=128 if k in (3, 9) else 64)]
    assert idn.perfil_dispositivo(tramas)["ttl"]["mediana"] == 64


def test_senales_que_faltan_no_se_inventan():
    perfil = _perfil_estable()
    udp = [Trama(ts_us=150_000_000, longitud=80, mac_src=VICTIMA, mac_dst="bb", ip_src="10.0.0.5",
                 ip_dst="10.0.0.2", proto="udp", sport=5000, dport=53, ip_ttl=64, ip_id=1300)]
    d = idn.desviacion(perfil, udp)
    assert set(d["por_senal"]) == {"ttl"} and d["puntaje"] == 0.0
    sin_ip = [Trama(ts_us=150_000_000, longitud=60, mac_src=VICTIMA, mac_dst="ff", ethertype=0x0806, arp_op=1)]
    assert math.isnan(idn.desviacion(perfil, sin_ip)["puntaje"])


def test_sin_aprendizaje_durante_la_alerta():
    """Un clon no se vuelve «normal»: mientras hay alarma, sus ventanas no entran en el perfil."""
    seg = idn.SeguidorIdentidad()
    for k in range(idn.MIN_VENTANAS_PERFIL):
        seg.observar(_ventana(k))
    assert seg.estado == idn.CONFIABLE
    n_historia = len(seg.historia)
    salidas = [seg.observar(_ventana(k, ttl=128, window=64240, opciones=OPC_WIN)) for k in range(20, 40)]
    assert all(s["alarma"] for s in salidas) and seg.estado == idn.SOSPECHOSO
    assert len(seg.historia) == n_historia and not any(s["aprendio"] for s in salidas)


def test_recupera_tras_ventanas_limpias_sin_aprenderlas():
    seg = idn.SeguidorIdentidad()
    for k in range(idn.MIN_VENTANAS_PERFIL):
        seg.observar(_ventana(k))
    seg.observar(_ventana(20, ttl=128))
    n = len(seg.historia)
    limpias = [seg.observar(_ventana(21 + i)) for i in range(idn.VENTANAS_LIMPIAS_PARA_RECUPERAR)]
    assert seg.estado == idn.CONFIABLE and len(seg.historia) == n
    assert not any(s["aprendio"] for s in limpias)
    assert seg.observar(_ventana(30))["aprendio"]


def test_tope_de_actualizaciones_por_dia(monkeypatch):
    monkeypatch.setattr(idn, "TOPE_ACTUALIZACIONES_DIA", 3)
    seg = idn.SeguidorIdentidad()
    for k in range(idn.MIN_VENTANAS_PERFIL + 10):
        seg.observar(_ventana(k))
    assert len(seg.historia) == idn.MIN_VENTANAS_PERFIL + 3


@pytest.mark.parametrize("ipid", ["global", "aleatorio", "cero"])
def test_continuidad_de_ip_id(ipid):
    import random
    rng = random.Random(1)
    tramas = _ventana(0, n=10)
    for i, t in enumerate(tramas):
        t.ip_id = {"global": 500 + i, "aleatorio": rng.randrange(65536), "cero": 0}[ipid]
    s = idn.senales_ventana(tramas)
    esperado = {"global": 1.0, "aleatorio": 0.0, "cero": 0.0}[ipid]
    assert s["ipid_continuidad"] == pytest.approx(esperado, abs=0.12)


def test_clon_minoritario_en_la_misma_ventana_dispara():
    """Tres tramas de la víctima y una del clon con la misma MAC: la mediana esconde al clon; el valor no."""
    mezcla = _ventana(30) + _ventana(30, ttl=128, window=64240, n=1)
    assert idn.senales_ventana(mezcla)["ttl"] == 64
    assert idn.desviacion(_perfil_estable(), mezcla)["puntaje"] > idn.UMBRAL_DESVIACION


def test_un_valor_legitimo_repetido_se_aprende():
    """El TTL 255 del mDNS aparece en varias ventanas del perfil: no dispara."""
    def con_mdns(k):
        mdns = Trama(ts_us=int((5 * k + 4) * 1_000_000), longitud=90, mac_src=VICTIMA, mac_dst="01:00:5e:00:00:fb",
                     ip_src="10.0.0.5", ip_dst="224.0.0.251", proto="udp", sport=5353, dport=5353, ip_ttl=255, ip_id=0)
        return _ventana(k) + ([mdns] if k % 4 == 0 else [])
    perfil = idn.perfil_dispositivo([t for k in range(20) for t in con_mdns(k)])
    assert perfil["ttl_valores"][255] >= idn.MIN_APARICIONES_VALOR
    assert idn.desviacion(perfil, con_mdns(32))["por_senal"]["ttl"] == 0.0



# --- PEDIDO-E3B-1, bloque 1: IP-ID por flujo ----------------------------------------------

def _flujo_linux(k: int, sport: int, base: int, t0: float, n: int = 4) -> list[Trama]:
    """Un flujo con su propio contador de IP-ID (Linux): base propia, +1 por trama."""
    return [Trama(ts_us=int((5 * k + t0 + 0.2 * i) * 1_000_000), longitud=60, mac_src=VICTIMA, mac_dst="bb",
                  ip_src="10.0.0.5", ip_dst="10.0.0.80", proto="tcp", sport=sport, dport=443,
                  tcp_flags=0x02 if i == 0 else 0x10, ip_ttl=64, ip_id=(base + i) % 65536, ip_df=True,
                  tcp_window=29200 if i == 0 else 501, tcp_options=OPC_LINUX if i == 0 else ("NOP",),
                  tcp_seq=1000 * i, tcp_ack=1) for i in range(n)]


def _perfil_linux_un_flujo() -> dict:
    return idn.perfil_dispositivo([t for k in range(20) for t in _flujo_linux(k, 40000 + k, 997 * k + 13, 0.5)])


def test_dos_flujos_simultaneos_del_mismo_equipo_no_disparan():
    """Cada conexión lleva su contador: la mezcla de dos en una ventana no es una anomalía."""
    perfil = _perfil_linux_un_flujo()
    dos = sorted(_flujo_linux(30, 51000, 100, 0.5) + _flujo_linux(30, 52000, 40000, 0.6), key=lambda t: t.ts_us)
    d = idn.desviacion(perfil, dos)
    assert d["puntaje"] <= idn.UMBRAL_DESVIACION
    assert len(idn.senales_ventana(dos)["ipid_continuidad_valores"]) == 2


def test_la_version_por_equipo_si_disparaba_con_dos_flujos(monkeypatch):
    """Documenta por qué se descartó: con IPID_MODO = "equipo" la misma ventana da alarma."""
    monkeypatch.setattr(idn, "IPID_MODO", "equipo")
    perfil = _perfil_linux_un_flujo()
    dos = sorted(_flujo_linux(30, 51000, 100, 0.5) + _flujo_linux(30, 52000, 40000, 0.6), key=lambda t: t.ts_us)
    assert idn.desviacion(perfil, dos)["puntaje"] > idn.UMBRAL_DESVIACION


def test_un_flujo_con_ipid_aleatorio_en_un_equipo_por_flujo_dispara():
    """El cambio no ciega la señal: un flujo cuyo IP-ID salta al azar sigue delatándose."""
    import random
    rng = random.Random(3)
    raro = _flujo_linux(30, 53000, 0, 0.5, n=6)
    for t in raro:
        t.ip_id = rng.randrange(65536)
    assert idn.desviacion(_perfil_linux_un_flujo(), raro)["puntaje"] > idn.UMBRAL_DESVIACION
