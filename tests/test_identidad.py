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


# --- PEDIDO-E3B-1, bloques 2 y 4: reperfilado y defensas apagables ----------------------

def _confiable(**kw) -> idn.SeguidorIdentidad:
    seg = idn.SeguidorIdentidad(**kw)
    for k in range(idn.MIN_VENTANAS_PERFIL):
        seg.observar(_ventana(k))
    return seg


R = idn.REPERFILAR_REGISTRADO


def test_un_cambio_persistente_reperfila_tras_24_alarmas():
    seg = _confiable(reperfilar_tras=R)
    salidas = [seg.observar(_ventana(20 + k, ttl=128, window=64240)) for k in range(R + 14)]
    assert sum(s["alarma"] for s in salidas) == R
    assert salidas[R - 1]["reperfilado"] and seg.reperfilados == 1
    assert seg.estado == idn.CONFIABLE and seg.perfil["ttl"]["mediana"] == 128


def test_reperfilar_con_el_clon_presente_lo_lava():
    """El hallazgo del bloque 2: si el clon dura más de R ventanas, el perfil nuevo es el suyo."""
    seg = _confiable(reperfilar_tras=R)
    for k in range(R + idn.MIN_VENTANAS_PERFIL):
        seg.observar(_ventana(20 + k, ttl=128, window=64240, opciones=OPC_WIN))
    assert seg.reperfilados == 1 and seg.perfil["ttl"]["mediana"] == 128
    assert seg.observar(_ventana(100))["alarma"]  # la víctima, ya sin clon, pasa a ser la sospechosa


def test_por_defecto_no_se_reperfila():
    seg = _confiable()
    for k in range(3 * R):
        seg.observar(_ventana(20 + k, ttl=128, window=64240))
    assert seg.reperfilados == 0 and seg.estado == idn.SOSPECHOSO


def test_alarmas_intercaladas_no_reperfilan():
    seg = _confiable(reperfilar_tras=R)
    for k in range(60):
        seg.observar(_ventana(20 + k, ttl=128 if k % 2 else 64))
    assert seg.reperfilados == 0


def test_sin_congelar_el_clon_se_aprende():
    seg = _confiable(congelar_en_alerta=False)
    salidas = [seg.observar(_ventana(20 + k, ttl=128, window=64240, opciones=OPC_WIN)) for k in range(10)]
    assert salidas[0]["alarma"] and not salidas[-1]["alarma"]


def test_sin_no_confiable_acusa_desde_la_segunda_ventana():
    seg = idn.SeguidorIdentidad(min_ventanas=1)
    seg.observar(_ventana(0))
    assert seg.estado == idn.CONFIABLE and seg.observar(_ventana(1, ttl=128))["alarma"]



# --- PEDIDO-E3B-1, bloque 3: contadores de IP-ID y vigilante IP → MAC ---------------------

def _ventana_global(k: int, contador: int, n_flujos: int = 2, mac: str = VICTIMA, ip: str = "10.20.0.5",
                    t0: float = 0.5) -> tuple[list[Trama], int]:
    """Tramas de k con un contador de IP-ID global compartido por `n_flujos` flujos intercalados."""
    tramas = []
    for i in range(3 * n_flujos):
        f = i % n_flujos
        contador = (contador + 1) % 65536
        tramas.append(Trama(
            ts_us=int((5 * k + t0 + 0.1 * i) * 1_000_000), longitud=60, mac_src=mac, mac_dst="bb:bb:bb:00:00:01",
            ethertype=0x0800, ip_src=ip, ip_dst="93.184.216.34", proto="tcp", sport=50000 + 10 * k + f, dport=443,
            tcp_flags=0x02 if i < n_flujos else 0x10, ip_ttl=128, ip_id=contador, ip_df=True,
            tcp_window=64240 if i < n_flujos else 502, tcp_options=OPC_WIN if i < n_flujos else None,
            tcp_seq=1000 * i, tcp_ack=0))
    return tramas, contador


def _historia_global(n: int = 15) -> tuple[list[list[Trama]], int]:
    ventanas, c = [], 7000
    for k in range(n):
        v, c = _ventana_global(k, c)
        ventanas.append(v)
    return ventanas, c


def test_contador_global_abre_la_puerta_y_un_segundo_contador_dispara():
    ventanas, c = _historia_global()
    perfil = idn.perfil_dispositivo([t for v in ventanas for t in v])
    assert perfil["ipid_global"]
    limpia, c = _ventana_global(20, c)
    assert idn.desviacion(perfil, limpia)["por_senal"]["ipid_contadores"] == 0.0
    clon, _ = _ventana_global(20, 41000, t0=0.55)  # misma pila, su propio contador
    d = idn.desviacion(perfil, limpia + clon)
    assert d["por_senal"]["ipid_contadores"] == idn.Z_FIRMA_NUEVA and d["puntaje"] > idn.UMBRAL_DESVIACION


def test_contador_por_flujo_deja_la_puerta_cerrada():
    """Linux: cada flujo lleva su contador; dos flujos simultáneos no son dos emisores."""
    tramas = [t for k in range(15)
              for t in _flujo_linux(k, 51000 + k, 3000 + 97 * k, 0.5) + _flujo_linux(k, 52000 + k, 40000 + 13 * k, 0.6)]
    perfil = idn.perfil_dispositivo(tramas)
    assert not perfil["ipid_global"]
    d = idn.desviacion(perfil, _flujo_linux(30, 51000, 100, 0.5) + _flujo_linux(30, 52000, 30000, 0.6))
    assert "ipid_contadores" not in d["por_senal"]


def test_ipid_cero_no_cuenta_como_contador():
    ventanas, c = _historia_global()
    perfil = idn.perfil_dispositivo([t for v in ventanas for t in v])
    limpia, _ = _ventana_global(20, c)
    mdns = [Trama(ts_us=int((100 + 0.3 * i) * 1_000_000), longitud=80, mac_src=VICTIMA, mac_dst="01:00:5e:00:00:fb",
                  ethertype=0x0800, ip_src="10.20.0.5", ip_dst="224.0.0.251", proto="udp", sport=5353, dport=5353,
                  ip_ttl=255, ip_id=0) for i in range(3)]
    assert idn.desviacion(perfil, limpia + mdns)["por_senal"]["ipid_contadores"] == 0.0


def _tramas_ip(k: int, mac: str, ip: str) -> list[Trama]:
    return [Trama(ts_us=int((5 * k + 1) * 1_000_000), longitud=60, mac_src=mac, mac_dst="bb:bb:bb:00:00:01",
                  ethertype=0x0800, ip_src=ip, ip_dst="93.184.216.34", proto="tcp", sport=40000, dport=443)]


def _vigilante_con_vinculo() -> idn.VigilanteIP:
    vig = idn.VigilanteIP()
    for k in range(idn.MIN_VENTANAS_PERFIL):
        assert vig.observar(_tramas_ip(k, VICTIMA, "10.20.0.5"), int(5 * k * 1e6)) == []
    assert vig.vinculo["10.20.0.5"] == VICTIMA
    return vig


def test_misma_ip_con_dos_mac_a_la_vez_es_conflicto():
    vig = _vigilante_con_vinculo()
    a = vig.observar(_tramas_ip(20, VICTIMA, "10.20.0.5") + _tramas_ip(20, CLON, "10.20.0.5"), int(100e6))
    assert [x["tipo"] for x in a] == ["conflicto"]


def test_ip_de_la_victima_callada_con_otra_mac_es_reasignacion():
    vig = _vigilante_con_vinculo()
    a = vig.observar(_tramas_ip(30, CLON, "10.20.0.5"), int(150e6))
    assert [x["tipo"] for x in a] == ["reasignacion"] and a[0]["mac_anterior"] == VICTIMA


def test_pasada_la_gracia_el_vinculo_se_traspasa_sin_alerta():
    vig = _vigilante_con_vinculo()
    k0 = int(idn.GRACIA_REASIGNACION_S / 5) + 20
    alertas = [vig.observar(_tramas_ip(k0 + j, CLON, "10.20.0.5"), int(5 * (k0 + j) * 1e6))
               for j in range(idn.MIN_VENTANAS_PERFIL + 1)]
    assert not any(alertas) and vig.vinculo["10.20.0.5"] == CLON


def test_ip_externa_no_se_vigila():
    vig = idn.VigilanteIP()
    assert vig.observar(_tramas_ip(0, VICTIMA, "93.184.216.34") + _tramas_ip(0, CLON, "93.184.216.34"), 0) == []


# --- PEDIDO-E4C-1, bloque 1: el vigilante alimenta el mapa ip->MAC también con el ARP ---------

def _arp(k: int, mac_src: str, psrc: str, hwsrc: str, op: int = 2) -> list[Trama]:
    """Una trama ARP (sin capa 3): declara `psrc -> hwsrc`; `mac_src` es el Ether.src real."""
    return [Trama(ts_us=int((5 * k + 1) * 1_000_000), longitud=60, mac_src=mac_src, mac_dst="ff:ff:ff:ff:ff:ff",
                  ethertype=0x0806, arp_op=op, arp_psrc=psrc, arp_hwsrc=hwsrc, arp_pdst="10.20.0.1")]


def _vigilante_con_vinculo_arp() -> idn.VigilanteIP:
    """Vínculo 10.20.0.5 -> VICTIMA aprendido solo de anuncios ARP (sin capa 3)."""
    vig = idn.VigilanteIP()
    for k in range(idn.MIN_VENTANAS_PERFIL):
        assert vig.observar(_arp(k, VICTIMA, "10.20.0.5", VICTIMA, op=1), int(5 * k * 1e6)) == []
    assert vig.vinculo["10.20.0.5"] == VICTIMA
    return vig


def test_arp_spoofing_lento_una_trama_dispara_el_vigilante():
    """(a): un ARP falso que reclama la IP de la víctima con otra MAC alarma, con una sola trama."""
    vig = _vigilante_con_vinculo_arp()
    a = vig.observar(_arp(30, CLON, "10.20.0.5", CLON), int(150e6))  # víctima callada, 1 trama
    assert [x["tipo"] for x in a] == ["reasignacion"] and a[0]["mac_anterior"] == VICTIMA


def test_arp_gratuito_del_mismo_equipo_no_dispara():
    """(b): GARP legítimo (misma IP, misma MAC, Ether.src = hwsrc) no es suplantación."""
    vig = _vigilante_con_vinculo_arp()
    assert vig.observar(_arp(30, VICTIMA, "10.20.0.5", VICTIMA), int(150e6)) == []


def test_arp_cambio_secuencial_es_reasignacion_no_conflicto():
    """(c): dos MAC a la vez es conflicto; una MAC nueva con la anterior callada (dentro de la
    gracia de 600 s, que no se toca) es reasignación. Pasada la gracia sigue siendo traspaso
    silencioso (E3B); por eso el caso se mide dentro de la gracia."""
    conflicto = idn.VigilanteIP()
    for k in range(idn.MIN_VENTANAS_PERFIL):
        conflicto.observar(_arp(k, VICTIMA, "10.20.0.5", VICTIMA, op=1), int(5 * k * 1e6))
    a = conflicto.observar(_arp(20, VICTIMA, "10.20.0.5", VICTIMA) + _arp(20, CLON, "10.20.0.5", CLON), int(100e6))
    assert [x["tipo"] for x in a] == ["conflicto"]
    reasig = _vigilante_con_vinculo_arp()
    b = reasig.observar(_arp(40, CLON, "10.20.0.5", CLON), int(200e6))
    assert [x["tipo"] for x in b] == ["reasignacion"]


def test_dos_conexiones_solapadas_de_un_contador_global_no_son_dos_contadores(monkeypatch):
    """IDs intercalados de un mismo bloque contiguo: un contador (grupos); las cadenas registradas fallaban."""
    ventanas, c = _historia_global()
    perfil = idn.perfil_dispositivo([t for v in ventanas for t in v])
    base = ventanas[0][0]
    ids = [c + 1, c + 6, c + 2, c + 7, c + 3, c + 8, c + 4, c + 5]
    solapadas = [Trama(ts_us=int((200 + 0.01 * i) * 1e6), longitud=60, mac_src=VICTIMA, mac_dst=base.mac_dst,
                       ip_src=base.ip_src, ip_dst=base.ip_dst, proto="tcp", sport=60000 + (i % 2), dport=443,
                       ip_ttl=128, ip_id=x % 65536) for i, x in enumerate(ids)]
    assert idn.desviacion(perfil, solapadas)["por_senal"]["ipid_contadores"] == 0.0
    monkeypatch.setattr(idn, "IPID_CONTADORES_MODO", "cadenas")
    assert idn.desviacion(perfil, solapadas)["por_senal"]["ipid_contadores"] == idn.Z_FIRMA_NUEVA
