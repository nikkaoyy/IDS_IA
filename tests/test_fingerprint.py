"""Pruebas unitarias para el extractor de huella IEEE 802.3 (src/fingerprint.py)."""

from src.fingerprint import ExtractorHuellaDigital, HuellaDigital


class MockPaqueteScapy:
    """Simula un paquete capturado por Scapy con capa de enlace."""

    def __init__(self, src: str, raw_type: int | None = 0x0800, length: int = 120, time_val: float = 100.0):
        self.src = src
        self.type = raw_type
        self._length = length
        self.time = time_val

    def __len__(self):
        return self._length


def test_extraer_huella_basica():
    extractor = ExtractorHuellaDigital()
    pkt = MockPaqueteScapy(src="00:1A:2B:3C:4D:5E", raw_type=0x0800, length=64, time_val=1000.0)
    huella = extractor.extraer(pkt)

    assert isinstance(huella, HuellaDigital)
    assert huella.mac_origen == "00:1a:2b:3c:4d:5e"
    assert huella.oui == "001A2B"
    assert huella.longitud_trama == 64
    assert huella.ethertype == 0x0800
    assert huella.es_802_3 is False
    assert huella.tiempo_entre_tramas_ms == 0.0


def test_extraer_sin_capa_enlace():
    extractor = ExtractorHuellaDigital()
    huella = extractor.extraer(object())
    assert huella is None


def test_delta_tiempo_entre_tramas_misma_mac():
    extractor = ExtractorHuellaDigital()
    mac = "AA:BB:CC:11:22:33"
    pkt1 = MockPaqueteScapy(src=mac, time_val=100.0)
    pkt2 = MockPaqueteScapy(src=mac, time_val=100.025)  # 25 ms después

    h1 = extractor.extraer(pkt1)
    h2 = extractor.extraer(pkt2)

    assert h1.tiempo_entre_tramas_ms == 0.0
    assert abs(h2.tiempo_entre_tramas_ms - 25.0) < 1e-3


def test_distincion_802_3_vs_ethernet_ii():
    extractor = ExtractorHuellaDigital()
    # Trama 802.3 LLC con campo longitud = 120 (<= 1500)
    pkt_802_3 = MockPaqueteScapy(src="11:22:33:44:55:66", raw_type=120, length=124)
    h_802_3 = extractor.extraer(pkt_802_3)
    assert h_802_3.es_802_3 is True
    assert h_802_3.ethertype is None

    # Trama Ethernet II con EtherType IPv4 = 0x0800 (2048)
    pkt_eth2 = MockPaqueteScapy(src="11:22:33:44:55:66", raw_type=0x0800, length=124)
    h_eth2 = extractor.extraer(pkt_eth2)
    assert h_eth2.es_802_3 is False
    assert h_eth2.ethertype == 0x0800
