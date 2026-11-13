"""Pruebas del timeline de laboratorio y coherencia de flujos (etapa E1)."""
from __future__ import annotations

from collections import Counter, defaultdict

import pandas as pd
import pytest

pytest.importorskip("scapy.all")
from scapy.all import ARP, DNS, ICMP, IP, TCP, Dot1Q, Dot3, Ether, rdpcap  # noqa: E402

from scripts.lab import generar_trafico as g  # noqa: E402


@pytest.fixture(scope="module")
def paquetes(sesion_corta):
    return rdpcap(str(sesion_corta[1]))


def test_pcap_ordenado_y_rellenado(paquetes):
    tiempos = [float(p.time) for p in paquetes]
    assert tiempos == sorted(tiempos)
    assert min(len(p) for p in paquetes) >= 60


def test_topologia_y_semilla(sesion_corta):
    sesion, _ = sesion_corta
    assert len(sesion.dispositivos) >= 20
    assert len({d.mac for d in sesion.dispositivos}) == len(sesion.dispositivos)
    assert g.Sesion(1).dispositivos[0].mac != g.Sesion(2).dispositivos[0].mac


def test_mezcla_de_protocolos_benignos(paquetes):
    assert any(Dot3 in p for p in paquetes)
    assert any(Dot1Q in p for p in paquetes)
    assert any(p.haslayer(Ether) and p[Ether].type == 0x88cc for p in paquetes)
    assert any(p.haslayer("DHCP") for p in paquetes)
    assert any(ARP in p and p[ARP].psrc == p[ARP].pdst for p in paquetes)
    assert any(IP in p and p[IP].dst.startswith("224.") for p in paquetes)


def test_flujos_tcp_completos_son_coherentes(sesion_corta):
    """Benigno: SYN/SYN-ACK/ACK en orden, seq/ack encadenados, FIN y MACs por rol (B2)."""
    sesion, _ = sesion_corta
    flujos = defaultdict(list)
    for ts_us, crudo, marca in sesion.tramas:
        if marca is not None:
            continue
        p = Ether(crudo)
        if TCP in p:
            clave = tuple(sorted([(p[IP].src, p[TCP].sport), (p[IP].dst, p[TCP].dport)]))
            flujos[clave].append((ts_us, p))
    verificados = 0
    for tramas in flujos.values():
        primera = tramas[0][1]
        if len(tramas) < 7 or primera[TCP].flags != "S":
            continue
        verificados += 1
        syn, synack, ack = (t[1] for t in tramas[:3])
        assert synack[TCP].flags == "SA" and ack[TCP].flags == "A"
        assert synack[TCP].ack == syn[TCP].seq + 1
        assert ack[TCP].ack == synack[TCP].seq + 1
        assert syn[Ether].src == ack[Ether].src != synack[Ether].src
        assert tramas[0][0] < tramas[1][0] < tramas[2][0]
        cliente = (syn[IP].src, syn[TCP].sport)
        sig = {True: ack[TCP].seq, False: ack[TCP].ack}
        for _, p in tramas[3:]:
            desde_cliente = (p[IP].src, p[TCP].sport) == cliente
            assert p[TCP].seq == sig[desde_cliente]
            datos = len(bytes(p[TCP].payload)) if p[IP].len > 40 else 0
            sig[desde_cliente] = (sig[desde_cliente] + datos + bool(p[TCP].flags.F)) % 2**32
        assert any(p[TCP].flags.F for _, p in tramas)
    assert verificados > 50


def test_dns_y_arp_responden_tras_la_peticion(sesion_corta):
    """Coherencia del benigno. Desde E1 (bloque 3) se omiten las tramas de ataque: la
    variante `kaminsky` envía, a propósito, respuestas DNS sin consulta previa."""
    sesion, _ = sesion_corta
    consultas: dict = {}
    pedidos: set = set()
    respuestas_dns = replies = 0
    for ts_us, crudo, marca in sesion.tramas:
        if marca is not None:
            continue
        p = Ether(crudo)
        p.time = ts_us / 1e6
        if ARP in p and p[ARP].psrc != p[ARP].pdst:
            if p[ARP].op == 1:
                pedidos.add((p[ARP].psrc, p[ARP].pdst))
            elif p[ARP].hwdst != "00:00:00:00:00:00" and (p[ARP].pdst, p[ARP].psrc) in pedidos:
                replies += 1
        if DNS in p and IP in p and 53 in (p.sport, p.dport):
            if p[DNS].qr == 0:
                consultas[(p[IP].src, p.sport, p[DNS].id)] = float(p.time)
            else:
                t = consultas[(p[IP].dst, p.dport, p[DNS].id)]
                assert float(p.time) > t
                respuestas_dns += 1
    assert respuestas_dns > 20 and replies > 5


def test_manifiestos_y_ataques(sesion_corta):
    sesion, ruta = sesion_corta
    tramas = pd.read_csv(ruta.with_suffix(".tramas.csv"))
    episodios = pd.read_csv(ruta.with_suffix(".episodios.csv"))
    assert set(tramas["tipo"]) == set(g.ATAQUES)
    assert set(tramas["episodio"]) <= set(episodios["episodio"])
    assert (episodios["t_fin_s"] > episodios["t_inicio_s"]).all()
    for n, fila in tramas.sample(200, random_state=0).iterrows():
        ts_us, crudo, marca = sesion.tramas[int(fila["n_trama"])]
        assert ts_us == fila["ts_us"] and marca[2] == fila["tipo"]
    # Desde E1 (bloque 3) MAC flooding tiene dos variantes: `ether_aleatorio` conserva una
    # MAC por trama; `rafaga_por_mac` repite cada MAC falsa 2-4 veces.
    flood = tramas[tramas["tipo"] == "mac_flooding"]
    aleatorio = flood[flood["variante"] == "ether_aleatorio"]
    assert len(aleatorio) and aleatorio["mac_src"].nunique() > 0.9 * len(aleatorio)
    por_mac = flood[flood["variante"] == "rafaga_por_mac"].groupby("mac_src").size()
    assert por_mac.empty or por_mac.between(1, 4).all()
    # Atacantes con MACs reutilizadas entre episodios, no una MAC por ataque (B3).
    usos = Counter(episodios["atacante"])
    assert max(usos.values()) > 1


def test_vector_icmp_presente(sesion_corta):
    """Desde E1 (bloque 3) el tipo ICMP depende de la variante (antes: siempre eco, tipo 8)."""
    sesion, _ = sesion_corta
    tipo_por_variante = {"echo": 8, "echo_reply": 0, "unreachable": 3}
    marcadas = [(c, m[3]) for _, c, m in sesion.tramas if m is not None and m[2] == "icmp_flood"]
    assert marcadas
    assert all(Ether(c)[ICMP].type == tipo_por_variante[v] for c, v in marcadas[:200])


def test_generacion_reproducible():
    a, b = g.Sesion(11), g.Sesion(11)
    assert [d.mac for d in a.dispositivos] == [d.mac for d in b.dispositivos]


def test_manifiestos_anotan_intensidad_y_variante(sesion_corta):
    """E1 (bloque 3): cada episodio declara intensidad y variante, también por trama."""
    _, ruta = sesion_corta
    episodios = pd.read_csv(ruta.with_suffix(".episodios.csv"))
    tramas = pd.read_csv(ruta.with_suffix(".tramas.csv"))
    assert {"variante", "intensidad"} <= set(episodios.columns) & set(tramas.columns)
    assert set(episodios["intensidad"]) <= set(g.INTENSIDADES)
    for _, e in episodios.iterrows():
        tabla = g.VARIANTES[e["tipo"]]
        nombres = tabla.get(e["intensidad"], tabla.get("*"))[0]
        metodo = e["variante"].rsplit("_", 1)[0] if e["tipo"] == "arp_spoofing" else e["variante"]
        assert metodo in nombres or (metodo == "respuesta" and e["intensidad"] == "rafaga")
    por_trama = tramas.merge(episodios[["episodio", "intensidad", "variante"]], on="episodio", suffixes=("", "_ep"))
    assert (por_trama["intensidad"] == por_trama["intensidad_ep"]).all()
    assert (por_trama["variante"] == por_trama["variante_ep"]).all()


def test_rangos_de_intensidad_ordenados():
    """Suave por debajo de media y media por debajo de ráfaga, en tasa, para cada ataque."""
    for tipo, rangos in g.RANGOS_ATAQUE.items():
        assert rangos["suave"][0][1] < rangos["media"][0][1] < rangos["rafaga"][0][1], tipo
        assert rangos["suave"][0][0] <= rangos["media"][0][0] < rangos["rafaga"][0][0], tipo
    assert abs(sum(g.PESOS_INTENSIDAD) - 1) < 1e-9
