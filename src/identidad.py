"""
Identidad del dispositivo por su perfil de pila (PEDIDO-E3A-1; etapa E3, OE3).

E2 responde «¿esto es un ataque?»; este módulo responde «¿este equipo es el que dice ser?».
Las señales de pila (TTL, IP-ID, ventana y opciones TCP del SYN, continuidad de SEQ)
describen al equipo, no una violación: **no entran en `feature_schema.py` ni en
`COLUMNAS_MODELO`**. Viven aquí, con su propio perfil por dispositivo.

Señales por ventana de 5 s (solo tramas emitidas por el equipo):

- `ttl`: mediana del TTL IP.
- `tcp_window`: mediana de la ventana anunciada en SYN / SYN-ACK (la del arranque de la
  conexión es la que fija el sistema operativo; la de mitad de flujo varía con la carga).
- `tcp_opciones`: firmas (tupla de nombres) vistas en SYN / SYN-ACK. Categórica.
- `ipid_continuidad`: fracción de saltos de IP-ID entre tramas consecutivas **del mismo
  flujo** (destino, protocolo, puertos; flujos con ≥ 3 tramas) en [1, 2048]. Contador global
  o por flujo ≈ 1; aleatorio ≈ 0,03; cero con DF = 0. Un valor por flujo (PEDIDO-E3B-1).
- `ipid_salto_log2`: log2(1 + salto mediano de IP-ID dentro del flujo). Un valor por flujo.
  **Descartada la versión por equipo** (E3A): medía el salto entre tramas consecutivas del
  equipo y, con dos conexiones en la misma ventana, el salto era aleatorio. Dio 16,2 FA por
  dispositivo-día. Queda accesible con `IPID_MODO = "equipo"` solo para reproducir esa cifra.
- `seq_continuidad`: fracción de pares consecutivos del mismo flujo con SEQ que avanza menos
  de 2^20.

Perfil: **mediana y MAD** por señal numérica entre ventanas, más el mínimo y el máximo
vistos (informativos); para las opciones, el conjunto de firmas vistas. Sin promedios: un
pico no mueve una mediana.

Valores por trama: el clon emite con la MAC de la víctima y sus tramas comparten ventana con
las de ella; una mediana por ventana escondería a un clon minoritario. Por eso TTL y ventana
TCP se juzgan **por valor distinto** presente en la ventana: un valor que el perfil ya vio en
al menos `MIN_APARICIONES_VALOR` ventanas no cuenta (así se aprende, por ejemplo, el TTL 255
del mDNS legítimo); uno nuevo se mide contra la mediana y la MAD.

Decisiones fijadas antes de medir:

- `MIN_VENTANAS_PERFIL = 12`: doce ventanas con señal de pila, un minuto de actividad. Con
  n = 12 la mediana aguanta hasta 5 ventanas raras (punto de ruptura del 50 %) y la MAD deja
  de ser 0 por azar con pocas muestras. Además coincide con la ventana larga de 60 s del
  extractor. Por debajo, el equipo está `no_confiable` y no se le puede acusar.
- Puntaje = máximo, entre las señales disponibles en ambos lados, de |x − mediana| /
  max(1,4826·MAD, piso absoluto, 1 % de |mediana|). Una firma de opciones nunca vista vale
  `Z_FIRMA_NUEVA`. Las señales que faltan no aportan nada: no se inventan valores.
- Alarma si el puntaje supera `UMBRAL_DESVIACION = 6` (seis desviaciones robustas).
- Sin aprendizaje durante alertas: un equipo `sospechoso` no actualiza el perfil. Vuelve a
  `confiable` tras `VENTANAS_LIMPIAS_PARA_RECUPERAR` ventanas seguidas sin alarma, que
  tampoco se aprenden.
- Actualización limitada: como mucho una ventana por llamada, `TOPE_ACTUALIZACIONES_DIA`
  por día una vez confiable, y una historia de `HISTORIA_MAX` ventanas. El perfil deriva
  despacio a propósito.
- Reperfilado (PEDIDO-E3B-1, bloque 2): tras `REPERFILAR_REGISTRADO = 24` ventanas con
  alarma seguidas (dos minutos de contradicción continua), el equipo vuelve a
  `no_confiable` y rehace el perfil desde cero. Se registró como defensa por defecto para que
  un cambio legítimo y persistente (una actualización) no quedara acusado para siempre.
  Medido, **lava el clon**: si el clon dura más de dos minutos, el perfil se rehace con él
  dentro y la víctima acumula falsas alarmas cuando se va (0,38 → 12,05 FA/disp-día en las
  sesiones de E3A), y solo rescata 7 de 40 actualizaciones porque las ventanas sin SYN cortan
  la racha. Queda **apagado por defecto** (`REPERFILAR_TRAS_ALARMAS = inf`, decisión tomada
  después de medir y declarada así) y disponible para la ablación.
"""

from __future__ import annotations

import ipaddress
import math
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

import numpy as np

from .ventanas import Trama

VENTANA_S: float = 5.0
MIN_VENTANAS_PERFIL: int = 12
MIN_APARICIONES_VALOR: int = 2
SENALES_POR_VALOR: tuple[str, ...] = ("ttl", "tcp_window")
SENALES_POR_FLUJO: tuple[str, ...] = ("ipid_continuidad", "ipid_salto_log2")
MIN_TRAMAS_FLUJO_IPID: int = 3
IPID_MODO: str = "flujo"  # "equipo": versión descartada de E3A, solo para comparar
UMBRAL_DESVIACION: float = 6.0
Z_FIRMA_NUEVA: float = 10.0
VENTANAS_LIMPIAS_PARA_RECUPERAR: int = 3
TOPE_ACTUALIZACIONES_DIA: int = 96
REPERFILAR_REGISTRADO: int = 24  # valor registrado en E3B (2 min de alarma continua); lava el clon
REPERFILAR_TRAS_ALARMAS: float = math.inf  # apagado por defecto tras medirlo (ver docstring)
HISTORIA_MAX: int = 120
SALTO_IPID_CONTINUO: int = 2048
JUZGAR_CONTADORES_IPID: bool = True  # E3B bloque 3; False reproduce las cifras del bloque 2
IPID_CONTADORES_MODO: str = "grupos"  # "cadenas": versión registrada, rota por el orden (ver _cadenas_ipid)
MIN_VENTANAS_CRUCE: int = 3
FRACCION_CRUCE: float = 0.8
RED_LOCAL: str = "10.20.0.0/16"
GRACIA_REASIGNACION_S: float = 600.0
SALTO_SEQ_CONTINUO: int = 1 << 20
ESCALA_MAD: float = 1.4826
PISO_RELATIVO: float = 0.01

SENALES_NUMERICAS: tuple[str, ...] = ("ttl", "tcp_window", "ipid_continuidad", "ipid_salto_log2", "seq_continuidad")
PISOS: dict[str, float] = {
    "ttl": 1.0,
    "tcp_window": 1.0,
    "ipid_continuidad": 0.1,
    "ipid_salto_log2": 1.0,
    "seq_continuidad": 0.1,
}
NO_CONFIABLE, CONFIABLE, SOSPECHOSO = "no_confiable", "confiable", "sospechoso"


def _es_apertura(t: Trama) -> bool:
    return t.proto == "tcp" and bool(t.tcp_flags & 0x02)


def senales_ventana(tramas: Sequence[Trama]) -> dict:
    """Señales de pila de un conjunto de tramas emitidas por un mismo equipo (una ventana).

    Las que no se pueden calcular valen NaN (numéricas) o un conjunto vacío (opciones).
    """
    ip = [t for t in tramas if t.ip_ttl is not None]
    apert = [t for t in ip if _es_apertura(t)]
    s: dict = {k: math.nan for k in SENALES_NUMERICAS}
    s["tcp_opciones"] = frozenset(t.tcp_options for t in apert if t.tcp_options is not None)
    s["ttl_valores"] = frozenset(t.ip_ttl for t in ip)
    ventanas_tcp = [t.tcp_window for t in apert if t.tcp_window is not None]
    s["tcp_window_valores"] = frozenset(ventanas_tcp)
    if ip:
        s["ttl"] = float(np.median([t.ip_ttl for t in ip]))
    if ventanas_tcp:
        s["tcp_window"] = float(np.median(ventanas_tcp))
    _senales_ipid(ip, s)
    _cadenas_ipid(ip, s)
    flujos: dict[tuple, list[int]] = {}
    for t in sorted((t for t in ip if t.tcp_seq is not None), key=lambda t: t.ts_us):
        flujos.setdefault((t.ip_dst, t.sport, t.dport), []).append(t.tcp_seq)
    pares = [(b - a) % (1 << 32) for seqs in flujos.values() for a, b in zip(seqs, seqs[1:])]
    if pares:
        s["seq_continuidad"] = float(np.mean(np.array(pares) < SALTO_SEQ_CONTINUO))
    return s


def _continuidad_y_salto(ids: list[int]) -> tuple[float, float]:
    saltos = np.array([(b - a) % 65536 for a, b in zip(ids, ids[1:])])
    return (float(np.mean((saltos >= 1) & (saltos <= SALTO_IPID_CONTINUO))),
            float(np.log2(1 + np.median(saltos))))


def _senales_ipid(ip: Sequence[Trama], s: dict) -> None:
    """Continuidad y salto de IP-ID: por flujo (vigente) o por equipo (descartada en E3B)."""
    ordenadas = [t for t in sorted(ip, key=lambda t: t.ts_us) if t.ip_id is not None]
    if IPID_MODO == "equipo":
        if len(ordenadas) >= 2:
            c, salto = _continuidad_y_salto([t.ip_id for t in ordenadas])
            s["ipid_continuidad"], s["ipid_salto_log2"] = c, salto
            s["ipid_continuidad_valores"], s["ipid_salto_log2_valores"] = (c,), (salto,)
        return
    flujos: dict[tuple, list[int]] = {}
    for t in ordenadas:
        flujos.setdefault((t.ip_dst, t.proto, t.sport, t.dport), []).append(t.ip_id)
    pares = [_continuidad_y_salto(ids) for ids in flujos.values() if len(ids) >= MIN_TRAMAS_FLUJO_IPID]
    if pares:
        s["ipid_continuidad_valores"] = tuple(c for c, _ in pares)
        s["ipid_salto_log2_valores"] = tuple(x for _, x in pares)
        s["ipid_continuidad"] = float(np.median(s["ipid_continuidad_valores"]))
        s["ipid_salto_log2"] = float(np.median(s["ipid_salto_log2_valores"]))


def _cadenas_ipid(ip: Sequence[Trama], s: dict) -> None:
    """Contadores de IP-ID simultáneos en la ventana (PEDIDO-E3B-1, bloque 3).

    Encadena los IP-ID distintos de 0 en orden temporal: cada uno se une a la cadena cuyo
    último ID queda entre 1 y `SALTO_IPID_CONTINUO` por detrás (la más cercana). Un equipo con
    contador global produce una sola cadena que cruza flujos; dos emisores con contador global
    producen dos.
    """
    ordenadas = [t for t in sorted(ip, key=lambda t: t.ts_us) if t.ip_id]
    if not ordenadas:
        return
    s["ipid_multiflujo"] = len({(t.ip_dst, t.proto, t.sport, t.dport) for t in ordenadas}) >= 2
    if IPID_CONTADORES_MODO == "grupos":
        _grupos_ipid(ordenadas, s)
        return
    cadenas: list[list] = []  # [último ID, tramas, flujos]
    for t in ordenadas:
        flujo = (t.ip_dst, t.proto, t.sport, t.dport)
        candidatas = [(g, c) for c in cadenas if 1 <= (g := (t.ip_id - c[0]) % 65536) <= SALTO_IPID_CONTINUO]
        if candidatas:
            c = min(candidatas, key=lambda gc: gc[0])[1]
            c[0], c[1] = t.ip_id, c[1] + 1
            c[2].add(flujo)
        else:
            cadenas.append([t.ip_id, 1, {flujo}])
    largas = [c for c in cadenas if c[1] >= 2]
    s["ipid_cruce"] = any(len(c[2]) >= 2 for c in largas)
    s["ipid_contadores_extra"] = max(0, len(largas) - 1)


def _grupos_ipid(ordenadas: Sequence[Trama], s: dict) -> None:
    """Contadores como grupos de IDs separados por más de `SALTO_IPID_CONTINUO` (corrección post hoc).

    Los IDs se ordenan por valor en el círculo módulo 65536 y cada hueco mayor que el salto separa
    dos grupos. No depende del orden de llegada: dos conexiones solapadas de un mismo contador
    global forman un único bloque contiguo aunque sus IDs lleguen intercalados.
    """
    por_valor = sorted(ordenadas, key=lambda t: t.ip_id)
    ids = [t.ip_id for t in por_valor]
    huecos = [(b - a) for a, b in zip(ids, ids[1:])] + [ids[0] + 65536 - ids[-1]]
    cortes = [i for i, h in enumerate(huecos) if h > SALTO_IPID_CONTINUO]
    if not cortes:
        grupos = [por_valor]
    else:  # el grupo k empieza justo después del corte k (circular)
        n = len(por_valor)
        grupos = []
        for j, c in enumerate(cortes):
            fin = cortes[(j + 1) % len(cortes)]
            idx = [(c + 1 + m) % n for m in range((fin - c) % n or n)]
            grupos.append([por_valor[i] for i in idx])
    largos = [g for g in grupos if len(g) >= 2]
    s["ipid_cruce"] = any(len({(t.ip_dst, t.proto, t.sport, t.dport) for t in g}) >= 2 for g in largos)
    s["ipid_contadores_extra"] = max(0, len(largos) - 1)


def tiene_senal(s: dict) -> bool:
    """¿La ventana aporta alguna señal de pila? Solo esas cuentan para el perfil."""
    return bool(s["tcp_opciones"]) or any(not math.isnan(s[k]) for k in SENALES_NUMERICAS)


def perfil_desde_senales(ventanas: Sequence[dict]) -> dict:
    """Perfil robusto a partir de las señales de varias ventanas."""
    ventanas = [v for v in ventanas if tiene_senal(v)]
    perfil: dict = {"n_ventanas": len(ventanas),
                    "estado": CONFIABLE if len(ventanas) >= MIN_VENTANAS_PERFIL else NO_CONFIABLE}
    for k in SENALES_NUMERICAS:
        if k in SENALES_POR_FLUJO:
            x = np.array([x for v in ventanas for x in v.get(f"{k}_valores", ())])
        else:
            x = np.array([v[k] for v in ventanas if not math.isnan(v[k])])
        if len(x):
            med = float(np.median(x))
            perfil[k] = {"mediana": med, "mad": float(np.median(np.abs(x - med))),
                         "min": float(x.min()), "max": float(x.max()), "n": int(len(x))}
    firmas: set = set()
    for v in ventanas:
        firmas |= v["tcp_opciones"]
    perfil["tcp_opciones"] = frozenset(firmas)
    for k in SENALES_POR_VALOR:
        apariciones: dict[float, int] = {}
        for v in ventanas:
            for x in v.get(f"{k}_valores", ()):
                apariciones[x] = apariciones.get(x, 0) + 1
        perfil[f"{k}_valores"] = apariciones
    multi = [v for v in ventanas if v.get("ipid_multiflujo")]
    cruzan = [v for v in multi if v.get("ipid_cruce") and v.get("ipid_contadores_extra", 0) == 0]
    perfil["ipid_global"] = len(multi) >= MIN_VENTANAS_CRUCE and len(cruzan) >= FRACCION_CRUCE * len(multi)
    return perfil


def agrupar_por_ventana(tramas: Iterable[Trama], ventana_s: float = VENTANA_S) -> list[list[Trama]]:
    """Tramas en ventanas de `ventana_s`, en orden temporal (las vacías no aparecen)."""
    grupos: dict[int, list[Trama]] = {}
    for t in tramas:
        grupos.setdefault(int(t.ts_us // (ventana_s * 1_000_000)), []).append(t)
    return [grupos[k] for k in sorted(grupos)]


def perfil_dispositivo(tramas: Iterable[Trama], ventana_s: float = VENTANA_S) -> dict:
    """Perfil de pila de un equipo: mediana y MAD por señal entre sus ventanas.

    Con menos de `MIN_VENTANAS_PERFIL` ventanas con señal, `estado` = `no_confiable`.
    """
    return perfil_desde_senales([senales_ventana(g) for g in agrupar_por_ventana(tramas, ventana_s)])


def desviacion_senales(perfil: dict, s: dict) -> dict:
    """Puntaje de una ventana de señales frente al perfil; solo señales presentes en ambos."""
    por_senal: dict[str, float] = {}
    for k in SENALES_NUMERICAS:
        if k in perfil and not math.isnan(s[k]):
            p = perfil[k]
            escala = max(ESCALA_MAD * p["mad"], PISOS[k], PISO_RELATIVO * abs(p["mediana"]))
            if k in SENALES_POR_VALOR:
                vistos = perfil.get(f"{k}_valores", {})
                nuevos = [x for x in s.get(f"{k}_valores", ()) if vistos.get(x, 0) < MIN_APARICIONES_VALOR]
                por_senal[k] = max((abs(x - p["mediana"]) / escala for x in nuevos), default=0.0)
            elif k in SENALES_POR_FLUJO:
                por_senal[k] = max(abs(x - p["mediana"]) / escala for x in s[f"{k}_valores"])
            else:
                por_senal[k] = abs(s[k] - p["mediana"]) / escala
    if JUZGAR_CONTADORES_IPID and perfil.get("ipid_global") and "ipid_contadores_extra" in s:
        por_senal["ipid_contadores"] = Z_FIRMA_NUEVA if s["ipid_contadores_extra"] >= 1 else 0.0
    if s["tcp_opciones"] and perfil.get("tcp_opciones"):
        por_senal["tcp_opciones"] = 0.0 if s["tcp_opciones"] <= perfil["tcp_opciones"] else Z_FIRMA_NUEVA
    puntaje = max(por_senal.values()) if por_senal else math.nan
    return {"puntaje": puntaje, "por_senal": por_senal, "senales": len(por_senal)}


def desviacion(perfil: dict, tramas: Sequence[Trama]) -> dict:
    """Puntaje normalizado por MAD de unas tramas frente al perfil (NaN si no hay señal común)."""
    return desviacion_senales(perfil, senales_ventana(tramas))


@dataclass
class SeguidorIdentidad:
    """Perfil vivo de un equipo, ventana a ventana, con congelación durante alertas.

    `observar` recibe las tramas de una ventana del equipo y devuelve puntaje, alarma y
    estado. No acusa mientras el perfil sea `no_confiable`.

    Las tres defensas se pueden apagar para la ablación de PEDIDO-E3B-1 (bloque 4):
    `congelar_en_alerta=False` aprende también las ventanas con alarma; `tope_diario=math.inf`
    quita el tope; `min_ventanas=1` acusa desde la segunda ventana (sin `no_confiable`).
    `reperfilar_tras` (E3B, bloque 2): tras ese número de ventanas con alarma seguidas, el
    equipo vuelve a `no_confiable` y rehace el perfil; `math.inf` lo desactiva. `None` en
    cualquiera de ellos toma la constante del módulo.
    """

    congelar_en_alerta: bool = True
    tope_diario: float | None = None
    min_ventanas: int | None = None
    reperfilar_tras: float | None = None
    historia: deque = field(default_factory=lambda: deque(maxlen=HISTORIA_MAX))
    estado: str = NO_CONFIABLE
    limpias_seguidas: int = 0
    alarmas_seguidas: int = 0
    reperfilados: int = 0
    actualizaciones_dia: dict[int, int] = field(default_factory=dict)
    _perfil: dict | None = None

    def __post_init__(self) -> None:
        self.tope_diario = TOPE_ACTUALIZACIONES_DIA if self.tope_diario is None else self.tope_diario
        self.min_ventanas = MIN_VENTANAS_PERFIL if self.min_ventanas is None else self.min_ventanas
        self.reperfilar_tras = REPERFILAR_TRAS_ALARMAS if self.reperfilar_tras is None else self.reperfilar_tras

    @property
    def perfil(self) -> dict:
        if self._perfil is None:
            self._perfil = perfil_desde_senales(list(self.historia))
        return self._perfil

    def _aprender(self, s: dict, dia: int) -> bool:
        confiable = len(self.historia) >= self.min_ventanas
        if confiable and self.actualizaciones_dia.get(dia, 0) >= self.tope_diario:
            return False
        self.historia.append(s)
        if confiable:
            self.actualizaciones_dia[dia] = self.actualizaciones_dia.get(dia, 0) + 1
        self._perfil = None
        return True

    def _reperfilar(self) -> None:
        self.historia.clear()
        self._perfil = None
        self.estado, self.alarmas_seguidas, self.limpias_seguidas = NO_CONFIABLE, 0, 0
        self.reperfilados += 1

    def observar(self, tramas: Sequence[Trama], ts_us: int | None = None) -> dict:
        """Procesa una ventana del equipo; aprende solo si no hay alerta (salvo ablación)."""
        s = senales_ventana(tramas)
        ts = ts_us if ts_us is not None else (min(t.ts_us for t in tramas) if tramas else 0)
        dia = int(ts // 86_400_000_000)
        salida = {"puntaje": math.nan, "alarma": False, "estado": self.estado, "aprendio": False,
                  "reperfilado": False}
        if not tiene_senal(s):
            return salida
        if self.estado == NO_CONFIABLE:
            salida["aprendio"] = self._aprender(s, dia)
            if len(self.historia) >= self.min_ventanas:
                self.estado = CONFIABLE
            salida["estado"] = self.estado
            return salida
        d = desviacion_senales(self.perfil, s)
        salida["puntaje"] = d["puntaje"]
        salida["por_senal"] = d["por_senal"]
        alarma = not math.isnan(d["puntaje"]) and d["puntaje"] > UMBRAL_DESVIACION
        salida["alarma"] = alarma
        if alarma:
            self.estado, self.limpias_seguidas = SOSPECHOSO, 0
            self.alarmas_seguidas += 1
            if not self.congelar_en_alerta:
                salida["aprendio"] = self._aprender(s, dia)
            if self.alarmas_seguidas >= self.reperfilar_tras:
                self._reperfilar()
                salida["reperfilado"] = True
        else:
            self.alarmas_seguidas = 0
            if self.estado == SOSPECHOSO:
                self.limpias_seguidas += 1
                if self.limpias_seguidas >= VENTANAS_LIMPIAS_PARA_RECUPERAR:
                    self.estado = CONFIABLE
            else:
                salida["aprendio"] = self._aprender(s, dia)
        salida["estado"] = self.estado
        return salida


@dataclass
class VigilanteIP:
    """Vínculo IP → MAC de la red local (PEDIDO-E3B-1, bloque 3).

    Dos alertas, fijadas antes de medir:

    - `conflicto`: la misma IP con dos o más MAC en la misma ventana. Dos emisores con la misma
      IP no existen en una red sana (salvo failover de gateway).
    - `reasignacion`: una IP vinculada a una MAC (tras `MIN_VENTANAS_PERFIL` ventanas) aparece
      con otra mientras la anterior lleva menos de `gracia_s` callada. Pasada la gracia, el
      vínculo se traspasa sin alerta tras otras `MIN_VENTANAS_PERFIL` ventanas (como un DHCP).
      Límite declarado: un atacante que espere más que la gracia después de que la víctima
      calle no se acusa.

    Las alertas no aprenden: una IP en conflicto o en reasignación no cuenta para el vínculo.
    """

    red: str = RED_LOCAL
    gracia_s: float = GRACIA_REASIGNACION_S
    min_ventanas: int = MIN_VENTANAS_PERFIL
    vinculo: dict[str, str] = field(default_factory=dict)
    ultima_us: dict[str, int] = field(default_factory=dict)
    cuentas: dict[tuple[str, str], int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._red = ipaddress.ip_network(self.red)

    def _local(self, ip: str | None) -> bool:
        if not ip or ip == "0.0.0.0":
            return False
        try:
            return ipaddress.ip_address(ip) in self._red
        except ValueError:
            return False

    def observar(self, tramas: Sequence[Trama], ts_us: int) -> list[dict]:
        """Procesa las tramas de una ventana (de todos los equipos); devuelve sus alertas."""
        por_ip: dict[str, set[str]] = {}
        for t in tramas:
            if self._local(t.ip_src):
                por_ip.setdefault(t.ip_src, set()).add(t.mac_src)
        alertas = []
        for ip, macs in sorted(por_ip.items()):
            if len(macs) >= 2:
                alertas.append({"tipo": "conflicto", "ip": ip, "macs": sorted(macs)})
                continue
            mac, previa = next(iter(macs)), self.vinculo.get(ip)
            if previa is None or previa == mac:
                if previa is None:
                    self._contar(ip, mac)
                continue
            silencio_s = (ts_us - self.ultima_us.get(previa, -(1 << 62))) / 1_000_000
            if silencio_s <= self.gracia_s:
                alertas.append({"tipo": "reasignacion", "ip": ip, "mac": mac, "mac_anterior": previa,
                                "silencio_s": silencio_s})
            else:
                self._contar(ip, mac)
        for t in tramas:
            self.ultima_us[t.mac_src] = max(self.ultima_us.get(t.mac_src, 0), t.ts_us)
        return alertas

    def _contar(self, ip: str, mac: str) -> None:
        n = self.cuentas.get((ip, mac), 0) + 1
        self.cuentas[(ip, mac)] = n
        if n >= self.min_ventanas:
            self.vinculo[ip] = mac
            self.cuentas = {k: v for k, v in self.cuentas.items() if k[0] != ip}
