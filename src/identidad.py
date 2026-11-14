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
- `ipid_continuidad`: fracción de saltos de IP-ID entre tramas consecutivas en [1, 2048]
  (contador global ≈ 1; aleatorio ≈ 0,03; cero con DF = 0).
- `ipid_salto_log2`: log2(1 + salto mediano de IP-ID).
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
"""

from __future__ import annotations

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
UMBRAL_DESVIACION: float = 6.0
Z_FIRMA_NUEVA: float = 10.0
VENTANAS_LIMPIAS_PARA_RECUPERAR: int = 3
TOPE_ACTUALIZACIONES_DIA: int = 96
HISTORIA_MAX: int = 120
SALTO_IPID_CONTINUO: int = 2048
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
    ids = [t.ip_id for t in sorted(ip, key=lambda t: t.ts_us) if t.ip_id is not None]
    if len(ids) >= 2:
        saltos = np.array([(b - a) % 65536 for a, b in zip(ids, ids[1:])])
        s["ipid_continuidad"] = float(np.mean((saltos >= 1) & (saltos <= SALTO_IPID_CONTINUO)))
        s["ipid_salto_log2"] = float(np.log2(1 + np.median(saltos)))
    flujos: dict[tuple, list[int]] = {}
    for t in sorted((t for t in ip if t.tcp_seq is not None), key=lambda t: t.ts_us):
        flujos.setdefault((t.ip_dst, t.sport, t.dport), []).append(t.tcp_seq)
    pares = [(b - a) % (1 << 32) for seqs in flujos.values() for a, b in zip(seqs, seqs[1:])]
    if pares:
        s["seq_continuidad"] = float(np.mean(np.array(pares) < SALTO_SEQ_CONTINUO))
    return s


def tiene_senal(s: dict) -> bool:
    """¿La ventana aporta alguna señal de pila? Solo esas cuentan para el perfil."""
    return bool(s["tcp_opciones"]) or any(not math.isnan(s[k]) for k in SENALES_NUMERICAS)


def perfil_desde_senales(ventanas: Sequence[dict]) -> dict:
    """Perfil robusto a partir de las señales de varias ventanas."""
    ventanas = [v for v in ventanas if tiene_senal(v)]
    perfil: dict = {"n_ventanas": len(ventanas),
                    "estado": CONFIABLE if len(ventanas) >= MIN_VENTANAS_PERFIL else NO_CONFIABLE}
    for k in SENALES_NUMERICAS:
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
            else:
                por_senal[k] = abs(s[k] - p["mediana"]) / escala
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
    """

    historia: deque = field(default_factory=lambda: deque(maxlen=HISTORIA_MAX))
    estado: str = NO_CONFIABLE
    limpias_seguidas: int = 0
    actualizaciones_dia: dict[int, int] = field(default_factory=dict)
    _perfil: dict | None = None

    @property
    def perfil(self) -> dict:
        if self._perfil is None:
            self._perfil = perfil_desde_senales(list(self.historia))
        return self._perfil

    def _aprender(self, s: dict, dia: int) -> bool:
        confiable = len(self.historia) >= MIN_VENTANAS_PERFIL
        if confiable and self.actualizaciones_dia.get(dia, 0) >= TOPE_ACTUALIZACIONES_DIA:
            return False
        self.historia.append(s)
        if confiable:
            self.actualizaciones_dia[dia] = self.actualizaciones_dia.get(dia, 0) + 1
        self._perfil = None
        return True

    def observar(self, tramas: Sequence[Trama], ts_us: int | None = None) -> dict:
        """Procesa una ventana del equipo; aprende solo si no hay alerta."""
        s = senales_ventana(tramas)
        ts = ts_us if ts_us is not None else (min(t.ts_us for t in tramas) if tramas else 0)
        dia = int(ts // 86_400_000_000)
        salida = {"puntaje": math.nan, "alarma": False, "estado": self.estado, "aprendio": False}
        if not tiene_senal(s):
            return salida
        if self.estado == NO_CONFIABLE:
            salida["aprendio"] = self._aprender(s, dia)
            if len(self.historia) >= MIN_VENTANAS_PERFIL:
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
        elif self.estado == SOSPECHOSO:
            self.limpias_seguidas += 1
            if self.limpias_seguidas >= VENTANAS_LIMPIAS_PARA_RECUPERAR:
                self.estado = CONFIABLE
        else:
            salida["aprendio"] = self._aprender(s, dia)
        salida["estado"] = self.estado
        return salida
