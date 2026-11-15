"""
Mitigación: política de respuesta escalable, en dry-run por defecto (E6, OE3; Fig. 1, «Mitigación»).

Convierte las alertas del detector en acciones, escalando con la persistencia: registro → alerta →
bloqueo de la MAC → cuarentena. **Por defecto no ejecuta nada**: imprime y registra el comando que
ejecutaría (`ebtables`/`iptables`/VLAN). Para actuar de verdad en el laboratorio hay que pasar un
`ejecutor` explícito (una función que corra el comando); sin él, es imposible tocar la red por
accidente. Así se cumple OE3 («mecanismos de mitigación») sin inyectar en interfaces reales desde
estas ventanas.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum

logger = logging.getLogger("ids.mitigacion")


class NivelRespuesta(IntEnum):
    """Escalera de respuesta (OE3)."""

    REGISTRO = 0
    ALERTA = 1
    BLOQUEO = 2
    CUARENTENA = 3


@dataclass
class PoliticaMitigacion:
    """Cuándo escalar. `umbral_bloqueo` alertas en `ventana_s` llevan a BLOQUEO; si persiste tras el
    bloqueo, `umbral_cuarentena` más llevan a CUARENTENA."""

    ventana_s: float = 60.0
    umbral_bloqueo: int = 3
    umbral_cuarentena: int = 6
    vlan_cuarentena: int = 999


@dataclass
class GestorMitigacion:
    """Lleva el estado de alertas por MAC y decide la acción. Dry-run salvo que se dé `ejecutor`.

    `ejecutor(comando: list[str]) -> None` ejecuta el comando en el laboratorio. Si es None (por
    defecto), el gestor solo imprime y registra el comando: **no toca la red**.
    """

    politica: PoliticaMitigacion = field(default_factory=PoliticaMitigacion)
    ejecutor: Callable[[list[str]], None] | None = None
    _alertas: dict[str, list[float]] = field(default_factory=dict)
    _nivel: dict[str, NivelRespuesta] = field(default_factory=dict)
    bloqueados: set[str] = field(default_factory=set)
    cuarentena: set[str] = field(default_factory=set)
    acciones: list[dict] = field(default_factory=list)

    @property
    def modo(self) -> str:
        return "laboratorio" if self.ejecutor is not None else "dry_run"

    def procesar_alerta(self, mac: str, ts_s: float, score: float | None = None) -> NivelRespuesta:
        """Registra una alerta de `mac` y devuelve el nivel de respuesta resultante."""
        marcas = [t for t in self._alertas.get(mac, []) if ts_s - t <= self.politica.ventana_s]
        marcas.append(ts_s)
        self._alertas[mac] = marcas
        n = len(marcas)
        if mac in self.cuarentena:
            nivel = NivelRespuesta.CUARENTENA
        elif mac in self.bloqueados and n >= self.politica.umbral_cuarentena:
            nivel = NivelRespuesta.CUARENTENA
        elif n >= self.politica.umbral_bloqueo:
            nivel = NivelRespuesta.BLOQUEO
        elif n >= 1:
            nivel = NivelRespuesta.ALERTA
        else:
            nivel = NivelRespuesta.REGISTRO
        self._aplicar(mac, nivel, n, score)
        return nivel

    def _aplicar(self, mac: str, nivel: NivelRespuesta, n: int, score: float | None) -> None:
        nivel_previo = self._nivel.get(mac, NivelRespuesta.REGISTRO)
        self._nivel[mac] = nivel
        if nivel == NivelRespuesta.BLOQUEO and mac not in self.bloqueados:
            self.bloqueados.add(mac)
            self._ejecutar(self.comando_bloqueo(mac), mac, "bloqueo", n, score)
        elif nivel == NivelRespuesta.CUARENTENA and mac not in self.cuarentena:
            self.cuarentena.add(mac)
            self._ejecutar(self.comando_cuarentena(mac), mac, "cuarentena", n, score)
        elif nivel == NivelRespuesta.ALERTA and nivel_previo < NivelRespuesta.ALERTA:
            self.acciones.append({"mac": mac, "accion": "alerta", "nivel": int(nivel), "alertas": n,
                                  "score": score, "comando": None})
            logger.info("ALERTA MAC %s (%d en ventana)", mac, n)

    def comando_bloqueo(self, mac: str) -> list[str]:
        """Comando que descartaría las tramas de `mac` en el puente (no se ejecuta en dry-run)."""
        return ["ebtables", "-A", "FORWARD", "-s", mac, "-j", "DROP"]

    def comando_cuarentena(self, mac: str) -> list[str]:
        """Comando que movería `mac` a la VLAN de cuarentena (no se ejecuta en dry-run)."""
        return ["ebtables", "-t", "nat", "-A", "PREROUTING", "-s", mac,
                "-j", "mark", "--set-mark", str(self.politica.vlan_cuarentena)]

    def desbloquear(self, mac: str) -> None:
        """Quita el bloqueo/cuarentena de `mac` (comando inverso en dry-run o ejecutado)."""
        if mac in self.bloqueados:
            self._ejecutar(["ebtables", "-D", "FORWARD", "-s", mac, "-j", "DROP"], mac, "desbloqueo", 0, None)
        self.bloqueados.discard(mac)
        self.cuarentena.discard(mac)
        self._nivel[mac] = NivelRespuesta.REGISTRO
        self._alertas.pop(mac, None)

    def _ejecutar(self, comando: list[str], mac: str, accion: str, n: int, score: float | None) -> None:
        self.acciones.append({"mac": mac, "accion": accion, "nivel": int(self._nivel.get(mac, 0)),
                              "alertas": n, "score": score, "comando": comando, "modo": self.modo})
        if self.ejecutor is None:
            logger.warning("[dry-run] %s de %s → %s", accion, mac, " ".join(comando))
        else:
            logger.warning("[laboratorio] %s de %s → %s", accion, mac, " ".join(comando))
            self.ejecutor(comando)

    def resumen(self) -> dict:
        return {"modo": self.modo, "bloqueados": sorted(self.bloqueados),
                "cuarentena": sorted(self.cuarentena), "acciones": len(self.acciones)}
