"""Activo del cliente. Composición: el activo crea y contiene sus hallazgos."""
from __future__ import annotations

from .vulnerabilidad import Vulnerabilidad


class Activo:
    """El activo es dueño de sus hallazgos; si el activo se elimina, ellos también."""

    def __init__(self, id_activo: str, nombre: str, cliente: str, sla_dias: int) -> None:
        if not all((id_activo.strip(), nombre.strip(), cliente.strip())):
            raise ValueError("ID, nombre del activo y cliente son obligatorios.")
        if isinstance(sla_dias, bool) or not isinstance(sla_dias, int) or sla_dias <= 0:
            raise ValueError("El plazo SLA debe ser un entero positivo.")
        self._id_activo = id_activo.strip()
        self._nombre = nombre.strip()
        self._cliente = cliente.strip()
        self._sla_dias = sla_dias  # Plazo contractual del cliente dueño del activo
        self._vulnerabilidades: dict[str, Vulnerabilidad] = {}

    @property
    def id_activo(self) -> str:
        return self._id_activo

    @property
    def nombre(self) -> str:
        return self._nombre

    @property
    def cliente(self) -> str:
        return self._cliente

    @property
    def sla_dias(self) -> int:
        return self._sla_dias

    @property
    def vulnerabilidades(self) -> tuple[Vulnerabilidad, ...]:
        return tuple(self._vulnerabilidades.values())

    def tiene_hallazgo(self, cve: str) -> bool:
        return cve.strip().upper() in self._vulnerabilidades

    def registrar_hallazgo(self, **datos) -> Vulnerabilidad:
        """El propio activo crea el objeto Vulnerabilidad (composición)."""
        hallazgo = Vulnerabilidad(**datos)
        if hallazgo.cve in self._vulnerabilidades:
            raise ValueError("Ese CVE ya está registrado en este activo.")
        self._vulnerabilidades[hallazgo.cve] = hallazgo
        return hallazgo

    def obtener_hallazgo(self, cve: str) -> Vulnerabilidad:
        cve = cve.strip().upper()
        if cve not in self._vulnerabilidades:
            raise ValueError("Ese CVE no está registrado en este activo.")
        return self._vulnerabilidades[cve]

    def eliminar_hallazgo(self, cve: str) -> None:
        cve = cve.strip().upper()
        self.obtener_hallazgo(cve)
        del self._vulnerabilidades[cve]

    def eliminar_todos_hallazgos(self) -> None:
        """Eliminación en cascada: se usa cuando se elimina el activo."""
        self._vulnerabilidades.clear()
