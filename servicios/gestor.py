"""Gestor de vulnerabilidades.

Patrón Facade: el menú trabaja solo con esta clase, que oculta cómo se
recorren los activos y sus hallazgos.
Agregación: el gestor recibe activos que ya existen y no controla su ciclo de vida.
"""
from __future__ import annotations

import unicodedata

from modelos.activo import Activo
from modelos.vulnerabilidad import Vulnerabilidad


class GestorEliminadoError(RuntimeError):
    """Se lanza cuando se intenta operar después de eliminar el gestor."""


def normalizar(texto: str) -> str:
    """Quita tildes y mayúsculas para comparar textos ingresados por el usuario."""
    sin_tildes = unicodedata.normalize("NFD", texto.strip())
    sin_tildes = "".join(c for c in sin_tildes if unicodedata.category(c) != "Mn")
    return sin_tildes.casefold()


class GestorVulnerabilidades:
    """Fachada del sistema: registro, búsqueda, actualización y eliminación."""

    def __init__(self) -> None:
        self._activos: dict[str, Activo] = {}

    @property
    def activos(self) -> tuple[Activo, ...]:
        return tuple(self._activos.values())

    def agregar_activo(self, activo: Activo) -> None:
        if activo.id_activo in self._activos:
            raise ValueError("El activo ya está vinculado al gestor.")
        self._activos[activo.id_activo] = activo

    def obtener_activo(self, id_activo: str) -> Activo:
        if id_activo not in self._activos:
            raise ValueError("El activo no está vinculado al gestor.")
        return self._activos[id_activo]

    def eliminar_activo(self, id_activo: str) -> None:
        """Borra los hallazgos del activo y lo desvincula del gestor."""
        activo = self.obtener_activo(id_activo)
        activo.eliminar_todos_hallazgos()
        del self._activos[id_activo]

    def todos_los_hallazgos(self) -> list[tuple[Activo, Vulnerabilidad]]:
        return [(a, v) for a in self._activos.values() for v in a.vulnerabilidades]

    def existe_hallazgo(self, id_activo: str, cve: str) -> bool:
        return self.obtener_activo(id_activo).tiene_hallazgo(cve)

    def buscar_hallazgo(self, id_activo: str, cve: str) -> Vulnerabilidad:
        """La clave del hallazgo es (id_activo, CVE)."""
        return self.obtener_activo(id_activo).obtener_hallazgo(cve)

    def registrar_hallazgo(self, id_activo: str, **datos) -> Vulnerabilidad:
        return self.obtener_activo(id_activo).registrar_hallazgo(**datos)

    def buscar_por_cve(self, cve: str) -> list[tuple[Activo, Vulnerabilidad]]:
        cve = cve.strip().upper()
        return [(a, v) for a, v in self.todos_los_hallazgos() if v.cve == cve]

    def buscar_por_cliente(self, cliente: str) -> list[tuple[Activo, Vulnerabilidad]]:
        buscado = normalizar(cliente)
        return [(a, v) for a, v in self.todos_los_hallazgos()
                if buscado in normalizar(a.cliente)]

    def listar_por_severidad(self, severidad: str) -> list[tuple[Activo, Vulnerabilidad]]:
        buscada = normalizar(severidad)
        return [(a, v) for a, v in self.todos_los_hallazgos()
                if normalizar(v.obtener_severidad()) == buscada]

    def actualizar_estado(self, id_activo: str, cve: str, estado: str) -> None:
        self.buscar_hallazgo(id_activo, cve).actualizar_estado(estado)

    def eliminar_hallazgo(self, id_activo: str, cve: str) -> None:
        self.obtener_activo(id_activo).eliminar_hallazgo(cve)
