"""Clase abstracta que define la interfaz común de los reportes.

En el patrón Strategy cumple el rol de "estrategia": cada subclase es una
forma distinta de generar el reporte.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from servicios.gestor import GestorVulnerabilidades


class Reporte(ABC):
    """Abstracción: contrato común para todos los reportes."""

    @property
    @abstractmethod
    def nombre(self) -> str:
        """Nombre que se muestra en el menú."""

    @abstractmethod
    def generar(self, gestor: GestorVulnerabilidades) -> str:
        """Devuelve el reporte listo para imprimir."""
