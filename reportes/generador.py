"""Contexto del patrón Strategy para los reportes."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .reporte import Reporte

if TYPE_CHECKING:
    from servicios.gestor import GestorVulnerabilidades


class GeneradorReportes:
    """Guarda la estrategia elegida y le delega la generación del reporte.

    El generador no sabe qué tipo de reporte tiene; solo llama a generar().
    Para agregar un reporte nuevo basta con crear otra subclase de Reporte.
    """

    def __init__(self, estrategia: Reporte) -> None:
        self.estrategia = estrategia  # Pasa por el setter para validar

    @property
    def estrategia(self) -> Reporte:
        return self._estrategia

    @estrategia.setter
    def estrategia(self, nueva: Reporte) -> None:
        if not isinstance(nueva, Reporte):
            raise TypeError("La estrategia debe ser una subclase de Reporte.")
        self._estrategia = nueva

    def generar(self, gestor: GestorVulnerabilidades) -> str:
        return self._estrategia.generar(gestor)
