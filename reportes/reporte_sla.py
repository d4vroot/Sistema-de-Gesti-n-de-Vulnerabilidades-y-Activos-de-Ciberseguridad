"""Reporte de cumplimiento de los plazos contractuales (SLA)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .reporte import Reporte

if TYPE_CHECKING:
    from servicios.gestor import GestorVulnerabilidades


class ReporteSLA(Reporte):
    """Estrategia concreta: evalúa cada hallazgo contra el SLA del cliente."""

    @property
    def nombre(self) -> str:
        return "Reporte de SLA"

    def generar(self, gestor: GestorVulnerabilidades) -> str:
        hallazgos = gestor.todos_los_hallazgos()
        if not hallazgos:
            return "REPORTE DE SLA\nNo hay vulnerabilidades registradas."
        filas = ["REPORTE DE SLA (plazo contractual de cada cliente)"]
        for activo, v in hallazgos:
            filas.append(
                f"- {activo.id_activo} | {v.cve} | {activo.cliente} / {activo.nombre} | "
                f"{v.estado} | {v.dias_transcurridos()} días / SLA {activo.sla_dias} días "
                f"| {v.evaluar_sla(activo.sla_dias)}"
            )
        return "\n".join(filas)
