"""Reporte de priorización por Risk Score interno."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .reporte import Reporte

if TYPE_CHECKING:
    from servicios.gestor import GestorVulnerabilidades

# Equivale a un CVSS 7.5 (Alta) que lleva 30 días sin remediar.
UMBRAL_ALERTA = 15.0


class ReporteRiesgo(Reporte):
    """Estrategia concreta: ordena los hallazgos del mayor al menor Risk Score."""

    @property
    def nombre(self) -> str:
        return "Reporte de riesgo (Risk Score)"

    def generar(self, gestor: GestorVulnerabilidades) -> str:
        hallazgos = gestor.todos_los_hallazgos()
        if not hallazgos:
            return "REPORTE DE RIESGO\nNo hay vulnerabilidades registradas."

        def clave(par) -> float:
            score = par[1].calcular_risk_score()
            return -1 if score is None else score  # Sin CVSS va al final

        hallazgos.sort(key=clave, reverse=True)
        filas = ["REPORTE DE RIESGO (prioridad interna por CVSS y antigüedad)"]
        for activo, v in hallazgos:
            score = v.calcular_risk_score()
            score_txt = "N/D" if score is None else f"{score:.2f}"
            cvss_txt = "N/D" if v.cvss is None else f"{v.cvss:.1f}"
            alerta = "  << ATENDER" if score is not None and score >= UMBRAL_ALERTA else ""
            filas.append(
                f"- {activo.id_activo} | {v.cve} | {activo.nombre} | "
                f"CVSS {cvss_txt} ({v.obtener_severidad()}) | "
                f"{v.estado} | {v.dias_transcurridos()} días | Risk Score {score_txt}{alerta}"
            )
        return "\n".join(filas)
