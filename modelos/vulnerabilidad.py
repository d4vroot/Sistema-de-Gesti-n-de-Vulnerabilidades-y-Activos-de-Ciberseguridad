"""Hallazgo de vulnerabilidad y reglas de severidad, prioridad y SLA."""
from __future__ import annotations

from datetime import date
from math import isfinite
import re

ESTADOS = ("Pendiente", "En desarrollo", "Remediado")

# Formato oficial del identificador: CVE-AAAA-NNNN (cuatro o más dígitos al final).
PATRON_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class Vulnerabilidad:
    """Hallazgo de un CVE en un activo; el mismo CVE puede afectar a otros activos."""

    def __init__(
        self,
        cve: str,
        titulo: str,
        cvss: float | None,
        operador: str,
        fecha_deteccion: date,
        evidencia: str = "",
    ) -> None:
        if not titulo.strip() or not operador.strip():
            raise ValueError("Título y operador son obligatorios.")

        cve = cve.strip().upper()
        if not PATRON_CVE.fullmatch(cve):
            raise ValueError("CVE inválido. Debe tener formato CVE-AAAA-NNNN. Ej.: CVE-2024-12345.")

        if cvss is not None:
            if isinstance(cvss, bool) or not isinstance(cvss, (int, float)) \
                    or not isfinite(cvss) or not 0 <= cvss <= 10:
                raise ValueError("El CVSS debe estar entre 0.0 y 10.0.")

        if not isinstance(fecha_deteccion, date) or fecha_deteccion > date.today():
            raise ValueError("La fecha de detección no puede ser futura.")

        self._titulo = titulo.strip()
        self._cve = cve
        self._cvss = float(cvss) if cvss is not None else None
        self._operador = operador.strip()
        self._fecha_deteccion = fecha_deteccion
        self._evidencia = evidencia.strip()
        self._estado = "Pendiente"
        self._fecha_remediacion: date | None = None

    @property
    def titulo(self) -> str:
        return self._titulo

    @property
    def cve(self) -> str:
        return self._cve

    @property
    def cvss(self) -> float | None:
        return self._cvss

    @property
    def operador(self) -> str:
        return self._operador

    @property
    def evidencia(self) -> str:
        return self._evidencia

    @property
    def estado(self) -> str:
        return self._estado

    @property
    def fecha_deteccion(self) -> date:
        return self._fecha_deteccion

    @property
    def fecha_remediacion(self) -> date | None:
        return self._fecha_remediacion

    def obtener_severidad(self) -> str:
        """Clasificación según los rangos cualitativos de CVSS (FIRST)."""
        if self._cvss is None:
            return "Sin evaluar"
        if self._cvss == 0:
            return "Ninguna"
        if self._cvss < 4:
            return "Baja"
        if self._cvss < 7:
            return "Media"
        if self._cvss < 9:
            return "Alta"
        return "Crítica"

    def dias_transcurridos(self, hoy: date | None = None) -> int:
        """Días hasta la remediación, o hasta hoy si el hallazgo sigue abierto."""
        fecha_fin = self._fecha_remediacion or (hoy or date.today())
        return max(0, (fecha_fin - self._fecha_deteccion).days)

    def calcular_risk_score(self, hoy: date | None = None) -> float | None:
        """Índice interno de prioridad: CVSS * (1 + días sin remediar / 30).

        No forma parte del estándar CVSS. Un hallazgo remediado ya no requiere
        atención, por eso vale 0. Si no hay CVSS no se inventa un puntaje.
        """
        if self._estado == "Remediado":
            return 0.0
        if self._cvss is None:
            return None
        return round(self._cvss * (1 + self.dias_transcurridos(hoy) / 30), 2)

    def actualizar_estado(self, nuevo_estado: str) -> None:
        """El operador solo cambia el estado.

        Al pasar a Remediado se guarda la fecha del día para congelar el conteo
        de días y evaluar el SLA. Si el hallazgo se reabre, la fecha se borra.
        """
        if nuevo_estado not in ESTADOS:
            raise ValueError(f"Estado inválido. Opciones: {', '.join(ESTADOS)}.")

        if nuevo_estado == "Remediado":
            if self._estado != "Remediado":
                self._fecha_remediacion = date.today()
        else:
            self._fecha_remediacion = None
        self._estado = nuevo_estado

    def evaluar_sla(self, plazo_dias: int, hoy: date | None = None) -> str:
        if plazo_dias <= 0:
            raise ValueError("El SLA debe ser mayor que cero días.")
        dias = self.dias_transcurridos(hoy)
        if self._estado == "Remediado":
            return "Cumplido" if dias <= plazo_dias else "Incumplido"
        return "En plazo" if dias <= plazo_dias else "Vencido"
