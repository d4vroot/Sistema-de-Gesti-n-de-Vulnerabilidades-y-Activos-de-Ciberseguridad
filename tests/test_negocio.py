"""Pruebas de los métodos de negocio.

Ejecutar desde la carpeta GestorVulnerabilidades:
    python -m unittest -v
"""
import unittest
from datetime import date, timedelta

from modelos.activo import Activo
from modelos.vulnerabilidad import Vulnerabilidad
from reportes.generador import GeneradorReportes
from reportes.reporte import Reporte
from reportes.reporte_riesgo import ReporteRiesgo
from reportes.reporte_sla import ReporteSLA
from servicios.gestor import GestorVulnerabilidades

HOY = date.today()


def crear_vuln(cvss=8.0, dias=0, cve="CVE-2024-6387"):
    return Vulnerabilidad(
        cve=cve, titulo="Prueba", cvss=cvss, operador="Operador",
        fecha_deteccion=HOY - timedelta(days=dias),
    )


class TestSeveridad(unittest.TestCase):
    def test_rangos_cvss(self):
        casos = {0.0: "Ninguna", 0.1: "Baja", 3.9: "Baja", 4.0: "Media", 6.9: "Media",
                 7.0: "Alta", 8.9: "Alta", 9.0: "Crítica", 10.0: "Crítica"}
        for cvss, esperado in casos.items():
            with self.subTest(cvss=cvss):
                self.assertEqual(crear_vuln(cvss).obtener_severidad(), esperado)

    def test_sin_cvss(self):
        self.assertEqual(crear_vuln(None).obtener_severidad(), "Sin evaluar")


class TestValidaciones(unittest.TestCase):
    def test_cve_mal_formado(self):
        for cve in ("cve-1234", "CVE-24-1234", "CVE-2024-12", "2024-12345"):
            with self.subTest(cve=cve):
                with self.assertRaises(ValueError):
                    crear_vuln(cve=cve)

    def test_cve_se_normaliza_a_mayusculas(self):
        self.assertEqual(crear_vuln(cve="cve-2021-44228").cve, "CVE-2021-44228")

    def test_cvss_fuera_de_rango(self):
        for cvss in (-0.1, 10.1, float("nan")):
            with self.subTest(cvss=cvss):
                with self.assertRaises(ValueError):
                    crear_vuln(cvss)

    def test_fecha_futura(self):
        with self.assertRaises(ValueError):
            crear_vuln(dias=-1)

    def test_estado_invalido(self):
        with self.assertRaises(ValueError):
            crear_vuln().actualizar_estado("Cerrado")

    def test_sla_invalido_en_activo(self):
        with self.assertRaises(ValueError):
            Activo("A1", "Servidor", "Cliente", 0)


class TestRiskScore(unittest.TestCase):
    def test_dia_cero_es_el_cvss(self):
        self.assertEqual(crear_vuln(8.0, dias=0).calcular_risk_score(), 8.0)

    def test_a_los_30_dias_se_duplica(self):
        self.assertEqual(crear_vuln(8.0, dias=30).calcular_risk_score(), 16.0)

    def test_redondeo_dos_decimales(self):
        self.assertEqual(crear_vuln(9.8, dias=10).calcular_risk_score(), 13.07)

    def test_remediado_vale_cero(self):
        v = crear_vuln(10.0, dias=20)
        v.actualizar_estado("Remediado")
        self.assertEqual(v.calcular_risk_score(), 0.0)

    def test_sin_cvss_no_hay_puntaje(self):
        self.assertIsNone(crear_vuln(None, dias=5).calcular_risk_score())


class TestSLA(unittest.TestCase):
    def test_abierto_en_plazo(self):
        self.assertEqual(crear_vuln(dias=10).evaluar_sla(30), "En plazo")

    def test_abierto_vencido(self):
        self.assertEqual(crear_vuln(dias=31).evaluar_sla(30), "Vencido")

    def test_remediado_cumplido(self):
        v = crear_vuln(dias=30)
        v.actualizar_estado("Remediado")
        self.assertEqual(v.fecha_remediacion, HOY)
        self.assertEqual(v.evaluar_sla(30), "Cumplido")

    def test_remediado_incumplido(self):
        v = crear_vuln(dias=45)
        v.actualizar_estado("Remediado")
        self.assertEqual(v.evaluar_sla(30), "Incumplido")

    def test_reabrir_borra_fecha_de_remediacion(self):
        v = crear_vuln(dias=5)
        v.actualizar_estado("Remediado")
        v.actualizar_estado("En desarrollo")
        self.assertIsNone(v.fecha_remediacion)


class TestRelaciones(unittest.TestCase):
    def setUp(self):
        self.gestor = GestorVulnerabilidades()
        self.a1 = Activo("SRV-01", "Servidor web", "Financiera Andina", 30)
        self.a2 = Activo("SRV-02", "Base de datos", "Clínica Santa Rosa", 15)
        self.gestor.agregar_activo(self.a1)
        self.gestor.agregar_activo(self.a2)

    def registrar(self, id_activo, cve, cvss=7.5, dias=0):
        return self.gestor.registrar_hallazgo(
            id_activo, cve=cve, titulo="Hallazgo", cvss=cvss, operador="Ana",
            fecha_deteccion=HOY - timedelta(days=dias),
        )

    def test_mismo_cve_en_activos_distintos(self):
        self.registrar("SRV-01", "CVE-2021-44228")
        self.registrar("SRV-02", "CVE-2021-44228")
        self.assertEqual(len(self.gestor.buscar_por_cve("cve-2021-44228")), 2)

    def test_cve_duplicado_en_mismo_activo(self):
        self.registrar("SRV-01", "CVE-2021-44228")
        self.assertTrue(self.gestor.existe_hallazgo("SRV-01", "CVE-2021-44228"))
        with self.assertRaises(ValueError):
            self.registrar("SRV-01", "CVE-2021-44228")

    def test_composicion_eliminar_activo_borra_hallazgos(self):
        self.registrar("SRV-01", "CVE-2021-44228")
        self.gestor.eliminar_activo("SRV-01")
        self.assertEqual(len(self.a1.vulnerabilidades), 0)
        with self.assertRaises(ValueError):
            self.gestor.obtener_activo("SRV-01")

    def test_agregacion_activo_sobrevive_al_gestor(self):
        self.registrar("SRV-01", "CVE-2021-44228")
        del self.gestor
        self.assertEqual(self.a1.id_activo, "SRV-01")
        self.assertEqual(len(self.a1.vulnerabilidades), 1)

    def test_busqueda_por_cliente_sin_tildes(self):
        self.registrar("SRV-02", "CVE-2023-44487")
        self.assertEqual(len(self.gestor.buscar_por_cliente("clinica")), 1)

    def test_filtro_por_severidad_sin_tildes(self):
        self.registrar("SRV-01", "CVE-2021-44228", cvss=10.0)
        self.registrar("SRV-02", "CVE-2023-44487", cvss=7.5)
        self.assertEqual(len(self.gestor.listar_por_severidad("critica")), 1)
        self.assertEqual(len(self.gestor.listar_por_severidad("ALTA")), 1)

    def test_eliminar_hallazgo_mantiene_activo(self):
        self.registrar("SRV-01", "CVE-2021-44228")
        self.gestor.eliminar_hallazgo("SRV-01", "CVE-2021-44228")
        self.assertIs(self.gestor.obtener_activo("SRV-01"), self.a1)


class TestReportesStrategy(unittest.TestCase):
    def setUp(self):
        self.gestor = GestorVulnerabilidades()
        activo = Activo("SRV-01", "Servidor web", "Financiera Andina", 30)
        self.gestor.agregar_activo(activo)
        activo.registrar_hallazgo(cve="CVE-2021-44228", titulo="Log4Shell", cvss=10.0,
                                  operador="Ana", fecha_deteccion=HOY - timedelta(days=2))
        activo.registrar_hallazgo(cve="CVE-2024-6387", titulo="OpenSSH", cvss=8.1,
                                  operador="Luis", fecha_deteccion=HOY - timedelta(days=40))

    def test_reporte_es_abstracto(self):
        with self.assertRaises(TypeError):
            Reporte()

    def test_cambio_de_estrategia(self):
        generador = GeneradorReportes(ReporteRiesgo())
        self.assertIn("REPORTE DE RIESGO", generador.generar(self.gestor))
        generador.estrategia = ReporteSLA()
        self.assertIn("REPORTE DE SLA", generador.generar(self.gestor))

    def test_estrategia_invalida(self):
        with self.assertRaises(TypeError):
            GeneradorReportes("no es un reporte")

    def test_riesgo_ordena_de_mayor_a_menor(self):
        lineas = ReporteRiesgo().generar(self.gestor).splitlines()
        # 8.1 con 40 días (18.9) supera a 10.0 con 2 días (10.67)
        self.assertIn("CVE-2024-6387", lineas[1])
        self.assertIn("ATENDER", lineas[1])
        self.assertIn("CVE-2021-44228", lineas[2])

    def test_sla_marca_vencido(self):
        reporte = ReporteSLA().generar(self.gestor)
        self.assertIn("Vencido", reporte)
        self.assertIn("En plazo", reporte)


if __name__ == "__main__":
    unittest.main()
