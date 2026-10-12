"""Menú de consola del sistema de gestión de vulnerabilidades.

Ejecutar desde esta carpeta: python main.py
Requiere Python 3.10 o superior; no usa librerías externas.
Los datos se guardan solo en memoria durante cada ejecución.
"""
from __future__ import annotations

from datetime import date
from math import isfinite

from modelos.activo import Activo
from modelos.vulnerabilidad import PATRON_CVE, Vulnerabilidad
from servicios.gestor import GestorVulnerabilidades, GestorEliminadoError
from reportes.generador import GeneradorReportes
from reportes.reporte_riesgo import ReporteRiesgo
from reportes.reporte_sla import ReporteSLA


def pedir_texto(mensaje: str, obligatorio: bool = True) -> str:
    while True:
        valor = input(mensaje).strip()
        if valor or not obligatorio:
            return valor
        print("El campo no puede quedar vacío.")


def pedir_fecha(mensaje: str) -> date:
    while True:
        entrada = input(mensaje).strip()
        try:
            fecha = date.fromisoformat(entrada)
        except ValueError:
            print("Fecha inválida. Usa el formato AAAA-MM-DD.")
            continue
        if fecha > date.today():
            print("No se permiten fechas futuras.")
            continue
        return fecha


def pedir_sla() -> int:
    while True:
        try:
            dias = int(input("SLA contractual en días para el cliente (ej. 30): ").strip())
            if dias > 0:
                return dias
        except ValueError:
            pass
        print("Ingresa un número entero positivo.")


def pedir_cve(mensaje: str = "CVE (ej. CVE-2024-12345): ") -> str:
    """Valida el CVE apenas se escribe, para no perder los demás datos."""
    while True:
        cve = input(mensaje).strip().upper()
        if PATRON_CVE.fullmatch(cve):
            return cve
        print("CVE inválido. Usa CVE-AAAA-NNNN, por ejemplo CVE-2024-12345.")


def pedir_cvss() -> float | None:
    while True:
        entrada = input("CVSS (0-10; vacío si no se conoce): ").strip()
        if not entrada:
            return None
        try:
            valor = float(entrada)
            if isfinite(valor) and 0 <= valor <= 10:
                return valor
        except ValueError:
            pass
        print("CVSS inválido. Escribe un número entre 0 y 10.")


def mostrar_hallazgos(hallazgos: list[tuple[Activo, Vulnerabilidad]]) -> None:
    if not hallazgos:
        print("No se encontraron hallazgos.")
        return
    for activo, v in hallazgos:
        cvss = "Sin evaluar" if v.cvss is None else f"{v.cvss:.1f}"
        score = v.calcular_risk_score()
        print(
            f"[{activo.id_activo} / {v.cve}] {v.titulo} | Cliente: {activo.cliente} | "
            f"Activo: {activo.nombre} | CVSS: {cvss} | Severidad: {v.obtener_severidad()} | "
            f"Estado: {v.estado} | Risk Score: {'N/D' if score is None else f'{score:.2f}'}"
        )
        print(f"    Operador: {v.operador} | Detección: {v.fecha_deteccion} | "
              f"Evidencia: {v.evidencia or 'N/D'}")


def verificar_gestor(gestor: GestorVulnerabilidades | None) -> GestorVulnerabilidades:
    """Evita operar sobre un gestor eliminado."""
    if gestor is None:
        raise GestorEliminadoError(
            "El gestor fue eliminado. Sal (opción 0) y vuelve a ejecutar el programa."
        )
    return gestor


def main() -> None:
    gestor = GestorVulnerabilidades()
    # Catálogo externo: sus objetos Activo existen aparte del gestor (agregación).
    catalogo_activos: dict[str, Activo] = {}
    # Por cliente: nombre como se registró la primera vez y su SLA contractual.
    clientes: dict[str, tuple[str, int]] = {}
    estrategias = {"1": ReporteRiesgo(), "2": ReporteSLA()}
    generador = GeneradorReportes(estrategias["1"])

    while True:
        print("\n" + "=" * 57)
        print("SISTEMA DE GESTIÓN DE VULNERABILIDADES - TXDXSECURE")
        print("=" * 57)
        print("1. Registrar activo")
        print("2. Registrar vulnerabilidad en un activo")
        print("3. Buscar por CVE o cliente")
        print("4. Filtrar por severidad")
        print("5. Actualizar estado de vulnerabilidad")
        print("6. Generar reportes (Risk Score / SLA)")
        print("7. Eliminar hallazgo")
        print("8. Eliminar activo y sus hallazgos")
        print("9. Listar activos y hallazgos")
        print("10. Eliminar gestor (demostrar agregación)")
        print("0. Salir")
        opcion = input("Elige una opción: ").strip()

        try:
            if opcion == "0":
                print("Fin del programa. Los datos de esta ejecución no se guardan en disco.")
                return

            # Ninguna opción funciona después de eliminar el gestor.
            gestor = verificar_gestor(gestor)

            if opcion == "1":
                id_activo = pedir_texto("ID del activo: ")
                if id_activo in catalogo_activos:
                    raise ValueError("Ese ID de activo ya existe en el catálogo.")
                nombre = pedir_texto("Nombre del activo: ")
                cliente = pedir_texto("Cliente: ")
                clave = cliente.casefold()
                if clave not in clientes:
                    print("Cliente nuevo. Configura su plazo SLA contractual.")
                    clientes[clave] = (cliente, pedir_sla())
                else:
                    print(f"Cliente existente: {clientes[clave][0]} "
                          f"(SLA {clientes[clave][1]} días).")
                nombre_cliente, sla = clientes[clave]
                activo = Activo(id_activo, nombre, nombre_cliente, sla)
                catalogo_activos[id_activo] = activo
                gestor.agregar_activo(activo)  # Se entrega un objeto ya creado
                print("Activo registrado y vinculado.")

            elif opcion == "2":
                id_activo = pedir_texto("ID del activo vinculado: ")
                gestor.obtener_activo(id_activo)
                cve = pedir_cve()
                if gestor.existe_hallazgo(id_activo, cve):
                    raise ValueError("Ese CVE ya está registrado en este activo.")
                cvss = pedir_cvss()
                titulo = pedir_texto("Título: ")
                operador = pedir_texto("Operador responsable: ")
                fecha = pedir_fecha("Fecha de detección (AAAA-MM-DD): ")
                evidencia = pedir_texto("Evidencia / referencia (opcional): ", obligatorio=False)
                vuln = gestor.registrar_hallazgo(
                    id_activo, cve=cve, titulo=titulo, cvss=cvss, operador=operador,
                    fecha_deteccion=fecha, evidencia=evidencia,
                )
                print(f"{vuln.cve} registrado en {id_activo}. "
                      f"Severidad: {vuln.obtener_severidad()}. Estado: {vuln.estado}.")

            elif opcion == "3":
                tipo = pedir_texto("Buscar por (1) CVE o (2) cliente: ")
                if tipo == "1":
                    mostrar_hallazgos(gestor.buscar_por_cve(pedir_texto("CVE: ")))
                elif tipo == "2":
                    mostrar_hallazgos(gestor.buscar_por_cliente(pedir_texto("Cliente: ")))
                else:
                    print("Opción inválida.")

            elif opcion == "4":
                nivel = pedir_texto("Severidad (Ninguna/Baja/Media/Alta/Crítica/Sin evaluar): ")
                mostrar_hallazgos(gestor.listar_por_severidad(nivel))

            elif opcion == "5":
                id_activo = pedir_texto("ID del activo: ")
                cve = pedir_cve("CVE a actualizar: ")
                actual = gestor.buscar_hallazgo(id_activo, cve)
                print(f"Estado actual: {actual.estado}")
                print("1. Pendiente | 2. En desarrollo | 3. Remediado")
                indice = pedir_texto("Nuevo estado: ")
                mapa = {"1": "Pendiente", "2": "En desarrollo", "3": "Remediado"}
                if indice not in mapa:
                    raise ValueError("Estado no válido.")
                gestor.actualizar_estado(id_activo, cve, mapa[indice])
                if mapa[indice] == "Remediado":
                    print(f"Estado actualizado. Fecha de remediación registrada: "
                          f"{actual.fecha_remediacion}.")
                else:
                    print("Estado actualizado.")

            elif opcion == "6":
                print("1. Reporte de riesgo (Risk Score)")
                print("2. Reporte de SLA")
                print("3. Ambos")
                eleccion = pedir_texto("Reporte a generar: ")
                if eleccion in estrategias:
                    elegidas = [estrategias[eleccion]]
                elif eleccion == "3":
                    elegidas = list(estrategias.values())
                else:
                    raise ValueError("Opción de reporte no válida.")
                # Patrón Strategy: se cambia la estrategia y se llama al mismo método.
                for estrategia in elegidas:
                    generador.estrategia = estrategia
                    print("\n" + generador.generar(gestor))

            elif opcion == "7":
                id_activo = pedir_texto("ID del activo: ")
                cve = pedir_cve("CVE a eliminar: ")
                gestor.eliminar_hallazgo(id_activo, cve)
                print("Hallazgo eliminado; el activo sigue registrado.")

            elif opcion == "8":
                id_activo = pedir_texto("ID del activo a eliminar: ")
                if id_activo not in catalogo_activos:
                    raise ValueError("Activo inexistente en el registro.")
                confirmado = pedir_texto("Esto borrará sus hallazgos. Escribe SI para confirmar: ")
                if confirmado.upper() == "SI":
                    # Composición: al eliminar el activo se eliminan sus hallazgos.
                    gestor.eliminar_activo(id_activo)
                    del catalogo_activos[id_activo]
                    print("Activo y sus hallazgos eliminados del registro.")
                else:
                    print("Operación cancelada.")

            elif opcion == "9":
                print("\nActivos registrados:")
                if not catalogo_activos:
                    print("No hay activos registrados.")
                for activo in catalogo_activos.values():
                    print(f"- {activo.id_activo}: {activo.nombre} | {activo.cliente} | "
                          f"SLA {activo.sla_dias} días | "
                          f"{len(activo.vulnerabilidades)} hallazgo(s)")
                print("\nHallazgos:")
                mostrar_hallazgos(gestor.todos_los_hallazgos())

            elif opcion == "10":
                confirmado = pedir_texto(
                    "El gestor dejará de funcionar hasta reiniciar. Escribe SI para confirmar: "
                )
                if confirmado.upper() != "SI":
                    print("Operación cancelada.")
                    continue
                # Agregación: los activos del catálogo no dependen del gestor.
                gestor = None
                print("Gestor eliminado correctamente.")
                print(f"Activos que siguen existiendo: {len(catalogo_activos)}")
                for activo in catalogo_activos.values():
                    print(f"- {activo.id_activo}: {activo.nombre} "
                          f"({len(activo.vulnerabilidades)} hallazgo(s) conservados)")
                print("Para continuar, sal con 0 y vuelve a ejecutar el programa.")

            else:
                print("Opción no reconocida.")

        except (ValueError, TypeError, GestorEliminadoError) as error:
            print(f"Error: {error}")


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print("\nPrograma interrumpido.")
