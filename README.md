# Sistema de Gestión de Vulnerabilidades - TXDXSECURE

Trabajo Final de Fundamentos de Programación 2 (NRC 2879) - Grupo 1.

Aplicación de consola en **Python 3.10 o superior**. No usa librerías externas.

## Ejecución

Desde la carpeta `GestorVulnerabilidades`:

```bash
python main.py
```

En Windows también se puede usar `py main.py`.

## Pruebas

Desde la misma carpeta:

```bash
python -m unittest -v
```

Se ejecutan 30 pruebas sobre los métodos de negocio: severidad, validaciones,
Risk Score, SLA, relaciones entre clases y reportes.

## Estructura

```text
GestorVulnerabilidades/
├── main.py                     # Menú y lectura de datos
├── modelos/
│   ├── activo.py               # Activo y sus hallazgos (composición)
│   └── vulnerabilidad.py       # CVSS, severidad, Risk Score y SLA
├── servicios/
│   └── gestor.py               # Fachada: CRUD y asociación con activos (agregación)
├── reportes/
│   ├── reporte.py              # Clase abstracta (estrategia)
│   ├── reporte_riesgo.py       # Estrategia concreta: Risk Score
│   ├── reporte_sla.py          # Estrategia concreta: SLA
│   └── generador.py            # Contexto del patrón Strategy
└── tests/
    └── test_negocio.py         # Pruebas unitarias (unittest)
```

## Funcionalidades

- Registro de activos (con el plazo SLA del cliente) y de hallazgos.
- CVE obligatorio con formato `CVE-AAAA-NNNN` y CVSS opcional (0.0 a 10.0).
- El hallazgo se identifica por **ID del activo + CVE**, así el mismo CVE puede registrarse en activos distintos.
- Si el CVE ya existe en el activo, el sistema avisa antes de pedir el resto de datos.
- Severidad automática según los rangos de CVSS: Ninguna, Baja, Media, Alta y Crítica.
- Risk Score interno: `CVSS * (1 + días sin remediar / 30)`. No es una fórmula oficial de CVSS; sirve para priorizar.
- Estados: Pendiente, En desarrollo y Remediado. Al marcar Remediado el sistema guarda la fecha del día; el operador no la escribe.
- SLA: compara los días entre detección y remediación (o hasta hoy) con el plazo del cliente.
- Búsqueda por CVE o cliente y filtro por severidad (acepta texto con o sin tildes).
- Reportes de riesgo y de SLA, a elección desde el menú.
- Eliminación de hallazgos y de activos.

## Principios de POO

- **Encapsulamiento:** atributos protegidos con propiedades de solo lectura y validaciones en el constructor.
- **Abstracción:** `Reporte` es una clase abstracta (ABC) con `nombre` y `generar()` abstractos.
- **Herencia:** `ReporteRiesgo` y `ReporteSLA` heredan de `Reporte`; `GestorEliminadoError` hereda de `RuntimeError`.
- **Polimorfismo:** `GeneradorReportes` llama a `generar()` sin saber qué reporte tiene.
- **Agregación:** `GestorVulnerabilidades` recibe objetos `Activo` ya creados. Si se elimina el gestor (opción 10), los activos siguen en el catálogo.
- **Composición:** `Activo` crea y guarda sus `Vulnerabilidad`; al eliminar el activo se eliminan sus hallazgos.

## Patrones de diseño

- **Strategy:** `Reporte` es la estrategia, `ReporteRiesgo` y `ReporteSLA` son estrategias concretas y `GeneradorReportes` es el contexto. Para crear un reporte nuevo solo se agrega otra subclase.
- **Facade:** `GestorVulnerabilidades` ofrece una sola interfaz al menú y oculta el recorrido de activos y hallazgos.

## Menú

1. Registrar activo
2. Registrar vulnerabilidad en un activo
3. Buscar por CVE o cliente
4. Filtrar por severidad
5. Actualizar estado de vulnerabilidad
6. Generar reportes (Risk Score / SLA)
7. Eliminar hallazgo
8. Eliminar activo y sus hallazgos
9. Listar activos y hallazgos
10. Eliminar gestor (demostrar agregación)
0. Salir

Después de la opción 10 se bloquean las operaciones y el programa pide salir y volver a ejecutar.

## Alcance y limitaciones

- Los datos se guardan **en memoria** y se pierden al salir.
- No realiza escaneos ni se integra con herramientas como Nessus.
- Solo admite hallazgos con CVE. Por ejemplo, `cve-1234` no es válido porque le falta el año; se debe usar `CVE-2024-12345`.
- Se valida el formato del CVE, no que exista en la base pública. El CVSS se ingresa a mano.
- Se usa eliminación física de registros. En un entorno real convendría un borrado lógico para conservar el historial y la auditoría.
