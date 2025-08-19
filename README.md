# 🛠️ Herramientas de Administración y Auditoría para Windows

Este repositorio contiene una colección de herramientas de línea de comandos en Python diseñadas para simplificar tareas comunes de administración, auditoría y seguridad en entornos Windows. Cada script es una solución autónoma, enfocada en un objetivo específico.

---

### **1. `RemoteConnect-WorkPC.py`**

#### **🚀 Acceso Remoto Optimizado**

Este script es una herramienta para administradores de sistemas y usuarios con permisos de acceso remoto. Su objetivo es proporcionar una conexión de Escritorio Remoto (RDP) optimizada y robusta a un equipo de trabajo, priorizando la estabilidad y la fluidez.

#### **Características**
* **Conexión persistente**: Monitorea continuamente la conectividad de red y reintenta la conexión RDP en caso de interrupción.
* **Reporte de estado**: Informa sobre el estado del servicio de Escritorio Remoto, reglas de firewall y configuraciones de registro en el equipo local.
* **Generación de `.rdp` optimizado**: Crea un archivo de configuración (`.rdp`) con parámetros recomendados para un rendimiento óptimo (detección de ancho de banda, reconexión automática, etc.).
* **Requisitos de seguridad**: Requiere permisos de administrador para ciertas funciones y respeta los controles de seguridad empresariales.

#### **Requisitos**
* **Sistema**: Windows 10/11
* **Python**: Versión 3.9+
* **Paquetes**: `psutil` (opcional, pero recomendado). Instale con `pip install psutil`.
* **Permisos**: Ejecute como **Administrador**.

#### **Uso**
1.  Edite las variables de configuración en la sección `CONFIG` del script (ej. `HOST_TRABAJO`, `DOMINIO`, `USUARIO`).
2.  (Opcional) Guarde sus credenciales de forma segura con el Administrador de Credenciales de Windows:
    ```bash
    cmdkey /generic:TERMSRV/<HOST> /user:<DOMINIO\\USUARIO>
    ```
3.  Ejecute el script:
    ```bash
    python RemoteConnect-WorkPC.py
    ```

---

### **2. `auditor_forense.py`**

#### **🔍 Herramienta de Auditoría y Forense de Windows**

Este proyecto es una herramienta de auditoría forense que automatiza la recolección de información clave del sistema operativo, el registro, la red, usuarios y servicios. Está diseñado para administradores de sistemas y profesionales de la seguridad para investigar incidentes o realizar evaluaciones de rutina.

#### **Características**
* **Auditoría exhaustiva**: Ejecuta una serie de comandos (`netstat`, `systeminfo`, `wmic`, `wevtutil`, etc.) para recolectar datos del sistema.
* **Reportes profesionales**: Genera un informe consolidado en formato **HTML** que presenta los datos de forma legible, con un resumen de hallazgos y una sección de errores.
* **Preservación de la integridad**: Guarda los resultados en archivos JSON con un **hash SHA-256** para asegurar que la información no sea alterada.
* **Interfaz interactiva**: Proporciona un menú sencillo en la terminal para ejecutar la auditoría o generar reportes a partir de datos ya recolectados.
* **Detección de idioma**: Ajusta automáticamente los comandos a los nombres de grupos locales del sistema (ej. `Administradores` en lugar de `Administrators`).

#### **Requisitos**
* **Sistema**: Windows 10/11
* **Python**: Versión 3.9+
* **Paquetes**: `Jinja2` y `psutil`. Instale con `pip install Jinja2 psutil`.
* **Permisos**: Ejecute como **Administrador** para recolectar todos los datos.

#### **Uso**
* Ejecute el script sin argumentos:
    ```bash
    python auditor_forense.py
    ```
* Siga las instrucciones del menú interactivo para ejecutar una auditoría o generar un reporte.

---

### **3. `ad_inventory.py`**

#### **📋 Inventario de Red y Active Directory**

Este script es una herramienta de auditoría y reconocimiento diseñada para administradores de red y especialistas en seguridad. Su propósito es realizar un inventario detallado de la infraestructura de red y recolectar información de seguridad crítica de **Active Directory (AD)**.

#### **Características**
* **Descubrimiento de red multi-hilo**: Escanea de manera eficiente una subred completa (`/24`) para identificar hosts activos y escanear puertos clave (RDP, SMB, LDAP, SSH, etc.) utilizando múltiples hilos.
* **Auditoría de Active Directory (AD)**: Se conecta a un servidor de AD con credenciales de solo lectura para auditar:
    * **Usuarios**: Exporta datos sobre cuentas, fechas de creación y último inicio de sesión.
    * **Equipos**: Recopila información sobre los equipos registrados en el dominio.
    * **Política de Contraseñas**: Muestra la política de contraseñas por defecto del dominio, incluyendo la longitud mínima, edad y configuraciones de bloqueo.
* **Exportación de datos**: Guarda todos los resultados del escaneo y la auditoría en archivos **CSV** fáciles de analizar, ubicados en la carpeta `salidas_inventario`.

#### **Requisitos**
* **Sistema**: Windows 10/11
* **Python**: Versión 3.9+
* **Paquetes**: `ldap3`, `psutil` (opcional), `ipaddress` (generalmente incluido en Python 3.9+). Instale con `pip install ldap3`.
* **Configuración**: Edite la sección `CONFIG` del script con los detalles de su dominio AD, incluyendo el servidor, usuario y contraseña de una cuenta con permisos de lectura.

#### **Uso**
* Edite las variables en la sección `CONFIG` (ej. `RANGO_IP`, `AD_SERVER`, `AD_USER`).
* Ejecute el script:
    ```bash
    python ad_inventory.py
    ```
* Los archivos CSV se guardarán en la carpeta `salidas_inventario` al finalizar la ejecución.

---

### **Contribución**

Este repositorio es de código abierto. Si desea contribuir con mejoras, correcciones de errores o nuevas funcionalidades, ¡su colaboración es bienvenida!
