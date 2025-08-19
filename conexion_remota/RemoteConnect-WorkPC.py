r"""
RemoteConnect-WorkPC (Windows)
================================

⚠️ Uso responsable y con permiso:
Este script está pensado para administradores o usuarios con autorización explícita de su empresa para habilitar y usar acceso remoto. **No ayuda a evadir aprobaciones o controles de seguridad**. Si su organización requiere confirmación del usuario o políticas específicas, respételas. Para acceso sin intervención del usuario ("unattended"), utilice soluciones aprobadas por TI (p. ej., RDP con VPN + credenciales en el Administrador de Credenciales, Tailscale/MeshCentral/RustDesk/Guacamole configurados y autorizados).

Objetivo
--------
- Priorizar **estabilidad y fluidez** de conexión.
- Monitorear conectividad a red/VPN y al host destino.
- Verificar y reportar configuraciones de Windows necesarias para RDP (servicio, firewall, registro, NLA).
- Crear/actualizar un archivo .rdp optimizado (autoreconnect, autodetección de ancho de banda, etc.).
- Lanzar el cliente oficial de Windows (mstsc.exe) y reintentar reconexión ante caídas.

Requisitos
----------
- Sistema: Windows 10/11.
- Python 3.9+
- Paquetes: psutil (opcional pero recomendado). Instale con: `pip install psutil`.
- Permisos: Para habilitar RDP o reglas de firewall, ejecute **como Administrador** y cuente con aprobación de su empresa.
- VPN: Conecte su VPN corporativa (o ZeroTrust tipo Tailscale) antes de iniciar, si aplica.

Uso rápido
----------
1) Edite las variables en `CONFIG` más abajo (HOST_TRABAJO, DOMINIO, USUARIO, etc.).
2) (Opcional) Registre credenciales seguras en Windows:  
   `cmdkey /generic:TERMSRV/<HOST> /user:<DOMINIO\\USUARIO> /pass:<SU_CONTRASEÑA>`
3) Ejecute: `python remoteconnect_workpc.py`
4) El script crea `conexion_trabajo.rdp` con parámetros óptimos y lanza `mstsc`.

Nota sobre credenciales
-----------------------
- Evite hardcodear contraseñas en este archivo. Use `cmdkey` (Administrador de Credenciales de Windows). 
- Si necesita ingresar credenciales manualmente, MSTSC las solicitará la primera vez según políticas.

"""

import os
import sys
import time
import socket
import subprocess
import ctypes
from pathlib import Path

try:
    import psutil  # type: ignore
except Exception:
    psutil = None

# ==================== CONFIGURACIÓN ====================
CONFIG = {
    # Nombre o IP del equipo de trabajo (RDP/3389). Puede ser FQDN interno.
    "HOST_TRABAJO": "mi-pc-trabajo.company.local",
    # Puerto RDP estándar. Cambie si su organización usa otro.
    "PUERTO_RDP": 3389,
    # Dirección/IP del gateway o recurso para validar conectividad (VPN/Router).
    "PROBE_RED": "8.8.8.8",  # o su gateway VPN interno
    # Dominio/Usuario (sin contraseña aquí para no exponerla).
    "DOMINIO": "MIEMPRESA",
    "USUARIO": "miusuario",
    # Ruta del archivo .rdp a generar.
    "RDP_FILE": str(Path.cwd() / "conexion_trabajo.rdp"),
    # Intervalos (segundos)
    "PING_INTERVAL": 5,
    "RETRY_BACKOFF": [3, 5, 10, 20, 30],  # retrocesos progresivos
    # Si necesita intentar habilitar RDP/firewall automáticamente (requiere Admin y política que lo permita):
    "INTENTAR_HABILITAR_RDP": False,
}
# ======================================================


def es_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def tcp_abre(host: str, puerto: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, puerto), timeout=timeout):
            return True
    except Exception:
        return False


def ping_basico(host: str, timeout_ms: int = 1500) -> bool:
    """Ping simple usando 'ping' de Windows (sin privilegios elevados)."""
    try:
        # -n 1 (una solicitud), -w timeout en ms
        r = subprocess.run(["ping", "-n", "1", "-w", str(timeout_ms), host], capture_output=True, text=True)
        return r.returncode == 0
    except Exception:
        return False


# ---------- Comprobaciones de RDP en Windows ----------

def comprobar_servicio_rdp() -> bool:
    """Verifica que el servicio de Escritorio remoto (TermService) esté en ejecución."""
    try:
        if psutil is None:
            # Fallback usando 'sc query'
            r = subprocess.run(["sc", "query", "TermService"], capture_output=True, text=True)
            return "RUNNING" in r.stdout.upper()
        else:
            for s in psutil.win_service_iter():  # type: ignore[attr-defined]
                if s.name().lower() == "termservice":
                    return s.status().lower() == "running"
            return False
    except Exception:
        return False


def comprobar_firewall_rdp() -> bool:
    """Comprueba si hay una regla de Firewall que permita RDP (3389/TCP) para el perfil actual."""
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetFirewallRule -DisplayGroup 'Escritorio remoto' -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq 'True'} | Measure-Object | % {$_.Count}",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        salida = (r.stdout or "").strip()
        return salida.isdigit() and int(salida) > 0
    except Exception:
        return False


def comprobar_registro_rdp_habilitado() -> bool:
    """Valida la clave fDenyTSConnections = 0 (RDP habilitado)."""
    try:
        import winreg  # type: ignore

        key_path = r"SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
            val, _ = winreg.QueryValueEx(k, "fDenyTSConnections")
            return int(val) == 0
    except Exception:
        return False


def comprobar_nla_habilitada() -> bool:
    """Comprueba si NLA (Autenticación a nivel de red) está habilitada (recomendado)."""
    try:
        import winreg  # type: ignore

        key_path = r"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
            val, _ = winreg.QueryValueEx(k, "UserAuthentication")
            return int(val) == 1
    except Exception:
        # Si no se puede leer, no asumimos deshabilitado
        return True


def intentar_habilitar_rdp_si_autorizado():
    """Intenta habilitar RDP + regla de firewall si está permitido y ejecuta como Admin."""
    if not CONFIG["INTENTAR_HABILITAR_RDP"]:
        return False
    if not es_admin():
        print("[INFO] Se requiere ejecutar como Administrador para habilitar RDP automáticamente.")
        return False
    print("[ACCION] Intentando habilitar RDP y reglas de firewall (con permiso y políticas válidas)...")
    try:
        comandos = [
            # Habilitar RDP (fDenyTSConnections = 0)
            "Set-ItemProperty -Path 'HKLM:SYS\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0",
            # Habilitar reglas de firewall del grupo 'Escritorio remoto'
            "Enable-NetFirewallRule -DisplayGroup 'Escritorio remoto'",
        ]
        full = "; ".join(comandos)
        r = subprocess.run(["powershell", "-NoProfile", "-Command", full], capture_output=True, text=True)
        if r.returncode == 0:
            print("[OK] RDP y firewall habilitados (si las políticas lo permiten).")
            return True
        print("[WARN] No se pudo habilitar automáticamente. Salida:", r.stdout, r.stderr)
        return False
    except Exception as e:
        print("[ERROR] ", e)
        return False


# ---------- Generación archivo .RDP optimizado ----------

def generar_rdp_file(path: str, host: str, dominio: str, usuario: str):
    """Crea un .rdp con parámetros pensados para estabilidad y fluidez."""
    contenido = f"""
full address:s:{host}
server port:i:{CONFIG['PUERTO_RDP']}
username:s:{dominio}\\\\{usuario}
autoreconnect:i:1
authentication level:i:2
prompt for credentials on client:i:0
negotiate security layer:i:1
enablecredsspsupport:i:1
networkautodetect:i:1
bandwidthautodetect:i:1
connection type:i:7
redirectprinters:i:0
redirectsmartcards:i:0
redirectcomports:i:0
redirectdrives:i:0
redirectclipboard:i:1
redirectposdevices:i:0
redirectdirectx:i:1
promptcredentialonce:i:0
bitmapcachepersistenable:i:1
compression:i:1
videoplaybackmode:i:1
use multimon:i:0
screen mode id:i:2
smart sizing:i:1
desktopwidth:i:1600
desktopheight:i:900
session bpp:i:32
""".strip()

    with open(path, "w", encoding="utf-8") as f:
        f.write(contenido)
    print(f"[OK] Archivo RDP generado: {path}")


# ---------- Lanzamiento y reconexión ----------

def lanzar_mstsc(path_rdp: str):
    try:
        return subprocess.Popen(["mstsc.exe", path_rdp])
    except FileNotFoundError:
        print("[ERROR] No se encontró mstsc.exe. Asegúrese de estar en Windows.")
        return None


def monitor_y_conectar():
    host = CONFIG["HOST_TRABAJO"]
    puerto = CONFIG["PUERTO_RDP"]
    rdp_path = CONFIG["RDP_FILE"]
    probe = CONFIG["PROBE_RED"]

    # Informes previos
    print("[INFO] Comprobando requisitos de RDP en el equipo local...")
    s_ok = comprobar_servicio_rdp()
    fw_ok = comprobar_firewall_rdp()
    reg_ok = comprobar_registro_rdp_habilitado()
    nla_ok = comprobar_nla_habilitada()
    print(f"  - Servicio TermService en ejecución: {s_ok}")
    print(f"  - Firewall permite RDP: {fw_ok}")
    print(f"  - Clave fDenyTSConnections = 0: {reg_ok}")
    print(f"  - NLA habilitada (recomendado): {nla_ok}")

    if not (s_ok and fw_ok and reg_ok):
        intento = intentar_habilitar_rdp_si_autorizado()
        if not intento:
            print("[AVISO] RDP parece no estar habilitado o el firewall lo bloquea. Solicite a TI habilitarlo o use una solución aprobada de acceso remoto.")

    generar_rdp_file(rdp_path, host, CONFIG["DOMINIO"], CONFIG["USUARIO"])

    backoffs = CONFIG["RETRY_BACKOFF"]
    idx = 0
    proc = None

    print("[INFO] Iniciando bucle de monitorización y conexión...")
    while True:
        # 1) Verificar conectividad de red/VPN
        red_ok = ping_basico(probe) or tcp_abre(probe, 53, timeout=1.5)
        if not red_ok:
            print("[RED] Sin conectividad general/VPN. Reintentando...")
            time.sleep(CONFIG["PING_INTERVAL"])
            continue

        # 2) Verificar socket RDP al host
        if tcp_abre(host, puerto, timeout=1.5):
            # Si no hay proceso o se cerró, láncelo
            if proc is None or proc.poll() is not None:
                print("[CONEXION] Puerto RDP accesible. Lanzando MSTSC...")
                proc = lanzar_mstsc(rdp_path)
                idx = 0  # reset backoff
            else:
                # Proceso vivo: sleep corto y seguir monitoreando
                time.sleep(CONFIG["PING_INTERVAL"])
        else:
            # No hay acceso al puerto RDP
            espera = backoffs[min(idx, len(backoffs) - 1)]
            print(f"[RDP] No se puede abrir TCP {host}:{puerto}. Reintento en {espera}s...")
            idx += 1
            time.sleep(espera)


if __name__ == "__main__":
    try:
        monitor_y_conectar()
    except KeyboardInterrupt:
        print("\n[INFO] Cancelado por el usuario.")
        sys.exit(0)
