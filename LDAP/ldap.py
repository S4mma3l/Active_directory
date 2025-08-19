import concurrent.futures as cf
import csv
import ipaddress
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil  # opcional, útil para NICs
except Exception:
    psutil = None

from dateutil import tz
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

# ---------------- CONFIG ----------------
CONFIG = {
    "RANGO_IP": "172.28.24.0/24",        # ajusta tu subred
    "PUERTOS": [3389, 445, 389, 636, 22],
    "PING_TIMEOUT_MS": 800,
    "THREADS": 200,
    # Active Directory (cuenta de lectura autorizada)
    "AD_SERVER": "CRFF-DESIGN2.dominio.local",
    "AD_DOMAIN": "dominio.local",
    "AD_USER": "dominio\\cuenta_lectura",
    "AD_PASS": "********",               # usa un secreto/variable de entorno en producción
    "AD_BASE_DN": "DC=dominio,DC=com",
    "USE_LDAPS": False                   # True si tienes 636/TLS y certificado OK
}
OUT_DIR = Path.cwd() / "salidas_inventario"
OUT_DIR.mkdir(exist_ok=True)
# ---------------------------------------

def ping(host: str, timeout_ms: int) -> bool:
    # Windows: ping -n 1 -w <ms>
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", str(timeout_ms), host],
                           capture_output=True, text=True)
        return r.returncode == 0
    except Exception:
        return False

def tcp_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def scan_host(host: str, ports: list[int]) -> dict:
    alive = ping(host, CONFIG["PING_TIMEOUT_MS"])
    open_ports = []
    if alive:
        for p in ports:
            if tcp_open(host, p, 1.2):
                open_ports.append(p)
    return {"host": host, "alive": alive, "open_ports": open_ports}

def discover_subnet(cidr: str, ports: list[int], threads: int):
    results = []
    net = ipaddress.ip_network(cidr, strict=False)
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_host, str(ip), ports): str(ip) for ip in net.hosts()}
        for fut in cf.as_completed(futures):
            results.append(fut.result())
    return sorted(results, key=lambda r: (not r["alive"], r["host"]))

def save_csv(path: Path, rows: list[dict]):
    if not rows:
        path.write_text("")
        return
    fieldnames = sorted({k for r in rows for k in r.keys()})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

# ---------------- AD HELPERS ----------------

def ad_connect():
    server = Server(CONFIG["AD_SERVER"], use_ssl=CONFIG["USE_LDAPS"], get_info=ALL)
    conn = Connection(
        server,
        user=CONFIG["AD_USER"],
        password=CONFIG["AD_PASS"],
        authentication=NTLM,
        auto_bind=True
    )
    return conn

def filetime_to_dt(filetime: str | int | None):
    """
    Convierte Windows FileTime (100ns desde 1601) a datetime. 0 o None => None.
    """
    try:
        val = int(filetime)
        if val == 0:
            return None
        # FILETIME to UNIX epoch
        # 116444736000000000 = diferencia entre 1601 y 1970 en 100ns
        unix_100ns = val - 116444736000000000
        seconds = unix_100ns / 10_000_000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).astimezone(tz.tzlocal())
    except Exception:
        return None

def fetch_ad_users(conn) -> list[dict]:
    attrs = [
        "sAMAccountName", "userPrincipalName", "displayName", "distinguishedName",
        "userAccountControl", "pwdLastSet", "lastLogonTimestamp", "whenCreated",
        "memberOf"
    ]
    conn.search(CONFIG["AD_BASE_DN"],
                "(objectCategory=person)",
                search_scope=SUBTREE,
                attributes=attrs)
    rows = []
    for e in conn.entries:
        dn = str(e.distinguishedName)
        uac = int(e.userAccountControl.value) if e.userAccountControl.value else None
        pwd_dt = filetime_to_dt(e.pwdLastSet.value)
        lastlogon_dt = filetime_to_dt(e.lastLogonTimestamp.value)
        rows.append({
            "sAMAccountName": str(e.sAMAccountName) if e.sAMAccountName else "",
            "userPrincipalName": str(e.userPrincipalName) if e.userPrincipalName else "",
            "displayName": str(e.displayName) if e.displayName else "",
            "distinguishedName": dn,
            "userAccountControl": uac,
            "pwdLastSet": pwd_dt.isoformat() if pwd_dt else "",
            "lastLogonTimestamp": lastlogon_dt.isoformat() if lastlogon_dt else "",
            "whenCreated": str(e.whenCreated) if e.whenCreated else "",
            "memberOf": ";".join(e.memberOf.values) if e.memberOf else ""
        })
    return rows

def fetch_ad_computers(conn) -> list[dict]:
    attrs = ["dNSHostName", "operatingSystem", "operatingSystemVersion",
             "lastLogonTimestamp", "distinguishedName", "whenCreated"]
    conn.search(CONFIG["AD_BASE_DN"],
                "(objectCategory=computer)",
                search_scope=SUBTREE,
                attributes=attrs)
    rows = []
    for e in conn.entries:
        lastlogon_dt = filetime_to_dt(e.lastLogonTimestamp.value)
        rows.append({
            "dNSHostName": str(e.dNSHostName) if e.dNSHostName else "",
            "operatingSystem": str(e.operatingSystem) if e.operatingSystem else "",
            "operatingSystemVersion": str(e.operatingSystemVersion) if e.operatingSystemVersion else "",
            "lastLogonTimestamp": lastlogon_dt.isoformat() if lastlogon_dt else "",
            "distinguishedName": str(e.distinguishedName),
            "whenCreated": str(e.whenCreated) if e.whenCreated else "",
        })
    return rows

def fetch_password_policy(conn) -> list[dict]:
    # Política por defecto de dominio (resumen). Para FGPP habría que consultar msDS-PasswordSettings
    conn.search(CONFIG["AD_BASE_DN"],
                "(objectClass=domainDNS)",
                attributes=["minPwdLength", "pwdProperties", "maxPwdAge", "minPwdAge", "lockoutDuration",
                            "lockoutThreshold", "lockoutObservationWindow"])
    rows = []
    for e in conn.entries:
        # maxPwdAge, minPwdAge son FILETIME negativos en intervalos de 100ns
        def filetime_interval_to_days(v):
            try:
                i = int(v)
                if i == 0:
                    return ""
                seconds = abs(i) / 10_000_000
                return round(seconds / 86400, 2)
            except Exception:
                return ""
        rows.append({
            "minPwdLength": str(e.minPwdLength) if e.minPwdLength else "",
            "pwdProperties": str(e.pwdProperties) if e.pwdProperties else "",
            "maxPwdAge_days": filetime_interval_to_days(e.maxPwdAge.value if e.maxPwdAge else 0),
            "minPwdAge_days": filetime_interval_to_days(e.minPwdAge.value if e.minPwdAge else 0),
            "lockoutThreshold": str(e.lockoutThreshold) if e.lockoutThreshold else "",
            "lockoutDuration_minutes": (filetime_interval_to_days(e.lockoutDuration.value) or "") if e.lockoutDuration else "",
            "lockoutObservationWindow_minutes": (filetime_interval_to_days(e.lockoutObservationWindow.value) or "") if e.lockoutObservationWindow else "",
        })
    return rows

def main():
    print("[*] Descubriendo hosts en", CONFIG["RANGO_IP"])
    hosts = discover_subnet(CONFIG["RANGO_IP"], CONFIG["PUERTOS"], CONFIG["THREADS"])
    save_csv(OUT_DIR / "hosts_descubiertos.csv", hosts)
    vivos = [h for h in hosts if h["alive"]]
    print(f"    - Vivos: {len(vivos)} / {len(hosts)}  (CSV: hosts_descubiertos.csv)")

    print("[*] Conectando a AD (solo lectura)…")
    try:
        conn = ad_connect()
    except Exception as e:
        print("[!] No se pudo conectar a AD:", e)
        print("    Verifica servidor, credenciales y conectividad (389/636).")
        return

    print("[*] Consultando usuarios AD…")
    users = fetch_ad_users(conn)
    save_csv(OUT_DIR / "ad_usuarios.csv", users)
    print(f"    - Usuarios exportados: {len(users)}  (CSV: ad_usuarios.csv)")

    print("[*] Consultando equipos AD…")
    comps = fetch_ad_computers(conn)
    save_csv(OUT_DIR / "ad_equipos.csv", comps)
    print(f"    - Equipos exportados: {len(comps)}  (CSV: ad_equipos.csv)")

    print("[*] Consultando política de contraseñas…")
    policy = fetch_password_policy(conn)
    save_csv(OUT_DIR / "ad_politica_password.csv", policy)
    print("    - Política exportada (CSV: ad_politica_password.csv)")

    print("[OK] Listo. Revisa la carpeta:", str(OUT_DIR))

if __name__ == "__main__":
    main()
