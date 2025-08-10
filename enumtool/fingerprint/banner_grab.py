
# fingerprint/banner_grab.py
# Módulo de Banner Grabbing con escaneo TCP Connect previo.
# Fase 1: Identifica puertos abiertos con tcp_connect().
# Fase 2: Intenta leer banners sólo de puertos abiertos.
# Limpieza avanzada: elimina caracteres no imprimibles, saltos de línea, tabs y espacios duplicados.

# -------------------------------
# IMPORTACIONES NECESARIAS
# -------------------------------
from scan.tcp_connect import tcp_connect                # Escaneo TCP activo reutilizable
from utils.services import COMMON_PORTS                 # Diccionario de puertos conocidos
from utils import network                               # Expansión de rangos y subredes
from colorama import Fore, Style                        # Colores para salida por consola
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import string
import re
import ssl
from utils.config import BANNER_PATTERNS, PAYLOADS

# -------------------------------------
# Banners activos por protocolo conocido
# -------------------------------------
"""
PAYLOADS = {
    21: b"USER anonymous\r\n",                      # FTP
    23: b"\r\n",                                    # Telnet
    25: b"EHLO enumtool.local\r\n",                 # SMTP
    80: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",  # HTTP
    110: b"USER test\r\n",                          # POP3
    143: b"a001 CAPABILITY\r\n",                    # IMAP
    443: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", # HTTPS (TLS)
    993: b"\r\n",                                   # IMAPS
    995: b"\r\n",                                   # POP3S
}
"""
# -------------------------------------
# Expresiones regulares para extraer versión
# -------------------------------------
"""
VERSION_REGEX = [
    r"OpenSSH[_\-/\s]?([\d\.p]+)",
    r"vsFTPd[_\-/\s]?([\d\.]+)",
    r"Microsoft.*?(IIS|SMTP|Exchange)[/\s]?([\d\.]+)",
    r"Apache[/\s]?([\d\.]+)",
    r"ProFTPD[/\s]?([\d\.]+)",
    r"Postfix[/\s]?([\d\.]+)"
]
"""

# -------------------------------------
# Limpieza del banner para mostrar sólo caracteres válidos
# -------------------------------------
def clean_banner(banner):
    """
    Elimina caracteres no imprimibles y formateo extraño.
    - Quita saltos de línea, retorno de carro y tabs
    - Sustituye múltiples espacios/tabs por un único espacio
    """
    filtered = ''.join(c for c in banner if c in string.printable and c not in ('\r', '\n', '\t'))
    return re.sub(r'\s+', ' ', filtered).strip()

# -------------------------------------
# Intenta extraer la versión del banner mediante patrones
# -------------------------------------
def extract_version(banner):
    for pattern, proto in BANNER_PATTERNS:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.groupdict().get("version"), match.groupdict().get("product"), proto
    return None, None, None


# -------------------------------------
# Función principal para obtener banner activo
# -------------------------------------
def grab_banner(ip, port, timeout, insecure_tls=False):
    """
    Devuelve: (banner_str, version_str|None, status_str)
    """
    def _recv_all(sock, tries=3):
        sock.settimeout(timeout)
        chunks = []
        for _ in range(tries):
            try:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                # si llegó cabecera HTTP completa, paramos pronto
                if b"\r\n\r\n" in b"".join(chunks):
                    break
            except socket.timeout:
                break
            except Exception:
                break
        return (b"".join(chunks)).decode(errors="replace")

    def _tcp_plain():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # intento pasivo
            raw = _recv_all(s, tries=1)
            if not raw:
                # payload específico o “\r\n” genérico
                payload = PAYLOADS.get(port, b"\r\n")
                try:
                    s.sendall(payload)
                except Exception:
                    pass
                raw = _recv_all(s, tries=2)
            return raw, "OK"

    def _tcp_tls():
        # Para grabbing NO validamos cert/hostname
        ctx = ssl.create_default_context()
        if insecure_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    raw = _recv_all(ssock, tries=2)
                    if not raw:
                        payload = PAYLOADS.get(port, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        try:
                            ssock.sendall(payload)
                        except Exception:
                            pass
                        raw = _recv_all(ssock, tries=2)
            return raw, "TLS_OK"
        except Exception:
            return "", "TLS_FAIL"

    try:
        # Selección de canal
        if port in (443, 993, 995):
            raw, tls_status = _tcp_tls()
            status = tls_status
            if not raw and tls_status == "TLS_FAIL":
                # último intento en claro, por si está offloaded
                raw, status = _tcp_plain()
        else:
            raw, status = _tcp_plain()

        # Limpieza
        banner = clean_banner(raw)

        # Afinado para HTTP: quedarnos con líneas útiles
        if port in (80, 443, 8080):
            lines = raw.splitlines()
            headers = [l.strip() for l in lines if l.strip().startswith(("HTTP/", "Server:", "X-Powered-By:"))]
            if headers:
                banner = " | ".join(clean_banner(h) for h in headers)

        # Extracción de versión (usa patrones unificados)
        version = extract_version(banner)

        # Normaliza salida
        return (banner if banner else "Unknown", version, status if status else "OK")

    except socket.timeout:
        return "Unknown", None, "TIMEOUT"
    except Exception:
        return "Unknown", None, "ERROR"


# -------------------------------------
# Módulo principal: escanea puertos, recoge banners y los analiza
# -------------------------------------
def banner_grab(target, ports, timeout, threads=5, minimal_output=False, insecure_tls=False) :
    """
    Ejecuta el módulo completo:
    1. Escanea los puertos especificados con tcp_connect()
    2. Ejecuta banner grabbing sólo sobre puertos abiertos
    3. Muestra los resultados ordenados por número de puerto

    Parámetros:
        - target: IP o rango CIDR
        - ports: lista de puertos (int)
        - timeout: tiempo de espera por conexión
        - threads: número de hilos simultáneos
        - minimal_output: sin efecto aquí (conservado por compatibilidad)
    """
    threads = max(1, min(threads, 100))  # Seguridad: límite máximo de hilos
    hosts = network.expand_targets(target)
    results = {}

    print(f"{Fore.CYAN}[*] Fase 1: escaneo TCP Connect para puertos abiertos...{Style.RESET_ALL}")
    scan_results = tcp_connect(target, ports, timeout, threads=threads, minimal_output=True, verbose=False)

    print(f"\n{Fore.CYAN}[*] Fase 2: banner grabbing sobre puertos abiertos...{Style.RESET_ALL}")
    for ip_addr, ports_dict in scan_results.items():
        results[ip_addr] = {}
        open_ports = sorted(p for p, info in ports_dict.items() if info.get("status") == "OPEN")

        if not open_ports:
            print(f"{Fore.YELLOW}[!] No se encontraron puertos abiertos en {ip_addr}{Style.RESET_ALL}")
            continue

        # Ejecutamos tareas concurrentes por cada puerto abierto
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {
                executor.submit(grab_banner, ip_addr, port, timeout, insecure_tls=insecure_tls): port for port in open_ports
            }

            banners = {}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                banner, version, status = future.result()
                service = COMMON_PORTS.get(port, "Unknown")
                banners[port] = {"banner": banner, "version": version, "service": service, "status": status}

            # Mostramos resultados en orden numérico
            for port in sorted(banners):
                entry = banners[port]
                banner = entry["banner"]
                version = entry["version"]
                service = entry["service"]
                status = entry["status"]
                results[ip_addr][port] = entry
                version_str = f" | Version: {version}" if version else ""
                print(f"  {Fore.GREEN}[BANNER] {ip_addr}:{port} ({service}) -> {banner}{version_str}{Style.RESET_ALL}")

    return results
