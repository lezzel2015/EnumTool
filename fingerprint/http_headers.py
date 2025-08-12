# fingerprint/http_headers.py
# Extracción de cabeceras HTTP en hosts objetivo sobre puertos HTTP/HTTPS.
# Utiliza Scapy para descubrimiento (si es necesario) y requests/socket para la consulta HTTP(S).
# Por defecto, analiza los puertos 80 (HTTP) y 443 (HTTPS) si no se especifican otros.

import socket
import ssl
from colorama import Fore, Style
from utils import network, COMMON_PORTS

def get_http_headers(ip_addr, port, timeout=3, use_https=None):
    """
    Obtiene las cabeceras HTTP/HTTPS realizando una petición GET al host/puerto indicado.
    Si use_https==True fuerza TLS, si False HTTP normal, si None autodetecta por puerto.
    Devuelve un diccionario {header: valor} o None si hay error.
    """
    headers = {}
    try:
        # Construir petición HTTP básica
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip_addr}\r\n"
            f"User-Agent: EnumTool-HTTPHeaders/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        # Decide si se usa TLS (HTTPS)
        if use_https is not None:
            tls = use_https
        else:
            # Autodetecta: TLS para 443, 8443, 9443...
            tls = port in [443, 8443, 9443]

        # HTTPS (TLS)
        if tls:
            context = ssl.create_default_context()
            with socket.create_connection((ip_addr, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip_addr) as ssock:
                    ssock.sendall(req)
                    response = b""
                    while True:
                        data = ssock.recv(4096)
                        if not data:
                            break
                        response += data
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip_addr, port))
                s.sendall(req)
                response = b""
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data

        # Parsear las cabeceras
        text = response.decode(errors="replace")
        header_lines = text.split("\r\n\r\n")[0].split("\r\n")[1:]
        for line in header_lines:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.strip()] = v.strip()
        return headers

    except Exception as e:
        return None

def http_headers(target, ports, timeout=3, threads=10, minimal_output=False, use_https=None):
    """
    Analiza cabeceras HTTP(S) de uno o varios hosts objetivo en los puertos indicados.
    Si no se pasan puertos, usa 80 y 443 por defecto.
    Si use_https es True fuerza HTTPS, False fuerza HTTP, None autodetecta por puerto.
    Salida formateada y coloreada.
    """
    hosts = network.expand_targets(target)

    # Estructura de datos para devolver resultado a main
    results = {}

    for ip_addr in hosts:
        results.setdefault(ip_addr, {})
        print(f"{Fore.CYAN}Escaneando HTTP Headers en {ip_addr}:{Style.RESET_ALL}")
        for port in ports:
            # Decide protocolo a mostrar
            if use_https is not None:
                proto = "HTTPS" if use_https else "HTTP"
            else:
                proto = "HTTPS" if port in [443, 8443, 9443] else "HTTP"
            service = COMMON_PORTS.get(port, "Desconocido")
            print(f"\n  {Fore.YELLOW}[{proto}] {ip_addr}:{port} ({service}){Style.RESET_ALL}")

            headers = get_http_headers(ip_addr, port, timeout=timeout, use_https=use_https)
            if headers:
                for k, v in headers.items():
                    if k.lower() in ("server", "x-powered-by"):
                        print(f"    {Fore.GREEN}{k}: {v}{Style.RESET_ALL}")
                    else:
                        print(f"    {k}: {v}")
            else:
                print(f"    {Fore.RED}No se pudo obtener cabeceras HTTP de {ip_addr}:{port}{Style.RESET_ALL}")

            # Guardar resultados por puerto para devolver a main
            entry = {"service": COMMON_PORTS.get(port, "Desconocido"), "proto": proto, "headers": headers or {},
                     "status": "OPEN" if headers else "CLOSED"}
            results[ip_addr][port] = entry

    return results
