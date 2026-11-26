# fingerprint/http_headers.py
# Extracción de cabeceras HTTP/HTTPS en hosts objetivo.

import socket
import ssl

from utils import network, COMMON_PORTS, Fore, Style


def get_http_headers(
    ip_addr, port, timeout=3, use_https=None, insecure_tls=False, host_header=None
):
    """
    Obtiene las cabeceras HTTP/HTTPS realizando una petición GET.
    Devuelve un diccionario (posiblemente vacío) si la conexión termina sin
    excepción, o None si falla la conexión, TLS o la lectura.
    """
    headers = {}
    virtual_host = (host_header or ip_addr).strip()
    try:
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {virtual_host}\r\n"
            f"User-Agent: EnumTool-HTTPHeaders/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        if use_https is not None:
            tls = use_https
        else:
            tls = port in (443, 8443, 9443)

        if tls:
            context = ssl.create_default_context()
            if insecure_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip_addr, port), timeout=timeout) as sock:
                with context.wrap_socket(
                    sock,
                    # Keep SNI even with --insecure-tls; that option only disables
                    # certificate validation, it must not change virtual-host routing.
                    server_hostname=virtual_host,
                ) as ssock:
                    ssock.settimeout(timeout)
                    ssock.sendall(req)
                    response = bytearray()
                    while True:
                        data = ssock.recv(4096)
                        if not data:
                            break
                        response.extend(data)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip_addr, port))
                sock.sendall(req)
                response = bytearray()
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response.extend(data)

        text = bytes(response).decode(errors="replace")
        header_lines = text.split("\r\n\r\n")[0].split("\r\n")[1:]
        for line in header_lines:
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key.strip()] = value.strip()
        return headers

    except Exception:
        return None


def http_headers(
    target, ports, timeout=3, use_https=None, insecure_tls=False, host_header=None
):
    """
    Analiza cabeceras HTTP(S). Un fallo de HTTP/TLS no implica que el puerto
    TCP esté cerrado; en ese caso el estado del fingerprint es UNKNOWN.
    """
    hosts = network.expand_targets(target)
    results = {}

    for ip_addr in hosts:
        results.setdefault(ip_addr, {})
        print(f"{Fore.CYAN}Escaneando HTTP Headers en {ip_addr}:{Style.RESET_ALL}")

        for port in ports:
            if use_https is not None:
                proto = "HTTPS" if use_https else "HTTP"
            else:
                proto = "HTTPS" if port in (443, 8443, 9443) else "HTTP"
            registered_service = COMMON_PORTS.get(port, "Desconocido")
            print(f"\n  {Fore.YELLOW}[{proto}] {ip_addr}:{port}{Style.RESET_ALL}")

            request_options = {
                "timeout": timeout,
                "use_https": use_https,
                "insecure_tls": insecure_tls,
            }
            if host_header:
                request_options["host_header"] = host_header
            headers = get_http_headers(ip_addr, port, **request_options)
            if headers:
                for key, value in headers.items():
                    if key.lower() in ("server", "x-powered-by"):
                        print(f"    {Fore.GREEN}{key}: {value}{Style.RESET_ALL}")
                    else:
                        print(f"    {key}: {value}")
            else:
                print(
                    f"    {Fore.RED}No se pudieron obtener cabeceras HTTP de "
                    f"{ip_addr}:{port}{Style.RESET_ALL}"
                )

            detected_service = proto.lower() if headers is not None else None
            server = next(
                (value for key, value in (headers or {}).items() if key.lower() == "server"),
                None,
            )
            if headers is not None:
                label = proto
                if server:
                    label += f" ({server})"
                if registered_service.lower() not in ("http", "https", "desconocido", "unknown"):
                    label += f"; puerto registrado como {registered_service}"
                print(f"    Servicio detectado: {label}")

            entry = {
                # Keep the registered-port field for compatibility and expose
                # the protocol observed by the HTTP probe separately.
                "service": registered_service,
                "detected_service": detected_service,
                "product": server,
                "proto": proto,
                "headers": headers or {},
                "status": "OPEN" if headers is not None else "UNKNOWN",
            }
            if headers is None:
                entry["error"] = "http-header-request-failed"
            if host_header:
                entry["host_header"] = host_header
            results[ip_addr][port] = entry

    return results

