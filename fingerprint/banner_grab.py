# fingerprint/banner_grab.py
# Módulo de Banner Grabbing con escaneo TCP Connect previo.
# Intenta leer banners solo de los puertos confirmados como abiertos.

from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import socket
import ssl
import string

from scan.tcp_connect import tcp_connect
from utils import BANNER_PATTERNS, COMMON_PORTS, Fore, PAYLOADS, Style


def clean_banner(banner):
    """Elimina caracteres no imprimibles y normaliza el espacio."""
    filtered = "".join(" " if c in "\r\n\t" else c for c in banner if c in string.printable)
    cleaned = re.sub(r"\s+", " ", filtered).strip()
    return re.sub(r"([0-9][A-Za-z]+)(Debian|Ubuntu|Alpine|CentOS|RedHat)", r"\1 \2", cleaned)


def extract_version(banner):
    for pattern, proto in BANNER_PATTERNS:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.groupdict().get("version"), match.groupdict().get("product"), proto
    return None, None, None


def grab_banner(ip, port, timeout, insecure_tls=False, http_host=None, use_https=None):
    """Devuelve (banner, version_string|None, transport_status)."""
    def _recv_all(sock, tries=3):
        sock.settimeout(timeout)
        chunks = []
        for _ in range(tries):
            try:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if b"\r\n\r\n" in b"".join(chunks):
                    break
            except socket.timeout:
                break
            except Exception:
                break
        return b"".join(chunks).decode(errors="replace")

    def _tcp_plain():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            data = _recv_all(sock, tries=1)
            if data:
                # Keep services that speak first (such as SSH) as banners;
                # don't send them an HTTP request just because --http-host
                # was provided for other ports in the same scan.
                return data, "OK"
            if http_host:
                request = (
                    f"GET / HTTP/1.1\r\nHost: {http_host}\r\n"
                    "User-Agent: EnumTool-Banner/1.0\r\nConnection: close\r\n\r\n"
                ).encode()
                sock.sendall(request)
                return _recv_all(sock, tries=3), "OK"
            if not data:
                payload = PAYLOADS.get(port, b"\r\n")
                try:
                    sock.sendall(payload)
                except Exception:
                    pass
                data = _recv_all(sock, tries=2)
            return data, "OK"

    def _tcp_tls():
        ctx = ssl.create_default_context()
        if insecure_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=http_host or ip) as ssock:
                    if http_host:
                        request = (
                            f"GET / HTTP/1.1\r\nHost: {http_host}\r\n"
                            "User-Agent: EnumTool-Banner/1.0\r\nConnection: close\r\n\r\n"
                        ).encode()
                        ssock.sendall(request)
                        return _recv_all(ssock, tries=3), "TLS_OK"
                    data_raw = _recv_all(ssock, tries=2)
                    if not data_raw:
                        payload = PAYLOADS.get(
                            port,
                            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                        )
                        try:
                            ssock.sendall(payload)
                        except Exception:
                            pass
                        data_raw = _recv_all(ssock, tries=2)
            return data_raw, "TLS_OK"
        except Exception:
            return "", "TLS_FAIL"

    try:
        tls = use_https if use_https is not None else port in (443, 993, 995)
        if tls:
            raw, status = _tcp_tls()
            if not raw and status == "TLS_FAIL":
                raw, status = _tcp_plain()
        else:
            raw, status = _tcp_plain()

        banner = clean_banner(raw)
        if port in (80, 443, 8080) or http_host:
            lines = raw.splitlines()
            headers = [
                line.strip()
                for line in lines
                if line.strip().startswith(("HTTP/", "Server:", "X-Powered-By:"))
            ]
            if headers:
                banner = " | ".join(clean_banner(line) for line in headers)

        version, _product, _protocol = extract_version(banner)
        return banner if banner else "Unknown", version, status or "OK"

    except socket.timeout:
        return "Unknown", None, "TIMEOUT"
    except Exception:
        return "Unknown", None, "ERROR"


def banner_grab(target, ports, timeout, threads=5, insecure_tls=False, http_host=None, use_https=None):
    """
    Escanea los puertos indicados y obtiene banners únicamente de los que
    TCP Connect clasifica como abiertos.
    """
    threads = max(1, min(threads, 100))
    results = {}

    print(f"{Fore.CYAN}[*] Fase 1: escaneo TCP Connect para puertos abiertos...{Style.RESET_ALL}")
    scan_results = tcp_connect(
        target,
        ports,
        timeout,
        threads=threads,
        minimal_output=True,
        verbose=False,
    )

    print(f"\n{Fore.CYAN}[*] Fase 2: banner grabbing sobre puertos abiertos...{Style.RESET_ALL}")
    for ip_addr, ports_dict in scan_results.items():
        results[ip_addr] = {}
        open_ports = sorted(
            port for port, info in ports_dict.items() if info.get("status") == "OPEN"
        )
        if not open_ports:
            print(
                f"{Fore.YELLOW}[!] No se encontraron puertos abiertos en {ip_addr}."
                f"{Style.RESET_ALL}"
            )
            continue

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {
                executor.submit(
                    grab_banner,
                    ip_addr,
                    port,
                    timeout,
                    insecure_tls=insecure_tls,
                    http_host=http_host,
                    use_https=use_https,
                ): port
                for port in open_ports
            }

            banners = {}
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                banner, version, status = future.result()
                banners[port] = {
                    "banner": banner,
                    "version": version,
                    "service": COMMON_PORTS.get(port, "Unknown"),
                    "detected_service": (
                        "https" if status == "TLS_OK" and banner.startswith("HTTP/")
                        else "http" if banner.startswith("HTTP/")
                        else None
                    ),
                    "product": next(
                        (line.split(":", 1)[1].strip() for line in banner.split(" | ") if line.lower().startswith("server:")),
                        None,
                    ),
                    "status": status,
                }

            for port in sorted(banners):
                entry = banners[port]
                results[ip_addr][port] = entry
                version_str = f" | Version: {entry['version']}" if entry["version"] else ""
                detected = entry.get("detected_service")
                service_label = entry["service"]
                if detected:
                    service_label = detected.upper()
                    if entry.get("product"):
                        service_label += f" ({entry['product']})"
                    if entry["service"].lower() not in ("http", "https", "unknown"):
                        service_label += f"; registrado como {entry['service']}"
                print(
                    f"  {Fore.GREEN}[BANNER] {ip_addr}:{port} - [{entry['status']}] "
                    f"- ({service_label}) -> {entry['banner']}{version_str}{Style.RESET_ALL}"
                )

    return results

