# scan/tcp_connect.py
# SYN-based TCP Connect scan. Completes the handshake and immediately resets
# the connection so it does not remain established on the remote host.

from concurrent.futures import ThreadPoolExecutor, as_completed
import time

import errno
import socket
from utils import network, COMMON_PORTS, Fore, Style


def scan_port(ip_addr, port, timeout):
    """Conecta a un puerto TCP y devuelve siempre un estado explícito."""
    start_time = time.perf_counter()
    try:
        with socket.create_connection((ip_addr, int(port)), timeout=timeout):
            rtt = time.perf_counter() - start_time
            result = {
                "status": "OPEN",
                "service": COMMON_PORTS.get(port, "Unknown"),
                "rtt": rtt,
            }
    except socket.timeout:
        result = {"status": "FILTERED", "rtt": None}
    except ConnectionRefusedError:
        result = {"status": "CLOSED", "rtt": time.perf_counter() - start_time}
    except OSError as e:
        if e.errno == errno.ECONNREFUSED:
            result = {"status": "CLOSED", "rtt": time.perf_counter() - start_time}
        elif e.errno in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
            result = {"status": "FILTERED", "rtt": None}
        else:
            result = {"status": "ERROR", "error": str(e)}
    except Exception as e:
        result = {"status": "ERROR", "error": str(e)}

    return port, result

def tcp_connect(target, ports, timeout, threads=5, minimal_output=False, verbose=True):
    """
    Ejecuta un escaneo TCP Connect concurrente sobre varios hosts y puertos.
    Completa el handshake y envía RST inmediatamente después para cerrar
    cada conexión identificada como abierta.
    """
    ports = list(ports or [])
    if not ports:
        return {}

    threads = max(1, min(threads, 100))
    hosts = network.expand_targets(target)
    results = {}

    for ip_addr in hosts:
        print(f"\n{Fore.CYAN}Escaneando {ip_addr}:{Style.RESET_ALL}")
        results[ip_addr] = {}

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {
                executor.submit(scan_port, ip_addr, port, timeout): port for port in ports
            }

            completed = []
            total_ports = len(ports)
            completed_count = 0
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port, result = future.result()
                    results[ip_addr][port] = result
                    completed.append((port, result))
                except Exception as exc:
                    results[ip_addr][port] = {"status": "ERROR", "error": str(exc)}
                    completed.append((port, results[ip_addr][port]))

                completed_count += 1
                percent = (completed_count / total_ports) * 100
                print(f"\r[+] Progreso: {completed_count}/{total_ports} ({percent:.1f}%)", end="", flush=True)

            if verbose:
                count_open = sum(1 for _, item in completed if item.get("status") == "OPEN")
                count_closed = sum(1 for _, item in completed if item.get("status") == "CLOSED")
                print(
                    f"\n\n{Fore.CYAN}De {len(completed)} puertos escaneados, "
                    f"{count_open} están abiertos, {count_closed} cerrados y "
                    f"{len(completed) - count_closed - count_open} filtrados/desconocidos"
                    f"{Style.RESET_ALL}"
                )

                open_ports_list = []
                for port, item in sorted(completed):
                    status = item.get("status", "UNKNOWN")
                    rtt = item.get("rtt")
                    service = item.get("service", "")
                    if status == "OPEN":
                        rtt_text = f"{rtt:.3f}s" if rtt is not None else "n/a"
                        print(f"  {Fore.GREEN}[OPEN]  {ip_addr}:{port} ({service})  RTT={rtt_text}{Style.RESET_ALL}")
                        open_ports_list.append(port)
                    elif not minimal_output:
                        if status == "CLOSED":
                            rtt_text = f"{rtt:.3f}s" if rtt is not None else "n/a"
                            print(f"  {Fore.RED}[CLOSED] {ip_addr}:{port}  RTT={rtt_text}{Style.RESET_ALL}")
                        elif status == "FILTERED":
                            print(f"  {Fore.YELLOW}[FILTERED] {ip_addr}:{port}{Style.RESET_ALL}")
                        elif status == "NO_TCP":
                            print(f"  {Fore.YELLOW}[NO TCP] {ip_addr}:{port}{Style.RESET_ALL}")
                        elif status == "UNKNOWN":
                            print(f"  {Fore.MAGENTA}[UNKNOWN] {ip_addr}:{port} {item.get('reason', item.get('flags', '?'))}{Style.RESET_ALL}")
                        elif status == "ERROR":
                            print(f"  {Fore.RED}[ERROR] {ip_addr}:{port} - {item.get('error')}{Style.RESET_ALL}")

                if open_ports_list:
                    print(f"\nListado de puertos abiertos: {','.join(str(p) for p in open_ports_list)}")

    return results
