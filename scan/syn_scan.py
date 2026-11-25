# scan/syn_scan.py
# SYN Scan (half-open): classifies TCP replies and relevant ICMP errors.

from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from scapy.all import IP, TCP, sr1, send, ICMP
from utils import network, COMMON_PORTS, Fore, Style


def scan_syn_port(ip_addr, port, timeout):
    """Escanea un puerto SYN y devuelve siempre un estado explícito."""
    try:
        syn_pkt = IP(dst=ip_addr) / TCP(dport=port, flags="S")
        start_time = time.time()
        resp = sr1(syn_pkt, timeout=timeout, verbose=0)
        rtt = time.time() - start_time

        if resp is None:
            result = {"status": "FILTERED", "rtt": None}
        elif resp.haslayer(TCP) and resp.haslayer(IP):
            tcp_reply = resp.getlayer(TCP)
            if (
                resp.getlayer(IP).src != ip_addr
                or tcp_reply.sport != int(port)
                or tcp_reply.dport != syn_pkt.getlayer(TCP).sport
            ):
                result = {"status": "UNKNOWN", "reason": "unmatched-tcp-response", "rtt": rtt}
            else:
                flags = int(tcp_reply.flags)
                if flags & 0x04:
                    result = {"status": "CLOSED", "rtt": rtt}
                elif flags & 0x12 == 0x12:
                    result = {
                        "status": "OPEN",
                        "service": COMMON_PORTS.get(port, "Unknown"),
                        "rtt": rtt,
                    }
                    rst_pkt = IP(dst=ip_addr) / TCP(
                        sport=syn_pkt.getlayer(TCP).sport,
                        dport=port,
                        flags="R",
                        seq=tcp_reply.ack,
                    )
                    send(rst_pkt, verbose=0)
                else:
                    result = {"status": "UNKNOWN", "flags": str(tcp_reply.flags), "rtt": rtt}
        elif resp.haslayer(ICMP):
            icmp_reply = resp.getlayer(ICMP)
            if icmp_reply.type == 3:
                result = {
                    "status": "FILTERED",
                    "reason": "icmp-destination-unreachable",
                    "icmp": {"type": int(icmp_reply.type), "code": int(icmp_reply.code)},
                    "rtt": rtt,
                }
            else:
                result = {
                    "status": "UNKNOWN",
                    "reason": f"icmp(type={icmp_reply.type},code={icmp_reply.code})",
                    "rtt": rtt,
                }
        else:
            result = {"status": "NO_TCP", "rtt": rtt}

    except Exception as e:
        result = {"status": "ERROR", "error": str(e)}

    return port, result


def syn_scan(target, ports, timeout, threads=5, minimal_output=False, verbose=True):
    """
    Ejecuta un SYN scan concurrente sobre varios hosts y puertos.
    Usa RST para cerrar las respuestas SYN/ACK sin completar el handshake.
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
                executor.submit(scan_syn_port, ip_addr, port, timeout): port for port in ports
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
                        print(f"  {Fore.GREEN}[OPEN]   {ip_addr}:{port} ({service})  RTT={rtt_text}{Style.RESET_ALL}")
                        open_ports_list.append(port)
                    elif not minimal_output:
                        if status == "CLOSED":
                            rtt_text = f"{rtt:.3f}s" if rtt is not None else "n/a"
                            print(f"  {Fore.RED}[CLOSED]  {ip_addr}:{port}  RTT={rtt_text}{Style.RESET_ALL}")
                        elif status == "FILTERED":
                            print(f"  {Fore.YELLOW}[FILTERED] {ip_addr}:{port}{Style.RESET_ALL}")
                        elif status == "NO_TCP":
                            print(f"  {Fore.YELLOW}[NO TCP] {ip_addr}:{port}{Style.RESET_ALL}")
                        elif status == "UNKNOWN":
                            print(f"  {Fore.MAGENTA}[UNKNOWN] {ip_addr}:{port} {item.get('reason', item.get('flags', '?'))}{Style.RESET_ALL}")
                        elif status == "ERROR":
                            print(f"  {Fore.RED}[ERROR]  {ip_addr}:{port} - {item.get('error')}{Style.RESET_ALL}")

                if open_ports_list:
                    print(f"\nListado de puertos abiertos: {','.join(str(p) for p in open_ports_list)}")

    return results
