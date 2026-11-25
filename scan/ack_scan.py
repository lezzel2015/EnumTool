# scan/ack_scan.py
# ACK Scan con Scapy: distingue entre FILTERED y UNFILTERED.

import time

from scapy.all import IP, TCP, sr1, ICMP
from utils import network, COMMON_PORTS, Fore, Style


def ack_scan(target, ports, timeout=2):
    """
    Realiza un ACK scan sobre IP o rango y una lista de puertos.
    Marca como UNFILTERED si recibe RST desde el host objetivo y FILTERED
    ante ausencia de respuesta o un ICMP Destination Unreachable.
    """
    ports = list(ports or [])
    if not ports:
        return {}

    hosts = network.expand_targets(target)
    results = {}

    for ip_addr in hosts:
        results[ip_addr] = {}
        print(f"{Fore.CYAN}Escaneando {ip_addr}:{Style.RESET_ALL}")

        for port in ports:
            try:
                ack_pkt = IP(dst=ip_addr) / TCP(dport=port, flags="A")
                start_time = time.time()
                resp = sr1(ack_pkt, timeout=timeout, verbose=0)
                rtt = (time.time() - start_time) if resp is not None else None
                entry = {"service": COMMON_PORTS.get(port, "Unknown")}

                if resp is None:
                    print(f"  {Fore.YELLOW}[FILTERED]   {ip_addr}:{port}{Style.RESET_ALL}")
                    entry.update({"status": "FILTERED", "rtt": None, "reason": "no-response"})
                elif resp.haslayer(TCP):
                    tcp_reply = resp.getlayer(TCP)
                    if (
                        not resp.haslayer(IP)
                        or resp.getlayer(IP).src != ip_addr
                        or tcp_reply.sport != int(port)
                        or tcp_reply.dport != ack_pkt.getlayer(TCP).sport
                    ):
                        entry.update({
                            "status": "UNKNOWN",
                            "rtt": rtt,
                            "reason": "unmatched-tcp-response",
                            "flags": int(tcp_reply.flags),
                        })
                    elif int(tcp_reply.flags) & 0x04:
                        print(f"  {Fore.GREEN}[UNFILTERED] {ip_addr}:{port}{Style.RESET_ALL}")
                        entry.update({"status": "UNFILTERED", "rtt": rtt, "flags": "RST"})
                    else:
                        entry.update({
                            "status": "UNKNOWN",
                            "rtt": rtt,
                            "flags": int(tcp_reply.flags),
                        })
                elif resp.haslayer(ICMP):
                    icmp_reply = resp.getlayer(ICMP)
                    if icmp_reply.type == 3:
                        print(f"  {Fore.YELLOW}[FILTERED] {ip_addr}:{port} (ICMP){Style.RESET_ALL}")
                        entry.update({
                            "status": "FILTERED",
                            "rtt": rtt,
                            "reason": "icmp-destination-unreachable",
                            "icmp": {
                                "type": int(icmp_reply.type),
                                "code": int(icmp_reply.code),
                            },
                        })
                    else:
                        entry.update({
                            "status": "UNKNOWN",
                            "rtt": rtt,
                            "reason": f"icmp(type={icmp_reply.type},code={icmp_reply.code})",
                        })
                else:
                    entry.update({"status": "UNKNOWN", "rtt": rtt, "reason": "unexpected-response"})

                results[ip_addr][port] = entry

            except Exception as e:
                print(f"  {Fore.RED}[ERROR] {ip_addr}:{port} - {e}{Style.RESET_ALL}")
                results[ip_addr][port] = {
                    "status": "ERROR",
                    "error": str(e),
                    "service": COMMON_PORTS.get(port, "Unknown"),
                }

    return results
