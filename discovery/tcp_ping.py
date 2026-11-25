# discovery/tcp_ping.py
# TCP Ping - Envía SYN y detecta respuestas SYN/ACK o RST del host objetivo

from scapy.all import IP, TCP, sr1
from utils import network, Fore, Style
import time


def tcp_ping(target, ports, tout):
    """
    Realiza TCP ping a uno o varios hosts (IP o rango CIDR) y puertos.
    Solo devuelve hosts que responden con SYN/ACK o RST desde la IP objetivo.
    target: IP o rango (ej: '192.168.1.0/24')
    ports: iterable de puertos (ej: [22, 80, 443])
    """
    print(f"[+] TCP Ping - Target: {target} Port: {ports}")
    results = {}

    try:
        hosts = network.expand_targets(target)

        for ip_addr in hosts:
            for port in ports:
                pkt = IP(dst=ip_addr) / TCP(dport=port, flags="S")
                start = time.time()
                resp = sr1(pkt, timeout=tout, verbose=0)
                rtt = (time.time() - start) if resp else None

                if not resp or not resp.haslayer(IP) or resp.getlayer(IP).src != ip_addr:
                    continue
                if not resp.haslayer(TCP):
                    continue

                tcp_reply = resp.getlayer(TCP)
                if tcp_reply.sport != int(port) or tcp_reply.dport != pkt.getlayer(TCP).sport:
                    continue

                flags = int(tcp_reply.flags)
                if flags & 0x12 == 0x12 and not flags & 0x04:
                    flag_name = "SYN/ACK"
                elif flags & 0x04:
                    flag_name = "RST"
                else:
                    continue

                print(f"{Fore.GREEN}[+] Host {ip_addr} is on{Style.RESET_ALL}")
                results[ip_addr] = {
                    "method": "TCP",
                    "ports": [port],
                    "rtt": rtt,
                    "flags": flag_name,
                }
                break

    except network.TargetExpansionError:
        raise
    except Exception as e:
        print(f"{Fore.RED}[!] Error en TCP Ping: {e}{Style.RESET_ALL}")

    return results
