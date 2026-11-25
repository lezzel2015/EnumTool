# discovery/udp_ping.py
# UDP Ping estilo Nmap: registra respuestas UDP o ICMP atribuibles al host objetivo

from scapy.all import IP, UDP, sr1, ICMP
from utils import network, Fore, Style


def udp_ping(target, ports, tout):
    """
    Envía paquetes UDP a uno o varios hosts (IP o rango CIDR) y a varios puertos.
    Solo devuelve respuestas UDP o ICMP Destination Unreachable originadas por
    la propia IP objetivo.
    Parámetros:
    - target: IP o rango (ej: '192.168.1.0/24')
    - ports: iterable de puertos (ej: [53, 161, 123])
    """
    print(f"[+] UDP Ping - Target: {target} Port: {ports}")
    results = {}

    try:
        hosts = network.expand_targets(target)

        for ip_addr in hosts:
            for port in ports:
                pkt = IP(dst=ip_addr) / UDP(dport=port)
                resp = sr1(pkt, timeout=tout, verbose=0)

                if not resp or not resp.haslayer(IP) or resp.getlayer(IP).src != ip_addr:
                    continue

                if resp.haslayer(UDP) and resp.getlayer(UDP).dport == pkt.getlayer(UDP).sport:
                    print(f"{Fore.GREEN}[+] Host {ip_addr} is on{Style.RESET_ALL}")
                    results[ip_addr] = {
                        "method": "UDP",
                        "ports": [port],
                        "response": "UDP",
                    }
                    break

                if not resp.haslayer(ICMP):
                    continue

                icmp_reply = resp.getlayer(ICMP)
                if icmp_reply.type != 3 or icmp_reply.code not in [1, 2, 3, 9, 10, 13]:
                    continue

                print(f"{Fore.GREEN}[+] Host {ip_addr} is on{Style.RESET_ALL}")
                results[ip_addr] = {
                    "method": "UDP",
                    "ports": [port],
                    "icmp": {
                        "type": int(icmp_reply.type),
                        "code": int(icmp_reply.code),
                    },
                }
                break

    except network.TargetExpansionError:
        raise
    except Exception as e:
        print(f"{Fore.RED}[!] Error en UDP Ping: {e}{Style.RESET_ALL}")

    return results
