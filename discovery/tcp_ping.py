# discovery/tcp_ping.py
# TCP Ping - Envía SYN y detecta respuesta SYN/ACK o RST

import ipaddress
from scapy.all import IP, TCP, sr1
from colorama import Fore, Style
from utils import network
import time

def tcp_ping(target, ports, tOut):
    """
    Realiza TCP ping a uno o varios hosts (IP o rango CIDR) y puertos.
    Solo muestra los hosts que responden (SYN/ACK o RST) a al menos un puerto.
    target: IP o rango (ej: '192.168.1.0/24')
    ports: cadena de puertos separados por coma (ej: '22,80,443')
    """
    print(f"[+] TCP Ping - Target: {target} Port: {ports}")
    # Estructura para devolver los resultados
    results = {}

    try:
        # Llamo a la función encargada de procesar las ip/s objetivo
        hosts=network.expand_targets(target)

        for ip_addr in hosts:
            results.setdefault(ip_addr, {})
            for port in ports:
                pkt = IP(dst=ip_addr)/TCP(dport=port, flags='S')
                start = time.time()
                resp = sr1(pkt, timeout=tOut, verbose=0)
                rtt = (time.time() - start) if resp else None
                if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags in [0x12, 0x14]:
                    print(f"{Fore.GREEN}[+] Host {ip_addr} is on{Style.RESET_ALL}")
                    flag = int(resp.getlayer(TCP).flags)
                    flag_name = "SYN/ACK" if flag == 0x12 else "RST"
                    results[ip_addr] = {"method": "TCP", "ports": [port], "rtt": rtt, "flags": flag_name}
                    break  # Solo mostrar una vez el host, aunque responda en varios puertos

    except Exception as e:
        print(f"{Fore.RED}[!] Error en TCP Ping: {e}{Style.RESET_ALL}")

    return results
