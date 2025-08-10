# discovery/tcp_ping.py
# TCP Ping - Envía SYN y detecta respuesta SYN/ACK o RST

import ipaddress
from scapy.all import IP, TCP, sr1
from colorama import Fore, Style
from utils import network

def tcp_ping(target, ports, tOut):
    """
    Realiza TCP ping a uno o varios hosts (IP o rango CIDR) y puertos.
    Solo muestra los hosts que responden (SYN/ACK o RST) a al menos un puerto.
    target: IP o rango (ej: '192.168.1.0/24')
    ports: cadena de puertos separados por coma (ej: '22,80,443')
    """
    print(f"[+] TCP Ping - Target: {target} Port: {ports}")

    try:
        # Parsear puertos
        """port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        if not port_list:
            port_list = [80] """
        # Llamo a la función encargada de procesar las ip/s objetivo
        hosts=network.expand_targets(target)

        for ip_addr in hosts:
            for port in ports:
                pkt = IP(dst=ip_addr)/TCP(dport=port, flags='S')
                resp = sr1(pkt, timeout=tOut, verbose=0)
                if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags in [0x12, 0x14]:
                    print(f"{Fore.GREEN}[+] Host {ip_addr} is on{Style.RESET_ALL}")
                    break  # Solo mostrar una vez el host, aunque responda en varios puertos
    except Exception as e:
        print(f"{Fore.RED}[!] Error en TCP Ping: {e}{Style.RESET_ALL}")
