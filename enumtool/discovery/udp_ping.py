# discovery/udp_ping.py
# UDP Ping estilo Nmap: solo muestra los hosts activos que responden con ICMP Port Unreachable a cualquier puerto

import ipaddress
from scapy.all import IP, UDP, sr1, ICMP
from colorama import Fore, Style
from utils import network

def udp_ping(target, ports, tOut):
    """
    Envía paquetes UDP a uno o varios hosts (IP o rango CIDR) y a varios puertos.
    Muestra solo las IPs que responden con ICMP Port Unreachable (host activo).
    Parámetros:
    - target: IP o rango (ej: '192.168.1.0/24')
    - ports: cadena de puertos separados por coma (ej: '53,161,123')
    """
    print(f"[+] UDP Ping - Target: {target} Port: {ports}")

    try:
        # Llamo a la función encargada de procesar las ip/s objetivo
        hosts=network.expand_targets(target)

        for ip_addr in hosts:
            for port in ports:
                # Construir y enviar el paquete UDP al puerto destino
                pkt = IP(dst=ip_addr)/UDP(dport=port)
                resp = sr1(pkt, timeout=tOut, verbose=0)
                # Considerar activo si responde con ICMP type 3 (Destination Unreachable) y código relacionado con el puerto
                if resp and resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 3 and resp.getlayer(ICMP).code in [1,2,3,9,10,13]:
                    print(f"{Fore.GREEN}[+] Host {ip_addr} is on{Style.RESET_ALL}")
                    break  # Solo mostrar una vez el host, aunque responda en varios puertos

    except Exception as e:
        print(f"{Fore.RED}[!] Error en UDP Ping: {e}{Style.RESET_ALL}")
