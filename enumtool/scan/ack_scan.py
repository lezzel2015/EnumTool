# scan/ack_scan.py
# ACK Scan con Scapy: solo distingue entre FILTERED y UNFILTERED.
# El ACK Scan es útil para detectar la presencia de firewalls y reglas de filtrado.
# Envía paquetes TCP con la bandera ACK y analiza la respuesta.
# Si recibe RST, el puerto está UNFILTERED (no filtrado).
# Si no recibe respuesta o recibe ICMP unreachable, el puerto está FILTERED (filtrado)

import ipaddress
from scapy.all import IP, TCP, sr1, conf, ICMP
from colorama import Fore, Style
from utils import network

def ack_scan(target, ports, timeout=2):
    """
    Realiza un ACK scan sobre IP o rango y una lista de puertos.
    Marca como UNFILTERED si recibe RST, o FILTERED si no hay respuesta o ICMP unreachable relevante.
    Parámetros:
        - target: IP o rango (ej: '192.168.1.0/24')
        - ports: lista de enteros (ej: [22, 80, 443])
        - timeout: tiempo máximo de espera por puerto (en segundos)
    """
    conf.verb = 0  # Desactiva la verbosidad de Scapy

    # Llamo a la función encargada de procesar las ip/s objetivo
    hosts=network.expand_targets(target)

    for ip_addr in hosts:
        print(f"{Fore.CYAN}Escaneando {ip_addr}:{Style.RESET_ALL}")
        for port in ports:
            try:
                ack_pkt = IP(dst=ip_addr)/TCP(dport=port, flags='A')
                resp = sr1(ack_pkt, timeout=timeout, verbose=0)

                if resp is None:
                    # Sin respuesta: probablemente filtrado
                    print(f"  {Fore.YELLOW}[FILTERED]   {ip_addr}:{port}{Style.RESET_ALL}")
                elif resp.haslayer(TCP):
                    if resp[TCP].flags == 0x04:  # RST
                        print(f"  {Fore.GREEN}[UNFILTERED] {ip_addr}:{port}{Style.RESET_ALL}")
                    else:
                        # Cualquier otra bandera: lo ignoramos
                        #print(f"   Flags={resp[TCP].flags}")
                        pass
                elif resp.haslayer(ICMP):
                    icmp = resp.getlayer(ICMP)
                    if (icmp.type == 3 and icmp.code in [1,2,3,9,10,13]):
                        print(f"  {Fore.YELLOW}[FILTERED] {ip_addr}:{port} (ICMP){Style.RESET_ALL}")
                    # Otros ICMP se ignoran
                    else:
                        #print(f"   Flags={resp[TCP].flags}")
                        pass

            except Exception as e:
                print(f"  {Fore.RED}[ERROR] {ip_addr}:{port} - {e}{Style.RESET_ALL}")
