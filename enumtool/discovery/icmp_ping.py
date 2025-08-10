# discovery/icmp_ping.py
# ICMP Ping - Descubre hosts enviando ICMP Echo Request

# Para ocultar los "warnings" de Scapy
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
#
import ipaddress
from scapy.all import IP, ICMP, sr1
from colorama import Fore, Style
from utils import network

def icmp_ping(target, tOut):
    """
    Envía ICMP Echo Request a uno o varios hosts (IP única o rango CIDR).
    target: IP o rango (ej: '192.168.1.0/24')
    """
    print(f"[+] ICMP Ping - Target: {target}")

    try:
        # Llamo a la función encargada de procesar la/s ip/s objetivo
        hosts=network.expand_targets(target)
        #print(hosts)
        
        for ip_addr in hosts:
            pkt = IP(dst=ip_addr)/ICMP()
            resp = sr1(pkt, timeout=tOut, verbose=0)
            if resp:
                print(f"{Fore.GREEN}[+] Host {ip_addr} is on{Style.RESET_ALL}")
            #else:
               #print(f"[-] Sin respuesta de {ip_addr}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error en ICMP Ping: {e}{Style.RESET_ALL}")
