# discovery/icmp_ping.py
# ICMP Ping - Descubre hosts enviando ICMP Echo Request

# Para ocultar los "warnings" de Scapy
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
#
from scapy.all import IP, ICMP, sr1
from utils import network, Fore, Style
import time

def icmp_ping(target, tout):
    """
    Envía ICMP Echo Request a uno o varios hosts (IP única o rango CIDR).
    target: IP o rango (ej: '192.168.1.0/24')
    """
    print(f"[+] ICMP Ping - Target: {target}")
    # Estructura para devolver los resultados
    results = {}

    try:
        # Llamo a la función encargada de procesar la/s ip/s objetivo
        hosts=network.expand_targets(target)
        for ip_addr in hosts:
            pkt = IP(dst=ip_addr)/ICMP()
            t0=time.time()
            resp = sr1(pkt, timeout=tout, verbose=0)
            rtt=(time.time()-t0) if resp else None
            if resp:
                print(f"{Fore.GREEN}[+] Host {ip_addr} is on{Style.RESET_ALL}")
                results[ip_addr] = {"method": "ICMP", "rtt": rtt}

    except Exception as e:
        print(f"{Fore.RED}[!] Error en ICMP Ping: {e}{Style.RESET_ALL}")

    return results

