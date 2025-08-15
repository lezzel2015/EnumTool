# discovery/arp_ping.py
# ARP Ping - Descubre hosts en la misma red local usando ARP

from scapy.all import ARP, Ether, srp
from utils import Fore, Style

def arp_ping(interface, target, tout):
    """
    Envía paquetes ARP para descubrir hosts activos en una red local.
    target: rango objetivo en formato CIDR (ej: '192.168.1.0/24')
    interface: interfaz de red
    """
    print(f"[+] ARP Ping - Interface: {interface} Target: {target}")

    try:
        # Construir paquete Ethernet broadcast + ARP para el rango
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(pdst=target)
        packet = ether/arp
        # Estructura para devolver los resultados
        results = {}

        # Enviar y recibir respuestas en la interfaz indicada
        ans, _ = srp(packet, timeout=tout, iface=interface, verbose=0)

        for sent, received in ans:
            print(f"{Fore.GREEN}[+] Host {received.psrc} is on - MAC: {received.hwsrc}{Style.RESET_ALL}")
            results[received.psrc] = {"mac": received.hwsrc, "method": "ARP"}

        return results
    except Exception as e:
        print(f"{Fore.RED}[!] Error en ARP Ping: {e}{Style.RESET_ALL}")

    return None

