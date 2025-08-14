# scan/ack_scan.py
# ACK Scan con Scapy: solo distingue entre FILTERED y UNFILTERED.
# El ACK Scan es útil para detectar la presencia de firewalls y reglas de filtrado.
# Envía paquetes TCP con la bandera ACK y analiza la respuesta.
# Si recibe RST, el puerto está UNFILTERED (no filtrado).
# Si no recibe respuesta o recibe ICMP unreachable, el puerto está FILTERED (filtrado)

from colorama import Fore, Style
from scapy.all import IP, TCP, sr1, conf, ICMP
import time

from utils import network, COMMON_PORTS


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

    # Estructura para guardar los resultados
    results={}

    for ip_addr in hosts:
        results.setdefault(ip_addr, {})
        print(f"{Fore.CYAN}Escaneando {ip_addr}:{Style.RESET_ALL}")
        for port in ports:
            try:
                ack_pkt = IP(dst=ip_addr)/TCP(dport=port, flags='A')
                start_time = time.time()
                resp = sr1(ack_pkt, timeout=timeout, verbose=0)
                rtt = (time.time() - start_time) if resp is not None else None
                entry = {"service": COMMON_PORTS.get(port, "Unknown")}

                if resp is None:
                    # Sin respuesta: probablemente filtrado
                    print(f"  {Fore.YELLOW}[FILTERED]   {ip_addr}:{port}{Style.RESET_ALL}")
                    entry.update({"status": "FILTERED", "rtt": rtt, "reason": "no-response"})
                    results[ip_addr][port] = entry
                elif resp.haslayer(TCP):
                    if resp[TCP].flags == 0x04:  # RST
                        print(f"  {Fore.GREEN}[UNFILTERED] {ip_addr}:{port}{Style.RESET_ALL}")
                        entry.update({"status": "UNFILTERED", "rtt": rtt, "flags": "RST"})
                        results[ip_addr][port] = entry
                    else:
                        # Cualquier otra bandera: lo ignoramos (se registra como UNKNOWN)
                        entry.update({"status": "UNKNOWN", "rtt": rtt, "flags": int(resp[TCP].flags)})
                        results[ip_addr][port] = entry
                elif resp.haslayer(ICMP):
                    icmp = resp.getlayer(ICMP)
                    if icmp.type == 3 and icmp.code in [1, 2, 3, 9, 10, 13]:
                        print(f"  {Fore.YELLOW}[FILTERED] {ip_addr}:{port} (ICMP){Style.RESET_ALL}")
                        entry.update({"status": "FILTERED", "rtt": rtt, "reason": "icmp"})
                        results[ip_addr][port] = entry
                    # Otros ICMP se ignoran
                    else:
                        entry.update({"status": "UNKNOWN", "rtt": rtt, "reason": f"icmp(type={icmp.type},code={icmp.code})"})
                        results[ip_addr][port] = entry

            except Exception as e:
                print(f"  {Fore.RED}[ERROR] {ip_addr}:{port} - {e}{Style.RESET_ALL}")
                results.setdefault(ip_addr, {})
                results[ip_addr][port] = {"status": "ERROR", "error": str(e), "service": COMMON_PORTS.get(port, "Unknown")}

    return results

