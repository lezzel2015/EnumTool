# fingerprint/os_detection.py
# Detección heurística de SO basada en TCP_CONNECT + fingerprint activo solo en puertos abiertos

from scan.tcp_connect import tcp_connect
from scapy.all import IP, TCP, sr1
import scapy.modules.p0fv2 as p0fv2
from colorama import Fore, Style
from utils import network
from utils.top_ports import TOP_1000_TCP_PORTS

# Firmas de sistemas operativos (igual que antes)
os_signatures = [
        # Coincidencia estricta (probable)
        {"os": "Linux",   "ttl": 64,  "window": [29200, 5840], "opts": ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"], "color": Fore.GREEN, "strict": True},
        {"os": "Windows", "ttl": 128, "window": [8192, 65535], "opts": ["MSS", "NOP", "WScale", "SAckOK", "Timestamp"], "color": Fore.BLUE,  "strict": True},
        {"os": "FreeBSD", "ttl": 64,  "window": [65535],       "opts": ["MSS", "NOP", "WScale", "SAckOK", "Timestamp"], "color": Fore.CYAN,  "strict": True},
        {"os": "OpenBSD", "ttl": 64,  "window": [16384],       "opts": ["MSS", "NOP", "WScale", "SAckOK", "Timestamp"], "color": Fore.CYAN,  "strict": True},
        {"os": "Cisco",   "ttl": 255, "window": [4128],        "opts": ["MSS"],                                          "color": Fore.MAGENTA,"strict": True},
        # Coincidencia laxa (posible)
        {"os": "Linux",   "ttl": 64,  "window": [29200, 5840], "opts": ["MSS"], "color": Fore.GREEN, "strict": False},
        {"os": "Windows", "ttl": 128, "window": [8192, 65535], "opts": ["MSS"], "color": Fore.BLUE,  "strict": False},
]

def fingerprint_packet(ip_addr, port, timeout):
    """
    Realiza fingerprint activo sobre un host y puerto, devuelve (SO, nivel_confianza, detalle)
    """
    global os_signatures

    try:
        pkt = IP(dst=ip_addr)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None or not resp.haslayer(TCP):
            return (None, None, None)
        ttl = resp.ttl
        window = resp[TCP].window
        opts = [opt[0] for opt in resp[TCP].options]
        for sig in os_signatures:
            if ttl == sig["ttl"] and window in sig["window"]:
                if sig["strict"] and all(o in opts for o in sig["opts"]):
                    return (sig["os"], "probable", f"(TTL={ttl}, WIN={window}, OPTS={opts})")
                elif not sig["strict"] and sig["opts"][0] in opts:
                    return (sig["os"], "posible", f"(TTL={ttl}, WIN={window}, OPTS={opts})")
        # Si no hay coincidencia
        return (None, None, f"(TTL={ttl}, WIN={window}, OPTS={opts})")
    except Exception as e:
        return (None, None, f"Error: {e}")

def os_detection(target, ports, timeout):
    """
    1. Escanea con tcp_connect los 1000 puertos más comunes (o los que el usuario indique).
    2. Sólo realiza fingerprinting sobre los puertos realmente abiertos.
    3. Acumula la evidencia y muestra el SO con más coincidencias (score).
    """
    if not ports:
        print(f"{Fore.YELLOW}[INFO] No se indicaron puertos: escaneando los 1000 más comunes.{Style.RESET_ALL}")
        ports = TOP_1000_TCP_PORTS

    # Paso 1: escaneo rápido para detectar puertos abiertos
    print(f"{Fore.CYAN}[*] Escaneando puertos abiertos en hosts objetivo...{Style.RESET_ALL}")
    scan_results = tcp_connect(target, ports, timeout, threads=10, minimal_output=True, verbose=False)

    # Paso 2: fingerprint activo sólo en puertos abiertos
    for ip_addr, port_results in scan_results.items():
        open_ports = [p for p, res in port_results.items() if res.get("status") == "OPEN"]
        if not open_ports:
            print(f"{Fore.YELLOW}[{ip_addr}] No se detectan puertos abiertos.{Style.RESET_ALL}")
            continue

        so_counter = {}   # Acumulador de score
        detalles = []     # Para el detalle por puerto
        for port in open_ports:
            so, confianza, detalle = fingerprint_packet(ip_addr, port, timeout)
            if so:
                so_counter[so] = so_counter.get(so, 0) + (2 if confianza == "probable" else 1)
                detalles.append(f"{Fore.CYAN}{port}{Style.RESET_ALL}={so}({confianza})")
            else:
                detalles.append(f"{Fore.YELLOW}{port}{Style.RESET_ALL}=desconocido{detalle}")

        # Paso 3: Mostrar resultado consolidado por host
        if not so_counter:
            print(f"{Fore.YELLOW}[{ip_addr}] No se ha podido determinar el sistema operativo en ningún puerto abierto.{Style.RESET_ALL}")
        else:
            best_so = max(so_counter, key=so_counter.get)
            total = so_counter[best_so]
            color = next(sig['color'] for sig in fingerprint_packet.__globals__['os_signatures'] if sig['os'] == best_so)
            print(f"\n{color}[{ip_addr}] => Muy probable SO: {best_so} (score={total}){Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Detalle por puerto: {Style.RESET_ALL}")
            for d in detalles:
                print("    - " + d)