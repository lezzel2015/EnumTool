# fingerprint/os_detection_plus.py
# Versión mejorada añadiendo banner grabbing

from scan.tcp_connect import tcp_connect
from fingerprint.banner_grab import grab_banner
from scapy.all import IP, TCP, sr1
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

def os_detection_plus(target, ports, timeout):
    """
    Detección mejorada de sistema operativo:
    - Fingerprinting activo (TTL, ventana, opciones TCP)
    - Análisis de banners de servicios
    - Clasificación con puntuación combinada
    """
    if not ports:
        print(f"{Fore.YELLOW}[INFO] No se indicaron puertos: escaneando los 1000 más comunes.{Style.RESET_ALL}")
        #from utils.top_ports import TOP_1000_TCP_PORTS
        ports = TOP_1000_TCP_PORTS

    print(f"{Fore.CYAN}[*] Escaneando puertos abiertos en hosts objetivo...{Style.RESET_ALL}")
    scan_results = tcp_connect(target, ports, timeout, threads=10, minimal_output=True, verbose=False)

    for ip_addr, port_results in scan_results.items():
        # Ordenar puertos abiertos:
        open_ports = sorted([p for p, res in port_results.items() if res.get("status") == "OPEN"])
        if not open_ports:
            print(f"{Fore.YELLOW}[{ip_addr}] No se detectan puertos abiertos.{Style.RESET_ALL}")
            continue

        so_counter = {}
        detalles = []

        for port in open_ports:
            # A. Fingerprinting activo con SYN
            so, confianza, detalle_tcp = fingerprint_packet(ip_addr, port, timeout)
            linea = f"{port}="

            if so:
                score = 3 if confianza == "probable" else 2
                so_counter[so] = so_counter.get(so, 0) + score
                linea += f"{so}({confianza})"
            else:
                linea += f"desconocido"

            # B. Fingerprinting por banner grabber
            banner, version, status = grab_banner(ip_addr, port, timeout)
            so_name = None
            if banner and banner != "Unknown":
                banner_lower = banner.lower()
                if "ubuntu" in banner_lower:
                    so_name = "Ubuntu"
                elif "debian" in banner_lower:
                    so_name = "Debian"
                elif "kali" in banner_lower:
                    so_name = "Kali Linux"
                elif "centos" in banner_lower:
                    so_name = "CentOS"
                elif "fedora" in banner_lower:
                    so_name = "Fedora"
                elif "arch" in banner_lower:
                    so_name = "Arch Linux"
                elif "windows server 2016" in banner_lower:
                    so_name = "Windows Server 2016"
                elif "windows server 2019" in banner_lower:
                    so_name = "Windows Server 2019"
                elif "windows" in banner_lower:
                    so_name = "Windows"
                elif "linux" in banner_lower:
                    so_name = "Linux (genérico)"

                if so_name:
                    base_so = "Windows" if "windows" in so_name.lower() else "Linux"
                    banner_score = 2 if any(x in so_name.lower() for x in ["ubuntu", "kali", "windows server"]) else 1
                    so_counter[base_so] = so_counter.get(base_so, 0) + banner_score
                    linea += f" [Banner: {so_name}]"
                else:
                    linea += f" [{banner}]"

            detalles.append(linea)

        
        if not so_counter:
            print(f"{Fore.YELLOW}[{ip_addr}] No se ha podido determinar el sistema operativo en ningún puerto abierto.{Style.RESET_ALL}")
        else:
            best_so = max(so_counter, key=so_counter.get)
            total = so_counter[best_so]
            print(f"\n\n[{ip_addr}] Detalle por puerto: ")
            for d in detalles:
                print(f"   - {d}")

            print(f"{Fore.CYAN}\n[{ip_addr}] => Muy probable SO: {best_so} (score={total}){Style.RESET_ALL}")

            # C. Cálculo del desglose por variantes detectadas por banner
            variant_counter = {}
            total_variantes = 0

            for d in detalles:
                if "[Banner:" in d:
                    variante = d.split("[Banner:")[1].split("]")[0].strip()
                    if variante not in ["Linux", "Windows", "Linux (genérico)"]:
                        variant_counter[variante] = variant_counter.get(variante, 0) + 1
                        total_variantes += 1

            if total_variantes > 0:
                print(f"{Fore.YELLOW}  Análisis por banner:{Style.RESET_ALL}")
                for variante, count in sorted(variant_counter.items(), key=lambda x: x[1], reverse=True):
                    porcentaje = (count / total_variantes) * 100
                    print(f"{Fore.YELLOW}    - {variante}: {porcentaje:.0f}%{Style.RESET_ALL}")
                    
