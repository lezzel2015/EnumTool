# fingerprint/os_detection.py
# Versión mejorada añadiendo banner grabbing
from scan import tcp_connect
from fingerprint import grab_banner
from scapy.all import IP, TCP, sr1
import socket

from utils import TOP_1000_TCP_PORTS, Fore, Style

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
    Realiza fingerprint activo SYN sobre un host y puerto.
    Devuelve: SO, nivel_confianza, detalle_str, meta_dict.
    """
    global os_signatures

    try:
        pkt = IP(dst=ip_addr)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None or not resp.haslayer(TCP):
            return None, None, None, None
        ttl = resp.ttl
        window = resp[TCP].window
        opts = [opt[0] for opt in resp[TCP].options]
        for sig in os_signatures:
            if ttl == sig["ttl"] and window in sig["window"]:
                if sig["strict"] and all(o in opts for o in sig["opts"]):
                    #return (sig["os"], "probable", f"(TTL={ttl}, WIN={window}, OPTS={opts}),f"({"ttl": ttl, "win": window, "opts": opts}))
                    return sig["os"], "probable", f"(TTL={ttl}, WIN={window}, OPTS={opts})", {"ttl": ttl, "win": window, "opts": opts}
                elif not sig["strict"] and sig["opts"][0] in opts:
                    #return sig["os"], "posible", f"(TTL={ttl}, WIN={window}, OPTS={opts})"
                    return sig["os"], "posible", f"(TTL={ttl}, WIN={window}, OPTS={opts})", {"ttl": ttl, "win": window, "opts": opts}
        # Si no hay coincidencia
        return None, None, f"(TTL={ttl}, WIN={window}, OPTS={opts})", {"ttl": ttl, "win": window, "opts": opts}
    except Exception as e:
        return None, None, f"Error: {e}", None

# --- "Probes" SMB/RDP  ---
def probe_smb_hello(ip, timeout=1.0):
    negotiate = (
        b"\x00\x00\x00\x54\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x31\x00"
        b"\x02PC NETWORK PROGRAM 1.0\x00"
        b"\x02LANMAN1.0\x00"
        b"\x02Windows for Workgroups 3.1a\x00"
        b"\x02LM1.2X002\x00"
        b"\x02LANMAN2.1\x00"
        b"\x02NT LM 0.12\x00"
    )
    try:
        with socket.create_connection((ip, 445), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(negotiate)
            data = s.recv(1024)
        raw = data.lower()
        if b"smb2" in raw:
            return "SMBv2+", "445=SMBv2 (negotiation)"
        if b"nt lm 0.12" in raw or b"\xffsmb" in raw:
            return "SMBv1", "445=SMBv1 (NT LM 0.12)"
    except Exception:
        pass
    return None, None

def probe_rdp_hello(ip, timeout=1.0):
    rdp_neg_req = (
        b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x01\x00\x08\x00\x03\x00\x00\x00"
    )
    try:
        with socket.create_connection((ip, 3389), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(rdp_neg_req)
            data = s.recv(1024)
        if data.startswith(b"\x03\x00") and len(data) >= 11:
            return "RDP", "3389=RDP Negotiation Response"
    except Exception:
        pass
    return None, None

def os_detection(target, ports, timeout):
    """
    Detección mejorada de sistema operativo:
    - Fingerprinting activo (TTL, ventana, opciones TCP)
    - Análisis de banners de servicios
    - Clasificación con puntuación combinada
    - Scoring orientativo (se suma):
        - SYN estricto: +3 (probable) / +2 (posible).
        - TTL≈128 → +1 Windows; TTL≈64 → +1 Linux.
        - Ventana típica → +1.
        - Banner: OpenSSH → +2 Linux; Microsoft-IIS → +2 Windows.
        - SMBv2 → +3 Windows (SMBv1 → +2); RDP negotiation → +2 Windows.
    """
    if not ports:
        print(f"{Fore.YELLOW}[INFO] No se indicaron puertos: escaneando los 1000 más comunes.{Style.RESET_ALL}")
        #from utils.top_ports import TOP_1000_TCP_PORTS
        ports = TOP_1000_TCP_PORTS

    print(f"{Fore.CYAN}[*] Escaneando puertos abiertos en hosts objetivo...{Style.RESET_ALL}")
    scan_results = tcp_connect(target, ports, timeout, threads=5, minimal_output=True, verbose=False)

    # Variable para devolver resultados a main
    results = {}
    for ip_addr, port_results in scan_results.items():
        #añado ip actual a results:
        results.setdefault(ip_addr, {})
        # Ordenar puertos abiertos:
        open_ports = sorted([p for p, res in port_results.items() if res.get("status") == "OPEN"])
        if not open_ports:
            print(f"{Fore.YELLOW}[{ip_addr}] No se detectan puertos abiertos.{Style.RESET_ALL}")
            continue

        so_counter = {}
        detalles = []
        evidencias = []
        WINDOWS_WINS = {8192, 65535, 64240, 65520, 65495}
        LINUX_WINS = {29200, 5840, 14600, 29200, 29200}

        for port in open_ports:
            # A. Fingerprinting activo con SYN
            so, confianza, detalle_tcp, meta = fingerprint_packet(ip_addr, port, timeout)
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

                # Señales fuertes "extra":
                if "openssh" in banner_lower:
                    so_counter["Linux"] = so_counter.get("Linux", 0) + 2
                    evidencias.append("OpenSSH")

                if "microsoft-iis" in banner_lower:
                    so_counter["Windows"] = so_counter.get("Windows", 0) + 2
                    evidencias.append("Microsoft-IIS")

                if so_name:
                    base_so = "Windows" if "windows" in so_name.lower() else "Linux"
                    banner_score = 2 if any(x in so_name.lower() for x in ["ubuntu", "kali", "windows server"]) else 1
                    so_counter[base_so] = so_counter.get(base_so, 0) + banner_score
                    linea += f" [Banner: {so_name}]"
                else:
                    linea += f" [{banner}]"

            # Heurística TTL/ventana
            if meta:
                ttl, win = meta.get("ttl"), meta.get("win")
                if ttl is not None:
                    if 120 <= ttl <= 132:
                        so_counter["Windows"] = so_counter.get("Windows", 0) + 1
                        evidencias.append("TTL≈128")
                    elif 60 <= ttl <= 70:
                        so_counter["Linux"] = so_counter.get("Linux", 0) + 1
                        evidencias.append("TTL≈64")
                if win in WINDOWS_WINS:
                    so_counter["Windows"] = so_counter.get("Windows", 0) + 1
                    evidencias.append(f"WIN={win} típico Windows")
                elif win in LINUX_WINS:
                    so_counter["Linux"] = so_counter.get("Linux", 0) + 1
                    evidencias.append(f"WIN={win} típico Linux")

            detalles.append(linea)
            # Añadir resultados a "results[]" por puerto
            entry = {}
            if meta:
                entry.update({"ttl": meta.get("ttl"), "win": meta.get("win"), "opts": meta.get("opts")})
            if so:
                entry.update({"os_hint": so, "confidence": confianza})
            if banner and banner != "Unknown":
                entry.update({"banner": banner[:120]})
            # Conservar estado/servicio del connect scan
            svc = (port_results.get(port) or {}).get("service", "Unknown")
            st = (port_results.get(port) or {}).get("status", "OPEN")
            rtt = (port_results.get(port) or {}).get("rtt")
            entry.update({"status": st, "service": svc})
            if rtt is not None:
                entry.update({"rtt": rtt})
            # Safety: asegura el dict por host antes de asignar el puerto
            results.setdefault(ip_addr, {})  
            results[ip_addr][port] = entry

        # Probes SMB/RDP
        if 445 in open_ports:
            ver, ev = probe_smb_hello(ip_addr, timeout=timeout)
            if ver:
                so_counter["Windows"] = so_counter.get("Windows", 0) + (3 if ver != "SMBv1" else 2)
                evidencias.append(ev)
        if 3389 in open_ports:
            ver, ev = probe_rdp_hello(ip_addr, timeout=timeout)
            if ver:
                so_counter["Windows"] = so_counter.get("Windows", 0) + 2
                evidencias.append(ev)
        
        if not so_counter:
            print(f"{Fore.YELLOW}[{ip_addr}] No se ha podido determinar el sistema operativo en ningún puerto abierto.{Style.RESET_ALL}")
        else:
            best_so = max(so_counter, key=so_counter.get)
            total = so_counter[best_so]
            print(f"\n\n[{ip_addr}] Detalle por puerto: ")
            for d in detalles:
                print(f"   - {d}")

            print(f"{Fore.CYAN}\n[{ip_addr}] => Muy probable {best_so} (score={total}){Style.RESET_ALL}")
            if evidencias:
                ev_txt = ", ".join(sorted(set(evidencias)))[:50]
                print(f"{Fore.WHITE}  Evidencia: {ev_txt}{Style.RESET_ALL}")

            # Resumen por host (clave no numérica para no colisionar con puertos)
            results[ip_addr]["_host_os"] = {"best": best_so, "score": total, "evidence": sorted(set(evidencias))[:50], "open_ports": open_ports}

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
                    
    return results
