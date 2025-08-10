# scan/syn_scan.py
# Escaneo SYN Scan (Half-Open) - Envía un SYN al puerto destino sin completar handshake.
# Si recibe SYN/ACK, el puerto está ABIERTO. Si recibe RST, está CERRADO. Si no hay respuesta, está FILTRADO.
# Añadido concurrencia. Valor por defecto 10 threads.

from scapy.all import IP, TCP, sr1, conf, ICMP
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from utils import network
from utils.services import COMMON_PORTS

def scan_syn_port(ip_addr, port, timeout):
    """
    Escanea un único puerto con técnica SYN (half-open).
    No completa el handshake, solo evalúa la respuesta al SYN.
    """
    result = {}
    try:
        # Crear y enviar paquete SYN al puerto destino
        syn_pkt = IP(dst=ip_addr)/TCP(dport=port, flags='S')
        start_time = time.time()
        resp = sr1(syn_pkt, timeout=timeout, verbose=0)
        rtt = time.time() - start_time

        # Analizar respuesta
        if resp is None:
            # Sin respuesta: posiblemente filtrado por firewall
            result = {"status": "FILTERED", "rtt": None}

        elif resp.haslayer(TCP):
            flags = resp[TCP].flags
            if flags == 0x12:
                # Respuesta SYN/ACK: el puerto está abierto
                service = COMMON_PORTS.get(port, "Unknown")
                result = {"status": "OPEN", "service": service, "rtt": rtt}
                # Enviar RST para cerrar la conexión sin completar handshake
                rst_pkt = IP(dst=ip_addr)/TCP(dport=port, flags='R', seq=resp.ack)
                sr1(rst_pkt, timeout=timeout, verbose=0)
            elif flags == 0x14:
                # RST/ACK indica que el puerto está cerrado
                result = {"status": "CLOSED", "rtt": rtt}
            else:
                # Otros flags inesperados
                result = {"status": "UNKNOWN", "flags": str(flags), "rtt": rtt}

        elif resp.haslayer(ICMP):
            icmp = resp.getlayer(ICMP)
            if icmp.type == 3 and icmp.code in [1, 2, 3, 9, 10, 13]:
                # ICMP unreachable: puerto filtrado
                result = {"status": "FILTERED", "rtt": None}
        else:
            # Respuesta no TCP
            result = {"status": "NO_TCP", "rtt": None}

# --- NOTA IMPORTANTE SOBRE CONCURRENCIA Y SCAPY ---
# Scapy no es completamente "thread-safe" al utilizar múltiples hilos que invocan sr1() en paralelo.
# En sistemas con Python >= 3.12, y especialmente >= 3.13, se han reportado errores como:
# OSError: [Errno 9] Bad file descriptor
#
# Esto se debe a una condición de carrera al cerrar sniffers internos cuando varios hilos finalizan a la vez.
# Referencia oficial del bug: https://github.com/secdev/scapy/issues/3843
#
# ✅ Solución recomendada:
# - Limitar el número de hilos a un valor razonable (por ejemplo, threads <= 10)
#
# 🛠 Alternativas:
# - Reescribir la lógica para usar sr()/sniff() en lugar de sr1()
# - Usar colas (Queue) con workers controlados (más complejo)
#
# Este comportamiento puede documentarse como una limitación de la biblioteca usada (Scapy)
# y de su integración con Python multithreading en versiones recientes.

    except OSError as e:
        if e.errno == 9:
            print(f"{Fore.RED}[SCAPY BUG] Error en el puerto {port}: Bad file descriptor. "
                  f"Reduce --threads para evitar este fallo (recomendado ≤10).{Style.RESET_ALL}")
        result = {"status": "ERROR", "error": str(e)}
    
    except Exception as e:
        result = {"status": "ERROR", "error": str(e)}

    return port, result

def syn_scan(target, ports, timeout, threads=10, minimal_output=False, verbose=True):
    """
    Ejecuta un escaneo SYN Scan concurrente sobre varios hosts y puertos.
    Usa múltiples hilos (threads) para mejorar la velocidad del escaneo.
    """
    conf.verb = 0  # Suprimir salida de Scapy
    threads = max(1, min(threads, 500))  # Limita número de hilos a un rango seguro
    hosts = network.expand_targets(target)  # Expandir rangos o CIDR a lista de IPs
    results = {}

    for ip_addr in hosts:
        print(f"\n{Fore.CYAN}Escaneando {ip_addr}:{Style.RESET_ALL}")
        results[ip_addr] = {}

        # Crear pool de hilos y asignar tareas
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {
                executor.submit(scan_syn_port, ip_addr, port, timeout): port for port in ports
            }

            completed = []
            # Contadores para mostrar el progreso
            total_ports = len(ports)
            completed_count = 0
            # Esperar a que cada escaneo individual termine
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    port, result = future.result()
                    results[ip_addr][port] = result
                    completed.append((port, result))
                except Exception as exc:
                    results[ip_addr][port] = {"status": "ERROR", "error": str(exc)}
                    completed.append((port, results[ip_addr][port]))

                # Muestra el progreso por pantalla
                completed_count += 1
                percent = (completed_count / total_ports) * 100
                print(f"\r[+] Progreso: {completed_count}/{total_ports} ({percent:.1f}%)", end='', flush=True)

            if verbose:
                # Contadores para resumen
                count_open = sum(1 for _, r in completed if r.get("status") == "OPEN")
                count_closed = sum(1 for _, r in completed if r.get("status") == "CLOSED")

                # Número de puertos abiertos y cerrados
                print(f"\n\n{Fore.CYAN}De {len(completed)} puertos escaneados, {count_open} están abiertos, {count_closed} cerrados y {len(completed)-count_closed-count_open} filtrados/desconocidos{Style.RESET_ALL}")
                
                # Mostrar resultados ordenados por número de puerto
                open_ports_list=[]
                for port, result in sorted(completed):
                    status = result.get("status", "UNKNOWN")
                    rtt = result.get("rtt")
                    service = result.get("service", "")
                # Si la lista de puertos es por defecto, sólo se muestran los que estén abiertos
                    if status == "OPEN":
                        print(f"  {Fore.GREEN}[OPEN]   {ip_addr}:{port} ({service})  RTT={rtt:.3f}s{Style.RESET_ALL}")
                        open_ports_list.append(port)
                    elif not minimal_output:
                        if status == "CLOSED":
                            print(f"  {Fore.RED}[CLOSED]  {ip_addr}:{port}  RTT={rtt:.3f}s{Style.RESET_ALL}")
                        elif status == "FILTERED":
                            print(f"  {Fore.YELLOW}[FILTERED] {ip_addr}:{port}{Style.RESET_ALL}")
                        elif status == "NO_TCP":
                            print(f"  {Fore.YELLOW}[NO TCP] {ip_addr}:{port}{Style.RESET_ALL}")
                        elif status == "UNKNOWN":
                            flags = result.get("flags", "?")
                            print(f"  {Fore.MAGENTA}[UNKNOWN] {ip_addr}:{port} Flags={flags}{Style.RESET_ALL}")
                        elif status == "ERROR":
                            print(f"  {Fore.RED}[ERROR]  {ip_addr}:{port} - {result.get('error')}{Style.RESET_ALL}")

                # Imprimir lista de puertos abiertos, útil para posteriores análisis
                if len(open_ports_list) >= 1:
                    print(f"\nListado de puertos abiertos: {','.join(str(p) for p in open_ports_list)}")
   
    return results
