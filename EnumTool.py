#!/usr/bin/env python3
"""
EnumTool.py
Herramienta de enumeración y escaneo - Versión con flags cortos exclusivos

Este script permite elegir UNA acción específica de discovery, scan o fingerprint
con un flag corto único (por ejemplo -dA, -sT, -B...).

Permite especificar opciones comunes como --interface, --target, --port y --timeout.

Opciones clave añadidas/afinadas:
  --summary       -> Muestra al final un resumen estadístico (texto o JSON)
  --format        -> Formato del resumen ('text' o 'json')
  --output        -> Ruta de fichero para volcar ("append") el resumen
  --top N         -> Escaneo de los N puertos más comunes (N<=1000)
  --profile X     -> Perfiles de puertos ('web', 'windows', 'linux')
  --port-all      -> Escanear 1-65535

Ejemplo de uso:
    sudo python3 EnumTool.py -dA -i eth0 -t 192.168.1.0/24
    sudo python3 EnumTool.py -sT -t 192.168.1.5 -p 22,80,443
    sudo python3 EnumTool.py -B -t 192.168.1.5 -p 80,443
    sudo python3 EnumTool.py -dA -i eth0 -t 192.168.1.0/24 --summary
    sudo python3 EnumTool.py -sS -t 192.168.1.5 --top 100 --summary --format json --output results.log
    sudo python3 EnumTool.py -B  -t 192.168.1.5 -p 80,443 --summary
"""

import sys
import os
import time
import json
from argparse import RawTextHelpFormatter, ArgumentParser
from datetime import datetime
from dataclasses import dataclass, asdict, field   # Para estructurar el resumen de ejecución
from typing import Any, Dict, Optional

# Importación desde otros módulos
from discovery import arp_ping, icmp_ping, tcp_ping, udp_ping
from scan import tcp_connect, syn_scan, ack_scan
from fingerprint import banner_grab, os_detection, http_headers
from utils import banner, parse_ports, top_ports, PortParseError, TOP_1000_TCP_PORTS, build_module_summary, error, warning, info, result, Fore, Style


# ---------------------------------------------
# Mapeo de flags cortos (mode, technique)
ACTION_MAP = {
    "dA": ("discovery", "arp_ping"),
    "dI": ("discovery", "icmp_ping"),
    "dT": ("discovery", "tcp_ping"),
    "dU": ("discovery", "udp_ping"),
    "sT": ("scan", "tcp_connect"),
    "sS": ("scan", "syn_scan"),
    "sA": ("scan", "ack_scan"),
    "B":  ("fingerprint", "banner_grab"),
    "V":  ("fingerprint", "os_detection"),
    "H":  ("fingerprint", "http_headers")
}

# ---------------------------------------------
def need_root(technique):
    """
    Comprueba si la técnica seleccionada requiere permisos de root.
    Si el usuario no es root, muestra un warning y pide confirmación
    para continuar o aborta la ejecución si el usuario responde 'no'.

    Args:
        technique (str): Nombre de la técnica elegida (ej: arp_ping).
    """
    ROOT_REQUIRED_TECHNIQUES = [
        "arp_ping", "icmp_ping", "tcp_ping", "udp_ping",
        "syn_scan", "ack_scan"
    ]

    if technique in ROOT_REQUIRED_TECHNIQUES:
        try:
            # Unix/Linux
            if hasattr(os, "geteuid") and os.geteuid() != 0:
                warning(f"La técnica '{technique}' suele requerir permisos de root o sudo.")
                resp = input(f"{Fore.YELLOW}¿Deseas continuar de todas formas? (s/n): {Style.RESET_ALL}").strip().lower()
                if resp not in ("s", "si", "y", "yes"):
                    error("[*] Ejecución cancelada por el usuario.")
                    sys.exit(1)
        except AttributeError:
            # Sistemas sin geteuid (Windows)
            warning(f"La técnica '{technique}' puede requerir permisos de administrador en este sistema.")
            resp = input(f"{Fore.YELLOW}¿Deseas continuar de todas formas? (s/n): {Style.RESET_ALL}").strip().lower()
            if resp not in ("s", "si", "y", "yes"):
                error("[*] Ejecución cancelada por el usuario.")
                sys.exit(1)


# ---------------------------------------------
"""
Esta clase centraliza la impresión de mensajes en consola y opcionalmente en un archivo.
Soporta dos modos: texto o JSON.
"""
class Printer:
    def __init__(self, mode="text", outfile=None):
        self.mode = mode           # "text" o "json"
        self.outfile = outfile     # Ruta opcional para guardar salida

    def emit(self, level, message, **meta):
        """
        level: tipo de mensaje ('ok', 'info', 'warn', 'open', etc.)
        message: texto principal
        meta: datos adicionales (solo se incluyen en JSON)
        """
        if self.mode == "json":
            obj = {"level": level, "message": message, **meta}
            line = json.dumps(obj, ensure_ascii=False)
        else:
            prefix = {
                "ok": "[+]",
                "info": "[*]",
                "warn": "[!]",
                "open": "[OPEN]"
            }.get(level, "[-]")
            line = f"{prefix} {message}"

        print(line)
        # Guardar también en archivo si está configurado
        if self.outfile:
            try:
                with open(self.outfile, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass  # No romper la ejecución si no se puede escribir


# ---------------------------------------------
"""
 Estructura utilizada para encapsular un resumen de la ejecución y poder exportarlo en JSON limpio.
"""
@dataclass
class RunSummary:
    action_flag: str
    mode: str
    technique: str
    interface: str | None
    target: str | None
    ports: list[int] | None
    timeout: float | None
    threads: int | None
    elapsed_seconds: float
    exit_code: int = 0
    module_summary: Optional[Dict[str, Any]] = field(default=None)
    module_result: Optional[Dict[str, Any]] = field(default=None)  # opcional (JSON)

# ---------------------------------------------
# Función main()
#
def main():
    parser = ArgumentParser(
        description=banner.BANNER + """

            Enumeration and scanning tool for local networks

""",
        formatter_class=RawTextHelpFormatter
    )

    # Grupo de acciones mutuamente excluyentes
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("-dA", action="store_true", help="Discovery arp_ping")
    action_group.add_argument("-dI", action="store_true", help="Discovery icmp_ping")
    action_group.add_argument("-dT", action="store_true", help="Discovery tcp_ping")
    action_group.add_argument("-dU", action="store_true", help="Discovery udp_ping")
    action_group.add_argument("-sT", action="store_true", help="Scan tcp_connect")
    action_group.add_argument("-sS", action="store_true", help="Scan syn_scan")
    action_group.add_argument("-sA", action="store_true", help="Scan ack_scan")
    action_group.add_argument("-B",  action="store_true", help="Fingerprint banner grabbing")
    action_group.add_argument("-V", action="store_true", help="OS detection with banner grabbing (enhanced fingerprinting)")
    action_group.add_argument("-H", action="store_true", help="Fingerprint http_headers (HTTP/HTTPS headers analysis)")

    # Argumentos comunes
    parser.add_argument("-i", "--interface", metavar="", help="Network interface (required for arp_ping)")
    parser.add_argument("-t", "--target", metavar="", help="Target IP or CIDR range")
    parser.add_argument("-p", "--port", metavar="", help="Destination ports (comma-separated or as a range)")
    parser.add_argument("-S", "--summary", action="store_true", help="Show final summary with added metrics")
    parser.add_argument("--port-all", action="store_true", help="Scan all TCP ports (1–65535)")
    parser.add_argument('--top', type=int, metavar='N', help="Scan the top N most common TCP ports (based on nmap-services frequency, N<=1000)")
    parser.add_argument("--profile", choices=["web", "windows", "linux"], help="Use predefined port profiles")
    parser.add_argument("--timeout", metavar="", type=float, default=0.5, help="Timeout in seconds (default: 0.5)")
    parser.add_argument("--threads", metavar="", type=int, default=5, help="Number of threads to use in concurrent scans (default: 5)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Final summary output format: 'text' for short or 'json' for extended")
    parser.add_argument("--output", dest="output_file", default=None, help="File path to dump output (append)")
    parser.add_argument("--insecure-tls", action="store_true", help="Disable TLS certificate verification for HTTPS/SMTPS banner grabbing & HTTP Headers")

    # Argumentos autoexcluyentes para el análisis de cabeceras HTTP/HTTPS
    proto_group = parser.add_mutually_exclusive_group()
    proto_group.add_argument("--https", action="store_true", help="In option -H, force the use of HTTPS (TLS) for all target ports (ignore port number)")
    proto_group.add_argument("--http", action="store_true", help="In option -H, force the use of HTTP (no TLS) for all target ports (ignore port number)")
    

    args = parser.parse_args()

    # ---------------------------------------------
    # Determinar qué acción se ha elegido
    selected_flag = None
    for flag in ACTION_MAP.keys():
        if getattr(args, flag):
            selected_flag = flag
            break

    if not selected_flag:
        parser.error("Debes elegir una acción entre -dA, -dI, -dT, -dU, -sT, -sS, -sA, -B, -V, -H")

    # A partir del flag, sabemos el modo y técnica a aplicar
    mode, technique = ACTION_MAP[selected_flag]

    # Imprimir banner del programa (si no se ha pedido la ayuda)
    if selected_flag not in ["-h", "--help"]:
        print(banner.BANNER)

    # ---------------------------------------------
    # Validación de parámetros obligatorios por técnica
    if technique == "arp_ping":
        if not args.interface:
            parser.error("--interface (-i) es obligatorio para arp_ping")
        if not args.target:
            parser.error("--target (-t) es obligatorio para arp_ping")
    else:
        if not args.target:
            parser.error("--target (-t) es obligatorio para esta técnica")

    # ---------------------------------------------
    # Procesar puertos si aplica
    ports = None
    # La variable minimal indica si se muestran todos los puertos en el resumen o solo los abiertos.
    # Está configurado para que si hay más de 20 puertos a revisar, sólo se muestren los abiertos (para
    # facilitar la vista de resultados)
    minimal = False

    if args.port_all:
        ports = list(range(1, 65536))
        minimal = True
    elif args.top:
        ports = top_ports.get_top_ports(args.top)
        if args.top > 20:
            minimal = True
    elif args.profile:
        ports = top_ports.get_profile_ports(args.profile)
    elif args.port:
        try:
            ports = parse_ports(args.port)
        except PortParseError as e:
            print(f"[!] {e}")
            sys.exit(2)
        # Para mejorar la visual, si el número de puertos es elevado (más de 20) sólo se muestran por pantalla los puertos que están abiertos
        if len(ports) > 20:
            minimal = True
    else:
        # Asignar valor por defecto para técnicas que usen puertos
        if technique in ["tcp_ping"]:
            ports = [80]
        elif technique in ["udp_ping"]:
            ports = [40125]
        elif technique in ["syn_scan", "ack_scan", "tcp_connect", "banner_grab"]:
            warning("No se ha indicado ningún puerto, se escanearán los 1000 puertos más comunes.")
            ports = TOP_1000_TCP_PORTS
            minimal = True
        elif technique in ["http_headers"]:
            warning("No se ha indicado ningún puerto, se utilizarán por defecto 80 y 443.")
            ports = [80, 443]
        elif technique in ["arp_ping", "icmp_ping", "os_detection"]:  #técnicas que no necesitan definir un puerto
            ports = None

    # Validación de root si es necesario para la ejecución
    need_root(technique)

    # ---------------------------------------------
    # Procesar valor de Timeout
    timeout = args.timeout if args.timeout else 0.5

    # ---------------------------------------------
    # Inicialización de "Printer"
    printer = Printer(mode=args.format, outfile=args.output_file)
        
    # ---------------------------------------------
    # Inicio contador de tiempo para evaluar la duración de la acción
    #start_time = datetime.now()
    t0 = time.perf_counter()
    exit_code = 0   # <-- Inicializa para caso “sin errores”
    module_result = None

    try:
        # ---------------------------------------------
        # Ejecutar técnica correspondiente
        if mode == "discovery":
            if technique == "arp_ping":
                module_result = arp_ping(args.interface, args.target, args.timeout)
            elif technique == "icmp_ping":
                module_result = icmp_ping(args.target, args.timeout)
            elif technique == "tcp_ping":
                module_result = tcp_ping(args.target, ports, args.timeout)
            elif technique == "udp_ping":
                module_result = udp_ping(args.target, ports, args.timeout)

        elif mode == "scan":
            if technique == "tcp_connect":
                module_result = tcp_connect(args.target, ports, args.timeout, threads=args.threads, minimal_output=minimal, verbose=True)
            elif technique == "syn_scan":
                module_result = syn_scan(args.target, ports, args.timeout, threads=args.threads, minimal_output=minimal, verbose=True)
            elif technique == "ack_scan":
                module_result = ack_scan(args.target, ports, args.timeout)

        elif mode == "fingerprint":
            if technique == "banner_grab":
                module_result = banner_grab(args.target, ports, args.timeout, threads=args.threads, insecure_tls=args.insecure_tls)
            elif technique == "os_detection":
                module_result = os_detection(args.target, ports, args.timeout)
            elif technique == "http_headers":
                module_result = http_headers(args.target, ports, args.timeout, insecure_tls=args.insecure_tls)

        # ---------------------------------------------
        # Finalizar y mostrar duración
        #end_time = datetime.now()
        #duration = (end_time - start_time).total_seconds()
        #elapsed = time.perf_counter() - t0
        result(f"\nEjecución completada en {round(time.perf_counter() - t0, 2):.2f} segundos.")

    except SystemExit as e:
        exit_code = int(getattr(e, "code", 1) or 1)
        raise
    
    except Exception as ex:
        exit_code = 1
        printer.emit("warn", f"Excepción no controlada: {ex.__class__.__name__}: {ex}")
        raise

    finally:
        elapsed = time.perf_counter() - t0

        try:
            # Se reutiliza 'ports' para reflejar los puertos efectivos
            ports_list = ports if (locals().get("ports") is not None) else None

            module_summary = build_module_summary(technique, module_result) if args.summary else None
            
            summary = RunSummary(
                action_flag=selected_flag if 'selected_flag' in locals() else "",
                mode=mode if 'mode' in locals() else "",
                technique=technique if 'technique' in locals() else "",
                interface=getattr(args, "interface", None),
                target=getattr(args, "target", None),
                ports=ports_list,
                timeout=getattr(args, "timeout", None),
                threads=getattr(args, "threads", None),
                elapsed_seconds=round(elapsed, 2),
                exit_code=exit_code,
                module_summary=module_summary,
                module_result=module_result if (args.summary and args.format=="json") else None,
            )
                                  
            if args.summary:
                if args.format == "json":
                    # asdict(summary) -->Convierte un dataclass (summary) en un dict de Python (recursivo).
                    # json.dumps(..., ensure_ascii=False) --> Serializa ese dict a una cadena JSON y no escapa los caracteres no ASCII.
                    line = json.dumps(asdict(summary), ensure_ascii=False)
                    # para diferenciar entre los diferentes resultados en un mismo fichero, se añade fecha y hora.
                    if args.output_file:
                        with open(args.output_file, "a", encoding="utf-8") as f:
                            f.write(f"\n### {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ###\n")
                            f.write(line + "\n")

                    print(line)
                    
                else:
                    printer.emit(
                        "info",
                        (f"Resumen: {summary.mode}/{summary.technique} "
                        f"target={summary.target} elapsed={summary.elapsed_seconds}s exit={summary.exit_code}")
                    )
                    # para separar los diferentes resultados en un mismo fichero, se añade fecha y hora.
                    if args.output_file:
                        with open(args.output_file, "a", encoding="utf-8") as f:
                            f.write(f"\n### {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ###\n")
                            f.write(f"Resumen: {summary.mode}/{summary.technique} target={summary.target} "
                                    f"elapsed={summary.elapsed_seconds}s exit={summary.exit_code}\n")
                    if module_summary:
                        if module_summary.get("type") == "scan":
                            for ip, data in module_summary.get("hosts", {}).items():
                                c = data["counts"]
                                opened = ",".join(str(p) for p in data["open"]) if data["open"] else "-"
                                printer.emit(
                                    "info",
                                    (f"  {ip} -> open={c['open']} closed={c['closed']} "
                                    f"filtered+no_tcp={c['filtered_or_notcp']} other={c['other']} "
                                    f"total={c['total']} | OPEN: {opened}")
                                )
                        elif module_summary.get("type") == "discovery":
                            printer.emit(
                                "info",
                                f"  hosts activos: {module_summary.get('count', 0)} -> "
                                f"{', '.join(module_summary.get('hosts_summary', []) or module_summary.get('hosts', [])) or '-'}")
                        else:
                            printer.emit("info", f"  resumen módulo: {module_summary}")

        except Exception:
            # Si algo falla generando el resumen, se ignora para no romper la ejecución del programa
            pass
    
# ---------------------------------------------
if __name__ == "__main__":
    main()
