# utils/ports.py
# Parseado de puertos

import sys
from typing import List, Iterable, Set

class PortParseError(ValueError):
    """Excepción personalizada para errores al parsear puertos."""
    pass

# --------- COLORES ---------
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Colorama no instalado, define colores vacíos para no romper la salida
    class Dummy:
        RESET = RED = YELLOW = CYAN = WHITE = ""
    Fore = Style = Dummy()
# ----------------------------
# Funciones que muestran mensajes en un determinado color, dependiendo de 
# la información que proporcionan

def error(msg):
    print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")
    
def parse_ports(port_string: str) -> List[int]:
    """
    Procesa una cadena como:
      "22,80,443" o "20-25" o combinación "22,25-27,80"
    Devuelve una lista de enteros únicos y ordenados.
    Lanza PortParseError en caso de entrada inválida:
      - Un puerto no es numérico
      - Un rango tiene fin < inicio
      - Un puerto está fuera del rango 1-65535
    """
    if port_string is None:
        return []

    s = port_string.strip()
    if not s:
        return []

    ports = set()
    parts = [p.strip() for p in port_string.split(',') if p.strip()]

    for part in parts:
        # normaliza guiones “raros”
        pnorm = part.replace('–', '-').replace('—', '-')
        
        if '-' in pnorm:
            try:
                start_str, end_str = pnorm.split('-', 1)
                start, end = int(start_str), int(end_str)
            except ValueError:
                raise PortParseError(f"Rango mal formado: '{part}'")
            if end < start:
                raise PortParseError(f"Rango inválido (fin < inicio): '{part}'")
            if start < 1 or end > 65535:
                raise PortParseError(f"Rango fuera de 1–65535: '{part}'")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(pnorm)
            except ValueError:
                raise PortParseError(f"Puerto no numérico: '{part}'")
            if port < 1 or port > 65535:
                raise PortParseError(f"Puerto fuera de rango 1–65535: {port}")
            ports.add(port)

    return sorted(ports)
