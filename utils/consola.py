# utils/consola.py
# Fichero utilizado para centralizar las funciones de salida de consola.

from datetime import datetime

# ---------------------------------------------
# Configuración de colores y mensajes de error
#   - Se utiliza bloque Try-except para que si no está instalado colorama no falle la aplicación.
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Dummy:
        RESET_ALL = RED = YELLOW = CYAN = WHITE = ""
    Fore = Style = Dummy()

def error(msg):
    print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")

def warning(msg):
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

def info(msg):
    print(msg)

def result(msg, show_time=False):
    if show_time:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{Fore.CYAN}{msg} [{now}]{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}{msg}{Style.RESET_ALL}")

