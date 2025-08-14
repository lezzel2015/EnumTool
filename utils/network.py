# utils/network.py
# Implementación de funciones relacionadas con la red.

import sys

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

def expand_targets(target_string):
    """
    Procesa una cadena de targets con IPs individuales, rangos o redes CIDR.
    Ejemplo de entrada:
      "192.168.56.3,192.168.56.6-192.168.56.9,192.168.1.0/24"
    Salida:
      ['192.168.56.3', '192.168.56.6', '192.168.56.7', '192.168.56.8', '192.168.56.9', '192.168.1.0', '192.168.1.1', ...]
    """
    import ipaddress
    
    hosts = []
    # Primero separamos por comas la entrada
    targets = [p.strip() for p in target_string.split(',') if p.strip()]
    # Se procesa cada parte... Si hay un guión --> es un rango de Ips, sino, es
    # una ip aislada
    for target in targets:
        if '/' in target:
            # Notación CIDR - Se valida y se expande:
            try:
                net = ipaddress.IPv4Network(target, strict=False)
                hosts_in_net = list(net.hosts())
                # Si el rango de IP es /32 --> es una Ip única
                if not hosts_in_net and net.prefixlen == 32:
                    hosts.append(str(net.network_address))
                # Si no hay ningún host en el listado... error    
                elif not hosts_in_net:
                    error(f"La red {target} no tiene hosts utilizables.")
                    sys.exit(1)
                else:
                    for ip in hosts_in_net:
                        hosts.append(str(ip))
            except ValueError:
                error(f"Red CIDR no válida: {target}")
                sys.exit(1)
        elif '-' in target:
            try:
                # Se acepta 192.168.1.6-12 como 192.168.1.6 - 192.168.1.12
                start_ip_str, end_ip_str = target.split('-')
                start_ip = ipaddress.IPv4Address(start_ip_str.strip())

                # Si el final es un número (último octeto)
                if '.' not in end_ip_str:
                    # Expandir final con mismo prefijo
                    last_octet = int(end_ip_str)
                    start_octets = start_ip_str.strip().split('.')
                    # Se verifica que la ip está bien formada (4 octetos)
                    if len(start_octets) != 4:
                        raise ValueError
                    # Se guarda el valor inicial de los octetos
                    base = list(map(int, start_octets))
                    # Se verifica que el último octeto es correcto
                    if not (0 <= last_octet <= 255):
                        raise ValueError
                    # Se verifica que el rango indicado es correcto:    
                    if last_octet < base[3]:
                        error(f"Rango inválido: {target} (último octeto menor que el inicial)")
                        sys.exit(1)

                    for i in range(base[3], last_octet + 1):
                        ip = f"{base[0]}.{base[1]}.{base[2]}.{i}"
                        hosts.append(ip)
                else:
                    # Rango completo con IP final
                    end_ip = ipaddress.IPv4Address(end_ip_str.strip())
                    if int(end_ip) < int(start_ip):
                        error(f"Rango inválido: {target} (IP final menor que la inicial)")
                        sys.exit(1)
                    current = start_ip
                    while current <= end_ip:
                        hosts.append(str(current))
                        current += 1
            except ValueError:
                error(f"Rango de IPs no válido: {target}")
                sys.exit(1)

        else:
            # IP única
            try:
                ip = ipaddress.IPv4Address(target)
                hosts.append(str(ip))
            except ValueError:
                error(f"IP no válida: {target}")
                sys.exit(1)

    # Verificar si hay demasiadas IPs
    if len(hosts) > 100:
        print(f"\n[!] Se han generado {len(hosts)} direcciones IP a escanear.")
        resp = input("¿Deseas continuar? (s/n): ").strip().lower()
        if resp != 's':
            print("[-] Cancelado por el usuario.")
            sys.exit(0)
    
    # Se devuelve la lista de hosts a escanear
    return hosts

