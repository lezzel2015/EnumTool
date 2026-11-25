# utils/network.py
# Funciones relacionadas con la validación y expansión de objetivos IPv4.


_EXPAND_ASSUME_YES = False
_EXPAND_CONFIRM_THRESHOLD = 100
_EXPAND_MAX_TARGETS = 4096


class TargetExpansionError(ValueError):
    """Error de validación, límite o confirmación al expandir objetivos."""


def set_expand_targets_policy(assume_yes=False, confirm_threshold=100, max_targets=4096):
    """Configura la confirmación y el máximo de IPs únicas permitido."""
    global _EXPAND_ASSUME_YES, _EXPAND_CONFIRM_THRESHOLD, _EXPAND_MAX_TARGETS

    try:
        confirm_threshold = int(confirm_threshold)
        max_targets = int(max_targets)
    except (TypeError, ValueError) as exc:
        raise TargetExpansionError("Los límites de expansión deben ser enteros.") from exc

    if confirm_threshold < 0:
        raise TargetExpansionError("confirm_threshold no puede ser negativo.")
    if max_targets < 1:
        raise TargetExpansionError("max_targets debe ser mayor que cero.")

    _EXPAND_ASSUME_YES = bool(assume_yes)
    _EXPAND_CONFIRM_THRESHOLD = confirm_threshold
    _EXPAND_MAX_TARGETS = max_targets


def expand_targets(target_string):
    """
    Procesa IPs individuales, rangos IPv4 o redes CIDR.
    El resultado conserva el orden de entrada, elimina duplicados y no supera
    el máximo configurado de direcciones únicas.
    """
    import ipaddress

    if not isinstance(target_string, str) or not target_string.strip():
        raise TargetExpansionError("Debes indicar al menos un objetivo IPv4.")

    targets = [part.strip() for part in target_string.split(",") if part.strip()]
    hosts = []
    seen = set()

    def add_host(address):
        address = str(address)
        if address in seen:
            return
        if len(hosts) >= _EXPAND_MAX_TARGETS:
            raise TargetExpansionError(
                f"La expansión supera el límite de {_EXPAND_MAX_TARGETS} objetivos. "
                "Ajusta --max-targets si necesitas un rango mayor."
            )
        seen.add(address)
        hosts.append(address)

    for target in targets:
        if "/" in target:
            try:
                net = ipaddress.IPv4Network(target, strict=False)
            except ValueError as exc:
                raise TargetExpansionError(f"Red CIDR no válida: {target}") from exc

            if net.num_addresses == 1:
                add_host(net.network_address)
            else:
                for address in net.hosts():
                    add_host(address)

        elif "-" in target:
            try:
                start_ip_str, end_ip_str = target.split("-", 1)
                start_ip = ipaddress.IPv4Address(start_ip_str.strip())

                if "." not in end_ip_str:
                    last_octet = int(end_ip_str)
                    octets = [int(part) for part in start_ip_str.strip().split(".")]
                    if not 0 <= last_octet <= 255:
                        raise ValueError("último octeto fuera de rango")
                    if last_octet < octets[3]:
                        raise ValueError("último octeto menor que el inicial")

                    start_value = int(start_ip)
                    count = last_octet - octets[3] + 1
                    for value in range(start_value, start_value + count):
                        add_host(ipaddress.IPv4Address(value))
                else:
                    end_ip = ipaddress.IPv4Address(end_ip_str.strip())
                    if int(end_ip) < int(start_ip):
                        raise ValueError("IP final menor que la inicial")
                    for value in range(int(start_ip), int(end_ip) + 1):
                        add_host(ipaddress.IPv4Address(value))

            except TargetExpansionError:
                raise
            except (ValueError, IndexError) as exc:
                raise TargetExpansionError(f"Rango de IPs no válido: {target}") from exc

        else:
            try:
                add_host(ipaddress.IPv4Address(target))
            except TargetExpansionError:
                raise
            except ValueError as exc:
                raise TargetExpansionError(f"IP no válida: {target}") from exc

    if not hosts:
        raise TargetExpansionError("No se encontraron objetivos IPv4 válidos.")

    if not _EXPAND_ASSUME_YES and len(hosts) > _EXPAND_CONFIRM_THRESHOLD:
        response = input(
            f"Se van a escanear {len(hosts)} hosts. ¿Continuar? (s/n): "
        ).strip().lower()
        if response not in ("s", "si", "y", "yes"):
            raise TargetExpansionError("Expansión cancelada por el usuario.")

    return hosts
