# utils/module_summary.py
from typing import Any, Dict, Optional, Union, List

# ---------------------------------------------
def _is_scan_schema(d: Any) -> bool:
    """
    Detecta si el resultado tiene forma de escaneo por puertos:
    {ip: {port(int): {...}, ...}, ...}
    """
    if not isinstance(d, dict):
        return False
    # tomar primer valor
    for v in d.values():
        if isinstance(v, dict):
            # ¿tiene claves int (puertos)?
            return any(isinstance(k, int) for k in v.keys()) or any(
                isinstance(k, str) and k.isdigit() for k in v.keys()
            )
        break
    return False

# ---------------------------------------------
#   Crear sumario final para resultados del módulo scan
# ---------------------------------------------
def summarize_scan_results(results_dict: Dict[str, Dict[Union[int, str], Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Convierte resultados detallados por puerto en métricas agregadas por host.
    Acepta claves de puerto int o str.
    """
    if not results_dict:
        return {"type": "scan", "hosts": {}, "open_flat": []}
    hosts_summary = {}
    open_flat = []
    for ip, ports_map in results_dict.items():
        c_open = c_closed = c_filtered = c_other = 0
        open_ports = []
        for p, r in ports_map.items():
            try:
                port = int(p)
            except Exception:
                port = p
            st = (r or {}).get("status", "UNKNOWN")
            if st == "OPEN":
                c_open += 1
                open_ports.append(port)
                open_flat.append((ip, port, (r or {}).get("service", "Unknown"), (r or {}).get("rtt")))
            elif st == "CLOSED":
                c_closed += 1
            elif st in ("FILTERED", "NO_TCP"):
                c_filtered += 1
            else:
                c_other += 1
        hosts_summary[ip] = {
            "open": sorted(open_ports, key=lambda x: (isinstance(x, str), x)),
            "counts": {
                "open": c_open,
                "closed": c_closed,
                "filtered_or_notcp": c_filtered,
                "other": c_other,
                "total": c_open + c_closed + c_filtered + c_other
            }
        }
    return {"type": "scan", "hosts": hosts_summary, "open_flat": open_flat}


# ---------------------------------------------
# Crear sumario final para resultados del modulo discovery
# ---------------------------------------------
def summarize_discovery_results(resultado: Any) -> Dict[str, Any]:
    """
    Soporta:
      - lista/iterable de IPs
      - dict { ip: {...} } (p.ej. incluye MAC, method, ports, rtt, flags...)
    """
    #hosts = []
    #data = {}
    if isinstance(resultado, dict):
        hosts = list(resultado.keys())
        data = resultado
    elif isinstance(resultado, (list, tuple, set)):
        hosts = list(resultado)
        data = {}
    else:
        # desconocido: resumen mínimo
        return {"type": "discovery", "count": 0, "hosts": [], "hosts_summary": [], "data": {}}

    # Construir representación más detallada: IP (METHOD[:PORT])
    hosts_summary = []
    hosts_sorted = sorted(hosts)
    for ip in hosts_sorted:
        info = data.get(ip, {}) if isinstance(data, dict) else {}
        meth = (info.get("method") or "").upper() if isinstance(info, dict) else ""
        #tag = ""
        if meth in {"TCP", "UDP"}:
            ports = info.get("ports") or []
            if isinstance(ports, (list, tuple)) and ports:
                tag = f"{meth}:{ports[0]}"
            else:
                tag = meth
        elif meth in {"ICMP", "ARP"}:
            tag = meth
        else:
            tag = meth or ""

        hosts_summary.append(f"{ip} ({tag})" if tag else ip)

    return {"type": "discovery", "count": len(hosts_sorted), "hosts": sorted(hosts_sorted), "hosts_summary": hosts_summary , "data": data}


# ---------------------------------------------
# Crear sumario final para resultados del módulo fingerprint
# ---------------------------------------------
def summarize_fingerprint_results(result: Dict[str, Dict[Union[int, str], Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Resume resultados de fingerprint (banner_grab, http_headers, os_detection):
      - Agrega por host: os_hint/confidence (si existen), y una lista 'services'
        con resúmenes por puerto (banner/Server/X-Powered-By/proto).
    Devuelve:
      {
        "type": "fingerprint",
        "count": N,
        "hosts": {
          ip: {
            "os_hint": str|None,
            "confidence": int|None,
            "services": [{"port": int|str, "service": str|None, "desc": str|None}, ...]
          } , ...
        }
      }
    """
    hosts: Dict[str, Any] = {}
    for ip, ports_map in (result or {}).items():
        if not isinstance(ports_map, dict):
            continue
        best_hint: Optional[str] = None
        best_conf: int = -1
        services: List[Dict[str, Any]] = []
        for p, entry in ports_map.items():
            try:
                port = int(p)
            except Exception:
                port = p
            if not isinstance(entry, dict):
                continue
            # Coger el mejor "os_hint/confidence"
            hint = entry.get("os_hint")
            conf = entry.get("confidence")
            if hint is not None and isinstance(conf, (int, float)) and int(conf) > best_conf:
                best_hint = str(hint)
                best_conf = int(conf)
            # Añadir descripción corta
            desc = entry.get("banner") or ""
            if not desc:
                headers = entry.get("headers") or {}
                server = headers.get("Server") or headers.get("server")
                xpb = headers.get("X-Powered-By") or headers.get("x-powered-by")
                bits = [b for b in [server, xpb] if b]
                if bits:
                    desc = " | ".join(bits)
            if not desc:
                desc = entry.get("proto") or entry.get("service") or None
            services.append({"port": port, "service": entry.get("service"), "desc": desc})
        services = sorted(services, key=lambda s: (isinstance(s["port"], str), s["port"]))
        hosts[ip] = {
            "os_hint": best_hint,
            "confidence": (None if best_conf < 0 else best_conf),
            "services": services,
        }

    return {"type": "fingerprint", "count": len(hosts), "hosts": hosts}


# ---------------------------------------------
def summarize_generic_mapping(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Para módulos tipo banner/http/os_detection que devuelven por host/puerto
    pero no exactamente estado OPEN/CLOSED. Se resume por host y cuenta claves.
    """
    summary = {}
    for ip, v in (result or {}).items():
        if isinstance(v, dict):
            summary[ip] = {"keys": list(v.keys()), "count": len(v)}
        else:
            summary[ip] = {"value_type": type(v).__name__}
    return {"type": "generic", "hosts": summary}


# ---------------------------------------------
def build_module_summary(technique: str, module_result: Any) -> Optional[Dict[str, Any]]:
    if module_result is None:
        return None

    # 1) Escaneo por puertos (syn_scan, tcp_connect, ack_scan, banner_grab/http si usan puertos)
    if _is_scan_schema(module_result):
        return summarize_scan_results(module_result)

    # 2) Discovery (arp_ping, icmp_ping, tcp_ping, udp_ping)
    if technique in ("arp_ping", "icmp_ping", "tcp_ping", "udp_ping"):
        return summarize_discovery_results(module_result)

    # 3) Fingerprint (banner_grab, http_headers, os_detection)
    if technique in ("banner_grab", "http_headers", "os_detection"):
        if isinstance(module_result, dict):
            return summarize_fingerprint_results(module_result)

    # 4) Otros mapeos por host/puerto "genericos"
    if isinstance(module_result, dict):
        return summarize_generic_mapping(module_result)

    # 5) Lista simple → discovery
    if isinstance(module_result, (list, tuple, set)):
        return summarize_discovery_results(module_result)

    # Fallback mínimo
    return {"type": "raw", "repr": repr(module_result)[:800]}

