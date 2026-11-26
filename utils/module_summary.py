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
        c_open = c_closed = c_filtered = c_no_response = c_no_tcp = c_unfiltered = c_unknown = c_errors = 0
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
            elif st == "FILTERED":
                c_filtered += 1
                if (r or {}).get("reason") in ("timeout-no-response", "no-response"):
                    c_no_response += 1
            elif st == "NO_TCP":
                c_no_tcp += 1
            elif st == "UNFILTERED":
                c_unfiltered += 1
            elif st == "ERROR":
                c_errors += 1
            else:
                c_unknown += 1
        hosts_summary[ip] = {
            "open": sorted(open_ports, key=lambda x: (isinstance(x, str), x)),
            "counts": {
                "open": c_open,
                "closed": c_closed,
                "filtered": c_filtered,
                "no_response": c_no_response,
                "no_tcp": c_no_tcp,
                "unfiltered": c_unfiltered,
                "unknown": c_unknown,
                "errors": c_errors,
                # Retain aggregate fields for consumers of the prior JSON schema.
                "filtered_or_notcp": c_filtered + c_no_tcp,
                "other": c_unknown + c_errors,
                "total": c_open + c_closed + c_filtered + c_no_tcp + c_unfiltered + c_unknown + c_errors
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
    Resume resultados de banner_grab, http_headers y os_detection.
    Conserva el nivel cualitativo de confianza y el score/evidencias globales
    de OS Detection por separado.
    """
    hosts: Dict[str, Any] = {}
    confidence_ranks = {"posible": 1, "probable": 2}

    for ip, ports_map in (result or {}).items():
        if not isinstance(ports_map, dict):
            continue

        confidence_by_hint: Dict[str, Any] = {}
        rank_by_hint: Dict[str, float] = {}
        host_os = ports_map.get("_host_os")
        services: List[Dict[str, Any]] = []

        for raw_port, entry in ports_map.items():
            if raw_port == "_host_os" or not isinstance(entry, dict):
                continue

            try:
                port = int(raw_port)
            except (TypeError, ValueError):
                port = raw_port

            hint = entry.get("os_hint")
            confidence = entry.get("confidence")
            if hint is not None:
                hint = str(hint)
                if isinstance(confidence, (int, float)):
                    rank = float(confidence)
                else:
                    rank = float(confidence_ranks.get(str(confidence).lower(), 0))
                if rank > rank_by_hint.get(hint, -1.0):
                    confidence_by_hint[hint] = confidence
                    rank_by_hint[hint] = rank

            desc = entry.get("banner") or ""
            if not desc:
                headers = entry.get("headers") or {}
                server = headers.get("Server") or headers.get("server")
                powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
                bits = [value for value in (server, powered_by) if value]
                if entry.get("http_status"):
                    bits.insert(0, entry["http_status"])
                if bits:
                    desc = " | ".join(bits)
            if not desc:
                desc = entry.get("proto") or entry.get("service") or None

            services.append({
                "port": port,
                "service": entry.get("detected_service") or entry.get("service"),
                "registered_service": entry.get("service"),
                "product": entry.get("product"),
                "desc": desc,
            })

        score = None
        evidence = []
        evidence_sources = []
        host_confidence = None
        if isinstance(host_os, dict):
            best_hint = host_os.get("best")
            score = host_os.get("score")
            evidence = host_os.get("evidence") or []
            evidence_sources = host_os.get("evidence_sources") or []
            host_confidence = host_os.get("confidence")
            best_confidence = confidence_by_hint.get(best_hint)
        else:
            best_hint = max(rank_by_hint, key=rank_by_hint.get) if rank_by_hint else None
            best_confidence = confidence_by_hint.get(best_hint)

        services.sort(key=lambda service: (isinstance(service["port"], str), service["port"]))
        host_summary = {
            "os_hint": best_hint,
            "confidence": best_confidence,
            "services": services,
        }
        if score is not None:
            host_summary["score"] = score
        if isinstance(host_os, dict) and host_confidence:
            host_summary["confidence"] = host_confidence
        if evidence_sources:
            host_summary["evidence_sources"] = evidence_sources
        if evidence:
            host_summary["evidence"] = evidence
        hosts[ip] = host_summary

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

    # El tipo de técnica prevalece sobre la forma de las claves por puerto:
    # banner_grab también usa puertos numéricos, pero no es un escaneo de estados.
    if technique in ("banner_grab", "http_headers", "os_detection"):
        return summarize_fingerprint_results(module_result)

    if technique in ("arp_ping", "icmp_ping", "tcp_ping", "udp_ping"):
        return summarize_discovery_results(module_result)

    if _is_scan_schema(module_result):
        return summarize_scan_results(module_result)

    if isinstance(module_result, dict):
        return summarize_generic_mapping(module_result)

    if isinstance(module_result, (list, tuple, set)):
        return summarize_discovery_results(module_result)

    return {"type": "raw", "repr": repr(module_result)[:800]}

