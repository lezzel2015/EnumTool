#tests/test_module_summary.py

from utils import (
    summarize_scan_results,
    summarize_discovery_results,
    build_module_summary,
)


def test_summarize_scan_results():
    raw = {"1.1.1.1": {80: {"status": "OPEN", "service": "http", "rtt": 0.1}, 22: {"status": "CLOSED"}}}
    summary = summarize_scan_results(raw)
    host = summary["hosts"]["1.1.1.1"]
    assert host["counts"]["open"] == 1
    assert host["open"] == [80]


def test_summarize_discovery_results_list():
    summary = summarize_discovery_results(["1.1.1.1", "1.1.1.2"])
    assert summary["count"] == 2
    assert "1.1.1.1" in summary["hosts"]


def test_build_module_summary_scan():
    res = {"1.1.1.1": {80: {"status": "OPEN"}}}
    assert build_module_summary("tcp_connect", res)["type"] == "scan"


def test_build_module_summary_discovery():
    res = {"1.1.1.1": {"method": "ARP"}}
    assert build_module_summary("arp_ping", res)["type"] == "discovery"


def test_build_module_summary_banner_uses_fingerprint_summary():
    res = {"1.1.1.1": {80: {"banner": "Apache", "service": "http"}}}
    summary = build_module_summary("banner_grab", res)
    assert summary["type"] == "fingerprint"
    assert summary["hosts"]["1.1.1.1"]["services"][0]["desc"] == "Apache"


def test_summarize_os_detection_preserves_confidence_and_host_evidence():
    res = {
        "1.1.1.1": {
            22: {
                "os_hint": "Linux",
                "confidence": "probable",
                "status": "OPEN",
                "service": "ssh",
            },
            "_host_os": {
                "best": "Linux",
                "score": 5,
                "evidence": ["OpenSSH"],
                "open_ports": [22],
            },
        }
    }

    host = build_module_summary("os_detection", res)["hosts"]["1.1.1.1"]

    assert host["os_hint"] == "Linux"
    assert host["confidence"] == "probable"
    assert host["score"] == 5
    assert host["evidence"] == ["OpenSSH"]
    assert [service["port"] for service in host["services"]] == [22]

def test_os_summary_confidence_matches_global_host_hint():
    res = {
        "1.1.1.1": {
            22: {"os_hint": "Linux", "confidence": "probable", "status": "OPEN"},
            80: {"os_hint": "Windows", "confidence": "posible", "status": "OPEN"},
            "_host_os": {
                "best": "Windows",
                "score": 4,
                "evidence": ["Microsoft-IIS"],
                "open_ports": [80],
            },
        }
    }

    host = build_module_summary("os_detection", res)["hosts"]["1.1.1.1"]

    assert host["os_hint"] == "Windows"
    assert host["confidence"] == "posible"
