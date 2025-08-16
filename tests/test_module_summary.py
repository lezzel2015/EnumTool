#tests/test_module_summary.py

from utils.module_summary import (
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


def test_build_module_summary_generic():
    res = {"1.1.1.1": {"banner": "abc"}}
    assert build_module_summary("banner_grab", res)["type"] == "generic"

