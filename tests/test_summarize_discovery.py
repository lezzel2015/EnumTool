#tests/test_summarize_discovery.py

from utils.module_summary import summarize_discovery_results

def test_hosts_summary():
    data = {
        "10.0.0.1": {"method": "TCP", "ports": [80]},
        "10.0.0.2": {"method": "ICMP"},
        "10.0.0.3": {"method": "ARP"},
    }
    s = summarize_discovery_results(data)
    assert s["type"] == "discovery"
    assert any("(TCP:80)" in item for item in s["hosts_summary"])

