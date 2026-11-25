# Regression tests for TCP and UDP host discovery responses.

from importlib import import_module

from scapy.all import ICMP, IP, TCP, UDP


tcp_ping_module = import_module("discovery.tcp_ping")
udp_ping_module = import_module("discovery.udp_ping")


def _use_target(monkeypatch, module, target):
    monkeypatch.setattr(module.network, "expand_targets", lambda _target: [target])


def test_tcp_ping_omits_hosts_without_a_reply(monkeypatch):
    target = "192.0.2.10"
    _use_target(monkeypatch, tcp_ping_module, target)
    monkeypatch.setattr(tcp_ping_module, "sr1", lambda *_args, **_kwargs: None)

    assert tcp_ping_module.tcp_ping(target, [80], 0.01) == {}


def test_tcp_ping_ignores_a_reply_from_another_host(monkeypatch):
    target = "192.0.2.10"
    _use_target(monkeypatch, tcp_ping_module, target)
    monkeypatch.setattr(
        tcp_ping_module,
        "sr1",
        lambda probe, **_kwargs: IP(src="192.0.2.254", dst=probe[IP].src)
        / TCP(sport=probe[TCP].dport, dport=probe[TCP].sport, flags="SA"),
    )

    assert tcp_ping_module.tcp_ping(target, [80], 0.01) == {}


def test_tcp_ping_accepts_syn_ack_from_the_target(monkeypatch):
    target = "192.0.2.10"
    _use_target(monkeypatch, tcp_ping_module, target)
    monkeypatch.setattr(
        tcp_ping_module,
        "sr1",
        lambda probe, **_kwargs: IP(src=target, dst=probe[IP].src)
        / TCP(sport=probe[TCP].dport, dport=probe[TCP].sport, flags="SA"),
    )

    result = tcp_ping_module.tcp_ping(target, [80], 0.01)

    assert result[target]["method"] == "TCP"
    assert result[target]["ports"] == [80]
    assert result[target]["flags"] == "SYN/ACK"


def test_udp_ping_omits_hosts_without_a_reply(monkeypatch):
    target = "192.0.2.10"
    _use_target(monkeypatch, udp_ping_module, target)
    monkeypatch.setattr(udp_ping_module, "sr1", lambda *_args, **_kwargs: None)

    assert udp_ping_module.udp_ping(target, [53], 0.01) == {}


def test_udp_ping_accepts_a_matching_udp_reply(monkeypatch):
    target = "192.0.2.10"
    _use_target(monkeypatch, udp_ping_module, target)
    monkeypatch.setattr(
        udp_ping_module,
        "sr1",
        lambda probe, **_kwargs: IP(src=target, dst=probe[IP].src)
        / UDP(sport=53, dport=probe[UDP].sport),
    )

    result = udp_ping_module.udp_ping(target, [53], 0.01)

    assert result[target]["method"] == "UDP"
    assert result[target]["ports"] == [53]
    assert result[target]["response"] == "UDP"


def test_udp_ping_ignores_icmp_from_a_router(monkeypatch):
    target = "192.0.2.10"
    _use_target(monkeypatch, udp_ping_module, target)
    monkeypatch.setattr(
        udp_ping_module,
        "sr1",
        lambda probe, **_kwargs: IP(src="192.0.2.254", dst=probe[IP].src)
        / ICMP(type=3, code=3),
    )

    assert udp_ping_module.udp_ping(target, [53], 0.01) == {}


def test_udp_ping_accepts_port_unreachable_from_the_target(monkeypatch):
    target = "192.0.2.10"
    _use_target(monkeypatch, udp_ping_module, target)
    monkeypatch.setattr(
        udp_ping_module,
        "sr1",
        lambda probe, **_kwargs: IP(src=target, dst=probe[IP].src)
        / ICMP(type=3, code=3),
    )

    result = udp_ping_module.udp_ping(target, [53], 0.01)

    assert result[target]["method"] == "UDP"
    assert result[target]["ports"] == [53]
    assert result[target]["icmp"] == {"type": 3, "code": 3}
