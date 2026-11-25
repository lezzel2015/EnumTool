# Regression tests for TCP Connect, SYN Scan, and ACK Scan classification.

from importlib import import_module
import socket

from scapy.all import ICMP, IP, TCP


tcp_connect_module = import_module("scan.tcp_connect")
syn_scan_module = import_module("scan.syn_scan")
ack_scan_module = import_module("scan.ack_scan")


TARGET = "192.0.2.10"
PORT = 8080


def _tcp_reply(probe, flags, source=TARGET):
    return IP(src=source, dst=probe[IP].src) / TCP(
        sport=probe[TCP].dport,
        dport=probe[TCP].sport,
        flags=flags,
        seq=1000,
        ack=probe[TCP].seq + 1,
    )


def test_tcp_connect_marks_timeout_filtered(monkeypatch):
    def raise_timeout(*_args, **_kwargs):
        raise socket.timeout()

    monkeypatch.setattr(tcp_connect_module.socket, "create_connection", raise_timeout)

    _port, result = tcp_connect_module.scan_port(TARGET, PORT, 0.01)

    assert result["status"] == "FILTERED"


def test_tcp_connect_closes_successful_connection(monkeypatch):
    class FakeConnection:
        closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.closed = True

    connection = FakeConnection()
    monkeypatch.setattr(
        tcp_connect_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: connection,
    )

    _port, result = tcp_connect_module.scan_port(TARGET, PORT, 0.01)

    assert result["status"] == "OPEN"
    assert connection.closed


def test_tcp_connect_classifies_refused_connection_as_closed(monkeypatch):
    def refuse_connection(*_args, **_kwargs):
        raise ConnectionRefusedError()

    monkeypatch.setattr(
        tcp_connect_module.socket,
        "create_connection",
        refuse_connection,
    )

    _port, result = tcp_connect_module.scan_port(TARGET, PORT, 0.01)

    assert result["status"] == "CLOSED"


def test_syn_scan_classifies_unexpected_icmp(monkeypatch):
    monkeypatch.setattr(
        syn_scan_module,
        "sr1",
        lambda probe, **_kwargs: IP(src="192.0.2.254", dst=probe[IP].src) / ICMP(type=11, code=0),
    )

    _port, result = syn_scan_module.scan_syn_port(TARGET, PORT, 0.01)

    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "icmp(type=11,code=0)"


def test_syn_scan_classifies_destination_unreachable_as_filtered(monkeypatch):
    monkeypatch.setattr(
        syn_scan_module,
        "sr1",
        lambda probe, **_kwargs: IP(src="192.0.2.254", dst=probe[IP].src) / ICMP(type=3, code=13),
    )

    _port, result = syn_scan_module.scan_syn_port(TARGET, PORT, 0.01)

    assert result["status"] == "FILTERED"
    assert result["icmp"] == {"type": 3, "code": 13}


def test_syn_scan_resets_after_syn_ack(monkeypatch):
    sent = []
    monkeypatch.setattr(syn_scan_module, "sr1", lambda probe, **_kwargs: _tcp_reply(probe, "SA"))
    monkeypatch.setattr(syn_scan_module, "send", lambda packet, **_kwargs: sent.append(packet))

    _port, result = syn_scan_module.scan_syn_port(TARGET, PORT, 0.01)

    assert result["status"] == "OPEN"
    assert len(sent) == 1
    assert int(sent[0][TCP].flags) & 0x04


def test_ack_scan_accepts_rst_ack_as_unfiltered(monkeypatch):
    monkeypatch.setattr(ack_scan_module.network, "expand_targets", lambda _target: [TARGET])
    monkeypatch.setattr(ack_scan_module, "sr1", lambda probe, **_kwargs: _tcp_reply(probe, "RA"))

    result = ack_scan_module.ack_scan(TARGET, [PORT], timeout=0.01)

    assert result[TARGET][PORT]["status"] == "UNFILTERED"
    assert result[TARGET][PORT]["flags"] == "RST"


def test_ack_scan_classifies_other_icmp_as_unknown(monkeypatch):
    monkeypatch.setattr(ack_scan_module.network, "expand_targets", lambda _target: [TARGET])
    monkeypatch.setattr(
        ack_scan_module,
        "sr1",
        lambda probe, **_kwargs: IP(src="192.0.2.254", dst=probe[IP].src) / ICMP(type=11, code=0),
    )

    result = ack_scan_module.ack_scan(TARGET, [PORT], timeout=0.01)

    assert result[TARGET][PORT]["status"] == "UNKNOWN"
    assert result[TARGET][PORT]["reason"] == "icmp(type=11,code=0)"


def test_scan_functions_return_empty_results_for_empty_port_lists(monkeypatch):
    def unexpected_expand(_target):
        raise AssertionError("empty port lists should return before target expansion")

    monkeypatch.setattr(tcp_connect_module.network, "expand_targets", unexpected_expand)
    monkeypatch.setattr(syn_scan_module.network, "expand_targets", unexpected_expand)
    monkeypatch.setattr(ack_scan_module.network, "expand_targets", unexpected_expand)

    assert tcp_connect_module.tcp_connect(TARGET, [], 0.01) == {}
    assert syn_scan_module.syn_scan(TARGET, [], 0.01) == {}
    assert ack_scan_module.ack_scan(TARGET, [], timeout=0.01) == {}
