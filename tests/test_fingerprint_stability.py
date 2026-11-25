# Regression tests for fingerprinting behavior and CLI protocol flags.

import importlib
import sys

import pytest
from scapy.all import ICMP, IP


banner_module = importlib.import_module("fingerprint.banner_grab")
http_module = importlib.import_module("fingerprint.http_headers")


def test_banner_grab_does_not_probe_ports_when_none_are_open(monkeypatch):
    target = "192.0.2.5"
    monkeypatch.setattr(
        banner_module,
        "tcp_connect",
        lambda *_args, **_kwargs: {target: {80: {"status": "CLOSED"}}},
    )

    def unexpected_grab(*_args, **_kwargs):
        raise AssertionError("banner grabbing must skip closed ports")

    monkeypatch.setattr(banner_module, "grab_banner", unexpected_grab)

    result = banner_module.banner_grab(target, [80], timeout=0.01, threads=1)

    assert result == {target: {}}


def test_banner_grab_stores_version_as_a_string(monkeypatch):
    target = "192.0.2.5"
    monkeypatch.setattr(
        banner_module,
        "tcp_connect",
        lambda *_args, **_kwargs: {target: {80: {"status": "OPEN"}}},
    )
    monkeypatch.setattr(
        banner_module,
        "grab_banner",
        lambda *_args, **_kwargs: ("Server: Apache 2.4.41", "2.4.41", "OK"),
    )

    result = banner_module.banner_grab(target, [80], timeout=0.01, threads=1)

    assert result[target][80]["version"] == "2.4.41"
    assert isinstance(result[target][80]["version"], str)


def test_grab_banner_extracts_version_string(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.read = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def connect(self, _address):
            pass

        def recv(self, _size):
            if self.read:
                return b""
            self.read = True
            return b"220 ProFTPD 1.3.5e Server\r\n"

        def sendall(self, _payload):
            pass

    monkeypatch.setattr(banner_module.socket, "socket", lambda *_args: FakeSocket())

    banner, version, status = banner_module.grab_banner("192.0.2.5", 21, 0.01)

    assert banner.startswith("220 ProFTPD")
    assert version == "1.3.5e"
    assert isinstance(version, str)
    assert status == "OK"


def test_http_failure_is_unknown_not_closed(monkeypatch):
    target = "192.0.2.5"
    monkeypatch.setattr(http_module.network, "expand_targets", lambda _target: [target])
    monkeypatch.setattr(http_module, "get_http_headers", lambda *_args, **_kwargs: None)

    result = http_module.http_headers(target, [80], timeout=0.01)
    entry = result[target][80]

    assert entry["status"] == "UNKNOWN"
    assert entry["headers"] == {}
    assert entry["error"] == "http-header-request-failed"


def test_http_connection_with_no_headers_is_still_open(monkeypatch):
    target = "192.0.2.5"
    monkeypatch.setattr(http_module.network, "expand_targets", lambda _target: [target])
    monkeypatch.setattr(http_module, "get_http_headers", lambda *_args, **_kwargs: {})

    result = http_module.http_headers(target, [80], timeout=0.01)

    assert result[target][80]["status"] == "OPEN"
    assert result[target][80]["headers"] == {}


def test_http_headers_forwards_forced_https(monkeypatch):
    target = "192.0.2.5"
    calls = []
    monkeypatch.setattr(http_module.network, "expand_targets", lambda _target: [target])

    def fake_get_headers(_ip, port, timeout=3, use_https=None, insecure_tls=False):
        calls.append((port, use_https))
        return {"Server": "test"}

    monkeypatch.setattr(http_module, "get_http_headers", fake_get_headers)

    result = http_module.http_headers(target, [80, 443], use_https=True)

    assert calls == [(80, True), (443, True)]
    assert result[target][80]["proto"] == "HTTPS"
    assert result[target][443]["proto"] == "HTTPS"


@pytest.mark.parametrize(("flag", "expected"), [("--https", True), ("--http", False)])
def test_cli_forwards_http_protocol_flag(monkeypatch, flag, expected):
    import EnumTool

    captured = {}
    monkeypatch.setattr(sys, "argv", ["EnumTool.py", "-H", "-t", "192.0.2.5", flag])

    def fake_http_headers(target, ports, timeout, use_https=None, insecure_tls=False):
        captured["use_https"] = use_https
        return {}

    monkeypatch.setattr(EnumTool, "http_headers", fake_http_headers)

    EnumTool.main()

    assert captured["use_https"] is expected
