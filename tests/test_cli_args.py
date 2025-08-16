#tests/test_cli_args.py

import sys
import pytest
import EnumTool


def test_cli_requires_target(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["EnumTool.py", "-sT"])
    with pytest.raises(SystemExit):
        EnumTool.main()


def test_cli_arp_requires_interface(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["EnumTool.py", "-dA", "-t", "1.1.1.1"])
    with pytest.raises(SystemExit):
        EnumTool.main()


def test_cli_mutually_exclusive(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["EnumTool.py", "-sT", "-sS", "-t", "1.1.1.1"])
    with pytest.raises(SystemExit):
        EnumTool.main()


def test_cli_valid(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["EnumTool.py", "-sT", "-t", "1.1.1.1", "-p", "80"])
    monkeypatch.setattr("scan.tcp_connect.tcp_connect", lambda *a, **k: {})
    EnumTool.main()  # no excepción

