#tests/test_need_root.py

import pytest
import EnumTool


def test_need_root_denied(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    monkeypatch.setattr("builtins.input", lambda _: "n")
    with pytest.raises(SystemExit):
        EnumTool.need_root("syn_scan")


def test_need_root_assume_yes(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    EnumTool.need_root("syn_scan", assume_yes=True)  # no excepción

