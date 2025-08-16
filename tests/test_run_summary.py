#tests/test_run_summary.py

import sys
import json
import pytest
import EnumTool


def test_run_summary_json(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["EnumTool.py", "-sT", "-t", "1.1.1.1", "-p", "80", "--summary", "--format", "json"],
    )
    monkeypatch.setattr(
        "scan.tcp_connect.tcp_connect",
        lambda *a, **k: {"1.1.1.1": {80: {"status": "OPEN"}}},
    )

    EnumTool.main()
    out = capsys.readouterr().out.strip().splitlines()[-1]
    data = json.loads(out)

    assert data["action_flag"] == "-sT"
    assert data["technique"] == "tcp_connect"
    assert data["module_summary"]["type"] == "scan"
    assert data["elapsed_seconds"] >= 0

