#tests/test_printer.py

import json
from EnumTool import Printer


def test_printer_text(tmp_path, capsys):
    outfile = tmp_path / "out.log"
    p = Printer(mode="text", outfile=str(outfile))
    p.emit("ok", "todo bien")
    p.emit("warn", "cuidado")
    captured = capsys.readouterr().out
    assert "[+] todo bien" in captured
    assert "[!] cuidado" in captured
    assert outfile.read_text().strip().splitlines()[0] == "[+] todo bien"


def test_printer_json(tmp_path):
    outfile = tmp_path / "out.json"
    p = Printer(mode="json", outfile=str(outfile))
    p.emit("open", "puerto abierto", ip="1.1.1.1")
    data = [json.loads(line) for line in outfile.read_text().splitlines()]
    assert data[0]["level"] == "open"
    assert data[0]["ip"] == "1.1.1.1"

