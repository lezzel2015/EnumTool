# tests/test_ports.py

import pytest
from utils.ports import parse_ports, PortParseError


@pytest.mark.parametrize(
    "value, expected",
    [
        ("22,80,443", [22, 80, 443]),
        ("20-25", list(range(20, 26))),
        ("22,25-27,80", [22, 25, 26, 27, 80]),
    ],
)
def test_parse_ports_ok(value, expected):
    assert parse_ports(value) == expected


@pytest.mark.parametrize("value", ["abc", "30-20", "0", "65536"])
def test_parse_ports_error(value):
    with pytest.raises(PortParseError):
        parse_ports(value)

