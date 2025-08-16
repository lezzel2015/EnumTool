#tests/test_top_ports.py

from utils.top_ports import (
    get_top_ports,
    get_profile_ports,
    TOP_1000_TCP_PORTS,
    PROFILES,
)


def test_get_top_ports_basic():
    assert get_top_ports(5) == TOP_1000_TCP_PORTS[:5]


def test_get_top_ports_zero():
    assert get_top_ports(0) == []


def test_get_top_ports_overflow():
    assert get_top_ports(2000) == TOP_1000_TCP_PORTS


def test_get_profile_ports_known():
    assert get_profile_ports("web") == PROFILES["web"]
    assert get_profile_ports("windows") == PROFILES["windows"]
    assert get_profile_ports("linux") == PROFILES["linux"]


def test_get_profile_ports_unknown():
    assert get_profile_ports("unknown") == []
