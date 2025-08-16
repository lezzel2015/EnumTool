#tests/test_network.py

import pytest
from utils import network


def test_expand_targets_single():
    assert network.expand_targets("192.168.0.1") == ["192.168.0.1"]


def test_expand_targets_range_abbrev():
    res = network.expand_targets("192.168.0.10-12")
    assert res == ["192.168.0.10", "192.168.0.11", "192.168.0.12"]


def test_expand_targets_cidr():
    res = network.expand_targets("192.168.0.0/30")
    assert res == ["192.168.0.1", "192.168.0.2"]


def test_expand_targets_confirmation(monkeypatch):
    network.set_expand_targets_policy(assume_yes=False, confirm_threshold=1)
    monkeypatch.setattr("builtins.input", lambda _: "s")
    res = network.expand_targets("192.168.0.0/30")
    assert res == ["192.168.0.1", "192.168.0.2"]


@pytest.mark.parametrize(
    "value",
    ["192.168.0.0/33", "192.168.0.10-5", "999.999.999.999"],
)
def test_expand_targets_invalid(value):
    with pytest.raises(SystemExit):
        network.expand_targets(value)

