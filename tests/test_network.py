# tests/test_network.py

import pytest
from utils import network


@pytest.fixture(autouse=True)
def reset_expansion_policy():
    network.set_expand_targets_policy(assume_yes=True, confirm_threshold=100, max_targets=4096)
    yield
    network.set_expand_targets_policy(assume_yes=True, confirm_threshold=100, max_targets=4096)


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


def test_expand_targets_deduplicates_preserving_order():
    assert network.expand_targets("192.168.0.1,192.168.0.1,192.168.0.2") == [
        "192.168.0.1",
        "192.168.0.2",
    ]


@pytest.mark.parametrize(
    "targets",
    [
        "192.168.0.1-3",
        "192.168.0.0/29",
        "192.168.0.1,192.168.0.2,192.168.0.3",
    ],
)
def test_expand_targets_enforces_maximum(targets):
    network.set_expand_targets_policy(assume_yes=True, max_targets=2)
    with pytest.raises(network.TargetExpansionError, match="límite"):
        network.expand_targets(targets)


def test_expand_targets_declined_confirmation(monkeypatch):
    network.set_expand_targets_policy(assume_yes=False, confirm_threshold=1)
    monkeypatch.setattr("builtins.input", lambda _: "n")
    with pytest.raises(network.TargetExpansionError, match="cancelada"):
        network.expand_targets("192.168.0.0/30")


@pytest.mark.parametrize(
    "value",
    ["192.168.0.0/33", "192.168.0.10-5", "999.999.999.999", ""],
)
def test_expand_targets_invalid(value):
    with pytest.raises(network.TargetExpansionError):
        network.expand_targets(value)
