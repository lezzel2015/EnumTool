# tests/conftest.py
# Para evitar confirmaciones en todos los tests

import pytest
from utils import network

@pytest.fixture(autouse=True)
def _no_confirm_targets():
    network.set_expand_targets_policy(assume_yes=True, confirm_threshold=1)
    yield

