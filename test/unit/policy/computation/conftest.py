"""Shared fixtures for the PCE tests: the enforcement side (D16, D29) comes from the environment."""

import pytest

from aiac.policy.model.models import EnforcementSide


@pytest.fixture(autouse=True)
def _default_side(monkeypatch):
    """Every test starts with ``AIAC_ENFORCEMENT_SIDE`` unset (the default, target side), so a value in
    the developer's shell cannot change a test. A test that needs a side sets it (see ``agent_side``,
    ``side``)."""
    monkeypatch.delenv("AIAC_ENFORCEMENT_SIDE", raising=False)


@pytest.fixture
def agent_side(monkeypatch):
    """Run the test under agent side."""
    monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", EnforcementSide.AGENT_SIDE.value)
    return EnforcementSide.AGENT_SIDE


@pytest.fixture(params=[EnforcementSide.TARGET_SIDE, EnforcementSide.AGENT_SIDE], ids=lambda side: side.value)
def side(request, monkeypatch):
    """Run the test once under each side; the value is the side."""
    monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", request.param.value)
    return request.param
