"""The enforcement-side switch (D16, D29): ``AIAC_ENFORCEMENT_SIDE`` selects the side for every callee."""

import pytest

from aiac.policy.computation import enforcement_side
from aiac.policy.model.models import EnforcementSide


def test_the_default_side_is_target_side(monkeypatch):
    monkeypatch.delenv("AIAC_ENFORCEMENT_SIDE", raising=False)
    assert enforcement_side() == EnforcementSide.TARGET_SIDE


@pytest.mark.parametrize(
    ("value", "side"),
    [("target-side", EnforcementSide.TARGET_SIDE), ("agent-side", EnforcementSide.AGENT_SIDE)],
)
def test_the_switch_selects_the_side(monkeypatch, value, side):
    monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", value)
    assert enforcement_side() == side


def test_surrounding_white_space_is_ignored(monkeypatch):
    monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", " agent-side\n")
    assert enforcement_side() == EnforcementSide.AGENT_SIDE


@pytest.mark.parametrize("value", ["both", "Agent-Side", "agent_side", ""])
def test_an_unknown_value_raises_and_names_it(monkeypatch, value):
    monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", value)
    with pytest.raises(ValueError, match="AIAC_ENFORCEMENT_SIDE"):
        enforcement_side()
