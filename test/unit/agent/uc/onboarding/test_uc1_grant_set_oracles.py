"""Fixture-independent grant-set oracles for the UC-1 onboarding ladder — pure unit tests.

These are the *tracer bullet* for the ``test/system`` UC-1 suites: they assert the intended
grant-set truth table itself (inbound + outbound-subject, keyed on the **bare** runtime tool
names), independently of any cluster. If an oracle here is wrong, every live assertion in the
matching system suite is meaningless — so they are pinned here where a bare ``pytest`` runs them,
with no marker, no LLM and no cluster.

They were **extracted** from the four ``test/system`` suites (``test_policy_pipeline.py`` and
``test_uc1_onboard_{agent_only,agent_then_tool,tool_then_agent}.py``), where they inherited the
``system`` marker despite taking no fixture. This is a **content move, not a ``git mv``** — ``git
blame`` will not follow it. The assertions still read the scenario/harness definitions from the
system tree (``from test.system import scenario_uc1, uc1_onboard``); this is safe because that
harness does **no** cluster I/O at import time (every ``require_env``/``kubectl``/probe is inside a
function). The rung constants are re-derived here rather than imported from the (now oracle-free)
system suites.

Rung map:
- **Rung 1** (agent only): inbound == the scenario inbound truth table; the outbound-subject gate is
  **empty** (no tool onboarded).
- **Rung 2** (agent then tool) and **Rung 3** (tool then agent): inbound unchanged; the outbound-subject
  gate is the **non-empty** ``OUTBOUND_SUBJECT_BARE`` table. Rung 3's end state must **equal** rung 2's
  (onboarding order is irrelevant).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent  # test/unit/agent/uc/onboarding/
REPO_ROOT = HERE.parents[4]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from test.system import scenario_uc1 as scn  # noqa: E402
from test.system import uc1_onboard as uc1  # noqa: E402

# --- Re-derived rung grant sets (the oracle for the grant-set contract checks) ------------------
# Inbound uses the prefixed provisioned truth for every rung. The outbound-subject gate is empty for
# rung 1 (no tool onboarded) and the shared non-empty table for rungs 2/3 (tool onboarded).
RUNG1_INBOUND = uc1.INBOUND_GRANT_SET
RUNG1_OUTBOUND_SUBJECT_BARE: set[tuple[str, str]] = set()  # ∅ — no tool onboarded

RUNG2_INBOUND = uc1.INBOUND_GRANT_SET
RUNG2_OUTBOUND_SUBJECT_BARE = scn.OUTBOUND_SUBJECT_BARE

RUNG3_INBOUND = uc1.INBOUND_GRANT_SET
RUNG3_OUTBOUND_SUBJECT_BARE = scn.OUTBOUND_SUBJECT_BARE


def _rung1_expected_outbound(subject: str, tool_bare: str) -> bool:
    """Rung 1: the outbound user gate is entirely empty (no tool onboarded), so every
    ``(subject, tool_bare)`` is denied."""
    return (scn.USERS[subject], tool_bare) in RUNG1_OUTBOUND_SUBJECT_BARE


# ======================================================================================
# Shared inbound oracle (identical across every rung — tool onboarding never touches inbound)
# ======================================================================================


@pytest.mark.parametrize(
    "subject, allowed",
    [("dev-user", True), ("test-user", True), ("devops-user", False)],
)
def test_inbound_oracle(subject: str, allowed: bool) -> None:
    """Inbound: dev-user ✅, test-user ✅, devops-user ❌ (devops sources no agent scope) — unaffected
    by tool onboarding or onboarding order; identical for rungs 1, 2 and 3 and the full-matrix suite."""
    assert uc1.expected_inbound(subject) is allowed


# ======================================================================================
# Rung 1 (agent only) — the outbound gate is empty
# ======================================================================================


@pytest.mark.parametrize("subject", list(scn.USERS))
@pytest.mark.parametrize("tool_bare", scn.TOOL_REQUEST_NAMES)
def test_rung1_outbound_oracle_all_deny(subject: str, tool_bare: str) -> None:
    """Rung 1's defining property: the outbound user gate is empty, so every ``(subject, tool)`` is
    denied — no tool was onboarded, so no tool scope is in the universe."""
    assert _rung1_expected_outbound(subject, tool_bare) is False


def test_rung1_grant_set_oracle() -> None:
    """Rung 1 grant-set oracle: inbound == the ``scenario_uc1`` inbound truth table; the
    outbound-subject gate is empty."""
    assert RUNG1_INBOUND == set(scn.INBOUND_PAIRS)
    assert RUNG1_OUTBOUND_SUBJECT_BARE == set()


# ======================================================================================
# Rungs 2 & 3 (tool onboarded) — the full, non-empty user→tool gate
# ======================================================================================


@pytest.mark.parametrize(
    "subject, tool_bare, allowed",
    [
        # dev-user (developer): source read/write + issues read; NOT issues write.
        ("dev-user", "source-read", True),
        ("dev-user", "source-write", True),
        ("dev-user", "issues-read", True),
        ("dev-user", "issues-write", False),
        # test-user (tester): issues read/write only.
        ("test-user", "source-read", False),
        ("test-user", "source-write", False),
        ("test-user", "issues-read", True),
        ("test-user", "issues-write", True),
        # devops-user (devops): no access to anything.
        ("devops-user", "source-read", False),
        ("devops-user", "source-write", False),
        ("devops-user", "issues-read", False),
        ("devops-user", "issues-write", False),
    ],
)
def test_tool_onboarded_outbound_oracle(subject: str, tool_bare: str, allowed: bool) -> None:
    """The full user→tool outbound gate over the **bare** tool names (developer: source rw + issues
    read; tester: issues rw; devops: nothing) — the gate tool onboarding completes on the agent, shared
    by rungs 2 and 3 and the full-matrix suite."""
    assert uc1.expected_outbound_bare(subject, tool_bare) is allowed


def test_rung2_grant_set_oracle() -> None:
    """Rung 2 grant-set oracle: inbound == the ``scenario_uc1`` inbound truth table; the outbound-subject
    (bare) grant set == the (non-empty) ``OUTBOUND_SUBJECT_BARE`` truth table."""
    assert RUNG2_INBOUND == set(scn.INBOUND_PAIRS)
    assert RUNG2_OUTBOUND_SUBJECT_BARE == scn.OUTBOUND_SUBJECT_BARE
    assert RUNG2_OUTBOUND_SUBJECT_BARE, "rung 2's outbound gate must be non-empty (the tool was onboarded)"


def test_rung3_grant_set_oracle() -> None:
    """Rung 3 grant-set oracle: inbound == the ``scenario_uc1`` inbound truth table; the outbound-subject
    (bare) grant set == the (non-empty) ``OUTBOUND_SUBJECT_BARE`` truth table."""
    assert RUNG3_INBOUND == set(scn.INBOUND_PAIRS)
    assert RUNG3_OUTBOUND_SUBJECT_BARE == scn.OUTBOUND_SUBJECT_BARE
    assert RUNG3_OUTBOUND_SUBJECT_BARE, "rung 3's outbound gate must be non-empty (the tool was onboarded)"


def test_order_independence_oracle() -> None:
    """The order-independence property at the oracle level: rung 3's intended end state is **identical
    to rung 2's** (both the inbound and the outbound-subject bare grant sets). The live matrices in the
    system suites then prove the *real plugin's decisions* match this in both orders — that onboarding
    order did not change the enforced policy."""
    assert RUNG3_INBOUND == RUNG2_INBOUND
    assert RUNG3_OUTBOUND_SUBJECT_BARE == RUNG2_OUTBOUND_SUBJECT_BARE
