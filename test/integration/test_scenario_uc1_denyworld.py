"""Fixture-independent oracle-contract tests for the Policy-B (denyworld) oracle.

Not an integration test (no ``pytest.mark.integration``): these need **no** cluster, Keycloak, or
LLM and run in the routine ``-m "not integration"`` unit lane. They pin the handoff §6 intended
allow/deny matrix **directly** (mirroring ``test_policy_pipeline.py:64-93``) so a wrong oracle cannot
silently validate the live denyworld test — if these are wrong, every live assertion is meaningless.

Policy B is permissive-default prose that constrains **user roles only**, deployed under
``default_effect=ALLOW`` so every deny in its matrix is a load-bearing explicit ``DENY``. The
``devops → issues-*`` = ✅ cells are the signature that ``default=ALLOW`` is live (they are **deny**
under Policy A). Source of truth: ``aiac/docs/handoffs/02-policy-b-deny-full-deployment.md`` §5-§7.1.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))

from test.integration import scenario_uc1 as scn  # noqa: E402
from test.integration import scenario_uc1_denyworld as scn_b  # noqa: E402


# ======================================================================================
# §6 matrix — the oracle contract (pin the intended tables directly)
# ======================================================================================


@pytest.mark.parametrize(
    "subject, allowed",
    [("dev-user", True), ("test-user", True), ("devops-user", True)],
)
def test_inbound_oracle(subject: str, allowed: bool) -> None:
    """Inbound (§6): all three roles ✅. Policy B emits no inbound denies, so under
    ``default=ALLOW`` every subject reaches the agent — including devops (deny under Policy A)."""
    assert scn_b.expected_inbound_denyworld(subject) is allowed


@pytest.mark.parametrize(
    "subject, tool_bare, allowed",
    [
        # developer → source ✅✅ / issues ❌❌ (exclusivity)
        ("dev-user", "source-read", True),
        ("dev-user", "source-write", True),
        ("dev-user", "issues-read", False),
        ("dev-user", "issues-write", False),
        # tester → source ❌❌ / issues ✅✅ (exclusivity)
        ("test-user", "source-read", False),
        ("test-user", "source-write", False),
        ("test-user", "issues-read", True),
        ("test-user", "issues-write", True),
        # devops → source ❌❌ (direct prohibition) / issues ✅✅ (permissive default — the
        # default-flip tracer; these two cells are DENY under Policy A)
        ("devops-user", "source-read", False),
        ("devops-user", "source-write", False),
        ("devops-user", "issues-read", True),
        ("devops-user", "issues-write", True),
    ],
)
def test_outbound_oracle(subject: str, tool_bare: str, allowed: bool) -> None:
    """The full user→tool outbound matrix over the **bare** tool names (§6). Every ❌ is a
    load-bearing explicit DENY overriding the permissive default; the ``devops → issues-*`` ✅ cells
    prove ``default=ALLOW`` is live (they are deny under Policy A)."""
    assert scn_b.expected_outbound_denyworld_bare(subject, tool_bare) is allowed


# ======================================================================================
# Internal consistency — one source of truth (the prefixed deny pair-lists)
# ======================================================================================


def test_no_inbound_or_target_denies() -> None:
    """Policy B's prose constrains user roles only and phrases no agent-access prohibition, so the
    PRB emits no inbound denies and no target/capability-gate denies (§6, §7.1)."""
    assert scn_b.INBOUND_SUBJECT_DENY_PAIRS == []
    assert scn_b.OUTBOUND_TARGET_DENY_PAIRS == []


def test_outbound_subject_deny_pairs_are_the_six_expected() -> None:
    """The subject-gate DENY pair-list is exactly the six prefixed (role, tool-scope) entries from
    §6: developer→issues-*, tester→source-*, devops→source-*."""
    assert set(scn_b.OUTBOUND_SUBJECT_DENY_PAIRS) == {
        ("developer", "github-tool.issues-read"),
        ("developer", "github-tool.issues-write"),
        ("tester", "github-tool.source-read"),
        ("tester", "github-tool.source-write"),
        ("devops", "github-tool.source-read"),
        ("devops", "github-tool.source-write"),
    }
    assert len(scn_b.OUTBOUND_SUBJECT_DENY_PAIRS) == 6


def test_bare_deny_set_is_derived_from_the_prefixed_pairs_via_shared_bare() -> None:
    """The bare-name deny set is derived from the prefixed pair-list via the shared ``bare()`` (one
    source of truth), so it matches the prefixed truth de-prefixed on the first ``.``."""
    assert scn_b.OUTBOUND_SUBJECT_DENY_BARE == {
        (role, scn.bare(scope)) for role, scope in scn_b.OUTBOUND_SUBJECT_DENY_PAIRS
    }
    assert scn_b.OUTBOUND_SUBJECT_DENY_BARE == {
        ("developer", "issues-read"),
        ("developer", "issues-write"),
        ("tester", "source-read"),
        ("tester", "source-write"),
        ("devops", "source-read"),
        ("devops", "source-write"),
    }


def test_deny_pairs_reference_only_known_roles_and_tool_scopes() -> None:
    """Every deny pair keys on a provisioned realm role and a discovered, prefixed tool scope reused
    from ``scenario_uc1`` — guarding against a typo forking the shared deployment truth."""
    for role, scope in scn_b.OUTBOUND_SUBJECT_DENY_PAIRS:
        assert role in scn.USER_ROLES, role
        assert scope in scn.TOOL_SCOPES, scope


def test_reuses_deployment_fixed_constants_from_scenario_uc1() -> None:
    """Policy B is a sibling scenario on the **same** deployed workloads, so it reuses (does not
    redefine) the deployment-fixed constants from ``scenario_uc1``."""
    assert scn_b.USERS is scn.USERS
    assert scn_b.TOOL_SCOPES is scn.TOOL_SCOPES
    assert scn_b.bare is scn.bare
