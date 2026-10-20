"""The order-agnostic CR compare of the UC-1 system harness (``uc1.cr_canonical``) — pure unit tests.

The system suites compare an AIAC CR with an earlier snapshot of it. The order of a scope or role
list, and of map keys, has no meaning in the rendered Rego, and the renderer keeps the order the IdP
returns. These tests pin that such an order is not a difference, and that a real change still is.
They render with the real ``rego._render_*`` helpers, so a format change of the renderer shows here.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent  # test/unit/agent/uc/onboarding/
REPO_ROOT = HERE.parents[4]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from aiac.pdp.service.policy.opa.rego import _render_list, _render_map  # noqa: E402
from test.system import uc1_onboard as uc1  # noqa: E402

_RULES = "default allow := false\nallow if { some scope in agent_scopes; scope == input.scope }\n"


def _package(*bindings: str) -> str:
    return "package authbridge.client.inbound.request\nimport rego.v1\n\n" + "\n".join(bindings) + "\n" + _RULES


def test_list_order_is_not_a_change() -> None:
    a = _package(_render_list("agent_scopes", ["github-agent.source_operations", "github-agent.issue_operations"]))
    b = _package(_render_list("agent_scopes", ["github-agent.issue_operations", "github-agent.source_operations"]))
    assert a != b
    assert uc1.cr_canonical({"inbound/request.rego": a}) == uc1.cr_canonical({"inbound/request.rego": b})


def test_map_key_and_value_order_is_not_a_change() -> None:
    a = _package(_render_map("subject_roles", {"dev-user": ["developer", "tester"], "test-user": ["tester"]}))
    b = _package(_render_map("subject_roles", {"test-user": ["tester"], "dev-user": ["tester", "developer"]}))
    assert uc1.rego_canonical(a) == uc1.rego_canonical(b)


def test_a_different_item_is_a_change() -> None:
    a = _package(_render_list("agent_scopes", ["github-agent.source_operations"]))
    b = _package(_render_list("agent_scopes", ["github-agent.issue_operations"]))
    assert uc1.rego_canonical(a) != uc1.rego_canonical(b)


def test_a_different_rule_is_a_change() -> None:
    binding = _render_list("agent_scopes", ["s1"])
    a = _package(binding)
    b = _package(binding).replace("default allow := false", "default allow := true")
    assert uc1.rego_canonical(a) != uc1.rego_canonical(b)


def test_empty_bindings_and_pass_through_stay_as_they_are() -> None:
    rego = _package(_render_list("agent_scopes", []), _render_map("source_roles", {}))
    pass_through = "package authbridge.client.outbound.request\nimport rego.v1\n\nallow := true\n"
    assert uc1.rego_canonical(rego) == rego.rstrip("\n")
    assert "agent_scopes := []" in uc1.rego_canonical(rego)
    assert uc1.rego_canonical(pass_through) == pass_through.rstrip("\n")


def test_a_comma_in_a_string_value_is_a_change() -> None:
    # Only the trailing comma of a map entry is removed, not a comma in a string.
    for render in (
        lambda v: _render_list("agent_scopes", [v]),
        lambda v: _render_map("subject_roles", {"dev-user": [v]}),
    ):
        assert uc1.rego_canonical(_package(render("p,]"))) != uc1.rego_canonical(_package(render("p]")))


def test_a_binding_that_is_not_json_stays_as_it_is() -> None:
    # A Rego set is not JSON: it is not sorted, so a format change of the renderer shows as a change.
    a = _package('session_methods := {"tools/list", "initialize"}')
    b = _package('session_methods := {"initialize", "tools/list"}')
    assert uc1.rego_canonical(a) == a.rstrip("\n")
    assert uc1.rego_canonical(a) != uc1.rego_canonical(b)


def test_no_cr_stays_none() -> None:
    assert uc1.cr_canonical(None) is None
