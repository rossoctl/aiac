"""Offline tests of ``probe_eval.rego``, the generalized outbound probe of
``test_policy_pipeline_eval.py`` (spec: ``docs/evaluation/policy-eval-scenarios.md``).

The probe reads the agent outbound package that the writer renders
(``aiac.pdp.service.policy.opa.rego.generate_outbound_rego``). These tests render a real package
from a small APM and evaluate the probe against it with ``opa eval``, so a change of the rendered
shape that the probe does not follow fails here, and not only in the live eval lane. The parity
test also evaluates the deployed gate (``authbridge.client.outbound.request.allow``) on each cell:
the probe must give the same decision, deny gates included, with only the soft match of the name
added.

Unmarked: an offline test of an eval harness helper runs in the unit lane
(``docs/testing/testing-strategy.md``). Skips cleanly when ``opa`` is not on PATH.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from aiac.idp.configuration.models import Role, RoleKind, Scope
from aiac.pdp.service.policy.opa.rego import generate_outbound_rego
from aiac.policy.model.models import AgentPolicyModel, PolicyRule, RuleEffect
from eval.test_policy_pipeline_eval import reformat_function_name

pytestmark = pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")

PROBE = Path(__file__).resolve().parent / "probe_eval.rego"
QUERY = "data.probe.outbound_eval.allow"
REAL_QUERY = "data.authbridge.client.outbound.request.allow"

# The eval scenarios key a target by its scenario id (``_scope_owner``), the serviceId of its scopes.
REPO_TOOL = "repo-tool"
TRACKER_TOOL = "tracker-tool"


def _user_role(name: str, *users: str) -> Role:
    return Role(id=f"role-{name}", name=name, composite=False, kind=RoleKind.USER, actorIds=list(users))


def _scope(name: str, service_id: str) -> Scope:
    return Scope(id=f"scope-{service_id}-{name}", name=name, serviceId=service_id)


def _outbound_rego(tmp_path: Path) -> Path:
    """alice (``user-role-developer``) is granted ``tool-scope-read`` on repo-tool only. tracker-tool
    has a different scope with the same name, and the agent may call both tools (LIM-02)."""
    developer = _user_role("user-role-developer", "alice")
    on_repo = _scope("tool-scope-read", REPO_TOOL)
    on_tracker = _scope("tool-scope-read", TRACKER_TOOL)
    apm = AgentPolicyModel(
        agent_id="team1/repo-agent",
        agent_roles=[],
        agent_scopes=[],
        source_roles={},
        subject_roles={"alice": [developer]},
        target_allow_scopes={REPO_TOOL: [on_repo], TRACKER_TOOL: [on_tracker]},
        outbound_subject_allow_rules=[PolicyRule(role=developer, scope=on_repo, effect=RuleEffect.ALLOW)],
    )
    path = tmp_path / "outbound.rego"
    path.write_text(generate_outbound_rego(apm))
    return path


def _opa_eval(paths: list[Path], query: str, input_doc: dict) -> bool:
    data = [arg for path in paths for arg in ("-d", str(path))]
    out = subprocess.run(
        [shutil.which("opa"), "eval", "-f", "json", *data, "--stdin-input", query],
        input=json.dumps(input_doc),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return json.loads(out)["result"][0]["expressions"][0]["value"]


def _probe(rego: Path, subject: str, target: str, function_name: str) -> bool:
    return _opa_eval([rego, PROBE], QUERY, {"subject": subject, "target": target, "function_name": function_name})


def _real_gate(rego: Path, subject: str, target: str, tool: str) -> bool:
    """The deployed outbound decision for a ``tools/call`` of ``tool`` (the exact bare name)."""
    return _opa_eval(
        [rego],
        REAL_QUERY,
        {
            "identity": {"subject": subject, "service_id": target},
            "mcp": {"method": "tools/call", "params": {"name": tool}},
        },
    )


def _deny_rego(tmp_path: Path) -> Path:
    """Grants and denies that the real gate combines (deny-overrides, LIM-02 keys).

    * alice holds ``user-role-developer`` and ``user-role-tester``. The tester role is granted
      ``tool-scope-write`` on repo-tool, and the developer role is denied it there: the deny of one
      role of the subject blocks the grant of another role.
    * carol holds only ``user-role-tester``, so the same grant admits her.
    * Both roles are granted ``tool-scope-read`` on repo-tool, and the target denies it there.
    * tracker-tool has its own ``tool-scope-write``: the developer deny on repo-tool decides nothing
      on it.
    """
    developer = _user_role("user-role-developer", "alice")
    tester = _user_role("user-role-tester", "alice", "carol")
    repo_read = _scope("tool-scope-read", REPO_TOOL)
    repo_write = _scope("tool-scope-write", REPO_TOOL)
    tracker_write = _scope("tool-scope-write", TRACKER_TOOL)
    apm = AgentPolicyModel(
        agent_id="team1/repo-agent",
        agent_roles=[],
        agent_scopes=[],
        source_roles={},
        subject_roles={"alice": [developer, tester], "carol": [tester]},
        target_allow_scopes={REPO_TOOL: [repo_read, repo_write], TRACKER_TOOL: [tracker_write]},
        target_deny_scopes={REPO_TOOL: [repo_read]},
        outbound_subject_allow_rules=[
            PolicyRule(role=tester, scope=repo_write, effect=RuleEffect.ALLOW),
            PolicyRule(role=tester, scope=tracker_write, effect=RuleEffect.ALLOW),
            PolicyRule(role=developer, scope=repo_read, effect=RuleEffect.ALLOW),
            PolicyRule(role=tester, scope=repo_read, effect=RuleEffect.ALLOW),
        ],
        outbound_subject_deny_rules=[PolicyRule(role=developer, scope=repo_write, effect=RuleEffect.DENY)],
    )
    path = tmp_path / "outbound-deny.rego"
    path.write_text(generate_outbound_rego(apm))
    return path


def test_probe_compiles_against_the_rendered_outbound(tmp_path: Path) -> None:
    rego = _outbound_rego(tmp_path)
    subprocess.run(
        [shutil.which("opa"), "check", "--strict", str(rego), str(PROBE)], capture_output=True, text=True, check=True
    )


def test_probe_allows_a_tool_granted_on_its_target(tmp_path: Path) -> None:
    """The soft match (``Tool.Scope.Read``) reaches the grant on the target that has it."""
    assert _probe(_outbound_rego(tmp_path), "alice", REPO_TOOL, "Tool.Scope.Read") is True


def test_probe_denies_a_tool_granted_on_another_target_only(tmp_path: Path) -> None:
    """The grant on repo-tool decides nothing on tracker-tool, which has a tool of the same name."""
    assert _probe(_outbound_rego(tmp_path), "alice", TRACKER_TOOL, "Tool.Scope.Read") is False


def test_probe_denies_a_subject_with_no_role(tmp_path: Path) -> None:
    assert _probe(_outbound_rego(tmp_path), "mallory", REPO_TOOL, "Tool.Scope.Read") is False


def test_probe_denies_a_tool_that_another_role_of_the_subject_denies_on_the_target(tmp_path: Path) -> None:
    """The real gate requires ``not subject_deny_ok``: a deny of one role blocks a grant of another."""
    rego = _deny_rego(tmp_path)
    assert _probe(rego, "alice", REPO_TOOL, "Tool.Scope.Write") is False
    assert _probe(rego, "carol", REPO_TOOL, "Tool.Scope.Write") is True


def test_probe_applies_a_subject_deny_only_on_the_target_that_it_is_keyed_by(tmp_path: Path) -> None:
    assert _probe(_deny_rego(tmp_path), "alice", TRACKER_TOOL, "Tool.Scope.Write") is True


def test_probe_denies_a_tool_that_the_target_denies(tmp_path: Path) -> None:
    """The real gate requires ``not target_deny_ok``: a target deny blocks every subject's grant."""
    rego = _deny_rego(tmp_path)
    assert _probe(rego, "alice", REPO_TOOL, "Tool.Scope.Read") is False
    assert _probe(rego, "carol", REPO_TOOL, "Tool.Scope.Read") is False


@pytest.mark.parametrize("apm_rego", [_outbound_rego, _deny_rego])
def test_probe_decides_as_the_real_gate(tmp_path: Path, apm_rego) -> None:
    """On every (subject, target, tool) cell, the probe with the eval's soft-match rendering of the
    tool name gives the decision of the deployed gate with the exact name."""
    rego = apm_rego(tmp_path)
    cells = [
        (subject, target, tool)
        for subject in ("alice", "carol", "mallory")
        for target in (REPO_TOOL, TRACKER_TOOL, "unknown-target")
        for tool in ("tool-scope-read", "tool-scope-write")
    ]
    mismatches = []
    for subject, target, tool in cells:
        real = _real_gate(rego, subject, target, tool)
        probe = _probe(rego, subject, target, reformat_function_name(tool))
        if real != probe:
            mismatches.append(((subject, target, tool), real, probe))
    assert mismatches == []
