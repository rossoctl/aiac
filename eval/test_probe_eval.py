"""Offline tests of ``probe_eval.rego``, the generalized tool-call probe of
``test_policy_pipeline_eval.py`` (spec: ``docs/evaluation/policy-eval-scenarios.md``).

The probe reads the inbound package of the callee that the writer renders
(``aiac.pdp.service.policy.opa.rego.render_target_side``). These tests render a real tool inbound
from a small tool SPM and evaluate the probe against it with ``opa eval``, so a change of the
rendered shape that the probe does not follow fails here, and not only in the live eval lane. The
parity test also evaluates the deployed gate (``authbridge.client.inbound.request.allow``) on each
cell: the probe must give the same decision, deny gates included, with only the soft match of the
name added.

Unmarked: an offline test of an eval harness helper runs in the unit lane
(``docs/testing/testing-strategy.md``). Skips cleanly when ``opa`` is not on PATH.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from aiac.idp.configuration.models import Role, RoleKind, Scope, ServiceType
from aiac.pdp.service.policy.opa.rego import render_target_side
from aiac.policy.model.models import PolicyRule, RuleEffect, ServicePolicyModel
from eval.test_policy_pipeline_eval import reformat_function_name

pytestmark = pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")

PROBE = Path(__file__).resolve().parent / "probe_eval.rego"
QUERY = "data.probe.inbound_eval.allow"
REAL_QUERY = "data.authbridge.client.inbound.request.allow"

# The eval scenarios give each service its scenario id as clientId (the serviceId of its scopes).
REPO_TOOL = "team1/repo-tool"
TRACKER_TOOL = "team1/tracker-tool"
AGENT = "team1/repo-agent"
UNKNOWN_AGENT = "team1/unknown-agent"


def _user_role(name: str, *users: str) -> Role:
    return Role(id=f"role-{name}", name=name, composite=False, kind=RoleKind.USER, actorIds=list(users))


def _agent_role(name: str, *clients: str) -> Role:
    return Role(id=f"role-{name}", name=name, composite=False, kind=RoleKind.AGENT, actorIds=list(clients))


def _scope(name: str, service_id: str) -> Scope:
    return Scope(id=f"scope-{service_id}-{name}", name=name, serviceId=service_id)


def _allow(role: Role, scope: Scope) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=RuleEffect.ALLOW)


def _deny(role: Role, scope: Scope) -> PolicyRule:
    return PolicyRule(role=role, scope=scope, effect=RuleEffect.DENY)


def _tool_inbound(tmp_path: Path, spm: ServicePolicyModel) -> Path:
    """Write the tool inbound package of ``spm``, as the writer renders it, to a file."""
    path = tmp_path / spm.service_id.replace("/", "_") / "inbound.rego"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_target_side(spm).inbound)
    return path


def _tool_spm(
    service_id: str, scopes: list[Scope], allow: list[PolicyRule], deny: list[PolicyRule]
) -> ServicePolicyModel:
    return ServicePolicyModel(
        service_id=service_id,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=scopes,
        inbound_allow_rules=allow,
        inbound_deny_rules=deny,
    )


def _grant_regos(tmp_path: Path) -> dict[str, Path]:
    """alice (``user-role-developer``) is granted ``tool-scope-read`` on repo-tool only. tracker-tool
    has a different scope with the same name. The agent may call both tools."""
    developer = _user_role("user-role-developer", "alice")
    agent_role = _agent_role("agent-role-repo", AGENT)
    on_repo = _scope("tool-scope-read", REPO_TOOL)
    on_tracker = _scope("tool-scope-read", TRACKER_TOOL)
    return {
        REPO_TOOL: _tool_inbound(
            tmp_path, _tool_spm(REPO_TOOL, [on_repo], [_allow(developer, on_repo), _allow(agent_role, on_repo)], [])
        ),
        TRACKER_TOOL: _tool_inbound(
            tmp_path, _tool_spm(TRACKER_TOOL, [on_tracker], [_allow(agent_role, on_tracker)], [])
        ),
    }


def _deny_regos(tmp_path: Path) -> dict[str, Path]:
    """Grants and denies that the real gate combines (deny-overrides).

    * alice holds ``user-role-developer`` and ``user-role-tester``. The tester role is granted
      ``tool-scope-write`` on repo-tool, and the developer role is denied it there: the deny of one
      role of the subject blocks the grant of another role.
    * carol holds only ``user-role-tester``, so the same grant admits her.
    * Both user roles are granted ``tool-scope-read`` on repo-tool. The agent holds
      ``agent-role-repo``, which is granted ``tool-scope-read`` and ``tool-scope-write`` there, and
      ``agent-role-restricted``, which is denied ``tool-scope-read`` there: the calling-agent deny
      blocks every subject's grant.
    * tracker-tool has its own ``tool-scope-write``: the developer deny on repo-tool decides nothing
      on it.
    """
    developer = _user_role("user-role-developer", "alice")
    tester = _user_role("user-role-tester", "alice", "carol")
    agent_role = _agent_role("agent-role-repo", AGENT)
    restricted = _agent_role("agent-role-restricted", AGENT)
    repo_read = _scope("tool-scope-read", REPO_TOOL)
    repo_write = _scope("tool-scope-write", REPO_TOOL)
    tracker_write = _scope("tool-scope-write", TRACKER_TOOL)
    repo = _tool_spm(
        REPO_TOOL,
        [repo_read, repo_write],
        [
            _allow(tester, repo_write),
            _allow(developer, repo_read),
            _allow(tester, repo_read),
            _allow(agent_role, repo_read),
            _allow(agent_role, repo_write),
        ],
        [_deny(developer, repo_write), _deny(restricted, repo_read)],
    )
    tracker = _tool_spm(
        TRACKER_TOOL, [tracker_write], [_allow(tester, tracker_write), _allow(agent_role, tracker_write)], []
    )
    return {REPO_TOOL: _tool_inbound(tmp_path, repo), TRACKER_TOOL: _tool_inbound(tmp_path, tracker)}


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


def _probe(rego: Path, subject: str, function_name: str, client_id: str = AGENT) -> bool:
    return _opa_eval([rego, PROBE], QUERY, {"subject": subject, "client_id": client_id, "function_name": function_name})


def _real_gate(rego: Path, subject: str, client_id: str, tool: str) -> bool:
    """The deployed tool inbound decision for a ``tools/call`` of ``tool`` (the exact bare name)."""
    return _opa_eval(
        [rego],
        REAL_QUERY,
        {
            "identity": {"subject": subject, "client_id": client_id},
            "mcp": {"method": "tools/call", "params": {"name": tool}},
        },
    )


def test_probe_compiles_against_the_rendered_tool_inbound(tmp_path: Path) -> None:
    rego = _grant_regos(tmp_path)[REPO_TOOL]
    subprocess.run(
        [shutil.which("opa"), "check", "--strict", str(rego), str(PROBE)], capture_output=True, text=True, check=True
    )


def test_probe_allows_a_tool_granted_on_its_tool(tmp_path: Path) -> None:
    """The soft match (``Tool.Scope.Read``) reaches the grant on the tool that has it."""
    assert _probe(_grant_regos(tmp_path)[REPO_TOOL], "alice", "Tool.Scope.Read") is True


def test_probe_denies_a_tool_granted_on_another_tool_only(tmp_path: Path) -> None:
    """The grant on repo-tool decides nothing on tracker-tool, which has a tool of the same name."""
    assert _probe(_grant_regos(tmp_path)[TRACKER_TOOL], "alice", "Tool.Scope.Read") is False


def test_probe_denies_a_subject_with_no_role(tmp_path: Path) -> None:
    assert _probe(_grant_regos(tmp_path)[REPO_TOOL], "mallory", "Tool.Scope.Read") is False


def test_probe_denies_a_caller_with_no_role(tmp_path: Path) -> None:
    """The calling-agent gate is mandatory: a grant to the subject does not admit an unknown caller."""
    assert _probe(_grant_regos(tmp_path)[REPO_TOOL], "alice", "Tool.Scope.Read", client_id=UNKNOWN_AGENT) is False


def test_probe_denies_a_tool_that_another_role_of_the_subject_denies(tmp_path: Path) -> None:
    """The real gate requires ``not subject_denies``: a deny of one role blocks a grant of another."""
    rego = _deny_regos(tmp_path)[REPO_TOOL]
    assert _probe(rego, "alice", "Tool.Scope.Write") is False
    assert _probe(rego, "carol", "Tool.Scope.Write") is True


def test_probe_applies_a_subject_deny_only_on_the_tool_that_has_it(tmp_path: Path) -> None:
    assert _probe(_deny_regos(tmp_path)[TRACKER_TOOL], "alice", "Tool.Scope.Write") is True


def test_probe_denies_a_tool_that_the_calling_agent_is_denied(tmp_path: Path) -> None:
    """The real gate requires ``not source_denies``: a deny of one role of the caller blocks every
    subject's grant."""
    rego = _deny_regos(tmp_path)[REPO_TOOL]
    assert _probe(rego, "alice", "Tool.Scope.Read") is False
    assert _probe(rego, "carol", "Tool.Scope.Read") is False


@pytest.mark.parametrize("tool_regos", [_grant_regos, _deny_regos])
def test_probe_decides_as_the_real_gate(tmp_path: Path, tool_regos) -> None:
    """On every (tool, subject, caller, tool name) cell, the probe with the eval's soft-match
    rendering of the tool name gives the decision of the deployed gate with the exact name."""
    regos = tool_regos(tmp_path)
    cells = [
        (target, subject, caller, tool)
        for target in (REPO_TOOL, TRACKER_TOOL)
        for subject in ("alice", "carol", "mallory")
        for caller in (AGENT, UNKNOWN_AGENT)
        for tool in ("tool-scope-read", "tool-scope-write")
    ]
    mismatches = []
    for target, subject, caller, tool in cells:
        real = _real_gate(regos[target], subject, caller, tool)
        probe = _probe(regos[target], subject, reformat_function_name(tool), client_id=caller)
        if real != probe:
            mismatches.append(((target, subject, caller, tool), real, probe))
    assert mismatches == []
