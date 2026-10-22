"""The staged gates of the UC-1 system-test harness (handoff 03) — pure unit tests.

``onboarded_stack`` gates each workload on positive facts, in the order the platform makes them: the
operator registers the client, then rolls the Deployment to its final template (the ``rossoctl.io/type``
label, then the client-credentials annotation), then AIAC onboards it. A gate that ends on time only
(the old single gate) can pass on the first ReplicaSet's pod, which has no AuthBridge sidecar, and its
app answers the inbound probe with HTTP 200 (``allow``) before any onboarding.

These tests pin the pure deciders with no cluster: each takes the observed objects and returns ``None``
(the fact holds) or one reason that names what is missing.

They import the system harness like ``test_uc1_cr_capture.py`` does
(``from test.system import uc1_onboard``): that harness does **no** cluster I/O at import time.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent  # test/unit/agent/uc/onboarding/
REPO_ROOT = HERE.parents[4]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from test.system import uc1_onboard as uc1  # noqa: E402

# ======================================================================================
# final_rollout_reason — the operator's final template, fully rolled out, sidecar on every pod
# ======================================================================================

SECRET = "rossoctl-keycloak-client-credentials-0123abcd"


def _deployment(
    *,
    kind: str | None = "agent",
    secret: str | None = SECRET,
    generation: int = 3,
    observed: int = 3,
    replicas: int = 1,
    updated: int | None = 1,
    ready: int | None = 1,
    available: int | None = 1,
) -> dict:
    labels = {"app.kubernetes.io/name": "github-agent"}
    if kind is not None:
        labels["rossoctl.io/type"] = kind
    annotations = {"rossoctl.io/config-hash": "h"}
    if secret is not None:
        annotations["rossoctl.io/keycloak-client-credentials-secret-name"] = secret
    status = {"observedGeneration": observed, "replicas": ready}
    if updated is not None:
        status["updatedReplicas"] = updated
    if available is not None:
        status["availableReplicas"] = available
    if ready is None:
        del status["replicas"]
    return {
        "metadata": {"name": "github-agent", "generation": generation},
        "spec": {
            "replicas": replicas,
            "template": {"metadata": {"labels": labels, "annotations": annotations}},
        },
        "status": status,
    }


def _pod(name: str, *, sidecar: bool = True, terminating: bool = False) -> dict:
    containers = [{"name": "agent"}] + ([{"name": "authbridge-proxy"}] if sidecar else [])
    meta: dict = {"name": name}
    if terminating:
        meta["deletionTimestamp"] = "2026-10-22T00:00:00Z"
    return {"metadata": meta, "spec": {"containers": containers}}


def test_the_final_template_fully_rolled_out_with_the_sidecar_is_ready() -> None:
    assert uc1.final_rollout_reason(_deployment(), [_pod("github-agent-7565-a")], kind="agent") is None


def test_a_template_without_the_type_label_is_not_final() -> None:
    reason = uc1.final_rollout_reason(_deployment(kind=None), [_pod("p")], kind="agent")
    assert reason is not None and "rossoctl.io/type" in reason


def test_a_template_of_another_type_is_not_final() -> None:
    reason = uc1.final_rollout_reason(_deployment(kind="tool"), [_pod("p")], kind="agent")
    assert reason is not None and "rossoctl.io/type" in reason and "tool" in reason


def test_a_template_without_the_credentials_annotation_is_not_final() -> None:
    """The operator adds the annotation after it registered the client and wrote the Secret: it is the
    last template write, so before it the workload rolls once more."""
    reason = uc1.final_rollout_reason(_deployment(secret=None), [_pod("p")], kind="agent")
    assert reason is not None and "rossoctl.io/keycloak-client-credentials-secret-name" in reason


def test_a_generation_the_controller_has_not_observed_is_not_complete() -> None:
    reason = uc1.final_rollout_reason(_deployment(generation=4, observed=3), [_pod("p")], kind="agent")
    assert reason is not None and "observedGeneration" in reason


def test_a_rollout_with_old_or_unavailable_replicas_is_not_complete() -> None:
    for dep in (
        _deployment(updated=0),  # the new ReplicaSet has no pod yet
        _deployment(ready=2),  # an old ReplicaSet's pod is left
        _deployment(available=0),  # the new pod is not available
        _deployment(updated=None, available=None),  # the API omits zero counters
    ):
        reason = uc1.final_rollout_reason(dep, [_pod("p")], kind="agent")
        assert reason is not None and "rollout" in reason


def test_a_live_pod_without_the_sidecar_is_named() -> None:
    reason = uc1.final_rollout_reason(_deployment(), [_pod("github-agent-78cf-x", sidecar=False)], kind="agent")
    assert reason is not None and "github-agent-78cf-x" in reason and "authbridge-proxy" in reason


def test_a_terminating_pod_without_the_sidecar_does_not_count() -> None:
    pods = [_pod("github-agent-78cf-x", sidecar=False, terminating=True), _pod("github-agent-7565-a")]
    assert uc1.final_rollout_reason(_deployment(), pods, kind="agent") is None


def test_no_live_pod_is_not_ready() -> None:
    reason = uc1.final_rollout_reason(_deployment(), [_pod("old", terminating=True)], kind="agent")
    assert reason is not None and "no live pod" in reason


# ======================================================================================
# operator_identity / operator_change_note — a restart or a replacement of the rossoctl operator
# ======================================================================================


def _operator_pod(name: str = "rossoctl-controller-manager-7cdf-mbzld", *, uid: str = "u1", restarts: int = 5) -> dict:
    return {
        "metadata": {"name": name, "uid": uid},
        "status": {
            "containerStatuses": [
                {"name": "manager", "restartCount": restarts, "state": {"running": {"startedAt": "T1"}}}
            ]
        },
    }


def _lease(holder: str = "rossoctl-controller-manager-7cdf-mbzld_aaa", transitions: int = 7) -> dict:
    return {"spec": {"holderIdentity": holder, "leaseTransitions": transitions}}


def test_the_same_operator_gives_no_note() -> None:
    before = uc1.operator_identity([_operator_pod()], _lease())
    after = uc1.operator_identity([_operator_pod()], _lease())
    assert uc1.operator_change_note(before, after) is None


def test_a_container_restart_in_the_same_pod_is_noted() -> None:
    """A lost lease makes the manager exit: the kubelet restarts the container in the same pod."""
    before = uc1.operator_identity([_operator_pod(restarts=5)], _lease())
    after = uc1.operator_identity(
        [_operator_pod(restarts=6)], _lease(holder="rossoctl-controller-manager-7cdf-mbzld_bbb")
    )
    note = uc1.operator_change_note(before, after)
    assert note is not None and "restarted" in note and "5" in note and "6" in note


def test_a_new_pod_is_noted_although_its_restart_count_is_lower() -> None:
    """A deleted or evicted pod comes back as a new pod with restartCount 0."""
    before = uc1.operator_identity([_operator_pod(restarts=5)], _lease())
    after = uc1.operator_identity(
        [_operator_pod("rossoctl-controller-manager-7cdf-zzzzz", uid="u2", restarts=0)],
        _lease(holder="rossoctl-controller-manager-7cdf-zzzzz_ccc", transitions=8),
    )
    note = uc1.operator_change_note(before, after)
    assert note is not None and "rossoctl-controller-manager-7cdf-mbzld" in note and "zzzzz" in note


def test_a_lease_change_alone_is_noted() -> None:
    before = uc1.operator_identity([_operator_pod()], _lease())
    after = uc1.operator_identity([_operator_pod()], _lease(holder="other_ddd", transitions=8))
    assert uc1.operator_change_note(before, after) is not None


def test_no_operator_pod_now_is_noted() -> None:
    before = uc1.operator_identity([_operator_pod()], _lease())
    after = uc1.operator_identity([], None)
    note = uc1.operator_change_note(before, after)
    assert note is not None and "no operator pod" in note


# ======================================================================================
# agent_cr_content_problems / tool_cr_content_problems — the CR names this run's roles and scopes
# ======================================================================================
#
# Rendered with the real ``rego._render_*`` helpers (as ``test_uc1_cr_canonical.py`` does), so a format
# change of the renderer shows here.

from aiac.pdp.service.policy.opa.rego import _render_list, _render_map  # noqa: E402
from test.system import scenario_uc1 as scn  # noqa: E402

_RULES = "default allow := false\nallow if { true }\n"
_PASS = "package authbridge.client.outbound.request\nimport rego.v1\n\nallow := true\n"
_AGENT_CLIENT = "spiffe://localtest.me/ns/team1/sa/github-agent"


def _cr(*bindings: str) -> dict[str, str]:
    inbound = "package authbridge.client.inbound.request\nimport rego.v1\n\n" + "\n".join(bindings) + "\n" + _RULES
    return {uc1.CR_INBOUND_PATH: inbound, uc1.CR_OUTBOUND_PATH: _PASS}


def _agent_cr(scopes: list[str]) -> dict[str, str]:
    return _cr(_render_list("agent_scopes", scopes), _render_map("subject_role_allow_scopes", {"developer": scopes}))


def _tool_cr(owned: list[str], source_allow: dict[str, list[str]]) -> dict[str, str]:
    source_roles = {_AGENT_CLIENT: sorted(source_allow)} if source_allow else {}
    return _cr(
        _render_list("owned_tools", owned),
        _render_map("source_roles", source_roles),
        _render_map("source_role_allow_scopes", source_allow),
    )


_OWNED = [scn.bare(s) for s in scn.TOOL_SCOPES]


def test_rego_binding_value_reads_a_list_and_a_map() -> None:
    rego = _cr(_render_list("agent_scopes", ["a", "b"]), _render_map("source_roles", {"c": ["x", "y"]}))[
        uc1.CR_INBOUND_PATH
    ]
    assert uc1.rego_binding_value(rego, "agent_scopes") == ["a", "b"]
    assert uc1.rego_binding_value(rego, "source_roles") == {"c": ["x", "y"]}
    assert uc1.rego_binding_value(rego, "absent") is None


def test_the_agent_cr_with_the_per_skill_scopes_has_no_problem() -> None:
    assert uc1.agent_cr_content_problems(_agent_cr(list(scn.AGENT_SCOPES))) == []


def test_the_agent_cr_with_the_default_access_scope_names_it() -> None:
    """The analyze_agent fallback (no synced skills): the agent's only scope is <workload>.access."""
    problems = uc1.agent_cr_content_problems(_agent_cr(["github-agent.access"]))
    assert problems and any("github-agent.access" in p for p in problems)


def test_an_agent_cr_with_no_agent_scopes_binding_is_a_problem() -> None:
    problems = uc1.agent_cr_content_problems(_cr(_render_map("subject_role_allow_scopes", {})))
    assert problems and any("agent_scopes" in p for p in problems)


def test_no_agent_cr_is_a_problem() -> None:
    assert uc1.agent_cr_content_problems(None) == ["no CR"]


def test_the_tool_cr_with_the_agent_roles_has_no_problem() -> None:
    source = {"github-agent.source_operations": ["source-read"], "github-agent.issue_operations": ["issues-read"]}
    assert uc1.tool_cr_content_problems(_tool_cr(_OWNED, source)) == []


def test_a_tool_cr_with_some_agent_roles_has_no_problem() -> None:
    """The PRB chooses the edges, so one agent role is enough; the names must still be the agent's."""
    assert uc1.tool_cr_content_problems(_tool_cr(_OWNED, {"github-agent.source_operations": ["source-read"]})) == []


def test_a_tool_cr_with_no_calling_agent_role_is_a_problem() -> None:
    problems = uc1.tool_cr_content_problems(_tool_cr(_OWNED, {}))
    assert problems and any("source_role_allow_scopes" in p for p in problems)


def test_a_tool_cr_that_grants_the_default_access_role_names_it() -> None:
    problems = uc1.tool_cr_content_problems(_tool_cr(_OWNED, {"github-agent.access": ["source-read"]}))
    assert problems and any("github-agent.access" in p for p in problems)


def test_a_tool_cr_with_other_owned_tools_is_a_problem() -> None:
    source = {"github-agent.source_operations": ["source-read"]}
    problems = uc1.tool_cr_content_problems(_tool_cr(["source-read"], source))
    assert problems and any("owned_tools" in p for p in problems)


# ======================================================================================
# probe_hint — what a raw inbound answer means, from the AuthBridge reject bodies
# ======================================================================================

_OPA_NOT_READY = '{"error":"upstream.unreachable","message":"opa policy engine not initialized","plugin":"opa"}'
_OPA_DENY = '{"error":"policy.forbidden","message":"denied","plugin":"opa"}'


def test_a_503_from_an_opa_with_no_bundle_points_at_bundle_service() -> None:
    hint = uc1.probe_hint(503, _OPA_NOT_READY)
    assert "no bundle" in hint and "bundle-service" in hint


def test_an_opa_403_points_at_the_cr() -> None:
    assert "CR" in uc1.probe_hint(403, _OPA_DENY)


def test_a_403_that_is_not_from_opa_says_so() -> None:
    hint = uc1.probe_hint(403, "RBAC: access denied")
    assert "not from OPA" in hint


def test_no_answer_points_at_the_probe_pod_or_the_service() -> None:
    for code, body in ((None, "inbound probe pod failed: timeout"), (0, "")):
        assert "probe pod" in uc1.probe_hint(code, body)


def test_another_503_names_its_plugin() -> None:
    hint = uc1.probe_hint(
        503, '{"error":"upstream.unreachable","message":"jwt-validation not configured","plugin":"jwt-validation"}'
    )
    assert "jwt-validation" in hint


def test_a_200_has_no_hint() -> None:
    assert uc1.probe_hint(200, '{"jsonrpc":"2.0"}') == ""


# ======================================================================================
# signals_report — what the poll saw last, never a new probe
# ======================================================================================


def test_the_report_prints_the_last_observation_with_its_raw_answer_and_hint() -> None:
    sig = uc1.ReadySignal("inbound", "dev-user", "allow")
    last = {sig.label(): {"decision": "error", "code": 503, "body": _OPA_NOT_READY}}
    report = uc1.signals_report([sig], last)
    assert "inbound(dev-user)='error' (want 'allow')" in report
    assert "HTTP 503" in report and "no bundle" in report


def test_a_signal_the_poll_never_observed_says_so() -> None:
    sig = uc1.ReadySignal("inbound", "devops-user", "deny")
    report = uc1.signals_report([sig], {sig.label(): {"error": "HTTPError: 401"}})
    assert "inbound(devops-user)" in report and "not observed" in report and "401" in report


# ======================================================================================
# controller_onboarding_lines — the Controller's lines that say why an onboarding did not end
# ======================================================================================

_UUID = "7e1af22a-f83f-481a-ad37-3fd075d5ab2b"
_LOG = "\n".join(
    [
        "2026-10-21T23:40:00Z INFO:aiac.onboarding:onboarding started",
        f"2026-10-21T23:43:28Z INFO:aiac.agent.eventbus.consumer:nak'd aiac.apply.service.{_UUID} "
        "(AgentCardNotReadyError, delivery 4); redelivery in 30s",
        f"2026-10-21T23:44:26Z ERROR:aiac.agent.eventbus.consumer:moved aiac.apply.service.{_UUID} to "
        "aiac.apply.dlq (retryable failure after 5 deliveries)",
        "2026-10-21T23:44:27Z INFO:aiac.agent.eventbus.consumer:nak'd aiac.apply.service.other-uuid "
        "(WorkloadNotReadyError, delivery 1); redelivery in 30s",
    ]
)


def test_the_dead_letter_move_of_this_client_is_named() -> None:
    """The consumer's DLQ line has the stream subject in lower case (``aiac.apply.dlq``)."""
    lines = uc1.onboarding_lines(_LOG, service_uuid=_UUID)
    assert any("aiac.apply.dlq" in ln for ln in lines) and any("nak'd" in ln for ln in lines)


def test_the_lines_of_another_client_do_not_count() -> None:
    assert not any("other-uuid" in ln for ln in uc1.onboarding_lines(_LOG, service_uuid=_UUID))


def test_the_dead_letter_move_is_kept_when_there_are_many_naks() -> None:
    """The last line that matters most is the DLQ move: keep it even after many nak lines."""
    many = "\n".join(
        [f"INFO:aiac.agent.eventbus.consumer:nak'd aiac.apply.service.{_UUID} (x, delivery {n})" for n in range(9)]
        + [f"ERROR:aiac.agent.eventbus.consumer:moved aiac.apply.service.{_UUID} to aiac.apply.dlq (after 5)"]
    )
    lines = uc1.onboarding_lines(many, service_uuid=_UUID, keep=3)
    assert len(lines) == 3 and "aiac.apply.dlq" in lines[-1]
