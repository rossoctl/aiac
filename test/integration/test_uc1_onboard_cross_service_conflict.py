"""Cross-service conflict integration test (#2504) — the live-cluster twin of the deterministic
cross-service unit/regression tests.

The deterministic suite proves the #2504 machinery in isolation (``applied_rules_for_scopes`` reads
the OTHER services' already-applied rules from the Policy Store, the builder unions them with its own
and runs the #2502 detector, and a cross-service overlap raises ``PolicyConflictError`` **before**
``compute_and_apply``). This test closes the loop end-to-end against the **real in-cluster UC-1
Controller**: it drives two onboardings whose derived rules genuinely collide **across services**,
and asserts the second ``POST /apply/service/{id}`` is refused with **HTTP 422 whose body is a
``ConflictReport``** — the same boundary shape the deterministic ``routes`` test pins.

Why the conflict is caught at ONBOARDING, before OPA. A cross-service conflict short-circuits inside
``ServicePolicyBuilder.build`` — the atomicity guarantee (ADR 0001): the builder raises before the
Orchestrator/Controller reach the PCE, so **no ``AuthorizationPolicy`` CR is ever upserted** and the
conflicting policy never reaches the deployed OPA plugin. The "OPA loop" here is therefore exercised
only to the extent that this is the *same live pipeline / same Controller* the OPA-loop rungs drive
(``uc1_onboard`` harness) — the assertion is the pre-apply 422, which is precisely the observable
proof that a conflict leaves the enforced OPA state untouched.

How the two onboardings collide **across services** (the #2504 store read is the load-bearing seam):

  * **Phase 1 — onboard the TOOL under an exclusivity policy** ("testers may access only issues; they
    may not access source"). The tool's Door B deny pass emits ``DENY (tester -> github-tool.source-*)``
    and the PCE persists it as an **inbound deny edge on ``SPM(github-tool)``** — the service that owns
    those scopes. Tool onboarding itself is clean (its own scope-focal grants and Door B denies are
    disjoint), so it returns 200 and the deny is now **applied state**.
  * **Phase 2 — onboard the AGENT under a policy that GRANTS testers source** ("testers may read and
    write source"). The agent's outbound *subject* gate derives ``ALLOW (tester -> github-tool.source-*)``
    — a ``(user role -> tool scope)`` rule routed onto the **same** ``SPM(github-tool)``, on the **same**
    ``(role.id, scope.id)`` the tool already denied. The agent's own build carries no deny (the policy
    states no prohibition), so this is invisible within the agent's rules alone. #2504's
    ``applied_rules_for_scopes`` reads ``SPM(github-tool)``'s already-applied inbound deny, the builder
    unions it with the fresh allow, and the #2502 detector surfaces the overlap -> ``PolicyConflictError``
    -> the Controller maps it to **422 + ``ConflictReport``**.

The store is cleared **once** before phase 1 and NOT between the phases — the whole point is that the
agent's build sees the tool's already-persisted rule (append-only, ``override=False``). This is why the
flow composes the harness primitives directly instead of ``uc1.onboarded_stack`` (which clears the
store on entry).

The exact ``(role, scope)`` the LLM-driven PRB lands on depends on live provisioning, so the assertion
is **structural**: HTTP 422, ``status == conflicts_found``, at least one conflict carrying a real role
and scope and the ``ConflictReport`` quote fields — not a hardcoded id (which would make the test
brittle against the live role/scope universe). That is enough to prove the cross-service overlap was
surfaced through the real pipeline in the shared ``ConflictReport`` shape.

Run (needs a live rossoctl/Kind cluster with the AuthBridge OPA pipeline wired in — see
``k8s/opa-kind-runbook.md`` / ``k8s/opa-kind-enable.sh`` — the demo workloads deployed + registered
into ``AIAC_TEST_REALM``, a real LLM in-pod, and ``test/integration/.env`` sourced). It also drives the
real PRB LLM, so it is marked both ``integration`` and ``llm``:

    .venv/bin/pytest test/integration/test_uc1_onboard_cross_service_conflict.py -m integration -v

Without ``-m integration`` the suite is not collected; without a wired cluster / env it skips cleanly.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import requests

# ``integration`` so ``-m "not integration"`` deselects it (no external services in the routine run);
# ``llm`` because phase 2 drives the real PRB LLM end-to-end, so it can also be selected on its own.
pytestmark = [pytest.mark.integration, pytest.mark.llm]

HERE = Path(__file__).resolve().parent  # test/integration/
REPO_ROOT = HERE.parents[1]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.integration.*`` resolves

from test.integration import scenario_uc1 as scn  # noqa: E402
from test.integration import uc1_onboard as uc1  # noqa: E402

TEST_REALM = uc1.TEST_REALM
NAMESPACE = uc1.NAMESPACE


# --- The two colliding policies (mounted one at a time, like the denyworld harness) ----------
#
# Phase 1: the tool's exclusivity deny — "only issues" prohibits testers from source, so the tool's
# Door B pass emits DENY(tester -> github-tool.source-*), persisted on SPM(github-tool).
POLICY_TOOL_EXCLUSIVE = """\
Grant access narrowly and state the exclusive scoping that constrains it.

- Testers may access only issues; they may not access source.
"""

# Phase 2: the agent grants testers source — the outbound subject gate derives
# ALLOW(tester -> github-tool.source-*) on the SAME tool scopes the tool already denied. This
# directly contradicts the tool's phase-1 applied deny (the cross-service overlap #2504 surfaces).
POLICY_AGENT_GRANTS_SOURCE = """\
Grant access on the basis of what each role does.

- Testers may read and write source.
"""


def _onboard_expect_conflict(base_url: str, service_id: str) -> dict:
    """``POST /apply/service/{service_id}`` and assert it is refused with HTTP 422 whose body is a
    ``ConflictReport``; return the parsed body. The cross-service twin of ``uc1.onboard`` (which asserts
    200): here the agent's fresh allow collides with the tool's already-applied deny, so the build must
    raise ``PolicyConflictError`` and the Controller must map it to 422 — never 200 (which would mean the
    conflict slipped through and a CR was upserted), never 500 (an unhandled error)."""
    resp = requests.post(f"{base_url}/apply/service/{service_id}", timeout=uc1.ONBOARD_TIMEOUT)
    assert resp.status_code == 422, (
        f"cross-service onboard of {service_id!r}: expected HTTP 422 (conflict surfaced before apply), "
        f"got {resp.status_code} — {resp.text[:800]}"
    )
    return resp.json()


def _onboard_via_fresh_controller(policy_md: str, workload: str, *, expect_conflict: bool) -> dict | None:
    """Mount ``policy_md`` on the Controller (rolling it so the PRB reads the new prose), then onboard
    ``workload`` against the freshly-resolved live Controller pod.

    Each phase re-mounts the policy and re-resolves the Controller pod because ``ensure_agent_policy``
    rolls the Deployment on a prose change: binding the port-forward to the current live pod (not the
    Service, which can still route to a lingering ``Terminating`` pod) avoids dropping the long onboard
    POST mid-flight — the same rationale as ``uc1.resolve_controller_pod``. Returns the parsed 422
    ``ConflictReport`` body when ``expect_conflict`` (else ``None`` after asserting a clean 200)."""
    uc1.ensure_agent_policy(uc1.CONTROLLER_NAMESPACE, policy_md=policy_md)
    service_id = uc1.resolve_service_id(uc1.connect_admin(), TEST_REALM, f"{NAMESPACE}/{workload}")
    controller_target = (
        uc1.CONTROLLER_TARGET
        if os.environ.get("AIAC_CONTROLLER_TARGET")
        else f"pod/{uc1.resolve_controller_pod()}"
    )
    with uc1.port_forward(
        controller_target,
        namespace=uc1.CONTROLLER_NAMESPACE,
        local_port=uc1.CONTROLLER_LOCAL_PORT,
        remote_port=uc1.CONTROLLER_REMOTE_PORT,
        ready_url=f"http://127.0.0.1:{uc1.CONTROLLER_LOCAL_PORT}/health",
    ) as base_url:
        if expect_conflict:
            return _onboard_expect_conflict(base_url, service_id)
        uc1.onboard(base_url, service_id)  # phase 1 must be clean (asserts 200)
        return None


# This live scenario is under revision and NOT yet confirmed to fire the 422 on a live cluster (see the
# PR description and the follow-ups it references). It also drives the real PRB LLM in phase 2, so the
# exact derived rule is model-dependent. ``xfail`` (non-strict) keeps a live run from false-greening
# while the scenario is being validated, and reports XPASS the moment it does fire — the signal to drop
# this marker. It stays deselected from the routine ``-m "not integration"`` run regardless.
@pytest.mark.xfail(strict=False, reason="live cross-service scenario under revision; not yet confirmed to fire 422")
def test_cross_service_conflict_is_surfaced_as_422_conflict_report() -> None:
    """End-to-end #2504: onboard the tool under an exclusivity policy (persisting a tool-side deny),
    then onboard the agent under a policy that grants the same testers source — the agent's outbound
    subject allow collides across services with the tool's already-applied deny. The real Controller
    must refuse the second onboarding with 422 + a ``ConflictReport``, and the atomicity guarantee holds
    (the conflicting policy never reaches OPA — no CR is upserted on the raising path).

    Skips cleanly (never false-passes) when the pipeline is not wired or the integration env is unset.
    The store is cleared once up front and NOT between phases, so the agent's build genuinely reads the
    tool's persisted rule (the #2504 seam under test)."""
    # Skip gates first — before any cluster mutation (acceptance: skip, never false-pass).
    uc1.require_pipeline(namespace=NAMESPACE, workloads=[scn.AGENT_WORKLOAD, scn.TOOL_WORKLOAD])
    creds = uc1.require_env_or_skip("KEYCLOAK_URL", "KEYCLOAK_ADMIN_USERNAME", "KEYCLOAK_ADMIN_PASSWORD")
    keycloak_url = creds["KEYCLOAK_URL"]

    admin = uc1.connect_admin()
    # Open the cleanup guard BEFORE the first shared-state mutation: the clean-slate steps below
    # (Agent CR delete, Keycloak cleanup, Policy Store clear, provisioning) already mutate shared
    # cluster state, so a failure mid-setup must still hit the ``finally`` teardown.
    try:
        uc1.delete_agent_cr()  # clean policy slate (drop any prior run's CR)
        uc1.cleanup_provisioned(admin, TEST_REALM)  # clean slate (Keycloak)
        uc1.clear_policy_store()  # clean slate ONCE — NOT between phases (the agent must see the tool's rule)
        uc1.provision_realm_and_users(admin, TEST_REALM)  # PRB reads the role universe
        uc1.verify_subject_mapper(
            keycloak_url=keycloak_url, realm=TEST_REALM, user="test-user", password=scn.USER_PASSWORD
        )

        # Phase 1 — tool onboarding under the exclusivity policy: clean (200), persists the tool-side
        # DENY(tester -> github-tool.source-*) on SPM(github-tool).
        _onboard_via_fresh_controller(POLICY_TOOL_EXCLUSIVE, scn.TOOL_WORKLOAD, expect_conflict=False)

        # Phase 2 — agent onboarding under the source-granting policy: the outbound subject gate's fresh
        # ALLOW(tester -> github-tool.source-*) collides with the tool's already-applied DENY on the same
        # (role, scope). The #2504 store read surfaces it -> 422 + ConflictReport.
        report = _onboard_via_fresh_controller(
            POLICY_AGENT_GRANTS_SOURCE, scn.AGENT_WORKLOAD, expect_conflict=True
        )
    finally:
        uc1.delete_agent_cr()  # after — drop any CR (there should be none on the raising path)
        uc1.cleanup_provisioned(admin, TEST_REALM)  # restore the pre-run Keycloak state
        # Phase 1 persisted a tool-side deny; clear it so later integration tests don't read stale
        # inbound rules and become order-dependent.
        uc1.clear_policy_store()

    # The 422 body is the shared ConflictReport shape (same as the deterministic routes test), carrying
    # at least one cross-service conflict with a real role + scope. Structural (not id-pinned) so it is
    # robust against the live role/scope universe.
    assert report is not None
    assert report["status"] == "conflicts_found", report
    assert report["conflicts"], f"expected >=1 surfaced conflict, got: {report}"
    c = report["conflicts"][0]
    assert c["role"]["id"] and c["role"]["name"], c
    assert c["scope"]["id"] and c["scope"]["name"], c
    # The report always carries the enrichment quote fields (possibly empty / unverified), proving the
    # boundary emitted the full ConflictReport, not a bare {"detail": ...}.
    assert "granting_quotes" in c and "prohibiting_quotes" in c and "quotes_verified" in c, c
