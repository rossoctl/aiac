"""Rung 6 of the UC-1 onboarding ladder — a Controller restart: the resync and the no-CR deny.

Spec ``docs/testing/uc1-onboarding-pipeline.md`` (§ *Controller restart — the resync and the no-CR deny
(rung 6)*); decisions D20 and D28 of ``docs/handoffs/12-target-side-ac-and-method-switch.md``.

At each start the Controller reads the enforcement side, runs the start check #4 (the changed
combiner), and then runs the **resync** under the PCE lock, before it serves (D28): ``PUT /policy`` with
the full policy model of the live side — built from the stored SPM of every live service (in the IdP
catalog and not disabled) — then a teardown (quarantine) of each disabled service that still has an
SPM. The ``PUT`` also deletes each AIAC CR whose service is not in the model. The new Controller pod is
Ready only after that start sequence, so ``restart_controller`` returns after the resync ran.

The rung onboards github-agent and github-tool (``onboarded_stack([agent, tool])``, module-scoped, so the
stack is torn down when this module's tests end), and then runs three phases in order. Each phase
records what it observed and the tests assert on the record, so a failed phase reports its own facts
and the later phases report "not reached":

1. **Restart, no change.** Record ``aiac_crs()`` (every AIAC CR: name → ``spec.policies``) and the CR
   uids. Call ``restart_controller``. Assert: the same set of AIAC CRs, each with the same
   ``spec.policies`` and the same uid (updated in place or not at all — a delete and a new create would
   open a deny window under D20); and the convergence signals still hold (``dev-user`` inbound allow,
   ``devops-user`` inbound deny, ``dev-user`` outbound ``source-read`` allow).
2. **No CR, so deny (D20).** Delete github-tool's CR by hand. Poll until the ``dev-user``
   ``source-read`` call, which phase 1 allowed, is denied. github-tool now has no client CR, so the
   changed combiner denies the call on github-tool's inbound (HTTP 403 with an OPA body), under both
   sides — ``deny_origin`` must give github-tool's inbound.
3. **Restart, repair.** Call ``restart_controller`` again. The resync writes the missing CR from
   ``SPM(github-tool)``. Assert: github-tool's CR is back with the same ``spec.policies`` as in phase 1
   (and the whole AIAC CR set equals phase 1's), and the ``dev-user`` ``source-read`` call is allowed
   again.

Like every rung it skips cleanly before any cluster mutation when its infra is absent:
``onboarded_stack`` runs ``require_pipeline`` (including the changed-combiner gate),
``require_env_or_skip`` and ``require_event_path`` first. The rung restarts the Controller twice, so it
takes several minutes.

    .venv/bin/pytest -m system -k uc1_onboard_resync -v

Without ``-m system`` the suite is not collected; without a wired cluster / env it skips cleanly.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Iterator

import pytest

pytestmark = pytest.mark.system

HERE = Path(__file__).resolve().parent  # test/system/
REPO_ROOT = HERE.parents[1]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from test.system import scenario_uc1 as scn  # noqa: E402
from test.system import uc1_onboard as uc1  # noqa: E402

AGENT = scn.AGENT_WORKLOAD
TOOL = scn.TOOL_WORKLOAD
PROBE_USER = "dev-user"
PROBE_TOOL = "source-read"  # dev-user ✅ on the happy path (the outbound table), so a deny is a transition

# The convergence signals that must still hold after a restart with no change (phase 1).
HOLD_SIGNALS: tuple[uc1.ReadySignal, ...] = (
    uc1.ReadySignal("inbound", "dev-user", "allow"),
    uc1.ReadySignal("inbound", "devops-user", "deny"),
    uc1.ReadySignal("outbound", PROBE_USER, "allow", tool_bare=PROBE_TOOL),
)


# ======================================================================================
# Phase helpers — each one polls to a terminal state and returns what it saw (never asserts)
# ======================================================================================


def _snapshot() -> dict:
    """Every AIAC CR now: ``{"crs": {key: {path: rego}}, "uids": {key: uid}}``."""
    return {"crs": uc1.aiac_crs(), "uids": uc1.aiac_cr_uids()}


def _hold(ctx: dict) -> dict[str, str]:
    """Poll ``HOLD_SIGNALS`` until every one gives its expected verdict (this waits out a one-off probe
    failure, not a real change); return the last ``{label: decision}`` observed."""
    seen: dict[str, str] = {}

    def _all_hold() -> bool:
        seen.clear()
        for sig in HOLD_SIGNALS:
            seen[sig.label()] = sig.decide(ctx)
        return all(seen[sig.label()] == sig.expected for sig in HOLD_SIGNALS)

    uc1.poll_until(_all_hold, timeout=uc1.BUNDLE_TIMEOUT, interval=uc1.BUNDLE_POLL_INTERVAL)
    return dict(seen)


def _poll_probe(ctx: dict, want: str) -> dict:
    """Poll the ``dev-user`` × ``source-read`` call until its decision is ``want`` (a CR change takes
    effect at the next poll of the OPA sidecar, up to 120 s); return the last probe
    (``{"decision", "origin", "code", "body"}``, see ``uc1.outbound_deny_probe``)."""
    seen = {"probe": {"decision": "unobserved", "origin": None, "code": None, "body": ""}}

    def _reached() -> bool:
        seen["probe"] = uc1.outbound_deny_probe(ctx, PROBE_USER, PROBE_TOOL)
        return seen["probe"]["decision"] == want

    uc1.poll_until(_reached, timeout=uc1.BUNDLE_TIMEOUT, interval=uc1.BUNDLE_POLL_INTERVAL)
    return seen["probe"]


def _restart(run: dict, phase: int) -> bool:
    """``restart_controller``; on a rollout that does not complete, record why in ``run["stopped"]`` and
    return ``False``. A failed resync stops the Controller (the pod restarts and never gets Ready), so
    this is a product failure that the later phases' tests report, not a harness error."""
    try:
        uc1.restart_controller()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        run["stopped"] = (
            f"the Controller did not come back after the restart of phase {phase} within "
            f"{uc1.CONTROLLER_RESTART_TIMEOUT:.0f}s ({detail.strip()[:300]}) — a failed resync or start check "
            "stops the Controller; see its log"
        )
        return False
    return True


def _run_phases(ctx: dict, run: dict) -> None:
    """Drive the three phases (module docstring) in order on the onboarded stack, recording into
    ``run``. A missing precondition or a Controller that does not come back sets ``run["stopped"]`` and
    returns early; any other harness failure (a CR delete that fails) raises."""
    wanted = {uc1.cr_key(AGENT), uc1.cr_key(TOOL)}

    # --- Phase 1 — restart with no change -------------------------------------------------------
    before = _snapshot()
    run["before"] = before
    missing = sorted(wanted - set(before["crs"]))
    if missing:
        run["stopped"] = f"the onboarded stack has no AIAC CR for {missing} before the first restart (phase 1)"
        return
    if not _restart(run, 1):
        return
    run["restarted"] = {**_snapshot(), "signals": _hold(ctx)}

    # --- Phase 2 — delete github-tool's CR by hand: the combiner denies it (D20) ---------------
    uc1.delete_authpolicy(TOOL)
    run["no_cr"] = {"cr": uc1.authpolicy_policies(TOOL), "probe": _poll_probe(ctx, "deny")}

    # --- Phase 3 — restart again: the resync writes the missing CR -----------------------------
    if not _restart(run, 3):
        return
    probe = _poll_probe(ctx, "allow")  # the allow needs the CR loaded, so read the CRs after it
    run["repaired"] = {"crs": uc1.aiac_crs(), "probe": probe}


# ======================================================================================
# Module fixture — onboarded stack → the three phases → teardown to pristine
# ======================================================================================


@pytest.fixture(scope="module")
def run() -> Iterator[dict]:
    """Onboard the agent and then the tool (the full stack), run the three phases once, and yield what
    each observed. Module-scoped, so this rung's stack is torn down as soon as its tests end; teardown
    undeploys both workloads and scrubs every registration + CR back to pristine, verified."""
    with uc1.onboarded_stack([AGENT, TOOL]) as ctx:
        observed: dict = {"side": ctx["side"]}
        _run_phases(ctx, observed)
        yield observed


def _phase(run: dict, key: str) -> dict:
    """The record of phase ``key``, or fail naming why the flow stopped before it."""
    if key not in run:
        pytest.fail(f"phase {key!r} not reached — {run.get('stopped', 'an earlier phase failed')}")
    return run[key]


def _changed_paths(before: dict[str, dict[str, str]], after: dict[str, dict[str, str]]) -> dict[str, list[str]]:
    """For each CR in both snapshots whose ``spec.policies`` differ, the paths that differ."""
    return {
        key: sorted(
            path for path in set(before[key]) | set(after[key]) if before[key].get(path) != after[key].get(path)
        )
        for key in sorted(set(before) & set(after))
        if before[key] != after[key]
    }


# ======================================================================================
# Phase 1 — restart, no change
# ======================================================================================


def test_restart_keeps_the_cr_set(run: dict) -> None:
    """After a Controller restart with no change, the set of AIAC CRs is the same: the resync's
    ``PUT /policy`` writes one CR per live stored SPM and deletes no CR of a managed service."""
    before = _phase(run, "before")["crs"]
    after = _phase(run, "restarted")["crs"]
    assert set(after) == set(before), (
        f"the resync changed the AIAC CR set: added={sorted(set(after) - set(before))}, "
        f"removed={sorted(set(before) - set(after))}"
    )


def test_restart_keeps_every_cr_unchanged(run: dict) -> None:
    """Each AIAC CR keeps the same ``spec.policies`` (the resync renders the same policy model from the
    same stored SPMs) and the same uid (it was not deleted and created again, which would open a deny
    window under D20)."""
    before, after = _phase(run, "before"), _phase(run, "restarted")
    changed = _changed_paths(before["crs"], after["crs"])
    assert not changed, f"the resync changed the spec.policies of AIAC CRs (key -> paths): {changed}"
    recreated = sorted(k for k in before["uids"] if k in after["uids"] and after["uids"][k] != before["uids"][k])
    assert not recreated, f"the resync deleted and created again the AIAC CRs {recreated} (new uid)"


def test_restart_keeps_the_verdicts(run: dict) -> None:
    """The convergence signals still hold after the restart: ``dev-user`` inbound allow, ``devops-user``
    inbound deny, ``dev-user`` outbound ``source-read`` allow."""
    signals = _phase(run, "restarted")["signals"]
    want = {sig.label(): sig.expected for sig in HOLD_SIGNALS}
    assert signals == want, f"verdicts after the restart: {signals} (want {want})"


# ======================================================================================
# Phase 2 — no CR, so deny (D20)
# ======================================================================================


def test_service_without_cr_is_denied(run: dict) -> None:
    """With github-tool's CR deleted by hand, the ``dev-user`` ``source-read`` call that phase 1 allowed
    is denied, and the deny comes from github-tool's inbound: the changed combiner denies a pod that has
    no client CR (D20). This holds under both sides — the agent's outbound (a pass-through under target
    side, a grant under agent side) lets the call through."""
    obs = _phase(run, "no_cr")
    assert obs["cr"] is None, f"github-tool's CR is still present after the delete: {obs['cr']}"
    probe = obs["probe"]
    assert probe["decision"] == "deny", (
        f"{run['side']}: dev-user / {PROBE_TOOL} with no github-tool CR: {probe['decision']!r} "
        f"(HTTP {probe['code']}, body={probe['body'][:300]!r}) — is the global combiner changed (D20)?"
    )
    assert probe["origin"] == uc1.DENY_ORIGIN_TOOL_INBOUND, (
        f"{run['side']}: the deny came from {probe['origin']!r}, not github-tool's inbound "
        f"(HTTP {probe['code']}, body={probe['body'][:300]!r})"
    )


# ======================================================================================
# Phase 3 — restart, repair
# ======================================================================================


def test_resync_writes_the_missing_cr_again(run: dict) -> None:
    """The next Controller restart repairs the hand-deleted CR: the resync writes github-tool's CR from
    ``SPM(github-tool)`` with the same ``spec.policies`` as in phase 1, and the whole AIAC CR set is
    phase 1's again."""
    before = _phase(run, "before")["crs"]
    repaired = _phase(run, "repaired")["crs"]
    key = uc1.cr_key(TOOL)
    assert key in repaired, f"the resync did not write github-tool's CR again (AIAC CRs: {sorted(repaired)})"
    assert repaired[key] == before[key], (
        f"github-tool's repaired CR differs from phase 1 in {_changed_paths(before, repaired).get(key)}"
    )
    assert set(repaired) == set(before), f"AIAC CR set after the repair {sorted(repaired)} != phase 1 {sorted(before)}"
    changed = _changed_paths(before, repaired)
    assert not changed, f"the repair restart changed other AIAC CRs (key -> paths): {changed}"


def test_repaired_tool_call_allowed(run: dict) -> None:
    """With github-tool's CR back, the ``dev-user`` ``source-read`` call is allowed again."""
    probe = _phase(run, "repaired")["probe"]
    assert probe["decision"] == "allow", (
        f"{run['side']}: dev-user / {PROBE_TOOL} after the repair: {probe['decision']!r} "
        f"(HTTP {probe['code']}, body={probe['body'][:300]!r})"
    )
