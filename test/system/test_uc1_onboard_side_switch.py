"""Rung 7 of the UC-1 onboarding ladder — the enforcement-side switch.

Spec ``docs/testing/uc1-onboarding-pipeline.md`` (§ *The enforcement-side switch (rung 7)* and § *CR end
state for each side*); decisions D16, D28 and D29 of ``docs/handoffs/12-target-side-ac-and-method-switch.md``
(P0b step 5 and "Tests (P0b)": the demo passes under each side; a restart with the other value moves every
CR, with no mixed state).

A side change is a ConfigMap patch (``AIAC_ENFORCEMENT_SIDE`` in ``aiac-agent-config``) and a Controller
restart. At start the Controller runs the resync (D28): ``PUT /policy`` with the full policy model of the new
side, which writes every AIAC CR in the new shape and deletes every other AIAC CR. Let ``S`` be the live side
at the start (``live_enforcement_side``) and ``O`` the other side.

The rung onboards github-agent and github-tool (``onboarded_stack([agent, tool])``, module-scoped, so the stack
is torn down when this module's tests end), and then runs three phases in order. Each phase records what it
observed and the tests assert on the record, so a failed phase reports its own facts and a later phase reports
"not reached":

1. **Under S.** Record every AIAC CR, the deny of an ungranted call (``test-user`` × ``source-read``) and the
   full verdict matrix (3 inbound cells, 12 outbound cells). Assert: github-agent's and github-tool's CRs match
   ``S`` (``cr_matches_side``), the deny comes from the enforcement point of ``S`` (``deny_origin``), and each
   cell has the verdict of *Expected output*.
2. **Switch to O** (``controller_enforcement_side(O)``: the ConfigMap patch + a Controller restart). Poll until
   every AIAC CR matches ``O``; then poll until the ungranted call is denied by the enforcement point of ``O``
   (this proves that the OPA sidecar of the deciding pod loaded its new bundle: a CR change takes effect at the
   next poll of the OPA plugin, up to 120 s); then measure the matrix again. Assert: the AIAC CR set is exactly
   github-agent's and github-tool's CRs; every one matches ``O`` and none still matches ``S`` (no mixed state:
   under agent side github-tool's CR is a pass-through and github-agent's outbound has the per-tool checks;
   under target side github-tool's inbound has the tool gates and github-agent's outbound is a pass-through);
   the deny comes from the enforcement point of ``O``; and each cell has the same verdict as under ``S``.
3. **Switch back.** The context always puts back the start value and restarts the Controller — also when the
   switch or phase 2 fails — so later rungs run under ``S``. Poll until every AIAC CR matches ``S`` again and
   the deny comes from the enforcement point of ``S``. Assert: the ConfigMap holds the start value again (an
   absent key stays absent), every AIAC CR matches ``S``, the two CRs are the same as in phase 1 (the resync
   renders the same policy model from the same stored SPMs), and the deny comes from the enforcement point of
   ``S``.

Which enforcement point decides: under target side github-tool's inbound OPA (an HTTP 403 with a plain OPA
body, relayed by the agent's pass-through outbound); under agent side the agent's outbound OPA (a JSON-RPC
error frame at HTTP 200). The OPA sidecars of the two pods poll their bundles on their own, so for up to one
bundle poll after a switch the two pods can hold bundles of different sides; the deny-origin poll waits that
out, and the probe ``trail`` in each record shows what the poll saw on the way.

Known limit (not asserted): under agent side the agent's outbound also denies its LLM and A2A calls
(``b435aa1``). The probes here never make such a call: the inbound probe stops at ``ping/nonexistent`` and the
outbound probe is an MCP ``tools/call`` to github-tool.

Like every rung it skips cleanly before any cluster mutation when its infra is absent: ``onboarded_stack`` runs
``require_pipeline`` (including the changed-combiner gate), ``require_env_or_skip`` and ``require_event_path``
first. The rung restarts the Controller twice and waits for the OPA bundle poll three times, so it takes
several minutes.

    .venv/bin/pytest -m system -k uc1_onboard_side_switch -v

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

# The ungranted call whose deny tells the two enforcement points apart (test-user ❌ source-read).
PROBE_USER = "test-user"
PROBE_TOOL = "source-read"

# The AIAC CRs of this rung (the managed set: the store is cleared before the onboarding), by kind.
DEMO_CR_KINDS: dict[str, str] = {uc1.cr_key(workload): kind for workload, kind in uc1.WORKLOAD_KIND.items()}

# A CR change takes effect at the next poll of the OPA plugin (10 s min, up to 120 s). The deny-origin poll
# waits that long plus a margin for bundle-service to recompose, and never less than the harness budget.
OPA_MAX_POLL = 120.0
SWITCH_TIMEOUT = max(uc1.BUNDLE_TIMEOUT, OPA_MAX_POLL + 60.0)

# The resync writes the CRs before the new Controller pod is Ready, so the CR poll needs only a margin.
CR_TIMEOUT = 60.0

# A matrix cell that reads "error" (a probe pod or token-exchange hiccup, not a verdict) is probed again
# for up to this long; an "allow" or a "deny" is final.
CELL_RETRY_TIMEOUT = 30.0

# Each failure the restart of a switch can raise (a rollout that does not complete, or a ConfigMap patch
# that fails). ``uc1.EnforcementSideRestoreError`` is a RuntimeError and is caught before these.
ROLLOUT_ERRORS = (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError)

# The verdict matrix of *Expected output*: (kind, subject, bare tool name or None).
CELLS: list[tuple[str, str, str | None]] = [("inbound", subject, None) for subject in scn.USERS] + [
    ("outbound", subject, tool) for subject in scn.USERS for tool in scn.TOOL_REQUEST_NAMES
]


def _cell_id(cell: tuple[str, str, str | None]) -> str:
    kind, subject, tool = cell
    return f"{kind}-{subject}" if tool is None else f"{kind}-{tool}-{subject}"


def _expected(cell: tuple[str, str, str | None]) -> str:
    kind, subject, tool = cell
    if kind == "inbound":
        return uc1.expected_inbound_decision(subject)
    return uc1.expected_outbound_decision(subject, tool)


# ======================================================================================
# Phase helpers — each one polls to a terminal state and returns what it saw (never asserts)
# ======================================================================================


def _shape_problems(crs: dict[str, dict[str, str]], side: str, *, exact: bool = True) -> dict[str, list[str]]:
    """Each way the AIAC CRs ``crs`` differ from the shape of ``side``: ``{key: [problem, ...]}`` for
    github-agent's and github-tool's CRs (``uc1.cr_side_mismatches``; a missing CR is a problem). With
    ``exact``, an AIAC CR of any other service is a problem too: the resync's ``PUT /policy`` deletes
    every AIAC CR that is not in the policy model, and the managed set is the demo pair."""
    problems = {key: uc1.cr_side_mismatches(crs.get(key), kind, side) for key, kind in DEMO_CR_KINDS.items()}
    if exact:
        problems.update({key: ["not a CR of the managed set"] for key in crs if key not in DEMO_CR_KINDS})
    return {key: found for key, found in problems.items() if found}


def _poll_crs(side: str) -> dict[str, dict[str, str]]:
    """Poll until every AIAC CR matches ``side`` (``_shape_problems`` is empty), then read and return
    every AIAC CR (the final read raises when the API is unreachable, so it never reads as "no CR")."""
    uc1.poll_until(lambda: not _shape_problems(uc1.aiac_crs(), side), timeout=CR_TIMEOUT, interval=5)
    return uc1.aiac_crs()


def _poll_origin(ctx: dict, side: str) -> dict:
    """Poll the ungranted call (``PROBE_USER`` × ``PROBE_TOOL``) until it is denied by the enforcement
    point of ``side`` (``uc1.SIDE_ENFORCEMENT_POINT``), up to ``SWITCH_TIMEOUT``. Return the last probe
    (``{"decision", "origin", "code", "body"}``, see ``uc1.outbound_deny_probe``) with ``trail``: each
    distinct outcome the poll saw, in order (an origin, or the decision when it is no OPA deny)."""
    want = uc1.SIDE_ENFORCEMENT_POINT[side]
    seen: dict = {"probe": {"decision": "unobserved", "origin": None, "code": None, "body": ""}, "trail": []}

    def _reached() -> bool:
        probe = uc1.outbound_deny_probe(ctx, PROBE_USER, PROBE_TOOL)
        seen["probe"] = probe
        label = probe["origin"] or probe["decision"]
        if not seen["trail"] or seen["trail"][-1] != label:
            seen["trail"].append(label)
        return probe["decision"] == "deny" and probe["origin"] == want

    uc1.poll_until(_reached, timeout=SWITCH_TIMEOUT, interval=uc1.BUNDLE_POLL_INTERVAL)
    return {**seen["probe"], "trail": list(seen["trail"])}


def _decide(ctx: dict, cell: tuple[str, str, str | None]) -> str:
    kind, subject, tool = cell
    if kind == "inbound":
        return uc1.inbound_decision(ctx, subject)
    return uc1.outbound_decision(ctx, subject, tool)


def _matrix(ctx: dict) -> dict[str, str]:
    """Probe every cell of ``CELLS`` once and return ``{cell id: decision}``. A cell that reads
    ``"error"`` (or whose probe raises) is probed again for up to ``CELL_RETRY_TIMEOUT``; an ``"allow"``
    or a ``"deny"`` is final. Call it after ``_poll_origin``: then the deciding pod has its new bundle."""
    matrix: dict[str, str] = {}
    for cell in CELLS:
        seen = {"decision": "unobserved"}

        def _definitive(c: tuple[str, str, str | None] = cell) -> bool:
            seen["decision"] = _decide(ctx, c)
            return seen["decision"] in ("allow", "deny")

        uc1.poll_until(_definitive, timeout=CELL_RETRY_TIMEOUT, interval=uc1.BUNDLE_POLL_INTERVAL)
        matrix[_cell_id(cell)] = seen["decision"]
    return matrix


def _switch_detail(exc: BaseException) -> str:
    return ((getattr(exc, "stderr", "") or str(exc)).strip() or type(exc).__name__)[:300]


def _run_phases(ctx: dict, run: dict) -> None:
    """Drive the three phases (module docstring) in order on the onboarded stack, recording into ``run``.
    A switch whose restart does not complete records why in ``run["stopped"]["switched"]``; a switch back
    that fails records why in ``run["stopped"]["restored"]``. Any other harness failure (an unreachable
    API in a read) raises — the context still switches back first."""
    start, other = run["side"], run["other"]
    run["start_value"] = uc1.enforcement_side_value()

    # --- Phase 1 — under S ---------------------------------------------------------------------
    crs = uc1.aiac_crs()  # the stack has converged; no poll
    run["start"] = {"crs": crs, "probe": _poll_origin(ctx, start), "matrix": _matrix(ctx)}

    # --- Phase 2 — switch to O; phase 3 is the switch back when the context exits ---------------
    entered = False
    try:
        with uc1.controller_enforcement_side(other):
            entered = True
            crs = _poll_crs(other)
            probe = _poll_origin(ctx, other)  # waits out the OPA bundle poll of the deciding pod
            run["switched"] = {"crs": crs, "probe": probe, "matrix": _matrix(ctx)}
    except uc1.EnforcementSideRestoreError as exc:
        run["stopped"]["restored"] = str(exc)
        if "switched" not in run:
            # The restore failure is the cause; the failure that stopped phase 2 is that cause's context.
            first = exc.__cause__.__context__ if exc.__cause__ is not None else None
            what = "the observation under" if entered else "the switch to"
            run["stopped"]["switched"] = f"{what} {other} did not complete ({_switch_detail(first or exc)})"
        return
    except ROLLOUT_ERRORS as exc:
        if entered:
            raise  # a harness failure in the observation; the context has switched back
        run["stopped"]["switched"] = (
            f"the switch to {other} did not complete ({_switch_detail(exc)}). A Controller that does not come "
            f"back within {uc1.CONTROLLER_RESTART_TIMEOUT:.0f}s means a failed start (the side, start check #4 or "
            "the resync); see its log. The context switched back to the start value."
        )

    # --- Phase 3 — back under S ----------------------------------------------------------------
    crs = _poll_crs(start)
    run["restored"] = {"value": uc1.enforcement_side_value(), "crs": crs, "probe": _poll_origin(ctx, start)}


# ======================================================================================
# Module fixture — onboarded stack → the three phases → teardown to pristine
# ======================================================================================


@pytest.fixture(scope="module")
def run() -> Iterator[dict]:
    """Onboard the agent and then the tool (the full stack) under the live side, run the three phases once,
    and yield what each observed. Module-scoped, so this rung's stack is torn down as soon as its tests end;
    teardown undeploys both workloads and scrubs every registration + CR back to pristine, verified. The
    switch back to the start side happens inside the phases (``controller_enforcement_side``), before the
    teardown, on every exit path."""
    with uc1.onboarded_stack([AGENT, TOOL]) as ctx:
        observed: dict = {"side": ctx["side"], "other": uc1.OTHER_SIDE[ctx["side"]], "stopped": {}}
        _run_phases(ctx, observed)
        yield observed


def _phase(run: dict, key: str) -> dict:
    """The record of phase ``key``, or fail naming why the flow stopped before it."""
    if key not in run:
        pytest.fail(f"phase {key!r} not reached — {run['stopped'].get(key, 'an earlier phase failed')}")
    return run[key]


def _probe_text(probe: dict) -> str:
    return (
        f"decision={probe['decision']!r} origin={probe['origin']!r}, HTTP {probe['code']}, "
        f"body={probe['body'][:300]!r}; the poll saw {probe['trail']}"
    )


def _demo_crs(crs: dict[str, dict[str, str]]) -> dict[str, dict[str, str] | None]:
    return {key: crs.get(key) for key in DEMO_CR_KINDS}


# ======================================================================================
# Phase 1 — under S
# ======================================================================================


def test_start_crs_match_start_side(run: dict) -> None:
    """Under the start side ``S``, github-agent's and github-tool's CRs both exist (D20) and have the shape
    of ``S`` (*CR end state for each side*)."""
    crs = _phase(run, "start")["crs"]
    problems = _shape_problems(crs, run["side"], exact=False)
    assert not problems, f"under {run['side']} the CRs do not match {run['side']}: {problems}"


def test_start_deny_comes_from_start_enforcement_point(run: dict) -> None:
    """Under ``S`` the ungranted call (``test-user`` × ``source-read``) is denied by the enforcement point
    of ``S``: github-tool's inbound under target side, the agent's outbound under agent side."""
    probe = _phase(run, "start")["probe"]
    want = uc1.SIDE_ENFORCEMENT_POINT[run["side"]]
    assert probe["decision"] == "deny" and probe["origin"] == want, (
        f"under {run['side']}: {PROBE_USER} / {PROBE_TOOL} (want 'deny' from {want!r}): {_probe_text(probe)}"
    )


@pytest.mark.parametrize("cell", CELLS, ids=[_cell_id(cell) for cell in CELLS])
def test_start_verdict(run: dict, cell: tuple[str, str, str | None]) -> None:
    """Under ``S`` each cell of the matrix has the verdict of *Expected output* (the real OPA plugin
    decides; verdicts computed from ``scenario_uc1``)."""
    observed = _phase(run, "start")["matrix"][_cell_id(cell)]
    assert observed == _expected(cell), (
        f"under {run['side']}: {_cell_id(cell)} = {observed!r} (want {_expected(cell)!r})"
    )


# ======================================================================================
# Phase 2 — switched to O
# ======================================================================================


def test_switch_keeps_the_cr_set(run: dict) -> None:
    """After the switch the AIAC CR set is exactly github-agent's and github-tool's CRs: the resync writes
    one CR per live stored SPM and deletes every other AIAC CR, so no service lost or gained a CR."""
    crs = _phase(run, "switched")["crs"]
    assert set(crs) == set(DEMO_CR_KINDS), (
        f"AIAC CRs after the switch to {run['other']}: {sorted(crs)} (want {sorted(DEMO_CR_KINDS)})"
    )


def test_switch_moves_every_cr(run: dict) -> None:
    """After the switch every AIAC CR has the shape of the other side ``O``: under agent side github-tool's
    CR is a pass-through and github-agent's outbound has the per-tool checks with grants; under target side
    github-tool's inbound has the tool gates with grants and github-agent's outbound is a pass-through."""
    crs = _phase(run, "switched")["crs"]
    problems = _shape_problems(crs, run["other"])
    assert not problems, f"after the switch to {run['other']} the CRs do not match {run['other']}: {problems}"


def test_switch_leaves_no_cr_in_the_start_shape(run: dict) -> None:
    """No mixed state: after the switch no CR of github-agent or github-tool still has the shape of ``S``
    (a CR left in the old shape would leave a call checked twice, or not at all)."""
    crs = _phase(run, "switched")["crs"]
    stale = sorted(
        key for key, kind in DEMO_CR_KINDS.items() if crs.get(key) and uc1.cr_matches_side(crs[key], kind, run["side"])
    )
    assert not stale, f"after the switch to {run['other']} these CRs still match {run['side']}: {stale}"


def test_switch_deny_comes_from_new_enforcement_point(run: dict) -> None:
    """After the switch (and the OPA bundle poll) the ungranted call is denied by the enforcement point of
    ``O``: the check moved with the CRs."""
    probe = _phase(run, "switched")["probe"]
    want = uc1.SIDE_ENFORCEMENT_POINT[run["other"]]
    assert probe["decision"] == "deny" and probe["origin"] == want, (
        f"after the switch to {run['other']}: {PROBE_USER} / {PROBE_TOOL} (want 'deny' from {want!r}): "
        f"{_probe_text(probe)}"
    )


@pytest.mark.parametrize("cell", CELLS, ids=[_cell_id(cell) for cell in CELLS])
def test_switch_keeps_the_verdict(run: dict, cell: tuple[str, str, str | None]) -> None:
    """The demo passes under ``O`` too: each cell has the verdict of *Expected output*, the same as under
    ``S`` (the verdict tables do not depend on the side)."""
    observed = _phase(run, "switched")["matrix"][_cell_id(cell)]
    before = run.get("start", {}).get("matrix", {}).get(_cell_id(cell))
    assert observed == _expected(cell), (
        f"after the switch to {run['other']}: {_cell_id(cell)} = {observed!r} (want {_expected(cell)!r}; "
        f"under {run['side']} it was {before!r})"
    )


# ======================================================================================
# Phase 3 — switched back to S
# ======================================================================================


def test_switch_back_restores_the_start_value(run: dict) -> None:
    """The context puts back the exact start value of ``AIAC_ENFORCEMENT_SIDE`` (an absent key stays
    absent), so later rungs run under ``S``."""
    restored = _phase(run, "restored")["value"]
    assert restored == run["start_value"], (
        f"{uc1.ENFORCEMENT_SIDE_KEY} after the switch back: {restored!r} (want the start value {run['start_value']!r})"
    )


def test_switch_back_moves_every_cr_back(run: dict) -> None:
    """After the switch back the AIAC CR set is github-agent's and github-tool's CRs again, and every one
    has the shape of ``S``."""
    crs = _phase(run, "restored")["crs"]
    problems = _shape_problems(crs, run["side"])
    assert not problems, f"after the switch back to {run['side']} the CRs do not match {run['side']}: {problems}"


def test_switch_back_restores_the_start_crs(run: dict) -> None:
    """After the switch back github-agent's and github-tool's CRs have the same ``spec.policies`` as in
    phase 1: the resync renders the same policy model of ``S`` from the same stored SPMs."""
    before = _demo_crs(_phase(run, "start")["crs"])
    after = _demo_crs(_phase(run, "restored")["crs"])
    changed = {
        key: sorted(
            path
            for path in set(before[key] or {}) | set(after[key] or {})
            if (before[key] or {}).get(path) != (after[key] or {}).get(path)
        )
        for key in DEMO_CR_KINDS
        if before[key] != after[key]
    }
    assert not changed, (
        f"after the switch back to {run['side']} these CRs differ from phase 1 (key -> paths): {changed}"
    )


def test_switch_back_deny_comes_from_start_enforcement_point(run: dict) -> None:
    """After the switch back (and the OPA bundle poll) the ungranted call is denied by the enforcement
    point of ``S`` again."""
    probe = _phase(run, "restored")["probe"]
    want = uc1.SIDE_ENFORCEMENT_POINT[run["side"]]
    assert probe["decision"] == "deny" and probe["origin"] == want, (
        f"after the switch back to {run['side']}: {PROBE_USER} / {PROBE_TOOL} (want 'deny' from {want!r}): "
        f"{_probe_text(probe)}"
    )
