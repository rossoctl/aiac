"""PRB run-to-run consistency suite (spec: ``docs/evaluation/
policy-eval-robustness-consistency.md``).

Checks whether the LLM-backed Policy Rules Builder (``aiac.agent.policy_rules_builder.graph``)
produces the *same* grant decision every time it's given the *same* input — orthogonal to whether
that decision is correct (correctness against a truth table is already covered by
``test_policy_pipeline_eval.py``'s ``test_grant_set_matches_truth_table``).

Scoped to the PRB's raw output only (no OPA/PCE/k8s in the loop — variance can only originate at
the LLM call boundary, so running the downstream deterministic compiler stages adds cost with no
added signal). Reuses the existing 8-scenario corpus (``SCENARIOS``, ``orchestrate_prb``,
``grant_sets`` from ``test_policy_pipeline_eval.py``) and builds synthetic, Keycloak-free
``Role``/``Scope`` objects via ``prb_direct.build_roles_and_scopes`` — no live IdP needed, since
``orchestrate_prb`` only reads ``.name``/``.description`` off these objects. Runs against each
scenario's committed **digested** policy (``eval/scenarios_digested/``), not its source prose — see
``docs/evaluation/policy-eval-robustness-consistency.md``'s "Digested corpus" section — with
``orchestrate_prb(..., best_effort=True)`` for the same "coarse-scope contradiction" reason the
robustness suite documents (see this suite's own test docstring).

Run (needs LLM_BASE_URL/LLM_MODEL/LLM_API_KEY exported; no Keycloak/opa needed):
    .venv/bin/pytest eval/test_policy_pipeline_consistency.py \
        -m eval -v

N (repeats per scenario) is overridable via ``PRB_CONSISTENCY_REPEATS`` (default 5).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.eval

HERE = Path(__file__).resolve().parent  # aiac/eval/
REPO_ROOT = HERE.parent  # -> aiac/
SRC = REPO_ROOT / "src"
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*``/``eval.*`` resolves
sys.path.insert(0, str(SRC))  # so ``import aiac.*`` resolves

from eval.prb_direct import build_roles_and_scopes  # noqa: E402
from eval.scenarios_digested import digested_policy_path  # noqa: E402
from eval.test_policy_pipeline_eval import (  # noqa: E402
    SCENARIOS,
    grant_sets,
    orchestrate_prb,
)
from test.system.launcher import require_env_or_skip  # noqa: E402

N = int(os.environ.get("PRB_CONSISTENCY_REPEATS", "5"))
if N < 2:
    raise ValueError("PRB_CONSISTENCY_REPEATS must be at least 2")


@pytest.mark.parametrize("scenario_name", sorted(SCENARIOS))
def test_prb_consistent_across_repeats(scenario_name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the PRB ``PRB_CONSISTENCY_REPEATS`` (default 5) times against the same unperturbed
    scenario input and assert every run's grant sets are exactly equal — no tolerance or
    majority vote, since this is access control: any run-to-run disagreement is a finding.

    Calls ``orchestrate_prb(..., best_effort=True)``: against the digested policy, ``agent_
    delegation``'s coarse ``agent-scope-dispatcher`` bundles manifest ops with the explicitly-
    denied ``initiate_customs_clearance_on_behalf``, which an auditor can read as a genuine
    partial-grant/partial-deny contradiction on some runs and not others — exactly the same
    "coarse-scope" failure mode ``test_policy_pipeline_robustness.py`` already documents and
    handles the same way. Without ``best_effort``, a rejection on any single repeat crashes the
    whole scenario instead of contributing a comparable (if unapproved) result — and a rejection
    on some repeats but not others is itself exactly the run-to-run disagreement this suite exists
    to catch, not a harness failure."""
    require_env_or_skip("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
    scenario = SCENARIOS[scenario_name]
    roles, scopes = build_roles_and_scopes(scenario)
    monkeypatch.setenv("AIAC_POLICY_FILE", str(digested_policy_path(scenario)))

    runs = []
    for _ in range(N):
        rules, _, _, _ = orchestrate_prb(roles, scopes, scenario, best_effort=True)
        runs.append(grant_sets(scenario, rules))

    baseline = runs[0]
    mismatches: list[str] = []
    for gate in ("inbound", "outbound_subject", "outbound_target"):
        base_pairs = baseline[gate]
        for run_index, run in enumerate(runs[1:], start=1):
            diff = base_pairs ^ run[gate]
            if diff:
                mismatches.append(f"gate={gate} run=0 vs run={run_index}: differing pairs={sorted(diff)}")

    assert not mismatches, f"PRB was inconsistent across {N} repeats for scenario '{scenario_name}':\n" + "\n".join(
        mismatches
    )
