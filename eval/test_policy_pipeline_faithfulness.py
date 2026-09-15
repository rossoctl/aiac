"""Policy Digester faithfulness suite (feature #2539).

The **faithfulness guard**: the Policy Digester adds, drops, or broadens NO access relative to
the source policy. This suite makes that operational by reusing the PRB-level correctness harness
(``test_policy_pipeline_correctness_prb.py``) with ONE change — the PRB is run over the scenario's
**digested** policy instead of its source:

    source policy --(digest_policy)--> digested policy --(PRB)--> rules --score--> truth table

For each scenario the source ``*.md`` is digested live, written to a temp file, and pointed at via
``AIAC_POLICY_FILE``; the PRB then runs exactly as in the correctness suite and its ``(name, effect)``
output is scored against the SAME hand-authored truth table. Scoring against the fixed per-scenario
oracle — rather than against a second live PRB run on the source — isolates digest faithfulness from
the PRB's own run-to-run non-determinism.

Gate: **zero over-grants** — a pair granted under the digest that the truth table does not permit is
a BROADENING of access and fails the test (the security-critical half of faithfulness). Under-grants
(dropped access) and incorrect denials are recorded/printed but do not gate, mirroring
``eval_correctness_prb`` (spec: under-grant threshold TBD, deferred).

Run (needs LLM_BASE_URL/LLM_MODEL/LLM_API_KEY; no Keycloak/opa). Scenarios are independent, so
``-n 8`` gives a near-linear speedup — but note each scenario now makes an EXTRA digest LLM call on
top of the PRB's ~5-8:
    .venv/bin/pytest eval/test_policy_pipeline_faithfulness.py -m eval_faithfulness -n 8 -v -s
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.eval_faithfulness

HERE = Path(__file__).resolve().parent  # aiac/eval/
REPO_ROOT = HERE.parent  # -> aiac/
SRC = REPO_ROOT / "src"
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.integration.*``/``eval.*`` resolves
sys.path.insert(0, str(SRC))  # so ``import aiac.*`` resolves

from aiac.agent.policy_digester import digest_policy  # noqa: E402
from aiac.policy.model.models import RuleEffect  # noqa: E402
from eval.correctness_scorer import score_scenario  # noqa: E402
from eval.prb_direct import build_roles_and_scopes  # noqa: E402
from eval.test_policy_pipeline_eval import (  # noqa: E402
    SCENARIOS,
    grant_sets,
    orchestrate_prb,
    truth,
)
from test.integration.launcher import require_env  # noqa: E402


@pytest.mark.parametrize("scenario_name", sorted(SCENARIOS))
def test_digest_is_faithful(scenario_name: str, monkeypatch: pytest.MonkeyPatch, tmp_path, record_property) -> None:
    """The PRB's output over the scenario's DIGESTED policy, scored against the scenario's truth
    table, has zero over-grants — the digest broadens no access (security-critical, gates this
    test). Under-grants (dropped access) and incorrect denials are tracked/reported only."""
    require_env("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
    scenario = SCENARIOS[scenario_name]
    roles, scopes = build_roles_and_scopes(scenario)

    # Digest the source policy (live LLM) and point the PRB at the DIGESTED artifact — the one
    # change from the correctness suite. Everything downstream is identical.
    source_path = Path(scenario.__file__).resolve().parent / scenario.POLICY_FILE
    digested_path = tmp_path / f"digested.{scenario.POLICY_FILE}"
    digested_path.write_text(digest_policy(source_path.read_text(encoding="utf-8")), encoding="utf-8")
    monkeypatch.setenv("AIAC_POLICY_FILE", str(digested_path))

    # best_effort=True: an auditor-rejected decision contributes a best-effort fallback rule rather
    # than aborting the whole scenario, so every scenario scores (see orchestrate_prb's docstring).
    rules, _, _, best_effort_notes = orchestrate_prb(roles, scopes, scenario, best_effort=True)
    granted = grant_sets(scenario, [r for r in rules if r.effect == RuleEffect.ALLOW])
    denied = grant_sets(scenario, [r for r in rules if r.effect == RuleEffect.DENY])
    expected = truth(scenario)
    score = score_scenario(scenario_name, granted, denied, expected)

    over_grants = {g: sorted(p) for g, p in score.over_grants.items()}
    under_grants = {g: sorted(p) for g, p in score.under_grants.items()}
    incorrectly_denied = {g: sorted(p) for g, p in score.incorrectly_denied.items()}

    record_property("precision", score.precision)
    record_property("recall", score.recall)
    record_property("denial_precision", score.denial_precision)
    record_property("over_grants", over_grants)
    record_property("under_grants", under_grants)
    record_property("incorrectly_denied", incorrectly_denied)
    record_property("best_effort_notes", best_effort_notes)
    record_property("true_positives", score.true_positive_count)
    record_property("denied_total", score.denied_total)
    print(
        f"[faithfulness] {scenario_name}: precision={score.precision:.3f} "
        f"recall={score.recall:.3f} denial_precision={score.denial_precision:.3f}\n"
        f"  over_grants (BROADENING — gates)={over_grants or '{}'}\n"
        f"  under_grants (dropped — reported)={under_grants or '{}'}\n"
        f"  incorrectly_denied={incorrectly_denied or '{}'}\n"
        f"  best_effort_notes={best_effort_notes or '{}'}"
    )

    assert score.passed, (
        f"Digest broadened access for scenario '{scenario_name}' — zero-tolerance over-grant "
        f"gate (a faithful digest never grants a pair the source does not): {over_grants}"
    )
