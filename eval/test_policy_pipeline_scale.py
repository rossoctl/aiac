"""Scale suite -- fixed-100 regression tier (spec: ``docs/evaluation/policy-eval-scale.md``,
``docs/evaluation/eval-framework.md`` §5).

Two independent dimensions (never blended into one "scale score"):

- **total-corpus** -- many roles/scopes/services overall, each individual PRB decision still
  facing a modest candidate list. Stresses the deterministic merge engine, Rego document size, OPA
  eval latency, and total wall-clock/cost across many PRB calls.
- **per-decision** -- one role/scope facing a very large candidate list in a single PRB call.
  Stresses the LLM itself (context pressure, needle-in-a-haystack degradation).

Both dimensions are checked by two check types, kept on separate assertions and separate metric
names -- but merged onto one trend-log row per dimension/level (``eval/conftest.py``'s
``_write_trend_log``, see ``_SCALE_TEST_MARKERS``), since what the spec actually guards against is
blending the two into one number, not which JSON object the keys live in:

- **structural** -- completeness, no duplication/orphans, latency, cost
  (``eval.scale_structural``). Completeness/no-duplication/no-orphans gate the test (objectively
  pass/fail); latency/cost are reported/trended only (no SLA exists anywhere in the spec/issue to
  gate against).
- **correctness** -- the same precision/recall scorer (``eval.correctness_scorer``) every other
  suite in this family uses, against the generated corpus's ground truth.

The corpus itself is procedurally generated (``eval.scale_generator`` -- pure, seeded,
deterministic; ground truth known by construction), never hand-authored -- see that module's
docstring for why. Every PRB decision uses ``best_effort=True`` (a rejected decision falls back to
a best-effort proposal instead of aborting the whole run -- critical at this scale, where one
rejection must not discard every other decision's real result) and every independent PRB call is
fanned out concurrently (``eval.scale_prb.orchestrate_prb_concurrent``/``run_concurrently``) rather
than run one after another.

PRB-level cases need only ``LLM_BASE_URL``/``LLM_MODEL``/``LLM_API_KEY``
(``require_env_or_skip``, first line of each fixture). End-to-end cases additionally need
``KEYCLOAK_URL``+admin creds and ``opa`` on ``PATH``.

Size overrides (mirrors ``PRB_CONSISTENCY_REPEATS``'s existing convention -- use a small size while
iterating, the full fixed-100 size for an actual regression run). Selection stays marker-only, same
as every other suite -- never a file path -- so ``-k scale`` narrows to this suite's own
``test_scale_*`` functions within the ``eval`` marker:

    SCALE_TOTAL_CORPUS_SIZE=10 SCALE_TOTAL_CORPUS_ROLES=4 SCALE_PER_DECISION_CANDIDATES=20 \\
        .venv/bin/pytest -m eval -k "scale and prb" -v -s
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.eval

HERE = Path(__file__).resolve().parent  # aiac/eval/
REPO_ROOT = HERE.parent  # -> aiac/
SRC = REPO_ROOT / "src"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(SRC))

from aiac.agent.policy_rules_builder.graph import ROLE_GRAPH, SCOPE_GRAPH  # noqa: E402
from aiac.idp.configuration.api import Configuration  # noqa: E402
from aiac.idp.configuration.models import Role, RoleKind, Scope  # noqa: E402
from aiac.policy.computation.engine import compute_and_apply  # noqa: E402
from aiac.policy.model.models import RuleEffect  # noqa: E402
from eval.correctness_scorer import score_scenario  # noqa: E402
from eval.prb_direct import build_roles_and_scopes  # noqa: E402
from eval.scale_generator import (  # noqa: E402
    FOCAL_ROLE_NAME,
    FOCAL_SCOPE_NAME,
    PER_DECISION_ROLE_AGENT_ID,
    PER_DECISION_SCOPE_AGENT_ID,
    generate_per_decision,
    generate_total_corpus,
)
from eval.scale_prb import _invoke_with_usage, orchestrate_prb_concurrent  # noqa: E402
from eval.scale_structural import (  # noqa: E402
    duplicate_rule_triples,
    invalid_selected_names,
    missing_decisions,
    missing_rego,
    orphaned_scope_names,
    summarize_usage,
)
from eval.test_policy_pipeline_correctness_e2e import _e2e_grant_sets  # noqa: E402
from eval.test_policy_pipeline_eval import (  # noqa: E402
    _connect_admin,
    _rego_path,
    grant_sets,
    opa_bin,
    provision_keycloak_admin,
    provision_via_config,
    truth,
)
from eval.test_policy_pipeline_eval import _read_back as read_back_idp  # noqa: E402
from test.system.launcher import Service, require_env_or_skip, running_services  # noqa: E402

# --- Size overrides (env), mirroring PRB_CONSISTENCY_REPEATS' convention ----------------------

TOTAL_CORPUS_SIZE = int(os.environ.get("SCALE_TOTAL_CORPUS_SIZE", "100"))
TOTAL_CORPUS_ROLES = int(os.environ.get("SCALE_TOTAL_CORPUS_ROLES", "10"))
PER_DECISION_CANDIDATES = int(os.environ.get("SCALE_PER_DECISION_CANDIDATES", "100"))
SCALE_SEED = int(os.environ.get("SCALE_SEED", "0"))

# Dedicated idp/store/opa port triples for the two e2e fixtures below -- a high, unused-elsewhere
# range so a Scale e2e run never collides with test_policy_pipeline_eval.py's own pipeline fixture
# (ports DEFAULT_IDP_PORT+i*10 for i in range(8)) even if both happened to run in the same session.
_TOTAL_CORPUS_E2E_PORTS = {"idp": 7500, "store": 7502, "opa": 7501}
_PER_DECISION_E2E_PORTS = {"idp": 7510, "store": 7512, "opa": 7511}


def _fix_agent_role_actor_ids(config: Configuration, roles: dict[str, Role], scenario) -> None:
    """``read_back_idp``'s flat ``config.get_roles()`` call does not reliably carry the correct
    ``kind``/``actorIds`` for an agent-owned role (confirmed empirically: it returned ``kind=USER``
    with an unrelated ``actorIds`` value for a role actually owned by an agent) -- a service's own
    ``.roles`` list does (``aiac.idp.configuration.api.Configuration._build_service`` merges the
    authoritative per-service ``kind``/``actorIds`` in). Patches ``roles`` in place for every agent
    role the scenario declares, so ``compute_and_apply`` correctly attributes each agent role's
    rules to its owning agent's own outbound APM -- getting this wrong is why an agent that
    genuinely received grants could still end up with no rendered outbound Rego at all."""
    agent_role_names = {name for agent in scenario.AGENTS.values() for name in agent["roles"]}
    if not agent_role_names:
        return
    for svc in config.get_services():
        for role in svc.roles:
            if role.name in agent_role_names:
                roles[role.name] = role


def _provision_scale_realm_and_services(
    scenario, *, rego_dir: Path, db_prefix: str, ports: dict[str, int]
) -> tuple[Service, Service, Service]:
    """Shared prefix of both e2e fixtures below: connect to Keycloak and provision the realm, wipe
    and recreate ``rego_dir``, point the four ``AIAC_*_URL`` env vars at ``ports``, and build the
    idp/store/opa ``Service`` triple -- everything each fixture needs before its own distinct
    PRB-calling logic runs inside its own ``with running_services(...)`` block (one fans a whole
    scenario's decisions out via ``orchestrate_prb_concurrent``, the other makes exactly two
    sequential ``_invoke_graph`` calls against two different policy files, so that part can't be
    shared here). Mirrors ``eval.test_policy_pipeline_eval._provision_scenario``'s own idp/store/opa
    construction shape -- not reused directly, since that function also runs its own fixed
    ``orchestrate_prb`` call inside its own ``with`` block."""
    admin = _connect_admin()
    os.environ["KEYCLOAK_REALM"] = scenario.REALM_DEFAULT
    provision_keycloak_admin(admin, scenario.REALM_DEFAULT, scenario)

    if rego_dir.exists():
        shutil.rmtree(rego_dir)
    rego_dir.mkdir(parents=True)
    db_path = Path(tempfile.mkdtemp(prefix=db_prefix)) / "policy_model.db"

    os.environ["AIAC_PDP_CONFIG_URL"] = f"http://127.0.0.1:{ports['idp']}"
    os.environ["AIAC_POLICY_STORE_URL"] = f"http://127.0.0.1:{ports['store']}"
    os.environ["AIAC_POLICY_MODEL_STORE_URL"] = f"http://127.0.0.1:{ports['store']}"
    os.environ["AIAC_PDP_POLICY_URL"] = f"http://127.0.0.1:{ports['opa']}"

    idp = Service("aiac.idp.service.configuration.keycloak.main:app", port=ports["idp"])
    store = Service(
        "aiac.policy.model_store.service.main:app", port=ports["store"], env={"SERVICEPOLICY_DB_PATH": str(db_path)}
    )
    opa = Service(
        "aiac.pdp.service.policy.opa.main:app",
        port=ports["opa"],
        env={"REGO_OUTPUT_DIR": str(rego_dir), "POLICY_WRITER_DUMP_REGO": "true"},
    )
    return idp, store, opa


# ======================================================================================
# Total-corpus dimension, PRB level
# ======================================================================================


@pytest.fixture(scope="module")
def total_corpus_prb_result(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Run the generated total-corpus scenario through the PRB exactly once (shared by both the
    structural and correctness tests below, so the ~100-150-call run is only paid for once)."""
    require_env_or_skip("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
    corpus = generate_total_corpus(n_services=TOTAL_CORPUS_SIZE, n_roles=TOTAL_CORPUS_ROLES, seed=SCALE_SEED)
    scenario = corpus.as_namespace()
    roles, scopes = build_roles_and_scopes(scenario)

    policy_path = tmp_path_factory.mktemp("scale_total_corpus") / "policy.md"
    policy_path.write_text(corpus.policy_text)
    os.environ["AIAC_POLICY_FILE"] = str(policy_path)

    start = time.perf_counter()
    rules, reasoning_by_scope, reasoning_by_agent_role, best_effort_notes, usage_by_name = orchestrate_prb_concurrent(
        roles, scopes, scenario, best_effort=True
    )
    elapsed = time.perf_counter() - start

    return {
        "corpus": corpus,
        "scenario": scenario,
        "rules": rules,
        "reasoning_by_scope": reasoning_by_scope,
        "reasoning_by_agent_role": reasoning_by_agent_role,
        "best_effort_notes": best_effort_notes,
        "usage_by_name": usage_by_name,
        "elapsed_seconds": elapsed,
    }


def test_scale_total_corpus_structural_prb(total_corpus_prb_result: dict, record_property) -> None:
    """Total-corpus dimension, PRB level: every generated decision ran (completeness), no
    duplicate/orphaned rule (no-duplication/no-orphans) -- gated. Latency/cost are reported and
    trended, never gated (no SLA exists anywhere in the spec/issue)."""
    scenario = total_corpus_prb_result["scenario"]
    missing = missing_decisions(
        scenario, total_corpus_prb_result["reasoning_by_scope"], total_corpus_prb_result["reasoning_by_agent_role"]
    )
    duplicates = duplicate_rule_triples(total_corpus_prb_result["rules"])
    orphans = orphaned_scope_names(scenario)
    cost = summarize_usage(total_corpus_prb_result["usage_by_name"])
    best_effort_notes = total_corpus_prb_result["best_effort_notes"]

    record_property("missing_decisions", missing)
    record_property("duplicate_triples", duplicates)
    record_property("orphaned_scopes", orphans)
    record_property("wall_clock_seconds", total_corpus_prb_result["elapsed_seconds"])
    record_property("total_tokens", cost.total_tokens)
    record_property("token_coverage", cost.coverage)
    record_property("decision_count", cost.total_calls)
    record_property("best_effort_notes", best_effort_notes)
    # Common fields every Scale structural test records, regardless of dimension -- lets
    # eval.trend_log.pool_scale_metrics pool both dimensions' rows with one shared shape rather
    # than needing to know each dimension's own field taxonomy. See that function's docstring.
    record_property("structural_pass", not missing and not duplicates and not orphans)
    record_property("structural_issue_count", len(missing) + len(duplicates) + len(orphans))
    print(
        f"[scale:total_corpus:structural:prb] decisions={cost.total_calls} "
        f"wall_clock={total_corpus_prb_result['elapsed_seconds']:.1f}s tokens={cost.total_tokens} "
        f"(coverage={cost.coverage:.2f}) missing={missing} duplicates={duplicates} orphans={orphans} "
        f"best_effort_notes={best_effort_notes or '{}'}"
    )
    assert not missing, f"decisions never ran: {missing}"
    assert not duplicates, f"duplicate (role, scope, effect) triples: {duplicates}"
    assert not orphans, f"scopes unreachable by any role: {orphans}"


def test_scale_total_corpus_correctness_prb(total_corpus_prb_result: dict, record_property) -> None:
    """Total-corpus dimension, PRB level: the PRB's grant/deny output, scored against the
    generated corpus's ground truth via the same precision/recall scorer every sibling suite uses.
    Zero-tolerance over-grant gate; under-grants/incorrect denials reported only."""
    scenario = total_corpus_prb_result["scenario"]
    rules = total_corpus_prb_result["rules"]
    granted = grant_sets(scenario, [r for r in rules if r.effect == RuleEffect.ALLOW])
    denied = grant_sets(scenario, [r for r in rules if r.effect == RuleEffect.DENY])
    expected = truth(scenario)
    score = score_scenario("scale_total_corpus", granted, denied, expected)

    over_grants = {g: sorted(p) for g, p in score.over_grants.items()}
    under_grants = {g: sorted(p) for g, p in score.under_grants.items()}
    incorrectly_denied = {g: sorted(p) for g, p in score.incorrectly_denied.items()}

    record_property("precision", score.precision)
    record_property("recall", score.recall)
    record_property("denial_precision", score.denial_precision)
    record_property("over_grants", over_grants)
    record_property("under_grants", under_grants)
    record_property("incorrectly_denied", incorrectly_denied)
    record_property("best_effort_notes", total_corpus_prb_result["best_effort_notes"])
    record_property("true_positives", score.true_positive_count)
    record_property("denied_total", score.denied_total)
    print(
        f"[scale:total_corpus:correctness:prb] precision={score.precision:.3f} "
        f"recall={score.recall:.3f} denial_precision={score.denial_precision:.3f}\n"
        f"  over_grants={over_grants or '{}'}\n"
        f"  under_grants={under_grants or '{}'}"
    )
    assert score.passed, f"PRB over-granted in the total-corpus scenario -- zero-tolerance gate: {over_grants}"


# ======================================================================================
# Per-decision dimension, PRB level
# ======================================================================================


@pytest.fixture(scope="module")
def per_decision_prb_result(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Run the two generated per-decision scenarios (one SCOPE_GRAPH call facing a large
    candidate-role list, one symmetric ROLE_GRAPH call facing a large candidate-scope list)
    exactly once, shared by the structural and correctness tests below. Sequential, not
    concurrent: only two calls total, and each needs its own distinct ``AIAC_POLICY_FILE`` --
    running them concurrently would race on that shared process env var for no wall-clock benefit
    (see ``eval.scale_prb``'s module docstring on why total-corpus's ~100+ *independent* calls
    warrant threading and these two single calls don't)."""
    require_env_or_skip("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")
    corpus = generate_per_decision(n_candidates=PER_DECISION_CANDIDATES, seed=SCALE_SEED)
    tmp_dir = tmp_path_factory.mktemp("scale_per_decision")
    start = time.perf_counter()

    candidate_roles = [
        Role(id=f"role-{n}", name=n, description="", composite=False, kind=RoleKind.USER)
        for n in corpus.scope_candidate_roles
    ]
    focal_scope = Scope(id="scope-focal", name=FOCAL_SCOPE_NAME, description="", serviceId="scale-tool-per-decision")
    (tmp_dir / "scope_policy.md").write_text(corpus.scope_policy_text)
    os.environ["AIAC_POLICY_FILE"] = str(tmp_dir / "scope_policy.md")
    scope_rules, _, scope_note, scope_usage = _invoke_with_usage(
        SCOPE_GRAPH, roles=candidate_roles, scope=focal_scope, best_effort=True
    )
    scope_selected = [r.role.name for r in scope_rules if r.effect == RuleEffect.ALLOW]
    scope_denied = [r.role.name for r in scope_rules if r.effect == RuleEffect.DENY]

    candidate_scopes = [
        Scope(id=f"scope-{n}", name=n, description="", serviceId="scale-tool-per-decision")
        for n in corpus.role_candidate_scopes
    ]
    focal_role = Role(id="role-focal", name=FOCAL_ROLE_NAME, description="", composite=False, kind=RoleKind.AGENT)
    (tmp_dir / "role_policy.md").write_text(corpus.role_policy_text)
    os.environ["AIAC_POLICY_FILE"] = str(tmp_dir / "role_policy.md")
    role_rules, _, role_note, role_usage = _invoke_with_usage(
        ROLE_GRAPH, role=focal_role, scopes=candidate_scopes, best_effort=True
    )
    role_selected = [r.scope.name for r in role_rules if r.effect == RuleEffect.ALLOW]
    role_denied = [r.scope.name for r in role_rules if r.effect == RuleEffect.DENY]
    elapsed = time.perf_counter() - start

    return {
        "corpus": corpus,
        "elapsed_seconds": elapsed,
        "scope_candidate_names": corpus.scope_candidate_roles,
        "scope_selected": scope_selected,
        "scope_denied": scope_denied,
        "scope_rules": scope_rules,
        "scope_note": scope_note,
        "scope_usage": scope_usage,
        "role_candidate_names": corpus.role_candidate_scopes,
        "role_selected": role_selected,
        "role_denied": role_denied,
        "role_rules": role_rules,
        "role_note": role_note,
        "role_usage": role_usage,
    }


def test_scale_per_decision_structural_prb(per_decision_prb_result: dict, record_property) -> None:
    """Per-decision dimension, PRB level: no hallucinated candidate name in the PRB's response
    (fidelity, gated) and no duplicate rule. Latency/cost are reported and trended, never gated.

    Completeness here is *not* "every candidate appears in selected or denied" -- production's own
    selection schema carries only explicit grants/prohibitions with no enumerated "everyone else is
    denied" complement (see ``eval.scale_structural.invalid_selected_names``'s docstring), so a
    candidate absent from both is an ordinary implicit deny. A truncation/needle-in-a-haystack
    failure instead shows up as an under-grant in the correctness test below."""
    r = per_decision_prb_result
    scope_invalid = invalid_selected_names(r["scope_candidate_names"], r["scope_selected"], r["scope_denied"])
    role_invalid = invalid_selected_names(r["role_candidate_names"], r["role_selected"], r["role_denied"])
    scope_duplicates = duplicate_rule_triples(r["scope_rules"])
    role_duplicates = duplicate_rule_triples(r["role_rules"])
    cost = summarize_usage({"scope_decision": r["scope_usage"], "role_decision": r["role_usage"]})
    best_effort_notes = {k: v for k, v in (("scope_decision", r["scope_note"]), ("role_decision", r["role_note"])) if v}

    record_property("scope_invalid_names", scope_invalid)
    record_property("role_invalid_names", role_invalid)
    record_property("duplicate_triples", scope_duplicates + role_duplicates)
    record_property("wall_clock_seconds", r["elapsed_seconds"])
    record_property("total_tokens", cost.total_tokens)
    record_property("token_coverage", cost.coverage)
    record_property("best_effort_notes", best_effort_notes)
    # Common fields every Scale structural test records -- see the total-corpus test's own
    # comment on why, and eval.trend_log.pool_scale_metrics's docstring.
    no_issues = not scope_invalid and not role_invalid and not scope_duplicates and not role_duplicates
    record_property("structural_pass", no_issues)
    record_property(
        "structural_issue_count", len(scope_invalid) + len(role_invalid) + len(scope_duplicates) + len(role_duplicates)
    )
    print(
        f"[scale:per_decision:structural:prb] n_candidates={len(r['scope_candidate_names'])} "
        f"wall_clock={r['elapsed_seconds']:.1f}s tokens={cost.total_tokens} (coverage={cost.coverage:.2f}) "
        f"scope_invalid={scope_invalid} role_invalid={role_invalid} "
        f"best_effort_notes={best_effort_notes or '{}'}"
    )
    assert not scope_invalid, f"hallucinated candidate role name(s) in the scope-direction response: {scope_invalid}"
    assert not role_invalid, f"hallucinated candidate scope name(s) in the role-direction response: {role_invalid}"
    assert not scope_duplicates and not role_duplicates, (
        f"duplicate (role, scope, effect) triples: {scope_duplicates + role_duplicates}"
    )


def test_scale_per_decision_correctness_prb(per_decision_prb_result: dict, record_property) -> None:
    """Per-decision dimension, PRB level: the PRB's selection over the large candidate list,
    scored against the generated ground truth via ``correctness_scorer.score_scenario`` -- the
    exact same call every sibling correctness suite makes, treating the two directions
    (scope-focal, role-focal) as two "gates" the way a real scenario's three gates are, so this
    test's report rendering and trend-log pooling are identical to ``test_scale_total_corpus_
    correctness_prb``'s with no special-casing. Each candidate becomes a ``(role_name,
    scope_name)`` pair against the fixed focal entity, matching every other suite's pair
    convention -- required so the report's pair-unpacking rendering
    (``eval/conftest.py``'s ``_format_pairs_dict``) works unmodified."""
    r = per_decision_prb_result
    corpus = r["corpus"]

    granted = {
        "scope_direction": {(role, FOCAL_SCOPE_NAME) for role in r["scope_selected"]},
        "role_direction": {(FOCAL_ROLE_NAME, scope) for scope in r["role_selected"]},
    }
    denied = {
        "scope_direction": {(role, FOCAL_SCOPE_NAME) for role in r["scope_denied"]},
        "role_direction": {(FOCAL_ROLE_NAME, scope) for scope in r["role_denied"]},
    }
    expected = {
        "scope_direction": {(role, FOCAL_SCOPE_NAME) for role in corpus.scope_granted_roles},
        "role_direction": {(FOCAL_ROLE_NAME, scope) for scope in corpus.role_granted_scopes},
    }
    score = score_scenario("scale_per_decision", granted, denied, expected)

    over_grants = {g: sorted(p) for g, p in score.over_grants.items()}
    under_grants = {g: sorted(p) for g, p in score.under_grants.items()}
    incorrectly_denied = {g: sorted(p) for g, p in score.incorrectly_denied.items()}

    record_property("precision", score.precision)
    record_property("recall", score.recall)
    record_property("denial_precision", score.denial_precision)
    record_property("over_grants", over_grants)
    record_property("under_grants", under_grants)
    record_property("incorrectly_denied", incorrectly_denied)
    record_property("true_positives", score.true_positive_count)
    record_property("denied_total", score.denied_total)
    print(
        f"[scale:per_decision:correctness:prb] precision={score.precision:.3f} "
        f"recall={score.recall:.3f} denial_precision={score.denial_precision:.3f}\n"
        f"  over_grants={over_grants or '{}'}\n"
        f"  under_grants={under_grants or '{}'}"
    )
    assert score.passed, f"PRB over-granted in the per-decision scenario -- zero-tolerance gate: {over_grants}"


# ======================================================================================
# Total-corpus dimension, end-to-end level
# ======================================================================================


@pytest.fixture(scope="module")
def total_corpus_e2e_result(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Provision the generated total-corpus scenario through real Keycloak, run the PRB
    concurrently, apply via the real Policy Computation Engine, and render real Rego through the
    real PDP Policy Writer + OPA -- the only level that can catch merge/rendering/OPA-semantics
    bugs a PRB-only check can't see (same rationale as ``test_e2e_correctness``). Reuses
    ``eval.test_policy_pipeline_eval``'s ``provision_keycloak_admin``/``provision_via_config``/
    ``_read_back`` **unmodified** -- both provisioning functions are already generic over any
    scenario's own ``AGENTS``/``TOOLS``/``USER_ROLES`` dicts, so the generated corpus needs no
    special-casing there.

    Deliberately pays for the full ~100-150-call PRB run a second time rather than reusing
    ``total_corpus_prb_result``'s already-computed rules: this fixture's own PRB run is against
    Keycloak-sourced ``Role``/``Scope`` objects (``read_back_idp``), not the PRB-level fixture's
    locally-constructed ones, and the two levels are meant to measure independent samples of LLM
    run-to-run variance rather than share one run's output -- so this is the deliberate cost of
    checking the PRB-level and e2e-level results separately, not an oversight to dedupe."""
    require_env_or_skip(
        "KEYCLOAK_URL", "KEYCLOAK_ADMIN_USERNAME", "KEYCLOAK_ADMIN_PASSWORD", "LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY"
    )
    opa_bin()  # skip cleanly if opa is not on PATH / OPA_BIN unset
    corpus = generate_total_corpus(n_services=TOTAL_CORPUS_SIZE, n_roles=TOTAL_CORPUS_ROLES, seed=SCALE_SEED)
    scenario = corpus.as_namespace()

    rego_dir = HERE / "rego_out" / "policy_pipeline_scale" / "total_corpus"
    idp, store, opa = _provision_scale_realm_and_services(
        scenario, rego_dir=rego_dir, db_prefix="aiac-store-scale-total-corpus-", ports=_TOTAL_CORPUS_E2E_PORTS
    )

    policy_path = tmp_path_factory.mktemp("scale_total_corpus_e2e") / "policy.md"
    policy_path.write_text(corpus.policy_text)
    os.environ["AIAC_POLICY_FILE"] = str(policy_path)
    with running_services([idp, store, opa], src=SRC):
        config = Configuration.for_realm(scenario.REALM_DEFAULT)
        provision_via_config(config, scenario)
        roles, scopes = read_back_idp(config)
        _fix_agent_role_actor_ids(config, roles, scenario)
        start = time.perf_counter()
        orchestrated = orchestrate_prb_concurrent(roles, scopes, scenario, best_effort=True)
        rules, reasoning_by_scope, reasoning_by_agent_role, best_effort_notes, usage_by_name = orchestrated
        compute_and_apply(rules, override=False)
        elapsed = time.perf_counter() - start

    return {
        "corpus": corpus,
        "scenario": scenario,
        "rego_dir": rego_dir,
        "rules": rules,
        "reasoning_by_scope": reasoning_by_scope,
        "reasoning_by_agent_role": reasoning_by_agent_role,
        "best_effort_notes": best_effort_notes,
        "usage_by_name": usage_by_name,
        "elapsed_seconds": elapsed,
    }


def test_scale_total_corpus_structural_e2e(total_corpus_e2e_result: dict, record_property) -> None:
    """Total-corpus dimension, e2e level: every generated PRB decision ran, every agent's
    inbound+outbound Rego actually landed on disk (completeness), no duplicate PRB rule and no
    orphaned scope (no-duplication/no-orphans) -- gated. Latency/cost (now including PCE+Rego
    rendering, not just the PRB) are reported and trended, never gated."""
    scenario = total_corpus_e2e_result["scenario"]
    rego_dir = total_corpus_e2e_result["rego_dir"]
    rules = total_corpus_e2e_result["rules"]
    missing_decisions_ = missing_decisions(
        scenario, total_corpus_e2e_result["reasoning_by_scope"], total_corpus_e2e_result["reasoning_by_agent_role"]
    )

    # Rego is expected only for an agent the PRB actually produced at least one rule for (its own
    # inbound scope, or one of its own agent roles) -- NOT unconditionally for every agent. The
    # generator's repair pass (eval.scale_generator) guarantees every scope is reachable in the
    # *ground truth*, but a live LLM can still legitimately propose zero grants for one agent's
    # every decision (a real correctness finding, already tracked/reported -- non-gating -- by the
    # correctness test's under_grants); treating that as a *structural* completeness failure would
    # double-penalize the same LLM behavior under two different checks and make this "stable
    # regression guard" flake on ordinary LLM variance rather than on an actual pipeline defect. A
    # genuine rendering/merge-engine bug still surfaces here for any agent that DID get rules.
    agent_role_names = {agent_id: set(agent["roles"]) for agent_id, agent in scenario.AGENTS.items()}
    agents_with_rules: set[str] = set()
    for rule in rules:
        if rule.scope.serviceId in scenario.AGENTS:
            agents_with_rules.add(rule.scope.serviceId)
        for agent_id, role_names in agent_role_names.items():
            if rule.role.name in role_names:
                agents_with_rules.add(agent_id)
    agents_with_no_rules = sorted(set(scenario.AGENTS) - agents_with_rules)

    rego_paths = [
        (f"{agent_id}/{direction}", _rego_path(rego_dir, agent_id, direction))
        for agent_id in agents_with_rules
        for direction in ("inbound", "outbound")
    ]
    missing_files = missing_rego(rego_paths)
    duplicates = duplicate_rule_triples(rules)
    orphans = orphaned_scope_names(scenario)
    cost = summarize_usage(total_corpus_e2e_result["usage_by_name"])
    best_effort_notes = total_corpus_e2e_result["best_effort_notes"]

    record_property("missing_decisions", missing_decisions_)
    record_property("missing_rego", missing_files)
    record_property("agents_with_no_rules", agents_with_no_rules)  # reported only, see above
    record_property("duplicate_triples", duplicates)
    record_property("orphaned_scopes", orphans)
    record_property("wall_clock_seconds", total_corpus_e2e_result["elapsed_seconds"])
    record_property("total_tokens", cost.total_tokens)
    record_property("token_coverage", cost.coverage)
    record_property("best_effort_notes", best_effort_notes)
    issue_count = len(missing_decisions_) + len(missing_files) + len(duplicates) + len(orphans)
    record_property("structural_pass", issue_count == 0)
    record_property("structural_issue_count", issue_count)
    print(
        f"[scale:total_corpus:structural:e2e] wall_clock={total_corpus_e2e_result['elapsed_seconds']:.1f}s "
        f"tokens={cost.total_tokens} (coverage={cost.coverage:.2f}) missing_decisions={missing_decisions_} "
        f"missing_rego={missing_files} agents_with_no_rules={agents_with_no_rules} duplicates={duplicates} "
        f"orphans={orphans} best_effort_notes={best_effort_notes or '{}'}"
    )
    assert not missing_decisions_, f"decisions never ran: {missing_decisions_}"
    assert not missing_files, f"agent/direction with no rendered rego despite having rules: {missing_files}"
    assert not duplicates, f"duplicate (role, scope, effect) triples: {duplicates}"
    assert not orphans, f"scopes unreachable by any role: {orphans}"


def test_scale_total_corpus_correctness_e2e(total_corpus_e2e_result: dict, record_property) -> None:
    """Total-corpus dimension, e2e level: the real Keycloak+PCE+OPA pipeline's rendered grant/deny
    output, sourced from the rendered Rego data maps
    (``eval.test_policy_pipeline_correctness_e2e._e2e_grant_sets``, reused unmodified), scored
    against the generated corpus's ground truth. Zero-tolerance over-grant gate."""
    scenario = total_corpus_e2e_result["scenario"]
    granted, denied = _e2e_grant_sets(total_corpus_e2e_result, scenario)
    expected = truth(scenario)
    score = score_scenario("scale_total_corpus_e2e", granted, denied, expected)

    over_grants = {g: sorted(p) for g, p in score.over_grants.items()}
    under_grants = {g: sorted(p) for g, p in score.under_grants.items()}
    incorrectly_denied = {g: sorted(p) for g, p in score.incorrectly_denied.items()}

    record_property("precision", score.precision)
    record_property("recall", score.recall)
    record_property("denial_precision", score.denial_precision)
    record_property("over_grants", over_grants)
    record_property("under_grants", under_grants)
    record_property("incorrectly_denied", incorrectly_denied)
    record_property("best_effort_notes", total_corpus_e2e_result["best_effort_notes"])
    record_property("true_positives", score.true_positive_count)
    record_property("denied_total", score.denied_total)
    print(
        f"[scale:total_corpus:correctness:e2e] precision={score.precision:.3f} "
        f"recall={score.recall:.3f} denial_precision={score.denial_precision:.3f}\n"
        f"  over_grants={over_grants or '{}'}\n"
        f"  under_grants={under_grants or '{}'}"
    )
    assert score.passed, f"E2E pipeline over-granted in the total-corpus scenario -- zero-tolerance gate: {over_grants}"


# ======================================================================================
# Per-decision dimension, end-to-end level
# ======================================================================================


@pytest.fixture(scope="module")
def per_decision_e2e_result(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """Provision ``eval.scale_generator.PerDecisionCorpus.e2e_scenario`` -- two agents, one owning
    the per-decision focal scope, one owning the per-decision focal role plus a tool owning every
    candidate scope -- through real Keycloak, then call ``_invoke_graph`` **directly** (not
    ``orchestrate_prb_concurrent``'s loop: there are exactly two decisions to make here, named
    explicitly, not a whole scenario's worth to enumerate) for each of the two per-decision calls,
    and apply both rule sets via the real Policy Computation Engine so real Rego gets rendered for
    both agents."""
    require_env_or_skip(
        "KEYCLOAK_URL", "KEYCLOAK_ADMIN_USERNAME", "KEYCLOAK_ADMIN_PASSWORD", "LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY"
    )
    opa_bin()
    corpus = generate_per_decision(n_candidates=PER_DECISION_CANDIDATES, seed=SCALE_SEED)
    scenario = corpus.e2e_scenario.as_namespace()

    rego_dir = HERE / "rego_out" / "policy_pipeline_scale" / "per_decision"
    idp, store, opa = _provision_scale_realm_and_services(
        scenario, rego_dir=rego_dir, db_prefix="aiac-store-scale-per-decision-", ports=_PER_DECISION_E2E_PORTS
    )

    tmp_dir = tmp_path_factory.mktemp("scale_per_decision_e2e")
    with running_services([idp, store, opa], src=SRC):
        config = Configuration.for_realm(scenario.REALM_DEFAULT)
        provision_via_config(config, scenario)
        roles, scopes = read_back_idp(config)
        _fix_agent_role_actor_ids(config, roles, scenario)

        candidate_role_objs = [roles[n] for n in corpus.scope_candidate_roles]
        focal_scope_obj = scopes[FOCAL_SCOPE_NAME]
        focal_role_obj = roles[FOCAL_ROLE_NAME]
        candidate_scope_objs = [scopes[n] for n in corpus.role_candidate_scopes]

        start = time.perf_counter()
        # Each direction needs AIAC_POLICY_FILE pointed at its own generated policy text (the
        # PRB's _fetch node reads it fresh per call) -- same as the PRB-level per-decision fixture,
        # and for the same reason: one process-global env var, two different policy texts, so this
        # must stay sequential, not fanned out via eval.scale_prb's concurrency helper.
        (tmp_dir / "scope_policy.md").write_text(corpus.scope_policy_text)
        os.environ["AIAC_POLICY_FILE"] = str(tmp_dir / "scope_policy.md")
        scope_rules, _, scope_note, scope_usage = _invoke_with_usage(
            SCOPE_GRAPH, roles=candidate_role_objs, scope=focal_scope_obj, best_effort=True
        )
        (tmp_dir / "role_policy.md").write_text(corpus.role_policy_text)
        os.environ["AIAC_POLICY_FILE"] = str(tmp_dir / "role_policy.md")
        role_rules, _, role_note, role_usage = _invoke_with_usage(
            ROLE_GRAPH, role=focal_role_obj, scopes=candidate_scope_objs, best_effort=True
        )
        compute_and_apply(scope_rules + role_rules, override=False)
        elapsed = time.perf_counter() - start

    return {
        "corpus": corpus,
        "scenario": scenario,
        "rego_dir": rego_dir,
        "scope_candidate_names": corpus.scope_candidate_roles,
        "scope_selected": [r.role.name for r in scope_rules if r.effect == RuleEffect.ALLOW],
        "scope_denied": [r.role.name for r in scope_rules if r.effect == RuleEffect.DENY],
        "scope_rules": scope_rules,
        "scope_note": scope_note,
        "role_candidate_names": corpus.role_candidate_scopes,
        "role_selected": [r.scope.name for r in role_rules if r.effect == RuleEffect.ALLOW],
        "role_denied": [r.scope.name for r in role_rules if r.effect == RuleEffect.DENY],
        "role_rules": role_rules,
        "role_note": role_note,
        "usage_by_name": {"scope_decision": scope_usage, "role_decision": role_usage},
        "elapsed_seconds": elapsed,
    }


def test_scale_per_decision_structural_e2e(per_decision_e2e_result: dict, record_property) -> None:
    """Per-decision dimension, e2e level: no hallucinated candidate name, no duplicate rule, and
    both agents' expected Rego file actually rendered (fidelity + completeness, gated). Latency/
    cost (now including PCE+Rego rendering) are reported and trended, never gated."""
    r = per_decision_e2e_result
    scope_invalid = invalid_selected_names(r["scope_candidate_names"], r["scope_selected"], r["scope_denied"])
    role_invalid = invalid_selected_names(r["role_candidate_names"], r["role_selected"], r["role_denied"])
    scope_duplicates = duplicate_rule_triples(r["scope_rules"])
    role_duplicates = duplicate_rule_triples(r["role_rules"])
    # PER_DECISION_SCOPE_AGENT_ID has no outbound-side roles/target-scopes at all, and
    # PER_DECISION_ROLE_AGENT_ID has no inbound scope -- both by design, not a gap, so at most
    # these two files are ever expected. But a file is expected only once the PRB actually
    # produced at least one rule for that direction: the PCE writes a CR/Rego only for a
    # scope/role some rule touches, and a live LLM can legitimately return zero rules for a
    # direction (a pure under-grant, or an exhausted best-effort fallback) -- that's a correctness
    # finding (already tracked, non-gating, by the correctness test's under_grants), not a
    # structural defect. Mirrors the total-corpus structural test's own agents_with_rules gating.
    rego_paths = []
    if r["scope_rules"]:
        rego_paths.append(
            (
                f"{PER_DECISION_SCOPE_AGENT_ID}/inbound",
                _rego_path(r["rego_dir"], PER_DECISION_SCOPE_AGENT_ID, "inbound"),
            )
        )
    if r["role_rules"]:
        rego_paths.append(
            (
                f"{PER_DECISION_ROLE_AGENT_ID}/outbound",
                _rego_path(r["rego_dir"], PER_DECISION_ROLE_AGENT_ID, "outbound"),
            )
        )
    missing_files = missing_rego(rego_paths)
    cost = summarize_usage(r["usage_by_name"])
    best_effort_notes = {k: v for k, v in (("scope_decision", r["scope_note"]), ("role_decision", r["role_note"])) if v}

    record_property("scope_invalid_names", scope_invalid)
    record_property("role_invalid_names", role_invalid)
    record_property("duplicate_triples", scope_duplicates + role_duplicates)
    record_property("missing_rego", missing_files)
    record_property("wall_clock_seconds", r["elapsed_seconds"])
    record_property("total_tokens", cost.total_tokens)
    record_property("token_coverage", cost.coverage)
    record_property("best_effort_notes", best_effort_notes)
    issue_count = (
        len(scope_invalid) + len(role_invalid) + len(scope_duplicates) + len(role_duplicates) + len(missing_files)
    )
    record_property("structural_pass", issue_count == 0)
    record_property("structural_issue_count", issue_count)
    print(
        f"[scale:per_decision:structural:e2e] n_candidates={len(r['scope_candidate_names'])} "
        f"wall_clock={r['elapsed_seconds']:.1f}s tokens={cost.total_tokens} (coverage={cost.coverage:.2f}) "
        f"scope_invalid={scope_invalid} role_invalid={role_invalid} missing_rego={missing_files} "
        f"best_effort_notes={best_effort_notes or '{}'}"
    )
    assert not scope_invalid, f"hallucinated candidate role name(s): {scope_invalid}"
    assert not role_invalid, f"hallucinated candidate scope name(s): {role_invalid}"
    assert not scope_duplicates and not role_duplicates, (
        f"duplicate (role, scope, effect) triples: {scope_duplicates + role_duplicates}"
    )
    assert not missing_files, f"expected rego files never rendered: {missing_files}"


def test_scale_per_decision_correctness_e2e(per_decision_e2e_result: dict, record_property) -> None:
    """Per-decision dimension, e2e level: the real pipeline's rendered grant/deny output for both
    decisions, sourced from the rendered Rego data maps
    (``eval.test_policy_pipeline_correctness_e2e._e2e_grant_sets``, reused unmodified -- the
    ``e2e_scenario``'s two gates, ``inbound``/``outbound_target``, separate the two directions with
    no new aggregation code), scored against the generated ground truth."""
    r = per_decision_e2e_result
    scenario = r["scenario"]
    granted, denied = _e2e_grant_sets(r, scenario)
    expected = truth(scenario)
    score = score_scenario("scale_per_decision_e2e", granted, denied, expected)

    over_grants = {g: sorted(p) for g, p in score.over_grants.items()}
    under_grants = {g: sorted(p) for g, p in score.under_grants.items()}
    incorrectly_denied = {g: sorted(p) for g, p in score.incorrectly_denied.items()}

    record_property("precision", score.precision)
    record_property("recall", score.recall)
    record_property("denial_precision", score.denial_precision)
    record_property("over_grants", over_grants)
    record_property("under_grants", under_grants)
    record_property("incorrectly_denied", incorrectly_denied)
    record_property("true_positives", score.true_positive_count)
    record_property("denied_total", score.denied_total)
    print(
        f"[scale:per_decision:correctness:e2e] precision={score.precision:.3f} "
        f"recall={score.recall:.3f} denial_precision={score.denial_precision:.3f}\n"
        f"  over_grants={over_grants or '{}'}\n"
        f"  under_grants={under_grants or '{}'}"
    )
    assert score.passed, f"E2E pipeline over-granted in the per-decision scenario -- zero-tolerance gate: {over_grants}"
