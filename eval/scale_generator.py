"""Procedural corpus generator for the Scale suite (spec: ``docs/evaluation/policy-eval-scale.md``,
``docs/evaluation/eval-framework.md`` §5).

Hand-authored truth tables (the primary Correctness corpus's approach) don't scale past low double
digits of entities, so Scale instead builds policy+truth pairs **procedurally**: a small, seeded,
deterministic grammar decides every ``(role, scope)`` grant fact itself, so the ground truth is
known *by construction* rather than needing a human (or an LLM) to derive it after the fact. The
same policy text is rendered directly from those facts, so text and truth can never drift apart.

Two entry points, one per scale dimension (spec §5's table):

- ``generate_total_corpus`` — many roles/scopes/services overall, each individual PRB decision
  still facing a modest candidate list.
- ``generate_per_decision`` — one scope (and, symmetrically, one role) facing a very large
  candidate list in a single PRB call.

Both return a :class:`ScaleCorpus` — a plain ``SimpleNamespace`` (not a ``ModuleType``, since it's
built at runtime, not imported from a file) shaped **exactly** like an existing ``eval/scenarios/``
scenario module: ``AGENTS``/``TOOLS``/``USER_ROLES``/``USERS``/``USER_PASSWORD``/``REALM_DEFAULT``/
``INBOUND_PAIRS``/``OUTBOUND_PAIRS``/``OUTBOUND_SUBJECT_PAIRS``. This is deliberate: every existing
PRB-level and end-to-end helper (``eval.prb_direct.build_roles_and_scopes``,
``eval.test_policy_pipeline_eval.orchestrate_prb``/``grant_sets``/``truth``/
``provision_keycloak_admin``/``provision_via_config``) already consumes that exact shape and needs
no changes to run against a generated corpus instead of a hand-authored one.

Policy text is rendered directly in digested-policy style (``docs/specs/digested-policy.md``'s
direct-grant grammar — "Role X may access Scope Y") rather than routed through the LLM digester
(``eval/scenarios_digested/convert_scenarios.py``): every generated fact is already unambiguous, so
there is nothing for digestion to resolve, and adding an LLM pass would only add cost and a
possible faithfulness drift between the rendered text and the ground truth it's supposed to match.
Only grant ("may access") facts are rendered — matching ``policy.eval_baseline.md``'s own digested
shape — everything not stated is denied by the PRB's own deny-by-default reading, so there is no
need for explicit "may not" lines here.

Deterministic: same ``(size params, seed)`` always yields byte-identical ``ScaleCorpus.policy_text``
and pair lists — required so a failing run is exactly reproducible, and so ``eval/
test_scale_generator.py`` can assert on fixed output.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from types import SimpleNamespace

Pair = tuple[str, str]


@dataclass(frozen=True)
class ScaleCorpus:
    """Shaped like an ``eval/scenarios/`` scenario module (see module docstring) plus the
    generated policy text every PRB call needs ``AIAC_POLICY_FILE`` pointed at."""

    REALM_DEFAULT: str
    AGENTS: dict[str, dict]
    TOOLS: dict[str, dict]
    USER_ROLES: dict[str, str]
    USERS: dict[str, str]
    USER_PASSWORD: str
    INBOUND_PAIRS: list[Pair]
    OUTBOUND_PAIRS: list[Pair]
    OUTBOUND_SUBJECT_PAIRS: list[Pair]
    policy_text: str
    # EXPECT_NO_REGO mirrors the hand-authored scenarios' own optional field (default: none
    # expected missing) -- present so this shape is a drop-in for _provision_scenario's existing
    # `getattr(scenario, "EXPECT_NO_REGO", frozenset())` read.
    EXPECT_NO_REGO: frozenset[str] = field(default_factory=frozenset)

    def as_namespace(self) -> SimpleNamespace:
        """A ``SimpleNamespace`` view carrying every field above as an attribute -- the exact
        interface every reused helper (``build_roles_and_scopes``, ``orchestrate_prb``,
        ``grant_sets``, ``truth``, ``provision_keycloak_admin``, ``provision_via_config``) reads a
        scenario ``ModuleType`` through. A ``dataclass`` already supports attribute access, but a
        plain namespace keeps every call site's ``scenario.FIELD`` reads agnostic to which of the
        two backs it -- callers should not need to care that this one wasn't ``import``ed."""
        return SimpleNamespace(**self.__dict__)


def _digested_grant_lines(pairs: list[Pair], subject_label: str, resource_label: str) -> list[str]:
    """Render one "``<subject>`` may access ``<resource>``." line per pair, in the pair list's own
    order (already deterministic -- callers build pairs by iterating sorted names)."""
    return [f"{subject_label} '{s}' may access {resource_label} '{r}'." for s, r in pairs]


def _render_total_corpus_text(inbound: list[Pair], outbound_subject: list[Pair], outbound_target: list[Pair]) -> str:
    """Digested-style text (``docs/specs/digested-policy.md``) for the total-corpus dimension: one
    direct-grant line per generated fact, grouped the same three ways
    ``eval.test_policy_pipeline_eval.grant_sets`` classifies rules -- purely for a human/LLM
    reader's benefit, since classification itself is name-based, not text-position-based."""
    lines = [
        "Domain knowledge",
        "- This is a procedurally generated access-control policy for a large corpus of services.",
        "- Access model: Least-privilege baseline -- only accesses explicitly granted below are "
        "permitted; every other access is denied.",
        "",
        "Policy statements",
        "",
        "Direct grants",
    ]
    lines += _digested_grant_lines(inbound, "Role", "Scope")
    lines += _digested_grant_lines(outbound_subject, "Role", "Scope")
    lines += _digested_grant_lines(outbound_target, "Role", "Scope")
    lines += ["", "Attribute invariants", "- (none)", "", "Role-assignment constraints", "- (none)"]
    return "\n".join(lines)


def generate_total_corpus(
    *,
    n_services: int = 100,
    n_roles: int = 10,
    seed: int = 0,
    inbound_density: float = 0.3,
    outbound_subject_density: float = 0.3,
    outbound_target_density: float = 0.5,
) -> ScaleCorpus:
    """Total-corpus dimension: ``n_services`` agents+tools (split evenly), ``n_roles`` user roles,
    one inbound scope + one agent role per agent, one scope per tool -- each individual PRB
    decision faces a modest candidate list (``n_roles`` for a scope decision, the tool-scope count
    for an agent-role decision), while the *total* decision count (``~2 * n_agents +
    n_tools``-ish, one per agent inbound scope, one per target scope, one per agent role) grows
    with ``n_services`` -- exactly the total-corpus stress the spec describes.

    ``*_density`` are the probability, per (subject, candidate) pair, that a seeded ``random.Random``
    grants it -- kept well under 1.0 so the truth table is neither degenerately full nor empty.
    Deterministic for a fixed ``(n_services, n_roles, seed, *_density)``.
    """
    rng = random.Random(seed)
    n_agents = n_services // 2
    n_tools = n_services - n_agents

    user_roles = {f"user-role-{i:03d}": f"Generated user role {i}." for i in range(n_roles)}
    user_names = sorted(user_roles)

    agents: dict[str, dict] = {}
    for i in range(n_agents):
        # "team1/" -- the PDP writer server-side-applies a real AuthorizationPolicy CR per agent
        # against a live cluster namespace matching the agent id's own namespace segment (not just
        # a local file dump), so this must be a namespace that actually exists there. Every
        # hand-authored eval scenario already shares "team1" for exactly this reason -- reused
        # here rather than inventing a new namespace that would need to be created out of band.
        agent_id = f"team1/scale-agent-{i:03d}"
        agents[agent_id] = {
            "description": f"Generated agent {i}.",
            "inbound_scopes": {f"agent-scope-{i:03d}": f"Inbound scope for generated agent {i}."},
            "delegation_scopes": {},
            "roles": {f"agent-role-{i:03d}": f"Role for generated agent {i}."},
        }

    tools: dict[str, dict] = {}
    for i in range(n_tools):
        tool_id = f"scale-tool-{i:03d}"
        tools[tool_id] = {
            "description": f"Generated tool {i}.",
            "scopes": {f"tool-scope-{i:03d}": f"Scope for generated tool {i}."},
        }

    inbound_scope_names = sorted(s for agent in agents.values() for s in agent["inbound_scopes"])
    target_scope_names = sorted(s for tool in tools.values() for s in tool["scopes"])
    agent_role_names = sorted(r for agent in agents.values() for r in agent["roles"])

    inbound_pairs = [
        (role, scope) for role in user_names for scope in inbound_scope_names if rng.random() < inbound_density
    ]
    outbound_subject_pairs = [
        (role, scope) for role in user_names for scope in target_scope_names if rng.random() < outbound_subject_density
    ]
    outbound_target_pairs = [
        (role, scope)
        for role in agent_role_names
        for scope in target_scope_names
        if rng.random() < outbound_target_density
    ]

    # Repair pass: guarantee no generated scope is orphaned (unreachable by any role in the
    # ground truth) -- with independent per-pair density, a scope can legitimately draw zero
    # grants by chance (e.g. ~3% of scopes at n_roles=10/density=0.3), which would make
    # eval.scale_structural.orphaned_scope_names fail nondeterministically on an otherwise
    # well-formed corpus rather than only on a genuine generator regression. Continues the same
    # rng stream, so this stays fully deterministic for a fixed seed.
    reachable_inbound = {s for _, s in inbound_pairs}
    for scope in inbound_scope_names:
        if scope not in reachable_inbound:
            inbound_pairs.append((rng.choice(user_names), scope))
    reachable_target = {s for _, s in outbound_subject_pairs} | {s for _, s in outbound_target_pairs}
    for scope in target_scope_names:
        if scope not in reachable_target:
            outbound_subject_pairs.append((rng.choice(user_names), scope))
            outbound_target_pairs.append((rng.choice(agent_role_names), scope))

    users = {f"scale-user-{i:03d}": role for i, role in enumerate(user_names)}

    return ScaleCorpus(
        REALM_DEFAULT=f"aiac-pp-eval-scale-total-corpus-{n_services}",
        AGENTS=agents,
        TOOLS=tools,
        USER_ROLES=user_roles,
        USERS=users,
        USER_PASSWORD="password",
        INBOUND_PAIRS=inbound_pairs,
        OUTBOUND_PAIRS=outbound_target_pairs,
        OUTBOUND_SUBJECT_PAIRS=outbound_subject_pairs,
        policy_text=_render_total_corpus_text(inbound_pairs, outbound_subject_pairs, outbound_target_pairs),
    )


@dataclass(frozen=True)
class PerDecisionCorpus:
    """Per-decision dimension: one focal scope with ``n_candidates`` candidate user roles (a
    single ``SCOPE_GRAPH`` call's worth), plus the symmetric one focal agent role with
    ``n_candidates`` candidate target scopes (a single ``ROLE_GRAPH`` call's worth). Not shaped
    like a scenario module -- this dimension drives ``_invoke_graph`` directly (one call, not
    ``orchestrate_prb``'s loop), so it only needs to hand a caller the raw candidate lists +
    ground truth for one decision, not a full agent/tool/user graph."""

    scope_candidate_roles: list[str]
    scope_granted_roles: frozenset[str]
    scope_policy_text: str
    role_candidate_scopes: list[str]
    role_granted_scopes: frozenset[str]
    role_policy_text: str
    # A ScaleCorpus-shaped view of this SAME ground truth, for the end-to-end level only: two
    # agents ("team1/scale-agent-pd-scope" owning the one focal inbound scope,
    # "team1/scale-agent-pd-role" owning the one focal agent role + a tool owning every candidate
    # scope), so the existing provisioning helpers (build_roles_and_scopes/
    # provision_keycloak_admin/provision_via_config) work unmodified -- see eval/
    # test_policy_pipeline_scale.py's per-decision e2e fixture. Kept as exactly the same
    # candidate/granted sets as scope_candidate_roles/role_candidate_scopes above -- one seed's
    # ground truth serves both levels, never re-derived.
    e2e_scenario: "ScaleCorpus"


FOCAL_SCOPE_NAME = "scale-scope-per-decision"
FOCAL_ROLE_NAME = "scale-role-per-decision"
# The two agents in PerDecisionCorpus.e2e_scenario -- named constants (not re-typed at each call
# site) so eval/test_policy_pipeline_scale.py's e2e fixture/structural test and this module agree
# by construction, never by convention.
PER_DECISION_SCOPE_AGENT_ID = "team1/scale-agent-pd-scope"
PER_DECISION_ROLE_AGENT_ID = "team1/scale-agent-pd-role"


def _render_per_decision_text(focal_description: str, grant_lines: list[str]) -> str:
    lines = [
        "Domain knowledge",
        f"- This is a procedurally generated access-control policy for {focal_description}, "
        "with a large candidate list.",
        "- Access model: Least-privilege baseline -- only accesses explicitly granted below are "
        "permitted; every other access is denied.",
        "",
        "Policy statements",
        "",
        "Direct grants",
    ]
    lines += grant_lines
    lines += ["", "Attribute invariants", "- (none)", "", "Role-assignment constraints", "- (none)"]
    return "\n".join(lines)


def generate_per_decision(*, n_candidates: int = 100, seed: int = 0, granted_density: float = 0.2) -> PerDecisionCorpus:
    """Per-decision dimension: ``n_candidates`` candidate roles for one focal scope
    (``FOCAL_SCOPE_NAME``), and (symmetrically) ``n_candidates`` candidate scopes for one focal
    agent role (``FOCAL_ROLE_NAME``) -- each drives exactly one PRB call
    (``_invoke_graph``/``SCOPE_GRAPH`` or ``ROLE_GRAPH``), the very-large-candidate-list stress the
    spec's per-decision dimension describes. Well under #2470's 1,000-entity exploratory ceiling.
    Deterministic for a fixed ``(n_candidates, seed, granted_density)``.

    Independent per-candidate density sampling can legitimately draw an all-empty grant set by
    chance at small ``n_candidates`` (a real risk when a smaller size is used for fast dev
    iteration, per ``docs/evaluation/policy-eval-scale.md``'s size-override convention) -- an
    empty ground truth would make the correctness check vacuously pass (recall trivially 1.0) and
    say nothing real. A repair pass (continuing the same rng stream, so still fully seed-
    deterministic) forces at least one grant in each direction when sampling comes up empty.
    """
    rng = random.Random(seed)

    candidate_roles = [f"user-role-{i:03d}" for i in range(n_candidates)]
    granted_roles = frozenset(name for name in candidate_roles if rng.random() < granted_density)
    if not granted_roles:
        granted_roles = frozenset({rng.choice(candidate_roles)})

    candidate_scopes = [f"tool-scope-{i:03d}" for i in range(n_candidates)]
    granted_scopes = frozenset(name for name in candidate_scopes if rng.random() < granted_density)
    if not granted_scopes:
        granted_scopes = frozenset({rng.choice(candidate_scopes)})

    e2e_scenario = ScaleCorpus(
        REALM_DEFAULT=f"aiac-pp-eval-scale-per-decision-{n_candidates}",
        AGENTS={
            PER_DECISION_SCOPE_AGENT_ID: {
                "description": "Generated agent owning the per-decision focal scope.",
                "inbound_scopes": {FOCAL_SCOPE_NAME: "The per-decision focal scope."},
                "delegation_scopes": {},
                "roles": {},
            },
            PER_DECISION_ROLE_AGENT_ID: {
                "description": "Generated agent owning the per-decision focal role.",
                "inbound_scopes": {},
                "delegation_scopes": {},
                "roles": {FOCAL_ROLE_NAME: "The per-decision focal agent role."},
            },
        },
        TOOLS={
            "scale-tool-pd-role": {
                "description": "Generated tool owning every per-decision candidate scope.",
                "scopes": {name: f"Candidate scope {name}." for name in candidate_scopes},
            }
        },
        USER_ROLES={name: f"Candidate role {name}." for name in candidate_roles},
        USERS={},
        USER_PASSWORD="password",
        # Ground truth for the two directions lives on two different gates -- INBOUND_PAIRS is the
        # scope-direction decision (candidate roles reaching the one focal inbound scope),
        # OUTBOUND_PAIRS is the role-direction decision (the one focal agent role reaching
        # candidate target scopes) -- so eval.test_policy_pipeline_eval.truth()'s existing
        # three-gate shape separates them with no new aggregation code.
        INBOUND_PAIRS=[(role, FOCAL_SCOPE_NAME) for role in sorted(granted_roles)],
        OUTBOUND_PAIRS=[(FOCAL_ROLE_NAME, scope) for scope in sorted(granted_scopes)],
        OUTBOUND_SUBJECT_PAIRS=[],
        policy_text="",  # unused at the e2e level -- each agent's own inbound/outbound rego is
        # rendered from whatever PolicyRules the caller directly computes with _invoke_graph and
        # hands to compute_and_apply, not from a policy document read off AIAC_POLICY_FILE.
    )

    return PerDecisionCorpus(
        scope_candidate_roles=candidate_roles,
        scope_granted_roles=granted_roles,
        scope_policy_text=_render_per_decision_text(
            f"one scope, '{FOCAL_SCOPE_NAME}'",
            [f"Role '{role}' may access Scope '{FOCAL_SCOPE_NAME}'." for role in sorted(granted_roles)],
        ),
        role_candidate_scopes=candidate_scopes,
        role_granted_scopes=granted_scopes,
        role_policy_text=_render_per_decision_text(
            f"one agent role, '{FOCAL_ROLE_NAME}'",
            [f"Role '{FOCAL_ROLE_NAME}' may access Scope '{scope}'." for scope in sorted(granted_scopes)],
        ),
        e2e_scenario=e2e_scenario,
    )
