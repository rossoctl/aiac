"""Policy-B ("denyworld") oracle — the pure-data truth for the ``default_effect=ALLOW`` full-deployment
integration test (``test_policy_pipeline_denyworld.py``). Source of truth:
``aiac/docs/handoffs/02-policy-b-deny-full-deployment.md`` §5, §6, §7.1.

**Sibling of ``scenario_uc1``, not a parametrization of it.** ``scenario_uc1`` encodes its truth as
**ALLOW** pair-lists over a deny-by-default base (``default_effect=DENY``); Policy B's truth is
naturally expressed as **DENY** sets over a **permissive** base (``default_effect=ALLOW``).
Parametrizing one module to carry two opposite default semantics would tangle both fact triads, so
each scenario keeps its own coherent triad. The two scenarios run **sequentially on the same shared
stack** (one ``policy.md`` mounted at a time), so the *deployed workloads* are identical — this module
therefore **reuses** the deployment-fixed constants from ``scenario_uc1`` (``USERS``, ``USER_ROLES``,
``AGENT_SCOPES``, ``AGENT_ROLES``, ``TOOL_SCOPES``, ``REALM_DEFAULT``, ``DEMO_NAMESPACE_DEFAULT``,
``AGENT_WORKLOAD``, ``TOOL_WORKLOAD``, ``bare``) rather than redefining them.

**Why the DENY sets are load-bearing (the whole point).** Under the shipped ``default=DENY`` an
explicit ``DENY`` rule is invisible at the enforced seam: an ungranted pair is already denied by the
absence of an ALLOW. Policy B is deployed under ``default_effect=ALLOW``, where an unmentioned pair is
**allowed** by default — so a ``DENY`` rule is the *only* thing that can deny a pair, and the deny
becomes fully **observable**. Every ❌ in the §6 matrix is therefore a load-bearing explicit ``DENY``;
if any DENY is dropped anywhere in the chain (PRB → PCE → Rego → bundle → OPA) the corresponding cell
flips back to allow and the live test fails.

**Every prohibition targets a pair the role's own description does NOT support** — so no DENY
contradicts a description-derived capability grant. (Resolving a prohibition that *does* contradict a
capability grant — e.g. denying the developer, whose description "consults issues", from issues — is
deferred future work; this scenario avoids it by leaving the developer **unconstrained**: its
description spans source and reading issues, so under the permissive default it is fully allowed and
carries no DENY at all.)

**Both PRB deny idioms are exercised** (handoff §5), over conflict-free pairs:
  - *exclusivity* — "testers may access only issues" ⇒ ALLOW tester→issues-* **and DENY** tester→source-*
    (the tester description works "in the issue tracker, not in source", so the DENY contradicts nothing).
    The ALLOW half is **inert** under ``default=ALLOW`` — everything not denied is already allowed — so
    the enforced matrix and this oracle depend only on the DENY half.
  - *direct prohibition* — "DevOps may not access source" ⇒ **DENY** devops→source-* only (no ALLOW
    derived; the devops description "does not author source code"). DevOps is **not** prohibited from
    issues and derives no ALLOW there, so ``devops→issues-*`` carries **no explicit rule at all** and is
    allowed **purely by the permissive default** — the signature that ``default=ALLOW`` is live (these
    cells are **deny** under Policy A). ``developer→*`` is likewise unconstrained and allowed by the
    default; ``developer→issues-write`` (deny under Policy A) is a second such default-flip tracer.

**Prefixed provisioned names vs. bare runtime names** (same convention as ``scenario_uc1``): the DENY
pair-lists hold the **prefixed** names the PCE writes into the CR data maps (``github-tool.source-read``
…), while AuthBridge's ``mcp-parser`` puts the **bare** invoked tool name into
``input.mcp.params.name`` (``source-read``). ``OUTBOUND_SUBJECT_DENY_BARE`` derives the bare forms from
the prefixed pair-list via the **shared** ``bare()`` so there is exactly one source of truth.

This module is **pure data**: it imports only ``scenario_uc1`` (which itself imports nothing, so this
module stays importable before any env-before-import step, exactly like ``scenario_uc1``).
"""

from __future__ import annotations

from test.integration import scenario_uc1 as scn

# --- Reused deployment-fixed constants (identical deployed workloads for Policy A and B) -----
#
# Re-exported by reference so denyworld callers and the contract tests can use a single ``scn_b``
# handle without reaching back into ``scenario_uc1`` for the shared truth. These describe the
# *deployed workloads*, which are the same for both policies.

USERS = scn.USERS
USER_ROLES = scn.USER_ROLES
AGENT_SCOPES = scn.AGENT_SCOPES
AGENT_ROLES = scn.AGENT_ROLES
TOOL_SCOPES = scn.TOOL_SCOPES
REALM_DEFAULT = scn.REALM_DEFAULT
DEMO_NAMESPACE_DEFAULT = scn.DEMO_NAMESPACE_DEFAULT
AGENT_WORKLOAD = scn.AGENT_WORKLOAD
TOOL_WORKLOAD = scn.TOOL_WORKLOAD
bare = scn.bare


# --- The mounted Policy B prose (handoff §5, verbatim) --------------------------------------
#
# User-intent prose that includes prohibitions; constrains **user roles only** (never the agent's own
# operator roles), exactly like Policy A's ``POLICY_ABSTRACT``. The AIAC pod mounts its own
# ``policy.md`` (via AIAC_POLICY_FILE); the denyworld harness swaps this in for the Policy-A prose.
POLICY_DENYWORLD = """\
Grant access on a permissive basis: allow by default; state only the prohibitions and the
exclusive scoping that narrow access.

- Testers may access only issues; they may not access source.
- DevOps may not access source.
"""


# --- DENY pair-lists over the DISCOVERED, PREFIXED names (the single source of truth) --------
#
# Mirrors ``scenario_uc1``'s prefixed convention (``github-tool.<scope>``). Each maps 1:1 to a
# generated Rego DENY gate. The subject gate carries the four denies from the §6 matrix; there are no
# inbound denies and no target/capability-gate denies under this prose (§6, §7.1). Every deny targets a
# (role, scope) pair the role's own description does NOT support, so none contradicts a capability grant
# (the developer, whose description consults issues, carries no prohibition — it is left unconstrained).

OUTBOUND_SUBJECT_DENY_PAIRS: list[tuple[str, str]] = [
    ("tester", "github-tool.source-read"),       # exclusivity complement (tester → issues only)
    ("tester", "github-tool.source-write"),
    ("devops", "github-tool.source-read"),        # direct prohibition (DevOps may not access source)
    ("devops", "github-tool.source-write"),
]

# No inbound denies and no target-side denies under this prose (§6): the PRB emits denies only at the
# fine tool-scope layer, and the prose constrains user roles only (not the agent's operator roles).
INBOUND_SUBJECT_DENY_PAIRS: list[tuple[str, str]] = []
OUTBOUND_TARGET_DENY_PAIRS: list[tuple[str, str]] = []


# --- Bare runtime deny set (what AuthBridge sends; what the live test crafts + expects) ------
#
# Derived from the prefixed pair-list above via the shared ``bare()`` so the prefixed truth stays the
# single source of truth (one split on the first ``.``, matching ``rego.py``'s ``_deprefix``).
OUTBOUND_SUBJECT_DENY_BARE: set[tuple[str, str]] = {
    (role, bare(scope)) for role, scope in OUTBOUND_SUBJECT_DENY_PAIRS
}

# Set of role names that carry an explicit inbound DENY (empty here) — the inbound oracle keys on it.
_INBOUND_DENY_ROLES: set[str] = {role for role, _ in INBOUND_SUBJECT_DENY_PAIRS}


# --- Deny-based oracle (verdicts computed from the deny sets under default=ALLOW) ------------
#
# These compute the intended verdict **from the deny sets under ``default=ALLOW``**, never from the
# Rego under test — so the live test's expected values are independent of the artifact it validates.


def expected_inbound_denyworld(subject: str) -> bool:
    """Inbound verdict for ``subject`` under ``default=ALLOW``. A subject is denied inbound only if an
    explicit inbound DENY removes its reach to the agent. Policy B emits **no** inbound denies
    (``INBOUND_SUBJECT_DENY_PAIRS`` is empty), so all three roles reach the agent — including devops,
    which is **deny** under Policy A's ``default=DENY``."""
    return scn.USERS[subject] not in _INBOUND_DENY_ROLES


def expected_outbound_denyworld_bare(subject: str, tool_bare: str) -> bool:
    """Outbound verdict for ``subject`` calling the **bare** tool name ``tool_bare`` under
    ``default=ALLOW``: allowed **unless** the subject gate explicitly denies this ``(role, tool)``
    pair. The target/capability gate emits no denies under Policy B (the prose constrains user roles
    only), so it never blocks — the matrix is driven purely by the subject-side denies."""
    return (scn.USERS[subject], tool_bare) not in OUTBOUND_SUBJECT_DENY_BARE
