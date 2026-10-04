"""Policy Computation Engine (SPM-based, order-independent).

A pure library that folds partial ``list[PolicyRule]`` updates into the persistent, per-service
source of truth — ``ServicePolicyModel`` (SPM) — and then deploys the **policy model** of the
affected services to the PDP Policy Writer.

Why SPMs. The previous design persisted only per-agent APMs with rules denormalised onto the
agent, which made the merge outcome depend on onboarding order (``UR→TS`` was dropped when the
tool onboarded before any agent targeted it). Here every rule ``(role → scope)`` is stored as an
inbound edge on ``SPM(scope.serviceId)`` — the service that *owns* the scope — so the fact
survives regardless of which services already exist, and both onboarding orders converge to the
same stored SPMs.

The enforcement side (D16, D29). ``enforcement_side()`` reads ``AIAC_ENFORCEMENT_SIDE``
(``target-side``, the default, or ``agent-side``). Each public operation reads it once and builds
the policy model of that side; the two sides never exist together.

- Target side. Each callee, agent or tool, checks the access to itself in its own inbound OPA, from
  its own CR. Every edge that callee X checks is already on ``SPM(X)``, so the render input is the
  stored SPM: the policy model is ``TargetSidePolicyModel(services=[SPM(x), ...])`` and the writer
  does no join.
- Agent side (the legacy method). Each agent's CR checks the agent's calls on its outbound, so the
  render input is the agent's ``AgentPolicyModel`` (APM), which ``_derive`` builds in memory from
  the SPMs (the join) and which is never stored. Each managed tool gets a pass-through CR (D24): the
  policy model is ``AgentSidePolicyModel(agents=[APM(a), ...], pass_through=[tool, ...])``.

The managed set (D21) is the services that have a stored SPM; every managed service has a CR under
both sides (D20). A run with a ``focus_service`` always stores ``SPM(focus)``, also with zero rules,
so the focus service joins the set and gets a CR.

The policy-model stage (D23). After the store writes, a run deploys only the affected services of
the side, filtered to live services (in the catalog and not disabled; the focus service counts as
live), in one ``apply_policy`` call — no call when the policy model is empty:

- target side: the services whose SPM changed in this run (the ``changed`` set: routed,
  override-purged, reconciled, and the focus SPM);
- agent side: the affected agents (the owners of the batch's agent roles, each touched owner that
  is an agent, and each agent that targets a touched SPM), plus the pass-through of the focus
  service when it is a tool.

A stale or missing CR stays until its service is affected again, or until the resync.

Input contract. Each ``PolicyRule`` arrives with ``scope.serviceId``, ``role.kind`` and
``role.actorIds`` already populated and with roles already flattened to their closure. The PCE
performs no IdP lookup for routing/classification and no role flattening — the only runtime IdP
read is ``Configuration.get_services()`` for the identity (P2) seed and the live check.

Drift GC. Because Keycloak UUIDs churn on delete/recreate, an append-only merge would let stale
edges pile up beside their superseded generations. So after routing, ``_reconcile`` prunes each
*touched* SPM against that same ``get_services()`` catalog (no extra IdP read) — dropping edges
whose scope or agent-role no longer exists and collapsing churned/duplicate user-role generations.
It removes only edges whose entity is gone, so order-independence is preserved.

Offboard / decommission. Reconcile is passive and catalog-anchored: it never wipes an SPM whose
owning service is absent from ``get_services()`` (a transient miss must not destroy state). That
leaves the *decommission* drift species uncovered — once a service's Keycloak client is deleted it
falls out of the catalog forever, so its own ``SPM(X)``, its outbound footprint (``X_role →
other_scope`` edges on *other* SPMs) and its CR would linger. ``decommission(service_id)`` is the
authoritative counterpart: it acts on an explicit offboard signal (not the catalog-miss guard),
tears down X's entire footprint, deletes the CR of X, and redeploys the affected services of the
side (target side: the services whose SPM changed; agent side: the agents that targeted X and the
agents whose SPM changed).

Service ids. Every service id the PCE takes is the **clientId** (``Service.serviceId``, the SPM key,
type ``ClientId``) — never the Keycloak internal UUID (``ServiceUuid``). The UUID is only for finding
the service in the IdP. The asymmetry stays at the HTTP/NATS boundary: an onboarding comes in with a
UUID, and the Orchestrator resolves the clientId once while the client still exists; an offboard
comes in with the clientId, because after the client is deleted UUID→clientId resolution is
impossible.

Quarantine. ``quarantine(service_id, deleted_roles)`` is the UC1 failure-path counterpart of
``decommission``: a failed onboarding leaves the service in the catalog (disabled). It tears down
the same store footprint and deletes the CR of the service (D20: in an AIAC setup the global
combiner denies a pod that has no client CR). ``compute_and_apply``'s routing guard then drops every
later rule that touches a disabled service, so a build that started before the quarantine cannot
write its rules back.

Resync, read model, bootstrap. ``resync()`` (D28) runs at every Controller start: one
``replace_policy`` (``PUT /policy``) with the full policy model of the side for the live managed
services, then a quarantine of each disabled service that still has an SPM. A side change is a
ConfigMap patch and a Controller restart, so the resync then writes every CR in the new side.
``policy_model_for(service_id)`` (D18) returns the policy model of the side with only that service's
entry, or ``None``. ``bootstrap(service_id, service_type)`` (checkpoint B1) writes the focus tool's CR
before UC-1 Provision, so that the discovery passes D20; it stores no SPM.

Fire-and-forget — ``compute_and_apply``, ``decommission``, ``quarantine``, ``resync`` and
``bootstrap`` log and re-raise dependency failures.

Serialization (the PCE lock). Every operation that writes reads SPMs, changes them, and writes them
back. The store has no versions, and its own write lock protects one write, not a
read-modify-write. So two runs that route rules into one shared SPM (for example two agents
granted on one tool's scope) would both read the old SPM, and the second write would silently
remove the first run's rules. One module-level lock, ``_pce_lock``, is held for the whole body of
``compute_and_apply``, ``decommission``, ``quarantine``, ``resync`` and ``bootstrap``;
``policy_model_for`` only reads and takes no lock. The PRB (the LLM work) runs before
``compute_and_apply``, outside the lock, so concurrent onboardings still build their rules in
parallel; the part under the lock makes no LLM call. Known limits:

- It serializes one process only (one Controller replica, as for the orchestrator's per-service
  lock). More replicas need store versions or a distributed lock.
- When two onboardings overlap, a pair between the two new services can stay unjudged (each
  service's resolver read the catalog before the other's Provision). That pair then gives no
  grant (fail closed).
"""

import logging
import os
import threading
from collections.abc import Iterable

from aiac.idp.configuration.api import Configuration
from aiac.idp.configuration.models import ClientId, Role, RoleKind, Scope, Service, ServiceType
from aiac.pdp.policy.library.api import apply_policy, delete_service_cr, replace_policy
from aiac.policy.model.models import (
    AgentPolicyModel,
    AgentSidePolicyModel,
    EnforcementSide,
    PolicyModel,
    PolicyRule,
    RuleEffect,
    ServicePolicyModel,
    TargetSidePolicyModel,
)
from aiac.policy.model.projection import add_by_id as _add_by_id
from aiac.policy.model.projection import add_rule as _add_rule
from aiac.policy.model.projection import project_inbound
from aiac.policy.model_store.library.api import (
    apply_service_policy,
    delete_service_policy,
    get_service_policies_by_role,
    get_service_policy,
    list_service_policies,
)

logger = logging.getLogger(__name__)

# The PCE lock — see "Serialization" in the module docstring.
_pce_lock = threading.Lock()


def _inbound_list(model: ServicePolicyModel, effect: RuleEffect) -> list[PolicyRule]:
    """The inbound list on ``model`` matching ``effect`` — the deny list for ``Deny``, else allow."""
    return model.inbound_deny_rules if effect == RuleEffect.DENY else model.inbound_allow_rules


def _route(model: ServicePolicyModel, rule: PolicyRule) -> bool:
    """Append ``rule`` to ``model``'s effect-matching inbound list (append-dedup). True iff added."""
    target = _inbound_list(model, rule.effect)
    before = len(target)
    _add_rule(target, rule)
    return len(target) != before


def _purge_role(model: ServicePolicyModel, role_id: str) -> bool:
    """Drop every inbound edge whose role is ``role_id`` from **both** lists (allow and deny) — the
    role-level revocation / footprint-purge primitive. Returns ``True`` iff any edge was removed."""
    removed = False
    for attr in ("inbound_allow_rules", "inbound_deny_rules"):
        rules: list[PolicyRule] = getattr(model, attr)
        kept = [r for r in rules if r.role.id != role_id]
        if len(kept) != len(rules):
            setattr(model, attr, kept)
            removed = True
    return removed


def _reconcile(
    model: ServicePolicyModel,
    catalog: dict[str, Service],
    catalog_agent_role_ids: set[str],
    batch_user_role_ids: set[str],
) -> bool:
    """Drop dangling inbound edges from a touched SPM against current IdP truth.

    Prevents cross-run drift accumulation (Keycloak UUIDs churn on delete/recreate, so an
    append-only merge grows stale edges beside the superseded ones). Uses only the ``get_services()``
    catalog the PCE already loads — no additional IdP read — so the ``get_services()``-only invariant
    holds. Order-independent: it removes **only** edges whose entity no longer exists, never a live
    edge, so onboarding-order convergence is preserved.

    An edge on ``SPM(X)`` is kept iff:

    1. its scope is still one of ``X``'s current ``aiac.managed`` scopes (``model.owned_scopes``,
       seeded from the catalog) — drops retired/churned scopes (e.g. ``*-aud``);
    2. for an ``Agent``-kind role, the role id is still in the catalog — drops retired/churned agent
       client roles (e.g. a focus-agent self-reference the current builder can no longer emit);
    3. for a ``User``-kind role, it is not a superseded generation: user realm roles are
       membership-derived (absent from the catalog, and the PCE must not read ``get_subjects()``), so
       among the ``User`` edges sharing ``(scope.id, role.name)`` a stale edge is dropped only when
       this batch carries a *different* id for that same ``(scope, name)`` — the fresh batch's
       current-generation id supersedes the old one.

    Runs over **both** inbound lists (allow and deny) independently: the churn collapse is computed
    per list, so a live ``Deny`` edge is never dropped because an unrelated ``Allow`` edge in the
    batch shares its ``(scope, name)``. Skips pruning entirely when ``X`` is absent from the catalog
    (a transient miss must never wipe an SPM). Returns ``True`` iff it removed at least one edge.
    """
    if catalog.get(model.service_id) is None:
        return False

    owner_scope_ids = {s.id for s in model.owned_scopes}

    def _prune(edges: list[PolicyRule]) -> list[PolicyRule]:
        # (1)+(2) existence prune.
        survivors = [
            edge
            for edge in edges
            if edge.scope.id in owner_scope_ids
            and not (edge.role.kind == RoleKind.AGENT and edge.role.id not in catalog_agent_role_ids)
        ]

        # (3) user-role churn collapse: a stale generation is dropped only when this batch carries a
        # different id for the same (scope, name).
        batch_ids_by_key: dict[tuple[str, str], set[str]] = {}
        for edge in survivors:
            if edge.role.kind == RoleKind.USER and edge.role.id in batch_user_role_ids:
                batch_ids_by_key.setdefault((edge.scope.id, edge.role.name), set()).add(edge.role.id)

        return [
            edge
            for edge in survivors
            if not (
                edge.role.kind == RoleKind.USER
                and edge.role.id not in batch_ids_by_key.get((edge.scope.id, edge.role.name), set())
                and batch_ids_by_key.get((edge.scope.id, edge.role.name))
            )
        ]

    changed = False
    for attr in ("inbound_allow_rules", "inbound_deny_rules"):
        edges: list[PolicyRule] = getattr(model, attr)
        kept = _prune(edges)
        if len(kept) != len(edges):
            setattr(model, attr, kept)
            changed = True
    return changed


def _seed_identity(model: ServicePolicyModel, svc: Service) -> None:
    """Seed ``model``'s identity from its catalog record: the service's own ``aiac.managed`` roles
    and scopes (Keycloak built-ins are dropped)."""
    model.owned_roles = [r for r in svc.roles if r.aiac_managed]
    model.owned_scopes = [s for s in svc.scopes if s.aiac_managed]


def _spm_cache(catalog: dict[str, Service]):
    """Build a store-backed SPM cache seeded from the ``get_services()`` catalog.

    Returns ``(spms, spm)``, shared by ``_run``, ``_decommission`` and ``_quarantine``. ``spm(id)``
    fetches each SPM from the store at most once (``get_service_policy`` returns a fresh empty SPM on
    404, so a brand-new — or already-deleted — service is handled), seeds its identity (type + own
    ``aiac.managed`` roles/scopes) from the catalog when the service is still present, and mutates in
    place. ``spms`` maps each loaded id to its cached SPM.
    """
    spms: dict[str, ServicePolicyModel] = {}

    def spm(service_id: str) -> ServicePolicyModel:
        if service_id not in spms:
            model = get_service_policy(service_id)
            svc = catalog.get(service_id)
            if svc is not None:
                if svc.type is not None:
                    model.service_type = svc.type
                _seed_identity(model, svc)
            spms[service_id] = model
        return spms[service_id]

    return spms, spm


def _fresh_apm(agent_id: str) -> AgentPolicyModel:
    # Agent side: the empty APM that ``_derive`` fills. Identity/aggregate maps are the only
    # required fields; the split target maps and the eight entity x effect rule lists default to
    # empty.
    return AgentPolicyModel(
        agent_id=agent_id,
        agent_roles=[],
        agent_scopes=[],
        source_roles={},
        subject_roles={},
    )


# The enforcement-side switch (D29) — see ``enforcement_side``.
ENFORCEMENT_SIDE_ENV = "AIAC_ENFORCEMENT_SIDE"


def enforcement_side() -> EnforcementSide:
    """The current enforcement side (D16, D29), from ``AIAC_ENFORCEMENT_SIDE``.

    Unset means ``target-side`` (the default). ``target-side`` and ``agent-side`` are the only
    values (surrounding white space is ignored); any other value, also an empty one, raises
    ``ValueError`` naming it. The Controller calls this at start, so an unknown value stops the
    Controller before it serves; the PCE reads it on each operation. The writer never reads it: it
    takes the side from the policy-model tag."""
    raw = os.environ.get(ENFORCEMENT_SIDE_ENV)
    if raw is None:
        return EnforcementSide.TARGET_SIDE
    try:
        return EnforcementSide(raw.strip())
    except ValueError:
        allowed = ", ".join(side.value for side in EnforcementSide)
        raise ValueError(f"{ENFORCEMENT_SIDE_ENV}={raw!r} is not an enforcement side (use one of: {allowed})") from None


def compute_and_apply(
    rules: list[PolicyRule],
    override: bool = False,
    focus_service: ClientId | None = None,
) -> None:
    """Route and persist ``rules``, then deploy the changed live services — fire-and-forget.

    ``override`` selects the merge mode at the SPM layer. ``False`` (default) appends each rule
    additively to the effect-matching inbound list on ``SPM(scope.serviceId)`` (``Deny`` →
    ``inbound_deny_rules``, else ``inbound_allow_rules``; dedup by ``role.id`` + ``scope.id`` +
    ``effect``). ``True`` authoritatively replaces every input role's mappings: the distinct
    input-role set is purged from **both** inbound lists of **every** SPM containing it, once,
    up-front, before the fresh rules are appended (role-level revocation).

    There is no default effect to pass: the deployed Rego always denies a ``(role, scope)`` pair
    that no rule mentions, so every deploy gives the same behavior.

    Focus SPM (D21). When ``focus_service`` is in the catalog, the run always stores
    ``SPM(focus)`` (seeded from the catalog; also with zero rules) and adds it to the ``changed``
    set, so the focus service joins the managed set and gets a CR: under target side its SPM; under
    agent side its APM (an agent) or its pass-through (a tool).

    The policy-model stage (D23). After the store writes, the run partial-upserts the policy model
    of the current side (``enforcement_side()``, read once) with one ``apply_policy`` call — no call
    when it is empty. Live = in the catalog and not disabled; the focus service counts as live.

    - target side: ``TargetSidePolicyModel(services=[SPM(x) for x in changed if x is live])``;
    - agent side: ``AgentSidePolicyModel(agents=[APM(a) for each live affected agent],
      pass_through=[focus_service] if it is a live tool)``. The affected agents are the owners of
      the batch's agent roles, each touched owner (a routed rule's scope owner, or a ``changed``
      SPM) that is an agent, and each agent that targets a touched SPM (an Agent-kind inbound edge
      on it). Each APM is derived from the store just written.

    Routing guard. A disabled client is a failed (quarantined) service; a service absent from the
    catalog is deleted. Under the PCE lock, after the catalog read, the run drops each rule whose
    scope owner, or the owner of whose agent role (``role.actorIds``), is disabled or absent, so a
    build that started before a quarantine or an offboard cannot write rules back into the removed
    footprint. The run also deploys only live services. ``focus_service`` — the
    clientId (``Service.serviceId``, the SPM key) of the service this onboarding builds, not its
    Keycloak UUID — is exempt: a re-onboarding applies while its client is still disabled
    (``reenable_service`` runs after the apply). The onboarding route and the NATS consumer pass the
    clientId that ``onboard_service`` returns; every other caller passes nothing, so every rule that
    touches a disabled service is dropped.

    Exceptions from any dependency (IdP, Policy Store, PDP) are logged and **re-raised** so the
    caller (the Controller) surfaces the failure — e.g. as a 500 — instead of returning success
    while silently applying nothing.
    """
    try:
        side = enforcement_side()
        with _pce_lock:
            _run(rules, override, focus_service, side)
    except Exception:
        logger.exception("compute_and_apply failed for %d rule(s)", len(rules))
        raise


def decommission(service_id: ClientId) -> None:
    """Authoritatively remove a decommissioned service's entire policy footprint.

    ``service_id`` is the **clientId (the SPM key)**, as for every PCE function. An offboarded client
    is gone from the IdP, so the offboard contract carries the clientId directly; an onboarding
    resolves it from its UUID in the Orchestrator. The asymmetry is only at the HTTP/NATS boundary,
    not in the PCE.

    Tears down everything reconcile's catalog-anchored GC cannot: deletes ``SPM(X)`` (removing every
    user→X and agent→X inbound edge, so X leaves the managed set), purges X's **outbound footprint**
    (``X_role → other_scope`` edges stored on other services' SPMs), deletes the CR of X
    (``delete_service_cr``, D20 — for an agent and for a tool; a 404 counts as success), and
    redeploys the affected live services of the current side in a single partial upsert (the
    policy-model stage, D23): under target side the services whose SPM the purge changed; under
    agent side the agents that targeted X (read before ``SPM(X)`` is deleted) and the agents whose
    SPM the purge changed, re-derived from the store. A never-onboarded / already-removed service
    (the store has no content for it) is a no-op: no store write, no CR delete.

    Exceptions from any dependency (IdP, Policy Store, PDP) are logged and **re-raised** so the
    Controller surfaces the failure instead of reporting a phantom success.
    """
    try:
        side = enforcement_side()
        with _pce_lock:
            _decommission(service_id, side)
    except Exception:
        logger.exception("decommission failed for service %r", _loggable(service_id))
        raise


def _disabled_services(catalog: dict[str, Service], focus_service: str | None) -> set[str]:
    """The ``serviceId`` of every disabled (quarantined) service in ``catalog``, except the focus
    service (given by its clientId, the catalog key)."""
    return {sid for sid, svc in catalog.items() if not svc.enabled and sid != focus_service}


def _live_services(catalog: dict[str, Service], focus_service: str | None = None) -> set[str]:
    """The ``serviceId`` of every live service: in ``catalog`` and not disabled (the focus service
    counts as live). Only a live service is deployed: a service absent from the catalog is deleted,
    and a disabled one is quarantined — it must stay with no CR until a re-onboarding writes one."""
    return catalog.keys() - _disabled_services(catalog, focus_service)


def _routable(rule: PolicyRule, catalog: dict[str, Service], disabled: set[str]) -> bool:
    """True iff every service ``rule`` touches — its scope owner, and the owner of its agent role —
    is live: present in ``catalog`` and not in ``disabled``. A service absent from the catalog is
    gone (its client was deleted, e.g. offboarded while its onboarding was still building)."""
    owners = {rule.scope.serviceId}
    if rule.role.kind == RoleKind.AGENT:
        owners.update(rule.role.actorIds)
    return all(owner in catalog and owner not in disabled for owner in owners)


def quarantine(service_id: ClientId, deleted_roles: Iterable[Role] = ()) -> None:
    """Tear down a failed onboarding's policy footprint — the UC1 failure path (after the rollback).

    ``service_id`` is the **clientId (the SPM key, ``Service.serviceId``)**, as for ``decommission``
    — not the Keycloak internal UUID. The orchestrator resolves it from the onboarding's UUID while
    the client still exists. The failed service X is still in the catalog (disabled). Holds the PCE
    lock. For X:

    1. delete ``SPM(X)`` from the store;
    2. remove X's roles from the other SPMs (as ``decommission`` step 4 does) — the roles X still
       has in the catalog, plus ``deleted_roles``: the roles the rollback already deleted from the
       IdP (the run's created-manifest). The catalog no longer lists those, but a concurrent run can
       have stored their grants on another SPM, which would keep allowing X. A role that another
       service also holds (a realm role reused by name) is kept: its grants are that service's too;
    3. delete the CR of X (``delete_service_cr``, D20), for an agent and for a tool. In an AIAC setup
       the global combiner denies a pod that has no client CR, so the delete denies every request to
       and from X. There is no no-rules CR;
    4. redeploy the affected live services of the current side (not X, not a deleted or disabled
       service) in one ``apply_policy`` call (the policy-model stage, D23): under target side the
       services whose SPMs lost X's roles; under agent side the agents that targeted X and the
       agents whose SPMs lost X's roles, re-derived from the store.

    Idempotent: a second call finds no SPM and no edges, and deletes the CR again (a 404 counts as
    success). A ``service_id`` that is not in the catalog is a logged no-op. The quarantine is lifted
    only by a successful re-onboarding: its ``compute_and_apply`` stores ``SPM(X)`` again (also with
    zero rules, D21) and writes a new CR, then ``reenable_service`` re-enables the client.

    Exceptions from any dependency are logged and **re-raised**.
    """
    try:
        side = enforcement_side()
        with _pce_lock:
            _quarantine(service_id, list(deleted_roles), side)
    except Exception:
        logger.exception("quarantine failed for service %r", _loggable(service_id))
        raise


def resync() -> None:
    """Replace every AIAC CR from the store, then tear down each disabled service (D28).

    The Controller calls it at every start, before it serves. Holds the PCE lock for the whole body,
    so onboardings wait. Steps:

    1. read the catalog once and list every stored SPM (``list_service_policies``, the managed set);
    2. ``replace_policy(<the full policy model of the current side>)`` — ``PUT /policy`` upserts one
       CR per entry and deletes every other AIAC CR. Live = in the catalog and enabled (checkpoint
       O3). Target side: ``TargetSidePolicyModel(services=[every stored SPM of a live service])``,
       the SPMs as stored. Agent side: ``AgentSidePolicyModel(agents=[the APM of every live stored
       agent], pass_through=[every live stored tool])``. The call is made also when the model is
       empty: the PUT then deletes every AIAC CR;
    3. quarantine (see ``quarantine``) each disabled service that still has a stored SPM (C2), under
       the same lock hold, with no ``deleted_roles``.

    A service that has a stored SPM but is absent from the catalog (deleted, not decommissioned) is
    not in the model, so the PUT deletes its CR; its SPM stays (removing it is ``decommission``'s
    job). The resync is also the path for a side change (a ConfigMap patch and a Controller restart:
    the PUT writes every CR in the new side, so no mixed state stays), for a stale or missing CR,
    and for the upgrade from the per-agent CRs of an older release.

    Exceptions from any dependency are logged and **re-raised**: the Controller then stops, the pod
    restarts, and the resync runs again.
    """
    try:
        side = enforcement_side()
        with _pce_lock:
            _resync(side)
    except Exception:
        logger.exception("resync failed")
        raise


def policy_model_for(service_id: ClientId) -> PolicyModel | None:
    """The read model of one service (D18): the policy model of the current side with only the entry
    of ``service_id``, or ``None`` if the store has no SPM for it (the service is not in the managed
    set; the Controller route then gives 404).

    - target side: ``TargetSidePolicyModel(services=[SPM(service_id)])``, the SPM as stored;
    - agent side: ``AgentSidePolicyModel(agents=[APM(service_id)])`` for an agent, derived from the
      store as at a deploy; else ``AgentSidePolicyModel(agents=[], pass_through=[service_id])``. The
      stored SPM's ``service_type`` tells an agent from a tool.

    It shows what the PCE deploys for the service from the current store. It does not read the CR in
    the cluster (which can be stale, D23) and makes no IdP read: the identity of the APM is the one
    stored on the SPM. Read-only: it takes no lock and writes nothing."""
    side = enforcement_side()
    stored = _stored_spm(service_id)
    if stored is None:
        return None
    if side == EnforcementSide.TARGET_SIDE:
        return TargetSidePolicyModel(services=[stored])
    if stored.service_type != ServiceType.AGENT:
        return AgentSidePolicyModel(agents=[], pass_through=[service_id])
    spms, spm = _spm_cache({})
    spms[service_id] = stored
    return AgentSidePolicyModel(agents=[_derive(service_id, spm)])


def _stored_spm(service_id: str) -> ServicePolicyModel | None:
    """The stored SPM of ``service_id``, or ``None`` if the store has none.

    Reads the list of every stored SPM (``list_service_policies``, C3), because
    ``get_service_policy`` cannot tell a 404 from a stored SPM: on a 404 it returns a fresh empty
    SPM, which looks the same as a stored zero-rule SPM with no ``aiac.managed`` roles or scopes."""
    return next((model for model in list_service_policies() if model.service_id == service_id), None)


def bootstrap(service_id: ClientId, service_type: ServiceType) -> None:
    """Write the focus tool's CR before UC-1 Provision (checkpoint B1).

    The global combiner denies a pod that has no client CR (D20), so at the first onboarding the
    UC-1 discovery (``tools/list`` through the tool's own inbound) needs a CR before the PRB runs.
    Under the PCE lock, one ``apply_policy`` call with the CR that the current side gives
    ``SPM(service_id)``:

    - ``SPM(service_id)`` is the stored SPM when the store has one (a re-onboarding), as stored;
    - else a zero-rule SPM of ``service_type`` — the type comes from the pod label, because the
      catalog type is not set before Provision — with its identity (the ``aiac.managed`` roles and
      scopes) seeded from the catalog if the service is in it.

    Target side: ``TargetSidePolicyModel(services=[that SPM])``; the tool's inbound then allows only
    the self-discovery rule (plus any stored rules), and its outbound is a pass-through. Agent side:
    ``AgentSidePolicyModel(agents=[], pass_through=[service_id])``, a pass-through CR. It stores no
    SPM: the service joins the managed set only when its onboarding stores ``SPM(focus)`` (D21).
    Agents get no bootstrap (AIAC does not call an agent at onboarding); that is the caller's
    choice. If an agent is given all the same, under agent side it gets the APM of that SPM, never a
    pass-through (which would allow every request).

    Exceptions from any dependency are logged and **re-raised**.
    """
    try:
        side = enforcement_side()
        with _pce_lock:
            _bootstrap(service_id, service_type, side)
    except Exception:
        logger.exception("bootstrap failed for service %r", _loggable(service_id))
        raise


def _bootstrap(service_id: str, service_type: ServiceType, side: EnforcementSide) -> None:
    model = _stored_spm(service_id)
    if model is None:
        model = ServicePolicyModel(service_id=service_id, service_type=service_type, owned_roles=[], owned_scopes=[])
        svc = {svc.serviceId: svc for svc in Configuration.for_default_realm().get_services()}.get(service_id)
        if svc is not None:
            _seed_identity(model, svc)
    if side == EnforcementSide.TARGET_SIDE:
        apply_policy(TargetSidePolicyModel(services=[model]))
    elif model.service_type == ServiceType.AGENT:
        # Never a pass-through for an agent: it would allow every request. Its APM, derived from
        # that SPM, as a deploy derives it.
        spms, spm = _spm_cache({})
        spms[service_id] = model
        apply_policy(AgentSidePolicyModel(agents=[_derive(service_id, spm)]))
    else:
        apply_policy(AgentSidePolicyModel(agents=[], pass_through=[service_id]))


def _loggable(value: str) -> str:
    """Strip CR/LF so a hostile id cannot forge log records."""
    return value.replace("\r", "").replace("\n", "")


def _run(rules: list[PolicyRule], override: bool, focus_service: str | None, side: EnforcementSide) -> None:
    config = Configuration.for_default_realm()

    # (1) Catalog once — the only runtime IdP read. Carries each service's type (agent vs tool)
    # and its own roles/scopes (the SPM identity, P2, filtered to aiac.managed), and tells which
    # services are live.
    catalog = {svc.serviceId: svc for svc in config.get_services()}

    # Distinct input roles (dedup by id) — the set purged under override. Built from the input
    # BEFORE the routing guard: under override, a role whose every new rule the guard drops must
    # still lose its old grants.
    distinct_roles: dict[str, Role] = {}
    for rule in rules:
        distinct_roles.setdefault(rule.role.id, rule.role)

    # (1.5) Routing guard — drop every rule that touches a service that is not live: disabled
    # (quarantined, except the focus service) or absent from the catalog (deleted). See
    # ``compute_and_apply``.
    disabled = _disabled_services(catalog, focus_service)
    kept = [rule for rule in rules if _routable(rule, catalog, disabled)]
    if len(kept) != len(rules):
        logger.warning(
            "routing guard dropped %d rule(s) that touch a disabled or deleted service", len(rules) - len(kept)
        )
    rules = kept

    # SPM cache: fetch each SPM from the store at most once, seed its identity from the catalog,
    # mutate in place, and persist the changed ones.
    spms, spm = _spm_cache(catalog)

    changed: set[str] = set()

    # (3) Override — role-level revocation, once up-front, BEFORE any fresh append (so a role
    # shared across the input is not wiped after being added).
    if override:
        for role in distinct_roles.values():
            for stored in get_service_policies_by_role(role):
                model = spm(stored.service_id)
                if _purge_role(model, role.id):
                    changed.add(model.service_id)

    # (2) Route each rule to the SPM of the service that owns its scope, into the inbound list
    # matching its ``effect`` (Deny → inbound_deny_rules, else inbound_allow_rules). Append-dedup by
    # role.id + scope.id + effect. No role-kind classification here — kind only matters at render.
    for rule in rules:
        model = spm(rule.scope.serviceId)
        if _route(model, rule) or override:
            changed.add(model.service_id)

    # (2b) Focus SPM (D21) — the run always stores SPM(focus), seeded from the catalog, also with
    # zero rules, so the focus service joins the managed set and gets a CR. A focus service that is
    # absent from the catalog is deleted: it gets no SPM. Loaded before the reconcile, so the
    # reconcile prunes its dangling edges as it prunes those of a routed SPM.
    if focus_service is not None and focus_service in catalog:
        changed.add(spm(focus_service).service_id)

    # (3.5) Reconcile touched SPMs against current IdP truth (get_services()-only — no extra IdP
    # read) so drift cannot accumulate across re-onboarding. At this point ``spms`` holds exactly
    # the touched SPMs (routed + override-purged + the focus SPM). Runs under both merge modes;
    # order-independent (drops only edges whose entity no longer exists).
    catalog_agent_role_ids = {r.id for svc in catalog.values() for r in svc.roles if r.aiac_managed}
    batch_user_role_ids = {rule.role.id for rule in rules if rule.role.kind == RoleKind.USER}
    for service_id, model in list(spms.items()):
        if _reconcile(model, catalog, catalog_agent_role_ids, batch_user_role_ids):
            changed.add(service_id)

    # (4) Persist every changed SPM.
    for service_id in changed:
        apply_service_policy(service_id, spms[service_id])

    # (5) The policy-model stage (D23): deploy the affected live services of the side. Only live
    # services: one absent from the catalog is deleted, and its stored SPM (or the store's 404
    # placeholder) must not bring its CR back — removing it is ``decommission``'s job; a disabled one
    # stays with no CR.
    live = _live_services(catalog, focus_service)
    if side == EnforcementSide.TARGET_SIDE:
        # Target side: the changed SPMs — each CR is rendered from the callee's own SPM.
        _deploy(changed & live, spms)
        return

    # Agent side: the affected agents, derived from the store just written (an agent's outbound
    # depends on the SPMs of the services it calls), plus the pass-through CR of a focus tool (D24).
    # Folding ``changed`` into the touched owners is what makes a revocation propagate: under
    # override an owner that only *lost* edges is in ``changed`` but carries no fresh rule.
    touched_owners = {rule.scope.serviceId for rule in rules} | changed
    affected = _affected_agents(distinct_roles.values(), touched_owners, spm, catalog)
    pass_through = [focus_service] if focus_service in live and _is_tool(catalog, focus_service) else []
    _deploy_agent_side(affected & live, spm, catalog, pass_through)


def _decommission(service_id: str, side: EnforcementSide) -> None:
    config = Configuration.for_default_realm()

    # (1) Catalog once — the only runtime IdP read. X itself is absent (it was offboarded); the
    # catalog is used to seed and filter the still-live services that the redeploy writes.
    catalog = {svc.serviceId: svc for svc in config.get_services()}
    spms, spm = _spm_cache(catalog)

    # (2) Load SPM(X) — X is gone from the catalog, so spm() does not reseed it; the persisted SPM
    # carries the roles/scopes X owned when it was onboarded. Content guard: a 404 fresh-empty SPM
    # (never onboarded / already removed) is a no-op — no spurious CR delete.
    spm_x = spm(service_id)
    if not (spm_x.owned_roles or spm_x.owned_scopes or spm_x.inbound_allow_rules or spm_x.inbound_deny_rules):
        return

    # (3)-(6) Tear down X's footprint in the store (see ``_remove_footprint``).
    changed, targeters = _remove_footprint(service_id, catalog, spms, spm)

    # (7) Delete the CR of X (D20), for an agent and for a tool. A 404 counts as success.
    delete_service_cr(service_id)

    # (8) Redeploy the affected live services of the side (X excluded) in one call (D23).
    _redeploy_after_removal(service_id, changed, targeters, catalog, spms, spm, side)


def _resync(side: EnforcementSide) -> None:
    config = Configuration.for_default_realm()

    # (1) Catalog once, and every stored SPM — the managed set (D21).
    catalog = {svc.serviceId: svc for svc in config.get_services()}
    stored = sorted(list_service_policies(), key=lambda model: model.service_id)

    # (2) Replace every AIAC CR with the CRs of the live managed services, in the current side. A
    # disabled service is not in the model: step 3 removes it, and its rules must not come back,
    # even for a moment.
    live = _live_services(catalog)
    live_stored = [model for model in stored if model.service_id in live]
    if side == EnforcementSide.TARGET_SIDE:
        replace_policy(TargetSidePolicyModel(services=live_stored))
    else:
        # The APM of each live stored agent, derived from the store, and a pass-through CR for each
        # live stored tool (D24).
        _, spm = _spm_cache(catalog)
        replace_policy(
            AgentSidePolicyModel(
                agents=[_derive(m.service_id, spm) for m in live_stored if _is_agent(catalog, m.service_id)],
                pass_through=[m.service_id for m in live_stored if _is_tool(catalog, m.service_id)],
            )
        )

    # (3) Quarantine each disabled service that still has an SPM (C2). The lock is already held.
    for model in stored:
        if model.service_id in catalog and model.service_id not in live:
            _quarantine_in(catalog, model.service_id, [], side)


def _quarantine(service_id: str, deleted_roles: list[Role], side: EnforcementSide) -> None:
    config = Configuration.for_default_realm()

    # (1) Catalog once. X is still in it (the rollback disables the client, it does not delete it).
    # spm() seeds X's current roles from the catalog, so step 4 removes the roles X still has. The
    # roles the rollback deleted are not in the catalog any more, so the caller passes them in
    # ``deleted_roles`` and step 4 removes their edges too — else an edge a concurrent run stored
    # (X_role → other_scope) keeps allowing X until a later run reconciles that SPM.
    _quarantine_in({svc.serviceId: svc for svc in config.get_services()}, service_id, deleted_roles, side)


def _quarantine_in(
    catalog: dict[str, Service], service_id: str, deleted_roles: list[Role], side: EnforcementSide
) -> None:
    """The body of ``quarantine`` for a catalog already read (``quarantine`` and ``resync``)."""
    if service_id not in catalog:
        logger.warning("quarantine: service %r is not in the IdP catalog — nothing to do", _loggable(service_id))
        return
    spms, spm = _spm_cache(catalog)

    # (3)-(6) Tear down X's footprint in the store (see ``_remove_footprint``).
    changed, targeters = _remove_footprint(service_id, catalog, spms, spm, deleted_roles)

    # (7) Delete the CR of X (D20), for an agent and for a tool. In an AIAC setup the global combiner
    # denies a pod that has no client CR, so the delete denies every request to and from X. A 404
    # counts as success, so a second quarantine deletes again without an error.
    delete_service_cr(service_id)

    # (8) Redeploy the affected live services of the side (X excluded) in one call (D23).
    _redeploy_after_removal(service_id, changed, targeters, catalog, spms, spm, side)


def _remove_footprint(
    service_id: str, catalog: dict[str, Service], spms, spm, extra_roles: Iterable[Role] = ()
) -> tuple[set[str], set[str]]:
    """Tear down service X's footprint in the store — the steps ``decommission`` and ``quarantine``
    share. ``extra_roles`` are X's roles that ``SPM(X)`` no longer lists (``quarantine``'s
    rollback-deleted roles); their edges are purged as X's own. A role that another service in
    ``catalog`` also holds (a realm role reused by name) is not purged: its grants are that
    service's grants too. Returns ``(changed, targeters)``: the services whose SPM the purge changed
    (X excluded), and the agents that targeted X."""
    spm_x = spm(service_id)

    # (3) Targeters — the agents whose outbound loses X: they hold an Agent-kind inbound edge (allow
    # or deny) on SPM(X) (their_role → X_scope), which goes when SPM(X) is deleted in step 5. So
    # they are read first.
    targeters = _targeters(spm_x)

    changed: set[str] = set()

    # (4) Purge X's outbound footprint — X_role → other_scope edges (allow AND deny) stored on OTHER
    # services' SPMs. Dedup by id: an extra role can also still be on SPM(X). Skip a role that
    # another service holds: the edges are keyed by role id, so a purge would also remove that
    # service's grants. X itself stays denied — its CR is deleted, and the combiner denies a pod
    # that has no client CR (D20).
    held_elsewhere = {r.id for sid, svc in catalog.items() if sid != service_id for r in svc.roles}
    roles = {role.id: role for role in [*spm_x.owned_roles, *extra_roles] if role.id not in held_elsewhere}
    for role in roles.values():
        for stored in get_service_policies_by_role(role):
            if stored.service_id == service_id:
                continue
            model = spm(stored.service_id)
            if _purge_role(model, role.id):
                changed.add(model.service_id)

    # (5) Delete SPM(X) — removes every user→X and agent→X inbound edge in one shot, so X leaves the
    # managed set — and evict it from the cache so the redeploy cannot resurrect it.
    delete_service_policy(service_id)
    spms.pop(service_id, None)

    # (6) Persist every changed (footprint-purged) SPM.
    for changed_id in sorted(changed):
        apply_service_policy(changed_id, spms[changed_id])

    return changed, targeters


def _redeploy_after_removal(
    service_id: str,
    changed: set[str],
    targeters: set[str],
    catalog: dict[str, Service],
    spms: dict[str, ServicePolicyModel],
    spm,
    side: EnforcementSide,
) -> None:
    """The policy-model stage of ``quarantine`` and ``decommission`` (D23): redeploy the affected
    live services of ``side``, X (``service_id``) excluded, in one call. Target side: the services
    whose SPM the purge changed. Agent side: the agents that targeted X, and the agents whose SPM the
    purge changed (their inbound ``source_roles[X]`` went); each is re-derived from the store, from
    which SPM(X) is gone."""
    live = _live_services(catalog) - {service_id}
    if side == EnforcementSide.TARGET_SIDE:
        _deploy(changed & live, spms)
        return
    affected = targeters | {sid for sid in changed if _is_agent(catalog, sid)}
    _deploy_agent_side(affected & live, spm, catalog)


def _deploy(service_ids: set[str], spms: dict[str, ServicePolicyModel]) -> None:
    """The policy-model stage (D23): partial-upsert the target-side policy model of ``service_ids``
    — their SPMs as just persisted — in one ``apply_policy`` call; no call when the set is empty."""
    if service_ids:
        apply_policy(TargetSidePolicyModel(services=[spms[sid] for sid in sorted(service_ids)]))


def _affected_agents(roles: Iterable[Role], touched_owners: set[str], spm, catalog: dict[str, Service]) -> set[str]:
    """The affected agents of a run under agent side (D23) — from the batch, never a full scan:

    - the owners (``actorIds``) of each input or purged ``Agent``-kind role: their outbound changed;
    - each touched owner that is an agent: its inbound changed;
    - each agent that targets a touched SPM (``_targeters``, a superset of the exact-scope match;
      a re-derive is idempotent, so that is safe): its outbound changed.

    The caller keeps only the live ones."""
    affected: set[str] = set()
    for role in roles:
        if role.kind == RoleKind.AGENT:
            affected.update(role.actorIds)  # owning agents — their outbound changed
    for owner in touched_owners:
        if _is_agent(catalog, owner):
            affected.add(owner)  # the touched owner is an agent — its inbound changed
        affected.update(_targeters(spm(owner)))  # the agents that target it — their outbound changed
    return affected


def _targeters(model: ServicePolicyModel) -> set[str]:
    """The agents that target ``model``'s service: the owners (``actorIds``) of every Agent-kind
    inbound edge on it, allow and deny."""
    return {
        actor
        for edge in model.inbound_allow_rules + model.inbound_deny_rules
        if edge.role.kind == RoleKind.AGENT
        for actor in edge.role.actorIds
    }


def _is_agent(catalog: dict[str, Service], service_id: str) -> bool:
    """True iff ``service_id`` is an agent in ``catalog``. Only a live service (in the catalog) is
    deployed, so the catalog type is the one that counts; a service with no catalog type is neither
    an agent nor a tool, and under agent side it gets no CR (D20 denies it)."""
    svc = catalog.get(service_id)
    return svc is not None and svc.type == ServiceType.AGENT


def _is_tool(catalog: dict[str, Service], service_id: str) -> bool:
    """True iff ``service_id`` is a tool in ``catalog``."""
    svc = catalog.get(service_id)
    return svc is not None and svc.type == ServiceType.TOOL


def _deploy_agent_side(agent_ids: set[str], spm, catalog: dict[str, Service], pass_through: Iterable[str] = ()) -> None:
    """The policy-model stage under agent side (D23): derive the APM of each agent in ``agent_ids``
    from the store, and partial-upsert them with the ``pass_through`` tools in one ``apply_policy``
    call; no call when both lists are empty."""
    agents = [_derive(agent_id, spm) for agent_id in sorted(agent_ids) if _is_agent(catalog, agent_id)]
    pass_through = list(pass_through)
    if agents or pass_through:
        apply_policy(AgentSidePolicyModel(agents=agents, pass_through=pass_through))


def _derive(agent_id, spm) -> AgentPolicyModel:
    """Build ``APM(agent_id)`` entirely from the persisted SPMs (zero IdP) — the agent-side render
    input (``AgentSidePolicyModel.agents``). The target side does not call it.

    Each inbound edge on ``SPM(A)`` is classified by ``role.kind`` (User → subject, Agent → source)
    **and** ``effect`` (allow/deny) into one of four inbound buckets; each outbound edge (one of A's
    own roles referenced on another SPM) is classified by ``effect`` into the target allow/deny
    bucket and grows ``target_allow_scopes`` / ``target_deny_scopes``. Identity/aggregate maps stay
    effect-agnostic — a deny-only role or subject still registers into them."""
    sa = spm(agent_id)
    apm = _fresh_apm(agent_id)

    # Identity (P2) — the agent's own aiac.managed roles/scopes, seeded from the catalog.
    apm.agent_roles = list(sa.owned_roles)
    apm.agent_scopes = list(sa.owned_scopes)

    # Inbound — every edge on SPM(A), split by (role.kind, effect) through the shared projection
    # (D18b), so the target-side renderer gives the same inbound for the same SPM. Identity maps
    # effect-agnostic.
    inbound = project_inbound(sa)
    apm.inbound_subject_allow_rules = inbound.subject_allow_rules
    apm.inbound_subject_deny_rules = inbound.subject_deny_rules
    apm.inbound_source_allow_rules = inbound.source_allow_rules
    apm.inbound_source_deny_rules = inbound.source_deny_rules
    apm.subject_roles = inbound.subject_roles
    apm.source_roles = inbound.source_roles

    # Outbound — for each of A's own roles, the edges on other services' SPMs that reference it,
    # split by effect. Relevance is directional: only A's *agent* roles confer an outbound edge, so
    # a merely shared user role never creates a false edge to a service A does not target.
    for role in sa.owned_roles:
        for stored in get_service_policies_by_role(role):
            _derive_outbound(apm, role, stored)

    return apm


def _derive_outbound(apm: AgentPolicyModel, role: Role, stored: ServicePolicyModel) -> None:
    """Project A's own ``role`` edges on ``stored`` into the outbound target + subject buckets,
    split by effect: an ``Allow`` target edge grows ``outbound_target_allow_rules`` /
    ``target_allow_scopes``; a ``Deny`` one grows the deny counterparts."""
    for effect, target_rules, target_scopes in (
        (RuleEffect.ALLOW, apm.outbound_target_allow_rules, apm.target_allow_scopes),
        (RuleEffect.DENY, apm.outbound_target_deny_rules, apm.target_deny_scopes),
    ):
        for edge in _inbound_list(stored, effect):
            if edge.role.id != role.id:
                continue
            scope = edge.scope
            _add_rule(target_rules, edge)
            _add_by_id(target_scopes.setdefault(scope.serviceId, []), scope)
            # Outbound subject gate — the User-kind edges on the SAME owning SPM whose scope is this
            # target scope (which users may / must not reach it through A).
            _derive_outbound_subject(apm, stored, scope)


def _derive_outbound_subject(apm: AgentPolicyModel, stored: ServicePolicyModel, scope: Scope) -> None:
    """Gather ``stored``'s User-kind edges for ``scope`` into the outbound subject buckets (allow /
    deny), and register each such user into the effect-agnostic ``subject_roles`` map."""
    for effect, subject_rules in (
        (RuleEffect.ALLOW, apm.outbound_subject_allow_rules),
        (RuleEffect.DENY, apm.outbound_subject_deny_rules),
    ):
        for user_edge in _inbound_list(stored, effect):
            if user_edge.scope.id == scope.id and user_edge.role.kind == RoleKind.USER:
                _add_rule(subject_rules, user_edge)
                for username in user_edge.role.actorIds:
                    _add_by_id(apm.subject_roles.setdefault(username, []), user_edge.role)
