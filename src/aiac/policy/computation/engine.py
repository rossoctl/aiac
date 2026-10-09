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
the side, filtered to live services (in the catalog and not disabled; the focus service and a
service that waits for its re-enable count as live, see "Quarantine"), in one ``apply_policy`` call
— no call when the policy model is empty:

- target side: the services whose SPM the run touched (routed a rule to, also a duplicate rule;
  override-purged; and the focus SPM), changed or not, and, when the run lifts a quarantine, the
  services whose SPM has an edge of a role of the focus service (see "Quarantine"). A render that
  writes no SPM (``rerender_role``, the resync, the redeploy of a shared role at a removal) can
  leave a CR with other holders than the stored snapshot, so a touched SPM is deployed whether or
  not its snapshot is stale; the stale check decides only the store write;
- agent side: the affected agents (the owners of the batch's agent roles, each touched owner that
  is an agent, each agent that targets a touched SPM, the former holders of each stale SPM, and, at
  a lift, the agents among those services), plus the pass-through of the focus service when it is a
  tool.

A stale or missing CR stays until its service is affected again, or until the resync. Known limit
(agent side): the CR that names a holder is the holder's own APM, so a holder that got a role in a
render with no SPM write and then lost it with no event keeps its outbound until a role-members
event or the resync; a run that touches the callee finds it only when the stored snapshot names it.

Input contract. Each ``PolicyRule`` arrives with ``scope.serviceId`` and ``role.kind`` already
populated and with roles already flattened to their closure. The PCE performs no IdP lookup for
routing/classification and no role flattening. The ``role.actorIds`` of a rule is only a snapshot
(see "Role holders").

Role holders (D32). A stored edge keeps a copy of ``role.actorIds`` from the run that built it, and
that copy goes stale: a role that two agents share carries only the holder that its build saw, and
a user role keeps the members that it had when the rule was stored. A membership change does not
change the policy (role → scope); it changes only who holds the role. So each operation reads the
IdP one time, under the PCE lock: ``Configuration.get_services()`` (the catalog: the identity (P2)
seed, the live check, and the holders of each agent role) and ``Configuration.get_roles()`` (the
current members of each user role). It never reads ``get_subjects()``. From these it builds one
``RoleHolders`` (``aiac.policy.model.holders``) and applies it, in memory, to every input rule and
to every SPM that it reads from the store, so the routing guard, the affected set, ``_derive`` and
the writer's ``project_inbound`` all see the current holders. The catalog also decides the kind of a
role: a role that a service in the catalog holds is an agent role, also when the edge carries
``kind=User`` (a child of a composite role does). The store schema does not change: the stored
``actorIds`` are a snapshot, refreshed when the PCE writes the SPM.
``rerender_role(role_id)`` is the entry point for a membership change (the role-members event): it
re-renders the CRs that use the role, with no PRB call and no store write.

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
side with the current role holders (target side: the services whose SPM changed, and every service
whose SPM keeps an edge that can still name X; agent side: the agents that targeted X, the current
holders of those roles, and the agents among those services). X is gone from the IdP, so the PCE
cannot tell which roles X held at the last render of each CR: an admin can map a role to X after
``SPM(X)`` was written, and the role-members event writes no SPM. So it renders again every CR that
has an edge of an agent role or an edge whose role has no holder now (a role that only X held, also
one stored with ``kind=User``), without X, and writes none of those SPMs. A removal (decommission or
quarantine) changes the store last: the CR delete and the redeploy come first, then the writes of
the purged SPMs, and the delete of ``SPM(X)`` is the last step. So a removal that fails part way
keeps ``SPM(X)``, and its retry finds the whole footprint again.

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
write its rules back. Only a successful re-onboarding lifts the quarantine: its ``compute_and_apply``
runs with the service as the focus while its client is still disabled. The quarantine rendered the
CRs of a shared role of the service without it but did not write those SPMs, so the stale-holders
check cannot find them. The lift therefore also deploys every live SPM that has an edge of a role of
the focus service, with the focus as a holder again. It writes only those whose stored holders are
stale (a run wrote them while the service was quarantined), so each snapshot names the holders that
its CR names.

The caller re-enables the client after ``compute_and_apply`` returns, outside the PCE lock, so a
render in that window would read the client as disabled and take the service out of the CRs again
(with no SPM write, so no later stale check finds it). So a lift that succeeds adds the focus, under
the lock, to an in-process set of services that wait for their re-enable, and every operation counts
a waiting service as live (``RoleHolders``, ``holders.live``). The caller (the onboarding route, the
NATS consumer) calls ``lift_done`` after ``reenable_service``, also when the re-enable fails: the
client then stays disabled, and the service must not count as live. A quarantine or a decommission
of the service ends every wait.

Resync, read model, bootstrap. ``resync()`` (D28) runs at every Controller start: one
``replace_policy`` (``PUT /policy``) with the full policy model of the side for the live managed
services, then a quarantine of each disabled service that still has an SPM. A side change is a
ConfigMap patch and a Controller restart, so the resync then writes every CR in the new side.
``policy_model_for(service_id)`` (D18) returns the policy model of the side with only that service's
entry, or ``None``. ``bootstrap(service_id, service_type)`` (checkpoint B1) writes the focus tool's CR
before UC-1 Provision, so that the discovery passes D20; it stores no SPM.

Fire-and-forget — ``compute_and_apply``, ``decommission``, ``quarantine``, ``resync``,
``bootstrap`` and ``rerender_role`` log and re-raise dependency failures.

Serialization (the PCE lock). Every operation that writes reads SPMs, changes them, and writes them
back. The store has no versions, and its own write lock protects one write, not a
read-modify-write. So two runs that route rules into one shared SPM (for example two agents
granted on one tool's scope) would both read the old SPM, and the second write would silently
remove the first run's rules. One module-level lock, ``_pce_lock``, is held for the whole body of
``compute_and_apply``, ``decommission``, ``quarantine``, ``resync``, ``bootstrap`` and
``rerender_role``; ``policy_model_for`` only reads and takes no lock. The PRB (the LLM work) runs
before ``compute_and_apply``, outside the lock, so concurrent onboardings still build their rules in
parallel; the part under the lock makes no LLM call. Known limits:

- It serializes one process only (one Controller replica, as for the orchestrator's per-service
  lock). More replicas need store versions or a distributed lock. The set of services that wait for
  their re-enable is in process too.
- When two onboardings overlap, a pair between the two new services can stay unjudged (each
  service's resolver read the catalog before the other's Provision). That pair then gives no
  grant (fail closed).
"""

import logging
import os
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field

from aiac.idp.configuration.api import Configuration
from aiac.idp.configuration.models import ClientId, Role, RoleKind, Scope, Service, ServiceType
from aiac.pdp.policy.library.api import apply_policy, delete_service_cr, replace_policy
from aiac.policy.model.holders import RoleHolders
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

# The services that wait for their re-enable after the lift of their quarantine, each with the number
# of lifts that wait (see "Quarantine" in the module docstring and ``lift_done``). In process: one
# Controller replica. ``_awaiting_lock`` guards it; it is held only for a set operation, so
# ``lift_done`` never waits for the PCE lock.
_awaiting_reenable: dict[str, int] = {}
_awaiting_lock = threading.Lock()


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
    catalog the PCE already loads — no additional IdP read. Order-independent: it removes **only**
    edges whose entity no longer exists, never a live edge, so onboarding-order convergence is
    preserved.

    An edge on ``SPM(X)`` is kept iff:

    1. its scope is still one of ``X``'s current ``aiac.managed`` scopes (``model.owned_scopes``,
       seeded from the catalog) — drops retired/churned scopes (e.g. ``*-aud``);
    2. for an ``Agent``-kind role, the role id is still in the catalog — drops retired/churned agent
       client roles (e.g. a role of the focus agent that the catalog no longer has);
    3. for a ``User``-kind role, it is not a superseded generation: user realm roles are
       membership-derived (absent from the catalog; the PCE reads ``get_roles()`` only for their
       current members at render time, D32, and never reads ``get_subjects()``), so among the
       ``User`` edges sharing ``(scope.id, role.name)`` a stale edge is dropped only when this batch
       carries a *different* id for that same ``(scope, name)`` — the fresh batch's
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


def _seed_from_catalog(model: ServicePolicyModel, catalog: dict[str, Service]) -> None:
    """Seed ``model``'s type and identity from the catalog when its service is still there (a deleted
    service keeps the stored ones)."""
    svc = catalog.get(model.service_id)
    if svc is not None:
        if svc.type is not None:
            model.service_type = svc.type
        _seed_identity(model, svc)


def _read_idp(focus_service: str | None = None) -> tuple[dict[str, Service], RoleHolders]:
    """Read the IdP one time for an operation (D32): the ``get_services()`` catalog, keyed by
    clientId, and the current holders of every role, from that catalog and one ``get_roles()`` call.
    The focus service counts as live, and so does each service that waits for its re-enable
    (``holders.live``). The PCE never reads ``get_subjects()``.

    The set of waiting services is read before the catalog: its caller ends a wait only after
    ``reenable_service`` returns, so a service that is not in the set any more is enabled in the
    catalog that this read gives, or its re-enable failed."""
    with _awaiting_lock:
        awaiting = frozenset(_awaiting_reenable)
    config = Configuration.for_default_realm()
    catalog = {svc.serviceId: svc for svc in config.get_services()}
    holders = RoleHolders(catalog.values(), config.get_roles(), focus_service=focus_service, awaiting_reenable=awaiting)
    return catalog, holders


def lift_done(service_id: ClientId) -> None:
    """End one wait of ``service_id`` (its clientId) for its re-enable after the lift of its
    quarantine (LIM-09).

    A run that lifts a quarantine (its focus service is in the catalog but disabled) adds the focus
    to the PCE's set of services that wait for their re-enable, under the PCE lock, when the run
    succeeds. The caller (the onboarding route and the NATS consumer) re-enables the client after
    ``compute_and_apply`` returns, outside the lock, and calls ``lift_done`` after
    ``reenable_service``, also when the re-enable fails. Until then every operation counts the
    service as live, so a render in that window (for example a role-members event) keeps it in the
    CRs of its roles, and the run's routing guard keeps its rules. After a failed re-enable the
    client stays disabled, so the service must not count as live any more.

    Each lift waits for its own ``lift_done``: two lifts that overlap (an HTTP onboarding and a NATS
    redelivery) keep the service live until both are done. A ``lift_done`` that finds no wait is a
    no-op: the caller cannot tell a lift from another onboarding, so it calls it after every
    onboarding that reaches the re-enable. A quarantine or a decommission of the service ends every
    wait. The set is in process: it serializes one Controller replica only, as the PCE lock does.
    Takes no PCE lock."""
    with _awaiting_lock:
        count = _awaiting_reenable.get(service_id, 0)
        if count > 1:
            _awaiting_reenable[service_id] = count - 1
        else:
            _awaiting_reenable.pop(service_id, None)


def _wait_for_reenable(service_id: str) -> None:
    """Add one wait of ``service_id`` for its re-enable (see ``lift_done``)."""
    with _awaiting_lock:
        _awaiting_reenable[service_id] = _awaiting_reenable.get(service_id, 0) + 1


def _end_every_wait(service_id: str) -> None:
    """End every wait of ``service_id`` for its re-enable: it is quarantined or decommissioned."""
    with _awaiting_lock:
        _awaiting_reenable.pop(service_id, None)


def _former_holders(stored: ServicePolicyModel, current: ServicePolicyModel) -> set[str]:
    """The services that the stored snapshot of an SPM names as holders of an ``Agent``-kind role
    (with the current holders) but that do not hold it now. ``current`` is ``stored`` with the
    current holders, so the edges have the same order."""
    former: set[str] = set()
    for old, new in zip(
        stored.inbound_allow_rules + stored.inbound_deny_rules,
        current.inbound_allow_rules + current.inbound_deny_rules,
        strict=True,
    ):
        if new.role.kind == RoleKind.AGENT:
            former.update(set(old.role.actorIds) - set(new.role.actorIds))
    return former


def _spm_cache(catalog: dict[str, Service], holders: RoleHolders, stale: dict[str, set[str]] | None = None):
    """Build a store-backed SPM cache seeded from the ``get_services()`` catalog.

    Returns ``(spms, spm)``, shared by every operation that renders. ``spm(id)`` fetches each SPM
    from the store at most once (``get_service_policy`` returns a fresh empty SPM on 404, so a
    brand-new — or already-deleted — service is handled), gives each edge the current holders of its
    role (``holders``, D32), seeds its identity (type + own ``aiac.managed`` roles/scopes) from the
    catalog when the service is still present, and mutates in place. ``spms`` maps each loaded id to
    its cached SPM. When ``stale`` is given, ``spm`` adds to it each SPM whose stored holders were not
    the current ones: its id, mapped to its former holders (``_former_holders``). A caller that has
    already read the stored SPM (for example from ``list_service_policies``) gives it as ``stored``,
    so the cache does not read it again; an SPM that is already cached stays as it is.
    """
    spms: dict[str, ServicePolicyModel] = {}

    def spm(service_id: str, stored: ServicePolicyModel | None = None) -> ServicePolicyModel:
        if service_id not in spms:
            if stored is None:
                stored = get_service_policy(service_id)
            model = holders.refresh_model(stored)
            if stale is not None and model != stored:
                stale[service_id] = _former_holders(stored, model)
            _seed_from_catalog(model, catalog)
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
    when it is empty. Live = in the catalog and not disabled; the focus service and a service that
    waits for its re-enable (see "The lift") count as live.

    - target side: ``TargetSidePolicyModel(services=[SPM(x) for x in touched | lifted if x is
      live])``. ``touched`` is every SPM that the run routed a rule to (also a duplicate rule),
      purged under override, or stored as the focus SPM, changed or not;
    - agent side: ``AgentSidePolicyModel(agents=[APM(a) for each live affected agent],
      pass_through=[focus_service] if it is a live tool)``. The affected agents are the owners of
      the batch's agent roles, each touched owner (a touched SPM) that is an agent, each agent that
      targets a touched SPM (an Agent-kind inbound edge on it), the former holders of each stale
      SPM (its stored holders that do not hold the role now), and each agent in ``lifted``. Each APM
      is derived from the store just written.

    Role holders (D32). Each input rule, and each SPM that the run reads, gets the current holders
    of its role before the routing guard (see "Role holders" in the module docstring). Every touched
    SPM is deployed, so a duplicate rule (for example the second holder of a shared role) still
    updates the callee's CR. A render that writes no SPM (``rerender_role``, the resync, the redeploy
    of a shared role at a quarantine or a decommission) can leave a CR with other holders than the
    stored snapshot, and a holder can lose the role with no event; the touched SPM is then not stale,
    and its deploy still repairs the CR. A touched SPM whose stored holders are not the current ones
    (stale) is also persisted, so its snapshot names the holders that its CR names.

    The lift (D32). A run whose ``focus_service`` is in the catalog but disabled lifts the
    quarantine of that service. ``lifted`` is then every live service whose SPM has an edge of a role
    of the focus service (its ``aiac.managed`` roles), with the focus as a holder again: the
    quarantine rendered those CRs without it but did not write the SPMs, so their stored holders can
    still name it and the stale-holders check does not find them, and the run's rules need not touch
    them. They are deployed. Their rules did not change, so the run writes only those whose stored
    holders are stale (for example a callee that a run wrote while the focus was quarantined): the
    snapshot then names the holders that the CR names, so a later stale-holders check sees a later
    change of the holders. In every other run ``lifted`` is empty. A lift that succeeds also adds the
    focus to the set of services that wait for their re-enable (LIM-09): the caller re-enables the
    client after this call returns, outside the lock, and every operation counts the focus as live
    until the caller's ``lift_done``, so a render in that window does not take it out of the CRs.

    Routing guard. A disabled client is a failed (quarantined) service; a service absent from the
    catalog is deleted. Under the PCE lock, after the IdP read, the run drops each rule whose scope
    owner is disabled or absent, or whose ``Agent``-kind role has no live holder now, so a build
    that started before a quarantine or an offboard cannot write rules back into the removed
    footprint. A shared role with one disabled holder and one live holder is kept: it is the live
    holder's grant too. The run also deploys only live services. ``focus_service`` — the
    clientId (``Service.serviceId``, the SPM key) of the service this onboarding builds, not its
    Keycloak UUID — is exempt: a re-onboarding applies while its client is still disabled
    (``reenable_service`` runs after the apply). A service that waits for its re-enable is exempt
    too. The onboarding route and the NATS consumer pass the
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
    policy-model stage, D23), with the current role holders: under target side the services whose
    SPM the purge changed; under agent side the agents that targeted X (read from ``SPM(X)``) and the
    agents whose SPM the purge changed, re-derived from the store and the SPM cache.

    Order: the CR delete and the redeploy come first, then the writes of the purged SPMs, and the
    delete of ``SPM(X)`` is the last step. Only the store gives the footprint of X again (the purged
    edges, the targeters, and ``SPM(X)`` for the content guard), so a decommission that fails part
    way keeps ``SPM(X)``, and its retry (the operator offboards X again) does the whole teardown
    again. Each step gives the same result when it runs again.

    A role of X that another service also holds (a shared role, D32) is not purged. X is not a
    holder of it any more, so the services whose SPM has an edge of that role are redeployed too,
    without X, but not written (their rules did not change); under agent side the remaining holders
    of the role and the agents among those services are re-derived. A client delete gives no
    role-mapping event, so without this X stays in those CRs until the resync. X is gone from the
    IdP, so ``SPM(X).owned_roles`` (from the last run that wrote ``SPM(X)``) does not list a role that
    an admin mapped to X later (its role-members event writes no SPM, B-04). So every live service
    whose SPM has an edge that can still name X is redeployed in the same way: an edge of an agent
    role (a role that a service in the catalog holds, or an ``Agent``-kind edge), or an edge whose
    role has no holder now (a role that only X held, also one stored with ``kind=User``, for example
    a child of a composite role). Nothing more is purged: X is not known to hold those roles. A user
    role with members cannot name a service (Assumption 1), so an SPM with only such edges is not
    redeployed. A never-onboarded / already-removed service (the store has no content for it) is a
    no-op: no store write, no CR delete.

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


def _live_current(
    models: Iterable[ServicePolicyModel], live: frozenset[str], holders: RoleHolders
) -> list[ServicePolicyModel]:
    """The SPMs of ``models`` whose service is ``live``, sorted by service id, each with the current
    holders of its roles (D32) — what a target-side render of stored SPMs deploys."""
    ordered = sorted(models, key=lambda model: model.service_id)
    return [holders.refresh_model(model) for model in ordered if model.service_id in live]


def _routable(rule: PolicyRule, live: frozenset[str]) -> bool:
    """True iff ``rule`` (with the current holders, D32) can take effect: its scope owner is
    ``live``, and an ``Agent``-kind role has at least one holder. The holders are live services
    only, so a role whose every holder is disabled or absent has none. A shared role is also the
    grant of its other holders, so one disabled holder does not drop it. A service absent from the
    catalog is gone (its client was deleted, e.g. offboarded while its onboarding was still
    building)."""
    if rule.scope.serviceId not in live:
        return False
    return rule.role.kind != RoleKind.AGENT or bool(rule.role.actorIds)


def quarantine(service_id: ClientId, deleted_roles: Iterable[Role] = ()) -> None:
    """Tear down a failed onboarding's policy footprint — the UC1 failure path (after the rollback).

    ``service_id`` is the **clientId (the SPM key, ``Service.serviceId``)**, as for ``decommission``
    — not the Keycloak internal UUID. The orchestrator resolves it from the onboarding's UUID while
    the client still exists. The failed service X is still in the catalog (disabled). Holds the PCE
    lock. For X:

    1. remove X's roles from the other SPMs (as ``decommission`` does), in the SPM cache — the roles
       X still has in the catalog, plus ``deleted_roles``: the roles the rollback already deleted
       from the IdP (the run's created-manifest). The catalog no longer lists those, but a
       concurrent run can have stored their grants on another SPM, which would keep allowing X. A
       role that another service also holds (a shared role, D32) is kept: its grants are that
       service's too;
    2. delete the CR of X (``delete_service_cr``, D20), for an agent and for a tool. In an AIAC setup
       the global combiner denies a pod that has no client CR, so the delete denies every request to
       and from X. There is no no-rules CR;
    3. redeploy the affected live services of the current side (not X, not a deleted or disabled
       service) in one ``apply_policy`` call (the policy-model stage, D23), with the current role
       holders: under target side the services whose SPMs lost X's roles, and the services whose
       SPMs keep an edge of a shared role of X (X, disabled, is not a holder any more, so it leaves
       their CRs; these SPMs are not written); under agent side the agents that targeted X, the
       agents whose SPMs lost X's roles or keep an edge of a shared role of X, and the remaining
       holders of that shared role, re-derived from the store and the SPM cache;
    4. write each SPM that lost X's roles, then delete ``SPM(X)`` from the store. The store changes
       last, so a quarantine that fails part way keeps ``SPM(X)``: its retry, or the resync (which
       quarantines each disabled service that still has an SPM), does the whole teardown again.

    Idempotent: a second call finds no SPM and no edges, and deletes the CR again (a 404 counts as
    success). A ``service_id`` that is not in the catalog is a logged no-op. The quarantine is lifted
    only by a successful re-onboarding: its ``compute_and_apply`` (X is the focus service, still
    disabled) stores ``SPM(X)`` again (also with zero rules, D21), writes a new CR, and deploys the
    SPMs of step 3 that keep an edge of a shared role of X, with X as a holder again (the quarantine
    did not write them, so the stale-holders check cannot find them; the lift writes only those whose
    stored holders are stale); then ``reenable_service`` re-enables the client, and the caller's
    ``lift_done`` ends the wait for the re-enable. A quarantine ends every wait of X for its re-enable:
    a lift of X whose caller has not re-enabled the client yet must not keep X live.

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

    1. read the IdP once (the catalog and the current role holders, D32) and list every stored SPM
       (``list_service_policies``, the managed set);
    2. ``replace_policy(<the full policy model of the current side>)`` — ``PUT /policy`` upserts one
       CR per entry and deletes every other AIAC CR. Live = in the catalog and enabled (checkpoint
       O3). Target side: ``TargetSidePolicyModel(services=[every stored SPM of a live service])``,
       the SPMs as stored with the current holders. Agent side: ``AgentSidePolicyModel(agents=[the
       APM of every live stored agent], pass_through=[every live stored tool])``. The call is made
       also when the model is empty: the PUT then deletes every AIAC CR;
    3. quarantine (see ``quarantine``) each disabled service that still has a stored SPM (C2), under
       the same lock hold, with no ``deleted_roles``.

    A service that has a stored SPM but is absent from the catalog (deleted, not decommissioned) is
    not in the model, so the PUT deletes its CR; its SPM stays (removing it is ``decommission``'s
    job). The resync is also the path for a side change (a ConfigMap patch and a Controller restart:
    the PUT writes every CR in the new side, so no mixed state stays), for a stale or missing CR,
    for a missed role-members event (the render uses the current holders), and for the upgrade from
    the per-agent CRs of an older release.

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


def rerender_role(role_id: str) -> None:
    """Re-render the CRs that use the role ``role_id`` with its current holders (D32) — the entry
    point of the role-members event (a user or a service account got or lost the role).

    A membership change does not change the policy (role → scope), only who holds the role. So it
    makes no PRB call and writes no SPM: the stored rules stay, and only the CRs change. Holds the
    PCE lock. Reads the IdP once (the catalog and the current role holders), then deploys in one
    ``apply_policy`` call (D23):

    - target side: the live stored SPMs that have an edge of the role
      (``get_service_policies_by_role``), each with the current holders; no call when there is none;
    - agent side (the legacy method): the APM of every live stored agent, re-derived from the store.
      An agent that lost the role is not a holder any more, so it cannot be found from the holders;
      no call when there is no live stored agent.

    ``role_id`` is the Keycloak role id. A deleted role still re-renders: its edges get no holder
    (fail closed). A missed event is repaired by the resync.

    Exceptions from any dependency are logged and **re-raised**.
    """
    try:
        side = enforcement_side()
        with _pce_lock:
            _rerender_role(role_id, side)
    except Exception:
        logger.exception("rerender_role failed for role %r", _loggable(role_id))
        raise


def _rerender_role(role_id: str, side: EnforcementSide) -> None:
    catalog, holders = _read_idp()
    live = holders.live
    if side == EnforcementSide.TARGET_SIDE:
        # The event gives only the role id, and ``get_service_policies_by_role`` sends only
        # ``role.id`` to the store, so the other fields of this Role are placeholders.
        role = Role(id=role_id, name=role_id, composite=False)
        services = _live_current(get_service_policies_by_role(role), live, holders)
        if services:
            apply_policy(TargetSidePolicyModel(services=services))
        return
    _, spm = _spm_cache(catalog, holders)
    agents = {model.service_id for model in list_service_policies() if model.service_id in live}
    _deploy_agent_side(agents, spm, catalog)


def policy_model_for(service_id: ClientId) -> PolicyModel | None:
    """The read model of one service (D18): the policy model of the current side with only the entry
    of ``service_id``, or ``None`` if the store has no SPM for it (the service is not in the managed
    set; the Controller route then gives 404).

    - target side: ``TargetSidePolicyModel(services=[SPM(service_id)])``, the SPM as stored with the
      current holders;
    - agent side: ``AgentSidePolicyModel(agents=[APM(service_id)])`` for an agent, derived from the
      store as at a deploy; else ``AgentSidePolicyModel(agents=[], pass_through=[service_id])``. The
      stored SPM's ``service_type`` tells an agent from a tool.

    It shows what the PCE deploys for the service from the current store. It does not read the CR in
    the cluster (which can be stale, D23). When the store has the SPM, it reads the IdP as a deploy
    does (``get_services()`` and ``get_roles()``, D32), because the render uses the current role
    holders, not the stored ``actorIds``. Under agent side the identity (P2) of the APM is seeded
    from the catalog, as at a deploy, not the one stored on the SPM: a role-members event changes the
    roles of an agent and writes no SPM, so the stored ``owned_roles`` can be old (G-21). Read-only:
    it takes no lock and writes nothing."""
    side = enforcement_side()
    stored = _stored_spm(service_id)
    if stored is None:
        return None
    if side == EnforcementSide.AGENT_SIDE and stored.service_type != ServiceType.AGENT:
        return AgentSidePolicyModel(agents=[], pass_through=[service_id])
    catalog, holders = _read_idp()
    model = holders.refresh_model(stored)
    if side == EnforcementSide.TARGET_SIDE:
        return TargetSidePolicyModel(services=[model])
    _seed_from_catalog(model, catalog)
    spms, spm = _spm_cache(catalog, holders)
    spms[service_id] = model
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

    - ``SPM(service_id)`` is the stored SPM when the store has one (a re-onboarding), as stored with
      the current role holders (D32);
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
    # The IdP once (D32): the catalog seeds a new SPM; the holders refresh a stored one. The service
    # is the focus of its onboarding, so it counts as live.
    catalog, holders = _read_idp(service_id)
    model = _stored_spm(service_id)
    if model is not None:
        model = holders.refresh_model(model)
    else:
        model = ServicePolicyModel(service_id=service_id, service_type=service_type, owned_roles=[], owned_scopes=[])
        svc = catalog.get(service_id)
        if svc is not None:
            _seed_identity(model, svc)
    if side == EnforcementSide.TARGET_SIDE:
        apply_policy(TargetSidePolicyModel(services=[model]))
    elif model.service_type == ServiceType.AGENT:
        # Never a pass-through for an agent: it would allow every request. Its APM, derived from
        # that SPM, as a deploy derives it.
        spms, spm = _spm_cache(catalog, holders)
        spms[service_id] = model
        apply_policy(AgentSidePolicyModel(agents=[_derive(service_id, spm)]))
    else:
        apply_policy(AgentSidePolicyModel(agents=[], pass_through=[service_id]))


def _loggable(value: str) -> str:
    """Strip CR/LF so a hostile id cannot forge log records."""
    return value.replace("\r", "").replace("\n", "")


def _run(rules: list[PolicyRule], override: bool, focus_service: str | None, side: EnforcementSide) -> None:
    # (1) The IdP once (D32). The catalog carries each service's type (agent vs tool) and its own
    # roles/scopes (the SPM identity, P2, filtered to aiac.managed), and tells which services are
    # live; with get_roles() it gives the current holders of every role.
    catalog, holders = _read_idp(focus_service)

    # (1a) The current holders on every input rule: the build's actorIds are a snapshot (a shared
    # role carries only the holder that the build saw).
    rules = [holders.refresh_rule(rule) for rule in rules]

    # Distinct input roles (dedup by id) — the set purged under override. Built from the input
    # BEFORE the routing guard: under override, a role whose every new rule the guard drops must
    # still lose its old grants.
    distinct_roles: dict[str, Role] = {}
    for rule in rules:
        distinct_roles.setdefault(rule.role.id, rule.role)

    # (1b) Routing guard — drop every rule whose scope owner is not live — disabled (quarantined,
    # except the focus service and a service that waits for its re-enable) or absent from the catalog
    # (deleted) — or whose agent role has no live holder. See ``compute_and_apply``.
    live = holders.live
    kept = [rule for rule in rules if _routable(rule, live)]
    if len(kept) != len(rules):
        logger.warning(
            "routing guard dropped %d rule(s) that touch a disabled or deleted service or whose agent role has no "
            "live holder",
            len(rules) - len(kept),
        )
    rules = kept

    # SPM cache: fetch each SPM from the store at most once, give its edges the current holders,
    # seed its identity from the catalog, mutate in place, and persist the changed ones. ``stale``
    # maps each loaded SPM whose stored holders were not the current ones to its former holders.
    stale: dict[str, set[str]] = {}
    spms, spm = _spm_cache(catalog, holders, stale)

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

    # (3b) Reconcile touched SPMs against current IdP truth (get_services()-only — no extra IdP
    # read) so drift cannot accumulate across re-onboarding. At this point ``spms`` holds exactly
    # the touched SPMs (routed + override-purged + the focus SPM). Runs under both merge modes;
    # order-independent (drops only edges whose entity no longer exists).
    catalog_agent_role_ids = {r.id for svc in catalog.values() for r in svc.roles if r.aiac_managed}
    batch_user_role_ids = {rule.role.id for rule in rules if rule.role.kind == RoleKind.USER}
    for service_id, model in list(spms.items()):
        if _reconcile(model, catalog, catalog_agent_role_ids, batch_user_role_ids):
            changed.add(service_id)

    # (3c) The touched SPMs: at this point ``spms`` holds exactly the SPMs that the run routed a
    # rule to, purged or loaded as the focus. Step 5 deploys each one, changed or not. A render that
    # writes no SPM (``rerender_role``, the resync, the redeploy of a shared role at a quarantine or a
    # decommission) can leave a CR with other holders than its snapshot, and a holder can then lose
    # the role with no event (a lost event): the SPM is then not stale, but its CR still names that
    # holder. So a duplicate rule still repairs the CR. ``stale`` decides only the store write: a
    # touched SPM whose stored holders are not the current ones (a holder came or went since it was
    # written) is written in step 4, so its snapshot names the holders that its CR names.
    touched = set(spms)

    # (3d) The lift (D32): when this run lifts a quarantine (the focus service is disabled), the
    # live services whose SPM has an edge of a role of the focus service. Each is deployed. It does
    # not join ``changed`` (its rules did not change), but loading it adds it to ``stale`` when its
    # stored holders are not the current ones (a run wrote it while the focus was quarantined), and
    # step 4 writes that one: its snapshot then names the holders that its CR names.
    lifted = _lift_callees(focus_service, catalog, live, spm)

    # (4) Persist every changed SPM, and every loaded SPM whose stored holders are stale.
    for service_id in changed | stale.keys():
        apply_service_policy(service_id, spms[service_id])

    # (5) The policy-model stage (D23): deploy the affected live services of the side. Only live
    # services: one absent from the catalog is deleted, and its stored SPM (or the store's 404
    # placeholder) must not bring its CR back — removing it is ``decommission``'s job; a disabled one
    # stays with no CR.
    if side == EnforcementSide.TARGET_SIDE:
        # Target side: the touched SPMs, and the lifted ones — each CR is rendered from the callee's
        # own SPM.
        _deploy((touched | lifted) & live, spms)
    else:
        # Agent side: the affected agents, derived from the store just written (an agent's outbound
        # depends on the SPMs of the services it calls), plus the pass-through CR of a focus tool
        # (D24). The touched owners include ``changed``, which is what makes a revocation propagate:
        # under override an owner that only *lost* edges is in ``changed`` but carries no fresh rule.
        # A lifted agent gets the focus back in its inbound ``source_roles``; a lifted tool keeps its
        # pass-through, and an outbound does not name the holders of its own role, so nothing else.
        # The former holders of each stale SPM lost a role that has an edge on it: they are not
        # holders now, so the touched owners do not find them, and each one's outbound loses those
        # edges.
        affected = _affected_agents(distinct_roles.values(), touched, spm, catalog)
        affected |= {sid for sid in lifted if _is_agent(catalog, sid)}
        affected |= {sid for former in stale.values() for sid in former}
        pass_through = [focus_service] if focus_service in live and _is_tool(catalog, focus_service) else []
        _deploy_agent_side(affected & live, spm, catalog, pass_through)

    # (6) A lift waits for its re-enable: the caller re-enables the client after this run returns,
    # outside the PCE lock, and every operation counts the focus as live until the caller's
    # ``lift_done``. Only a run that succeeded waits: a failed run lifts nothing, and its caller does
    # not re-enable the client.
    if _lifts(focus_service, catalog):
        _wait_for_reenable(focus_service)


def _lifts(focus_service: str | None, catalog: dict[str, Service]) -> bool:
    """True iff a run with ``focus_service`` lifts its quarantine: the focus service is in the
    catalog but disabled (a successful re-onboarding; ``reenable_service`` runs after the apply)."""
    svc = catalog.get(focus_service) if focus_service is not None else None
    return svc is not None and not svc.enabled


def _lift_callees(focus_service: str | None, catalog: dict[str, Service], live: frozenset[str], spm) -> set[str]:
    """The services that the lift of a quarantine re-renders (D32), the focus service excluded.

    A run whose focus service X is in the catalog but disabled is the successful re-onboarding that
    lifts the quarantine of X (``reenable_service`` runs after the apply). The quarantine rendered the
    CRs of the SPMs that have an edge of a shared role of X without X, and did not write those SPMs
    (``_remove_footprint``, a shared role). So their stored holders can still name X: the stale-holders
    check (step 3c) does not find them, and the run's rules need not touch them. Now X counts as
    live, so it is a holder again. This returns every live service whose SPM has an edge of a role of
    X (``SPM(X).owned_roles``, its ``aiac.managed`` roles from the catalog), loaded through the SPM
    cache with the current holders, so the cache adds to ``stale`` each one whose stored holders are
    not the current ones. The caller deploys them. Their rules did not change, so it writes only the
    stale ones: a callee that a run wrote while X was quarantined has a snapshot without X, and if
    its CR named X but the snapshot did not, a later stale-holders check could not see that X lost
    the role (the CR would keep X until the resync). After a quarantine, an edge of a role that only
    X holds is new in this run (the quarantine purged the old ones, and the routing guard dropped
    every later rule of the role, which had no live holder), so its SPM is already touched (and
    changed): the lift of a service that holds no shared role gets no extra deploy.

    Any other run returns an empty set: no focus service, or an enabled one, which is already a
    holder in those CRs.
    """
    if not _lifts(focus_service, catalog):
        return set()
    callees: set[str] = set()
    for role in spm(focus_service).owned_roles:
        for stored in get_service_policies_by_role(role):
            if stored.service_id != focus_service and stored.service_id in live:
                callees.add(spm(stored.service_id).service_id)
    return callees


def _decommission(service_id: str, side: EnforcementSide) -> None:
    # (1) The IdP once (D32). X itself is absent (it was offboarded); the catalog is used to seed
    # and filter the still-live services that the redeploy writes, and with get_roles() it gives
    # the current role holders (X is not one). X waits for no re-enable any more.
    _end_every_wait(service_id)
    catalog, holders = _read_idp()
    spms, spm = _spm_cache(catalog, holders)

    # (2) Load SPM(X) — X is gone from the catalog, so spm() does not reseed it; the persisted SPM
    # carries the roles/scopes X owned when it was onboarded. Content guard: a 404 fresh-empty SPM
    # (never onboarded / already removed: the delete of SPM(X) is the last step) is a no-op — no
    # spurious CR delete.
    spm_x = spm(service_id)
    if not (spm_x.owned_roles or spm_x.owned_scopes or spm_x.inbound_allow_rules or spm_x.inbound_deny_rules):
        return

    # (3)-(4b) Tear down X's footprint in the SPM cache (see ``_remove_footprint``).
    footprint = _remove_footprint(service_id, catalog, spms, spm)

    # (4c) The other edges that can still name X in a CR (see ``_add_callees_of_every_agent_role``).
    _add_callees_of_every_agent_role(service_id, footprint, holders.live, spm)

    # (5) Delete the CR of X (D20), for an agent and for a tool. A 404 counts as success.
    delete_service_cr(service_id)

    # (6) Redeploy the affected live services of the side (X excluded) in one call (D23).
    _redeploy_after_removal(service_id, footprint, catalog, holders.live, spms, spm, side)

    # (7)-(8) Change the store last (see ``_persist_removal``), so a retry of a decommission that
    # failed before this point finds SPM(X) and does the whole teardown again.
    _persist_removal(service_id, footprint, spms)


def _resync(side: EnforcementSide) -> None:
    # (1) The IdP once (the catalog and the current role holders, D32), and every stored SPM — the
    # managed set (D21).
    catalog, holders = _read_idp()
    stored = sorted(list_service_policies(), key=lambda model: model.service_id)

    # (2) Replace every AIAC CR with the CRs of the live managed services, in the current side. A
    # disabled service is not in the model: step 3 removes it, and its rules must not come back,
    # even for a moment. Each CR names the current role holders, so the resync repairs a missed
    # role-members event.
    live = holders.live
    live_stored = _live_current(stored, live, holders)
    if side == EnforcementSide.TARGET_SIDE:
        replace_policy(TargetSidePolicyModel(services=live_stored))
    else:
        # The APM of each live stored agent, derived from the store, and a pass-through CR for each
        # live stored tool (D24).
        _, spm = _spm_cache(catalog, holders)
        replace_policy(
            AgentSidePolicyModel(
                agents=[_derive(m.service_id, spm) for m in live_stored if _is_agent(catalog, m.service_id)],
                pass_through=[m.service_id for m in live_stored if _is_tool(catalog, m.service_id)],
            )
        )

    # (3) Quarantine each disabled service that still has an SPM (C2). The lock is already held.
    for model in stored:
        if model.service_id in catalog and model.service_id not in live:
            _quarantine_in(catalog, holders, model.service_id, [], side)


def _quarantine(service_id: str, deleted_roles: list[Role], side: EnforcementSide) -> None:
    # (1) The IdP once (the catalog and the current role holders, D32). X is still in the catalog
    # (the rollback disables the client, it does not delete it), but a disabled service is not a
    # holder. spm() seeds X's current roles from the catalog, so step 4 removes the roles X still
    # has. The roles the rollback deleted are not in the catalog any more, so the caller passes them
    # in ``deleted_roles`` and step 4 removes their edges too — else an edge a concurrent run stored
    # (X_role → other_scope) keeps allowing X until a later run reconciles that SPM. A quarantine ends
    # every wait of X for its re-enable first (a lift of X whose caller has not re-enabled the client
    # yet): X failed, so it must not count as live.
    _end_every_wait(service_id)
    catalog, holders = _read_idp()
    _quarantine_in(catalog, holders, service_id, deleted_roles, side)


def _quarantine_in(
    catalog: dict[str, Service],
    holders: RoleHolders,
    service_id: str,
    deleted_roles: list[Role],
    side: EnforcementSide,
) -> None:
    """The body of ``quarantine`` for an IdP read already done (``quarantine`` and ``resync``)."""
    if service_id not in catalog:
        logger.warning("quarantine: service %r is not in the IdP catalog — nothing to do", _loggable(service_id))
        return
    spms, spm = _spm_cache(catalog, holders)

    # (2)-(3) Tear down X's footprint in the SPM cache (see ``_remove_footprint``).
    footprint = _remove_footprint(service_id, catalog, spms, spm, deleted_roles)

    # (4) Delete the CR of X (D20), for an agent and for a tool. In an AIAC setup the global combiner
    # denies a pod that has no client CR, so the delete denies every request to and from X. A 404
    # counts as success, so a second quarantine deletes again without an error.
    delete_service_cr(service_id)

    # (5) Redeploy the affected live services of the side (X excluded) in one call (D23).
    _redeploy_after_removal(service_id, footprint, catalog, holders.live, spms, spm, side)

    # (6) Change the store last (see ``_persist_removal``), so a retry of a quarantine that failed
    # before this point (or the resync, which quarantines each disabled service that still has an
    # SPM) finds SPM(X) and does the whole teardown again.
    _persist_removal(service_id, footprint, spms)


@dataclass
class _Footprint:
    """What ``_remove_footprint`` found for service X; X is in none of the sets.

    ``changed``: the services whose SPM the purge changed, written to the store last
    (``_persist_removal``). ``shared``: the services whose SPM has an edge of a shared role of X (in
    a decommission also: an edge that can still name X, see ``_add_callees_of_every_agent_role``),
    not written (their rules did not change), so their stored holders can still name X; the lift of
    a quarantine deploys them again with X (``_lift_callees``).
    ``agents``: the agents whose agent-side policy uses X — the agents that targeted X, and the
    remaining holders of each shared role of X that has an edge."""

    changed: set[str] = field(default_factory=set)
    shared: set[str] = field(default_factory=set)
    agents: set[str] = field(default_factory=set)


def _remove_footprint(
    service_id: str, catalog: dict[str, Service], spms, spm, extra_roles: Iterable[Role] = ()
) -> _Footprint:
    """Tear down service X's footprint in the SPM cache — the steps ``decommission`` and
    ``quarantine`` share. It writes nothing: ``_persist_removal`` changes the store after the CR
    delete and the redeploy. ``extra_roles`` are X's roles that ``SPM(X)`` no longer lists
    (``quarantine``'s rollback-deleted roles); their edges are purged as X's own. A role that another
    service in ``catalog`` also holds (a shared role, D32) is not purged: its grants are that
    service's grants too. X is not a holder of it any more (X is disabled or absent), so the SPMs that
    have an edge of that role keep their rules but get a new render without X.

    Returns the :class:`_Footprint` of X."""
    spm_x = spm(service_id)

    # Targeters — the agents whose outbound loses X: they hold an Agent-kind inbound edge (allow or
    # deny) on SPM(X) (their_role → X_scope), which goes with SPM(X). So they are read first.
    footprint = _Footprint(agents=_targeters(spm_x))

    # Purge X's outbound footprint — X_role → other_scope edges (allow AND deny) stored on OTHER
    # services' SPMs. Dedup by id: an extra role can also still be on SPM(X). Skip a role that
    # another service holds: the edges are keyed by role id, so a purge would also remove that
    # service's grants. X itself stays denied — its CR is deleted, and the combiner denies a pod
    # that has no client CR (D20).
    held_elsewhere = {r.id for sid, svc in catalog.items() if sid != service_id for r in svc.roles}
    roles = {role.id: role for role in [*spm_x.owned_roles, *extra_roles]}
    for role in roles.values():
        for stored in get_service_policies_by_role(role):
            if stored.service_id == service_id:
                continue
            model = spm(stored.service_id)
            if role.id not in held_elsewhere:
                if _purge_role(model, role.id):
                    footprint.changed.add(model.service_id)
                continue
            # A shared role: the edges stay, but the cached SPM already names only the current
            # holders, so the redeploy takes X out of the callee's CR (a client delete gives no
            # role-mapping event). The remaining holders carry these edges on their outbound (agent
            # side).
            footprint.shared.add(model.service_id)
            edges = model.inbound_allow_rules + model.inbound_deny_rules
            footprint.agents.update(actor for edge in edges if edge.role.id == role.id for actor in edge.role.actorIds)

    # In the cache, SPM(X) has no edges from now on: the store still has SPM(X) until
    # ``_persist_removal``, so an agent-side re-derive can find it by role, and it must find no edge
    # there (every user→X and agent→X inbound edge goes with SPM(X)).
    spms[service_id] = spm_x.model_copy(update={"inbound_allow_rules": [], "inbound_deny_rules": []})

    footprint.agents.discard(service_id)
    return footprint


def _persist_removal(service_id: str, footprint: _Footprint, spms: dict[str, ServicePolicyModel]) -> None:
    """The store stage of ``quarantine`` and ``decommission``, after the CR delete and the redeploy:
    write each SPM that the purge changed, then delete ``SPM(X)``. A shared SPM is not written: its
    rules did not change.

    The store changes last because only the store gives the footprint of X again: a retry finds the
    purged edges and the targeters only on the stored SPMs, and ``decommission`` finds X only when
    ``SPM(X)`` is stored (its content guard). So a removal that fails at an earlier step (the CR
    delete, the redeploy, or one of these writes) keeps ``SPM(X)``, and its retry does the whole
    teardown again. Each step gives the same result when it runs again. The delete of ``SPM(X)``
    is the last step: X then leaves the managed set."""
    for changed_id in sorted(footprint.changed):
        apply_service_policy(changed_id, spms[changed_id])
    delete_service_policy(service_id)


def _add_callees_of_every_agent_role(service_id: str, footprint: _Footprint, live: frozenset[str], spm) -> None:
    """Decommission only (B-04, B-05): add to ``footprint`` the callees whose CR can still name the
    decommissioned service X, as the callees of a shared role of X (``_remove_footprint``).

    X is gone from the IdP, so the PCE cannot tell which roles X held when each CR was last
    rendered. ``SPM(X).owned_roles`` has the roles of X from the last run that wrote ``SPM(X)``, but
    an admin can map a role to X after that run: the role-members event (``rerender_role``) and the
    resync then render X into the CRs of the role, and they write no SPM, so the stored ``actorIds``
    do not name X either. A client delete gives no role-members event. So every live SPM (``live``
    is ``holders.live``; X excluded) that has an edge that can name a service as a caller joins
    ``footprint.shared``, unless the purge changed it: it is redeployed with the current holders (X
    is not one) and not written. Its rules did not change, and no edge is purged: X is not known to
    hold the role.

    With the current holders (the SPM cache), such an edge is ``Agent``-kind (a role that a service in
    the catalog holds, or an ``Agent``-kind edge), or it has no holder: a role that only X held, also
    one whose stored edge carries ``kind=User`` (a child of a composite role), has no holder now. A
    user role with members cannot name a service (Assumption 1), so an SPM with only such edges is
    not redeployed. Under agent side the current holders of the ``Agent``-kind edges join
    ``footprint.agents``. The scan reads ``list_service_policies()`` once and gives each listed SPM
    to the cache, so it reads no SPM again. Quarantine does not need this: X is still in the catalog
    (disabled), so ``SPM(X)`` is seeded with the roles that X has now."""
    for stored in list_service_policies():
        if stored.service_id == service_id or stored.service_id not in live:
            continue
        model = spm(stored.service_id, stored)
        edges = model.inbound_allow_rules + model.inbound_deny_rules
        if not any(edge.role.kind == RoleKind.AGENT or not edge.role.actorIds for edge in edges):
            continue
        if model.service_id not in footprint.changed:
            footprint.shared.add(model.service_id)
        footprint.agents.update(
            actor for edge in edges if edge.role.kind == RoleKind.AGENT for actor in edge.role.actorIds
        )


def _redeploy_after_removal(
    service_id: str,
    footprint: _Footprint,
    catalog: dict[str, Service],
    live: frozenset[str],
    spms: dict[str, ServicePolicyModel],
    spm,
    side: EnforcementSide,
) -> None:
    """The policy-model stage of ``quarantine`` and ``decommission`` (D23): redeploy the affected
    services of ``side`` that are ``live`` (``holders.live`` of the operation's IdP read), X
    (``service_id``) excluded, in one call, with the current role holders. Target side: the services
    whose SPM the purge changed, and the services whose SPM has an edge of a shared role of X (in a
    decommission also an edge that can still name X) (``footprint.changed`` and ``footprint.shared``).
    Agent side: ``footprint.agents`` (the agents that targeted X, and the remaining holders of a
    shared role of X), and the agents among the changed and the shared services (their inbound
    ``source_roles[X]`` went). Each is re-derived: the store finds the SPMs by role, and the SPM
    cache gives each one. The store changes only after this call (``_persist_removal``), so the
    cache gives ``SPM(X)`` with no edge and each purged SPM as purged."""
    deployable = live - {service_id}
    touched = footprint.changed | footprint.shared
    if side == EnforcementSide.TARGET_SIDE:
        _deploy(touched & deployable, spms)
        return
    affected = footprint.agents | {sid for sid in touched if _is_agent(catalog, sid)}
    _deploy_agent_side(affected & deployable, spm, catalog)


def _deploy(service_ids: set[str], spms: dict[str, ServicePolicyModel]) -> None:
    """The policy-model stage (D23): partial-upsert the target-side policy model of ``service_ids``
    — their SPMs as just persisted — in one ``apply_policy`` call; no call when the set is empty."""
    if service_ids:
        apply_policy(TargetSidePolicyModel(services=[spms[sid] for sid in sorted(service_ids)]))


def _affected_agents(roles: Iterable[Role], touched_owners: set[str], spm, catalog: dict[str, Service]) -> set[str]:
    """The affected agents of a run under agent side (D23) — from the batch, never a full scan:

    - the current holders (``actorIds``) of each input or purged ``Agent``-kind role: their outbound
      changed;
    - each touched owner that is an agent: its inbound changed;
    - each agent that targets a touched SPM (``_targeters``, a superset of the exact-scope match;
      a re-derive is idempotent, so that is safe): its outbound changed.

    The caller keeps only the live ones."""
    affected: set[str] = set()
    for role in roles:
        if role.kind == RoleKind.AGENT:
            affected.update(role.actorIds)  # holding agents — their outbound changed
    for owner in touched_owners:
        if _is_agent(catalog, owner):
            affected.add(owner)  # the touched owner is an agent — its inbound changed
        affected.update(_targeters(spm(owner)))  # the agents that target it — their outbound changed
    return affected


def _targeters(model: ServicePolicyModel) -> set[str]:
    """The agents that target ``model``'s service: the current holders (``actorIds``) of every
    Agent-kind inbound edge on it, allow and deny."""
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
    """Build ``APM(agent_id)`` entirely from the persisted SPMs — the agent-side render input
    (``AgentSidePolicyModel.agents``). The target side does not call it. Every SPM it reads comes
    from the ``spm`` cache, so each edge carries the current holders of its role (D32); it makes no
    IdP read of its own.

    Each inbound edge on ``SPM(A)`` is classified by ``role.kind`` (User → subject, Agent → source)
    **and** ``effect`` (allow/deny) into one of four inbound buckets; each outbound edge (one of A's
    own roles referenced on an SPM, also on ``SPM(A)`` itself for a self-mapping of a shared role,
    which D32 allows) is classified by ``effect`` into the target allow/deny
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

    # Outbound — for each of A's own roles, the edges on the SPMs that reference it (also on SPM(A)
    # itself for a self-mapping of a shared role, which D32 allows), split by effect. Relevance is
    # directional: only A's *agent* roles confer an outbound edge, so a merely shared user role never
    # creates a false edge to a service A does not target. The store finds the SPMs; the cache gives
    # each one with the current holders.
    for role in sa.owned_roles:
        for stored in get_service_policies_by_role(role):
            _derive_outbound(apm, role, spm(stored.service_id))

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
    deny), and register each such user into the effect-agnostic ``subject_roles`` map.

    A shared scope (D32) is one scope id with a copy on each owner, and each copy has the user rules
    of its own SPM. The writer keys each outbound subject rule by the copy that it names (LIM-02), so
    the APM keeps one rule for each copy (``_add_rule_of_copy``), also when two copies have the same
    rule: with the rule of one copy only, a deny that both copies have would not decide on the other
    copy (fail-open)."""
    for effect, subject_rules in (
        (RuleEffect.ALLOW, apm.outbound_subject_allow_rules),
        (RuleEffect.DENY, apm.outbound_subject_deny_rules),
    ):
        for user_edge in _inbound_list(stored, effect):
            if user_edge.scope.id == scope.id and user_edge.role.kind == RoleKind.USER:
                _add_rule_of_copy(subject_rules, user_edge)
                for username in user_edge.role.actorIds:
                    _add_by_id(apm.subject_roles.setdefault(username, []), user_edge.role)


def _add_rule_of_copy(rules: list[PolicyRule], rule: PolicyRule) -> None:
    """Append ``rule`` unless one with the same ``(role.id, scope.id, scope.serviceId, effect)`` is
    present: the dedup of ``_add_rule`` (shared projection, D18b) plus the owner of the scope copy."""
    if any(
        r.role.id == rule.role.id
        and r.scope.id == rule.scope.id
        and r.scope.serviceId == rule.scope.serviceId
        and r.effect == rule.effect
        for r in rules
    ):
        return
    rules.append(rule)
