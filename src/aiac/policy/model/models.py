from collections.abc import Callable
from enum import Enum

from pydantic import BaseModel, ConfigDict

from aiac.idp.configuration.models import Role, Scope, ServiceType


class RuleEffect(str, Enum):
    """Tags a :class:`PolicyRule` as a grant (``Allow``) or a prohibition (``Deny``).

    A string enum mirroring ``ServiceType`` / ``RoleKind`` style, so ``RuleEffect.ALLOW ==
    "Allow"`` holds and it serializes as the string ``"Allow"`` / ``"Deny"``. A ``Deny`` rule is
    a durable prohibition that subtracts from what the ``Allow`` rules grant (deny-overrides)."""

    ALLOW = "Allow"
    DENY = "Deny"


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="ignore")

    role: Role
    scope: Scope
    # ``effect`` participates in dedup identity ``(role.id, scope.id, effect)`` so the same
    # ``(role, scope)`` can coexist once as ``Allow`` and once as ``Deny``. Defaulting to
    # ``Allow`` keeps existing allow-only producers working unchanged.
    effect: RuleEffect = RuleEffect.ALLOW


class ServicePolicyModel(BaseModel):
    """The persistent source of truth — one per service (agent *and* tool), keyed by
    ``service_id``. Holds the service's own identity (owned roles/scopes) plus every inbound
    edge (``Allow`` and ``Deny``, in separate parallel lists) touching its ``owned_scopes``.

    Canonical form: *every rule is an inbound edge on the SPM of the service that owns the
    rule's scope.* An agent's outbound edge is the target's inbound edge (``AR→TS`` is stored on
    ``SPM(T)``, not on ``A``). Because ``UR→TS`` lands durably on ``SPM(T)`` at tool-onboarding —
    no agent required — it can never be lost. Storing every rule on the SPM of the scope owner
    fixes the order-dependence bug of the older per-agent model.

    ``owned_roles`` / ``owned_scopes`` are the service's own identity, filtered to the
    ``aiac.managed`` marker; they are seeded from the catalog by the PCE (this module only
    defines the shape)."""

    model_config = ConfigDict(extra="ignore")

    service_id: str
    service_type: ServiceType  # Agent | Tool — selects the inbound package that the writer renders
    owned_roles: list[Role]  # this service's own client roles (aiac.managed only)
    owned_scopes: list[Scope]  # this service's exposed scopes (aiac.managed only)
    # Canonical inbound edges, split into two explicitly separated parallel lists (never one
    # intermixed list filtered by ``effect``): every ``Allow`` edge granting access to
    # ``owned_scopes``, and every ``Deny`` edge prohibiting it. A ``Deny`` edge subtracts from
    # what the ``Allow`` edges grant (deny-overrides).
    inbound_allow_rules: list[PolicyRule] = []
    inbound_deny_rules: list[PolicyRule] = []

    def all_edges(self) -> list[PolicyRule]:
        """Every inbound edge, in a new list: the ``Allow`` edges, then the ``Deny`` edges."""
        return self.inbound_allow_rules + self.inbound_deny_rules

    def prune_edges(self, prune: Callable[[list[PolicyRule]], list[PolicyRule]]) -> bool:
        """Replace each inbound list (``Allow`` and ``Deny``, one at a time) with ``prune(list)``, the
        edges of that list to keep. Each list is pruned on its own, so an edge of one list never
        changes what is kept in the other list. Returns ``True`` iff an edge was removed."""
        changed = False
        for attr in ("inbound_allow_rules", "inbound_deny_rules"):
            edges: list[PolicyRule] = getattr(self, attr)
            kept = prune(edges)
            if len(kept) != len(edges):
                setattr(self, attr, kept)
                changed = True
        return changed


class PolicyModel(BaseModel):
    """The deploy input that the PCE gives to the PDP Policy Writer (D18a): the stored SPMs, one
    per callee.

    Every edge that service X checks on its inbound is already on ``SPM(X)`` (a rule is stored on
    the SPM of the service that owns its scope), so the stored SPM is the render input and the
    writer does no join. It is also the body of ``POST`` / ``PUT /policy``: a body without
    ``services`` is a ``ValidationError``, and an unknown field is ignored."""

    model_config = ConfigDict(extra="ignore")

    services: list[ServicePolicyModel]
