from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

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
    no agent required — it can never be lost, which fixes the order-dependence bug that motivated
    the two-layer model.

    ``owned_roles`` / ``owned_scopes`` are the service's own identity, filtered to the
    ``aiac.managed`` marker; they are seeded from the catalog by the PCE (this module only
    defines the shape)."""

    model_config = ConfigDict(extra="ignore")

    service_id: str
    service_type: ServiceType  # Agent | Tool — only Agents get a derived APM
    owned_roles: list[Role]  # this service's own client roles (aiac.managed only)
    owned_scopes: list[Scope]  # this service's exposed scopes (aiac.managed only)
    # Canonical inbound edges, split into two explicitly separated parallel lists (never one
    # intermixed list filtered by ``effect``): every ``Allow`` edge granting access to
    # ``owned_scopes``, and every ``Deny`` edge prohibiting it. A ``Deny`` edge subtracts from
    # what the ``Allow`` edges grant (deny-overrides).
    inbound_allow_rules: list[PolicyRule] = []
    inbound_deny_rules: list[PolicyRule] = []


class AgentPolicyModel(BaseModel):
    """Complete policy definition for a single agent (service).

    **Derived, not persisted.** ``AgentPolicyModel`` is a pure derived projection built by the
    PCE from the relevant ``ServicePolicyModel``s — it is **no longer a persisted entity** (the
    durable source of truth is ``ServicePolicyModel``). Its shape is unchanged so existing
    consumers (PDP Policy Library, Policy Store readers) keep working."""

    model_config = ConfigDict(extra="ignore")

    agent_id: str
    # There is no default-effect field: the deployed Rego always denies a (role, scope) pair
    # that NO rule mentions. A legacy payload that still carries ``default_effect`` is accepted
    # and ignored (``extra="ignore"``).
    # Identity / aggregate maps — effect-agnostic (no allow/deny split). A role or subject that
    # appears **only** in a DENY edge must still be registered here, or the Rego deny lookup
    # cannot resolve it and the prohibition silently fails to fire. Relationship maps are keyed
    # by the referenced entity's string id, so they serialize to JSON natively.
    agent_roles: list[Role]
    agent_scopes: list[Scope]
    source_roles: dict[str, list[Role]]  # source service id -> roles held (effect-agnostic)
    subject_roles: dict[str, list[Role]]  # subject id -> roles held (effect-agnostic)

    # Outbound target maps — split by effect. target service id -> scopes this agent may /
    # must not request on it.
    target_allow_scopes: dict[str, list[Scope]] = {}
    target_deny_scopes: dict[str, list[Scope]] = {}

    # 8 entity×effect rule lists — {inbound subject, inbound source, outbound target, outbound
    # subject} × {allow, deny}. Split explicitly (never one intermixed list filtered by effect);
    # a request is permitted iff some ALLOW gate passes and no DENY gate matches (deny-overrides).
    inbound_subject_allow_rules: list[PolicyRule] = []  # who may call this agent
    inbound_subject_deny_rules: list[PolicyRule] = []  # which subjects are barred
    inbound_source_allow_rules: list[PolicyRule] = []  # which calling services may call
    inbound_source_deny_rules: list[PolicyRule] = []  # which calling services are barred
    outbound_target_allow_rules: list[PolicyRule] = []  # what this agent may call
    outbound_target_deny_rules: list[PolicyRule] = []  # what this agent must not call
    # (user role, tool scope) pairs — the outbound subject gate: which users may / must not reach
    # the agent's targets. Outbound counterpart of the inbound subject rules (user role + agent
    # scope).
    outbound_subject_allow_rules: list[PolicyRule] = []
    outbound_subject_deny_rules: list[PolicyRule] = []


class EnforcementSide(str, Enum):
    """Where the access to a callee is checked (D16).

    Under ``target-side`` each callee (agent or tool) checks the access to itself in its own inbound
    OPA, from its own CR. Under ``agent-side`` (the legacy method) each agent's outbound OPA checks
    the agent's calls to tools. One global switch selects the side for every callee."""

    TARGET_SIDE = "target-side"
    AGENT_SIDE = "agent-side"


class PolicyModel(BaseModel):
    """The deploy input that the PCE gives to the PDP Policy Writer (D18a).

    The base of the hierarchy, never sent on its own. ``enforcement_side`` is the tag: each subclass
    fixes it as a ``Literal`` class constant with a default, so code never sets it by hand, and the
    writer dispatches on the subclass that the tag parses into. A model that mixes the sides
    cannot exist."""

    model_config = ConfigDict(extra="ignore")

    enforcement_side: EnforcementSide


class TargetSidePolicyModel(PolicyModel):
    """The target-side policy model: the stored SPMs, one per callee.

    Every edge that service X checks on its inbound is already on ``SPM(X)`` (a rule is stored on
    the SPM of the service that owns its scope), so the stored SPM is the render input and the
    writer does no join."""

    enforcement_side: Literal[EnforcementSide.TARGET_SIDE] = EnforcementSide.TARGET_SIDE
    services: list[ServicePolicyModel]


# The body of ``POST`` / ``PUT /policy``: every concrete policy model, told apart by its tag. The
# discriminator makes the tag mandatory in a body, although each subclass has it as a default.
AnyPolicyModel = Annotated[TargetSidePolicyModel, Field(discriminator="enforcement_side")]

_policy_model_adapter: TypeAdapter[AnyPolicyModel] = TypeAdapter(AnyPolicyModel)


def parse_policy_model(data: object) -> PolicyModel:
    """Parse a policy-model body into its concrete subclass, by its ``enforcement_side`` tag.

    Raises ``pydantic.ValidationError`` on a missing or unknown tag."""
    return _policy_model_adapter.validate_python(data)
