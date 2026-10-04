"""The shared inbound projection (D18b).

``project_inbound(spm)`` splits the inbound edges of one ``ServicePolicyModel`` into the user gate
(``role.kind == User`` → subject) and the calling-agent gate (``Agent`` → source), each by effect,
and builds the effect-agnostic identity maps. Both sides use it: ``_derive`` for an APM's inbound
(agent side), and the writer for the inbound of ``SPM(X)`` (target side). So, for one SPM, both
sides give the same inbound gates.

Pure: no I/O.
"""

from typing import TypeVar

from pydantic import BaseModel

from aiac.idp.configuration.models import Role, RoleKind, Scope
from aiac.policy.model.models import PolicyRule, RuleEffect, ServicePolicyModel

_Entity = TypeVar("_Entity", Role, Scope)


class InboundProjection(BaseModel):
    """The inbound gates of one service, from its own SPM."""

    subject_allow_rules: list[PolicyRule] = []  # (user role, own scope) — who may call
    subject_deny_rules: list[PolicyRule] = []  # (user role, own scope) — who is barred
    source_allow_rules: list[PolicyRule] = []  # (calling agent role, own scope) — which callers may call
    source_deny_rules: list[PolicyRule] = []  # (calling agent role, own scope) — which callers are barred
    # Effect-agnostic: a role or subject that appears only in a deny edge must still resolve, or the
    # Rego deny lookup cannot find it and the prohibition silently never fires.
    subject_roles: dict[str, list[Role]] = {}  # username -> roles held
    source_roles: dict[str, list[Role]] = {}  # calling clientId -> roles held


def add_rule(rules: list[PolicyRule], rule: PolicyRule) -> None:
    """Append ``rule`` unless one with the same dedup identity ``(role.id, scope.id, effect)`` is
    present."""
    if any(r.role.id == rule.role.id and r.scope.id == rule.scope.id and r.effect == rule.effect for r in rules):
        return
    rules.append(rule)


def add_by_id(items: list[_Entity], item: _Entity) -> None:
    """Append ``item`` unless one with the same ``.id`` is already present."""
    if any(existing.id == item.id for existing in items):
        return
    items.append(item)


def project_inbound(spm: ServicePolicyModel) -> InboundProjection:
    """Split ``spm``'s inbound edges by ``(role.kind, effect)`` and build the identity maps."""
    projection = InboundProjection()
    for effect, edges, subject_bucket, source_bucket in (
        (
            RuleEffect.ALLOW,
            spm.inbound_allow_rules,
            projection.subject_allow_rules,
            projection.source_allow_rules,
        ),
        (
            RuleEffect.DENY,
            spm.inbound_deny_rules,
            projection.subject_deny_rules,
            projection.source_deny_rules,
        ),
    ):
        for edge in edges:
            is_user = edge.role.kind == RoleKind.USER
            add_rule(subject_bucket if is_user else source_bucket, edge)
            identity = projection.subject_roles if is_user else projection.source_roles
            for actor in edge.role.actorIds:
                add_by_id(identity.setdefault(actor, []), edge.role)
    return projection
