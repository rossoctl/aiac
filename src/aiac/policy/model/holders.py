"""The render-time role holders (D32).

A stored edge keeps a copy of ``Role.actorIds`` from the run that built it: a snapshot. That copy
goes stale in two ways. A role that more than one agent holds (a shared role, D32) keeps only the
holders that the build saw. A user role keeps the members that it had when the rule was stored, so a
user who gets the role later is not in it, and a user who loses the role stays in it. A membership
change does not change the policy (role -> scope); it changes only who holds the role.

So the holders come from current IdP data at render time, not from the stored copy. ``RoleHolders``
gives the current holders of a role, and refreshes a role, a rule or a whole ``ServicePolicyModel``
with them:

- an ``Agent``-kind role: each **live** service in the catalog (``get_services()``) whose ``roles``
  contain the role id (its ``serviceId``). Live = in the catalog and enabled; the focus service of a
  run counts as live. A quarantined or deleted service is not a holder;
- a ``User``-kind role: the ``actorIds`` that ``get_roles()`` gives for the role id now (the direct
  members of an ``aiac.managed`` realm role). A role that ``get_roles()`` does not list (deleted) has
  no holder (fail closed).

The kind of the role in the edge selects the source. The holders are sorted, so the result does not
depend on the order that the IdP gives. Known limits (not resolved here): a role held through a group
or through a composite parent role, and an unmarked user role (``get_roles()`` gives it no
``actorIds``).

Pure: no I/O. The caller reads the IdP one time and gives the data.
"""

from collections.abc import Iterable

from aiac.idp.configuration.models import Role, RoleKind, Service
from aiac.policy.model.models import PolicyRule, ServicePolicyModel


class RoleHolders:
    """The current holders of every role, from one read of the catalog and of the realm roles."""

    def __init__(self, services: Iterable[Service], roles: Iterable[Role], *, focus_service: str | None = None):
        """``services`` is the ``get_services()`` catalog; ``roles`` the ``get_roles()`` realm roles
        (required: with no roles, every user role has no holder); ``focus_service`` the clientId of
        the service that a run builds (it counts as live)."""
        agents: dict[str, set[str]] = {}
        for svc in services:
            if svc.enabled or svc.serviceId == focus_service:
                for role in svc.roles:
                    agents.setdefault(role.id, set()).add(svc.serviceId)
        self._agents = {role_id: sorted(holders) for role_id, holders in agents.items()}
        self._users = {role.id: sorted(set(role.actorIds)) for role in roles}

    def of(self, role: Role) -> list[str]:
        """The current holders of ``role``: service clientIds (``Agent``) or usernames (``User``)."""
        index = self._agents if role.kind == RoleKind.AGENT else self._users
        return list(index.get(role.id, []))

    def refresh_role(self, role: Role) -> Role:
        """A copy of ``role`` whose ``actorIds`` are its current holders."""
        return role.model_copy(update={"actorIds": self.of(role)})

    def refresh_rule(self, rule: PolicyRule) -> PolicyRule:
        """A copy of ``rule`` whose role carries its current holders (scope and effect unchanged)."""
        return rule.model_copy(update={"role": self.refresh_role(rule.role)})

    def refresh_model(self, model: ServicePolicyModel) -> ServicePolicyModel:
        """A deep copy of ``model`` in which each inbound edge, allow and deny, carries the current
        holders of its role. The edges keep their order; the identity (owned roles and scopes) is
        unchanged."""
        fresh = model.model_copy(deep=True)
        fresh.inbound_allow_rules = [self.refresh_rule(rule) for rule in fresh.inbound_allow_rules]
        fresh.inbound_deny_rules = [self.refresh_rule(rule) for rule in fresh.inbound_deny_rules]
        return fresh
