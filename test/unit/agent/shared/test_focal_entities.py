"""Unit tests for the extracted focal-entity resolver (D13).

``resolve_focal_entities`` is the pure resolution logic lifted out of
``ServicePolicyBuilder.build()`` so both the live builder and the read-only Policy Conflict
Check diagnostic share one typed entity set. These tests exercise the resolver directly with a
mocked ``Configuration`` (passed via the ``config`` seam — no live IdP, no LLM):

- the own-scope / candidate-role / other-scope ownership split (by role id / ``scope.serviceId``,
  never by name),
- composite-role flatten + de-dup of the candidate universe,
- membership-derived user roles vs ``aiac.managed`` agent roles, with service-owned exclusion (a
  role that a service owns is not a user-kind candidate),
- a shared role or scope (D32) on both sides: the candidates come from the other services by owner
  service, so a pair where a holder of the role owns the scope (a self-mapping) is allowed,
- ``service_type`` echoed from the parameter (not ``focus.type``),
- the ``HTTPException(502/404)`` pre-survey boundary.

The live-builder-facing behavior is covered separately by ``test_builder.py``; here we assert on
the ``FocalEntitySet`` fields the diagnostic will consume.
"""

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from aiac.agent.shared.focal_entities import FocalEntitySet, resolve_focal_entities
from aiac.idp.configuration.models import Role as RoleModel
from aiac.idp.configuration.models import RoleKind, Scope, Service, ServiceType, Subject

FOCUS_ID = "svc-focus"
OTHER_ID = "svc-other"


def _role(name, *, role_id=None, composite=False, children=None, kind=RoleKind.USER, aiac_managed=True):
    return RoleModel(
        id=role_id or f"{name}-id",
        name=name,
        description=name,
        composite=composite,
        childRoles=children or [],
        attributes={"aiac.managed": ["true"]} if aiac_managed else {},
        kind=kind,
    )


def _scope(name, *, scope_id=None, service_id="", aiac_managed=True):
    return Scope(
        id=scope_id or f"{name}-id",
        name=name,
        description=name,
        attributes={"aiac.managed": "true"} if aiac_managed else {},
        serviceId=service_id,
    )


def _service(service_id, *, ref=None, roles=None, scopes=None, service_type=ServiceType.TOOL, enabled=True):
    return Service(
        id=service_id,
        serviceId=ref or service_id,
        enabled=enabled,
        type=service_type,
        roles=roles or [],
        scopes=scopes or [],
    )


def _subject(username, *, roles=None, subject_id=None):
    return Subject(id=subject_id or f"{username}-id", username=username, enabled=True, roles=roles or [])


def _resolve(service_type, *, services, subjects, service_id=FOCUS_ID):
    conf = MagicMock()
    conf.get_services.return_value = services
    conf.get_subjects.return_value = subjects
    return resolve_focal_entities(service_id, service_type, config=conf)


class TestSplit:
    def test_own_and_candidate_and_other_universes_partitioned_by_ownership(self):
        own_role = _role("weather.agent")
        own_scope = _scope("weather.forecast", service_id=FOCUS_ID)
        other_role = _role("github.agent", kind=RoleKind.AGENT)
        other_scope = _scope("github.issue", service_id=OTHER_ID)
        focus = _service(FOCUS_ID, roles=[own_role], scopes=[own_scope], service_type=ServiceType.AGENT)
        other = _service(OTHER_ID, roles=[other_role], scopes=[other_scope])

        result = _resolve(ServiceType.AGENT, services=[focus, other], subjects=[])

        assert isinstance(result, FocalEntitySet)
        assert [s.name for s in result.own_scopes] == ["weather.forecast"]
        assert [r.name for r in result.own_roles] == ["weather.agent"]
        assert [r.name for r in result.candidate_roles] == ["github.agent"]
        assert [s.name for s in result.other_scopes] == ["github.issue"]

    def test_non_aiac_managed_own_entities_dropped(self):
        managed_scope = _scope("weather.forecast", service_id=FOCUS_ID)
        builtin_scope = _scope("profile", service_id=FOCUS_ID, aiac_managed=False)
        managed_role = _role("weather.agent")
        builtin_role = _role("uma_protection", aiac_managed=False)
        focus = _service(
            FOCUS_ID,
            roles=[managed_role, builtin_role],
            scopes=[managed_scope, builtin_scope],
            service_type=ServiceType.AGENT,
        )

        result = _resolve(ServiceType.AGENT, services=[focus], subjects=[])

        assert [s.name for s in result.own_scopes] == ["weather.forecast"]
        assert [r.name for r in result.own_roles] == ["weather.agent"]

    def test_unmarked_subject_scope_is_neither_own_nor_other_scope(self):
        # D31: aiac-username-sub is one shared scope, linked to every managed client and carrying no
        # aiac.managed marker, so it never becomes an own scope or a candidate other scope.
        def subject_scope(service_id):
            return _scope("aiac-username-sub", scope_id="subject-id", service_id=service_id, aiac_managed=False)

        focus = _service(
            FOCUS_ID,
            scopes=[_scope("weather.forecast", service_id=FOCUS_ID), subject_scope(FOCUS_ID)],
            service_type=ServiceType.AGENT,
        )
        other = _service(OTHER_ID, scopes=[_scope("github.issue", service_id=OTHER_ID), subject_scope(OTHER_ID)])

        result = _resolve(ServiceType.AGENT, services=[focus, other], subjects=[])

        assert [s.name for s in result.own_scopes] == ["weather.forecast"]
        assert [s.name for s in result.other_scopes] == ["github.issue"]


class TestCandidateRoles:
    def test_composite_other_role_flattened_and_deduped_by_id(self):
        reader = _role("github.reader", role_id="reader-id", kind=RoleKind.AGENT)
        admin = _role("github.admin", role_id="admin-id", composite=True, children=[reader], kind=RoleKind.AGENT)
        focus = _service(FOCUS_ID, scopes=[_scope("weather.forecast", service_id=FOCUS_ID)])
        other = _service(OTHER_ID, roles=[admin, reader])

        result = _resolve(ServiceType.TOOL, services=[focus, other], subjects=[])

        assert [r.id for r in result.candidate_roles] == ["admin-id", "reader-id"]

    def test_user_role_included_as_candidate_and_self_owned_role_excluded(self):
        own_role = _role("weather.admin", role_id="own-role-id")
        user_role = _role("realm.viewer", kind=RoleKind.USER, aiac_managed=False)
        # a user also holds the focus's own role — ownership must still exclude it
        subject = _subject("alice", roles=[user_role, own_role])
        focus = _service(FOCUS_ID, roles=[own_role], scopes=[_scope("weather.forecast", service_id=FOCUS_ID)])
        other = _service(OTHER_ID)

        result = _resolve(ServiceType.TOOL, services=[focus, other], subjects=[subject])

        assert [r.name for r in result.candidate_roles] == ["realm.viewer"]
        assert result.candidate_roles[0].kind == RoleKind.USER

    def test_other_scopes_excludes_focus_owned_by_serviceid(self):
        own_scope = _scope("shared.scope", scope_id="own-scope-id", service_id=FOCUS_ID)
        other_scope = _scope("shared.scope", scope_id="other-scope-id", service_id=OTHER_ID)
        # same-named scope, different owner: exclusion is by serviceId, not name
        focus = _service(FOCUS_ID, scopes=[own_scope])
        other = _service(OTHER_ID, scopes=[other_scope])

        result = _resolve(ServiceType.TOOL, services=[focus, other], subjects=[])

        assert [s.id for s in result.other_scopes] == ["other-scope-id"]


class TestSharedRoles:
    """A realm role that more than one service holds (a shared role, D32). ``GET /services/{id}/roles``
    gives each service's copy with ``actorIds`` = only that service. The candidate is one role with
    every current holder (the same ``RoleHolders`` rule as the PCE render)."""

    TEAM1 = "spiffe://localtest.me/ns/team1/sa/github-agent"
    TEAM2 = "spiffe://localtest.me/ns/team2/sa/github-agent"

    def _holder(self, client_id, role, *, enabled=True):
        copy = role.model_copy(update={"actorIds": [client_id]})
        return _service(
            f"uuid-{client_id}", ref=client_id, roles=[copy], service_type=ServiceType.AGENT, enabled=enabled
        )

    def test_a_role_that_two_other_services_hold_is_one_candidate_with_both_holders(self):
        # One entry for each role id: the PRB prompt lists each candidate role once.
        shared = _role("github-agent.source_operations", role_id="shared-id", kind=RoleKind.AGENT)
        focus = _service(FOCUS_ID, scopes=[_scope("github-tool.source-read", service_id=FOCUS_ID)])

        result = _resolve(
            ServiceType.TOOL,
            services=[focus, self._holder(self.TEAM2, shared), self._holder(self.TEAM1, shared)],
            subjects=[],
        )

        assert [(r.id, r.actorIds) for r in result.candidate_roles] == [("shared-id", [self.TEAM1, self.TEAM2])]

    def test_a_disabled_holder_is_not_merged(self):
        shared = _role("github-agent.source_operations", role_id="shared-id", kind=RoleKind.AGENT)
        focus = _service(FOCUS_ID)

        result = _resolve(
            ServiceType.TOOL,
            services=[focus, self._holder(self.TEAM1, shared), self._holder(self.TEAM2, shared, enabled=False)],
            subjects=[],
        )

        assert [(r.id, r.actorIds) for r in result.candidate_roles] == [("shared-id", [self.TEAM1])]

    def test_a_user_role_keeps_its_members(self):
        # The members that GET /roles gives (sorted, as the render gives them), once for the role.
        developer = _role("developer", role_id="dev-id").model_copy(update={"actorIds": ["bob", "alice"]})
        focus = _service(FOCUS_ID)

        result = _resolve(
            ServiceType.TOOL,
            services=[focus],
            subjects=[_subject("alice", roles=[developer]), _subject("bob", roles=[developer])],
        )

        assert [(r.id, r.actorIds) for r in result.candidate_roles] == [("dev-id", ["alice", "bob"])]


class TestSelfMapping:
    """D32 allows a self-mapping. The candidates come from the other services by owner service, not by
    entity, so a role or a scope that the focus shares with another service is on both sides.
    team1/github-agent and team2/github-agent (the focus) hold the shared role and each owns a copy of
    the shared scope (the same scope id, with the owner as ``serviceId``)."""

    TEAM1 = "spiffe://localtest.me/ns/team1/sa/github-agent"
    TEAM2 = "spiffe://localtest.me/ns/team2/sa/github-agent"
    NAME = "github-agent.source_operations"  # the role and the scope of a github-agent skill

    def _agent(self, client_id, role, scope):
        """The catalog entry of one holder: its copy of the role and its copy of the scope."""
        return _service(
            f"uuid-{client_id}",
            ref=client_id,
            roles=[role.model_copy(update={"actorIds": [client_id]})],
            scopes=[scope.model_copy(update={"serviceId": client_id})],
            service_type=ServiceType.AGENT,
        )

    def test_the_shared_role_and_the_other_copy_of_the_shared_scope_are_candidates(self):
        shared_role = _role(self.NAME, role_id="role-id", kind=RoleKind.AGENT)
        shared_scope = _scope(self.NAME, scope_id="scope-id")
        team1 = self._agent(self.TEAM1, shared_role, shared_scope)
        team2 = self._agent(self.TEAM2, shared_role, shared_scope)

        result = _resolve(ServiceType.AGENT, services=[team1, team2], subjects=[], service_id=team2.id)

        # The own side: the focus's copies.
        assert [(r.id, r.actorIds) for r in result.own_roles] == [("role-id", [self.TEAM2])]
        assert [(s.id, s.serviceId) for s in result.own_scopes] == [("scope-id", self.TEAM2)]
        # The candidate side: the shared role through its other holder, with every current holder (the
        # focus included), and the other owner's copy of the shared scope.
        assert [(r.id, r.actorIds) for r in result.candidate_roles] == [("role-id", [self.TEAM1, self.TEAM2])]
        assert [(s.id, s.serviceId) for s in result.other_scopes] == [("scope-id", self.TEAM1)]


class TestServiceType:
    def test_service_type_echoed_from_parameter_not_focus_type(self):
        # focus.type is TOOL, but the requested classification is AGENT — the result must carry
        # the parameter, never focus.type.
        focus = _service(FOCUS_ID, service_type=ServiceType.TOOL)

        result = _resolve(ServiceType.AGENT, services=[focus], subjects=[])

        assert result.service_type is ServiceType.AGENT


class TestErrors:
    def test_idp_unreachable_raises_502(self):
        conf = MagicMock()
        conf.get_services.side_effect = RuntimeError("HTTP 503")
        with pytest.raises(HTTPException) as ei:
            resolve_focal_entities(FOCUS_ID, ServiceType.TOOL, config=conf)
        assert ei.value.status_code == 502

    def test_get_subjects_unreachable_raises_502(self):
        conf = MagicMock()
        conf.get_services.return_value = [_service(FOCUS_ID)]
        conf.get_subjects.side_effect = RuntimeError("HTTP 500")
        with pytest.raises(HTTPException) as ei:
            resolve_focal_entities(FOCUS_ID, ServiceType.TOOL, config=conf)
        assert ei.value.status_code == 502

    def test_unknown_service_raises_404(self):
        with pytest.raises(HTTPException) as ei:
            _resolve(ServiceType.TOOL, services=[_service(OTHER_ID)], subjects=[], service_id="nope")
        assert ei.value.status_code == 404

    def test_focus_resolved_by_uuid_not_clientid(self):
        uuid = "f5592be1-uuid"
        client_id = "spiffe://localtest.me/ns/team1/sa/github-agent"
        focus = _service(uuid, ref=client_id, scopes=[_scope("weather.forecast", service_id=uuid)])
        other = _service(OTHER_ID, ref="svc-other-client")

        # the UUID resolves
        result = _resolve(ServiceType.TOOL, services=[focus, other], subjects=[], service_id=uuid)
        assert [s.name for s in result.own_scopes] == ["weather.forecast"]

        # the clientId does not
        with pytest.raises(HTTPException) as ei:
            _resolve(ServiceType.TOOL, services=[focus, other], subjects=[], service_id=client_id)
        assert ei.value.status_code == 404


class TestDisabledServices:
    """A disabled client is a failed (quarantined) service: its roles and scopes are not candidates,
    so no build grants anything to or from it. The focus service still resolves while it is disabled
    (a re-onboarding runs before ``reenable_service``)."""

    def test_disabled_service_roles_and_scopes_are_not_candidates(self):
        focus = _service(FOCUS_ID, service_type=ServiceType.AGENT)
        live = _service(
            OTHER_ID,
            roles=[_role("live.agent", kind=RoleKind.AGENT)],
            scopes=[_scope("live.read", service_id=OTHER_ID)],
        )
        failed = _service(
            "svc-failed",
            roles=[_role("failed.agent", kind=RoleKind.AGENT)],
            scopes=[_scope("failed.read", service_id="svc-failed")],
            enabled=False,
        )

        result = _resolve(ServiceType.AGENT, services=[focus, live, failed], subjects=[])

        assert [r.name for r in result.candidate_roles] == ["live.agent"]
        assert [s.name for s in result.other_scopes] == ["live.read"]

    def test_disabled_service_role_held_by_a_user_is_not_a_user_candidate(self):
        # The disabled service still owns its roles: a user holding one does not turn it into a
        # user-kind candidate.
        failed_role = _role("failed.agent", kind=RoleKind.AGENT)
        focus = _service(FOCUS_ID, service_type=ServiceType.AGENT)
        failed = _service("svc-failed", roles=[failed_role], enabled=False)

        result = _resolve(
            ServiceType.AGENT, services=[focus, failed], subjects=[_subject("alice", roles=[failed_role])]
        )

        assert result.candidate_roles == []

    def test_disabled_focus_service_still_resolves_its_own_entities(self):
        own_role = _role("focus.agent")
        own_scope = _scope("focus.read", service_id=FOCUS_ID)
        focus = _service(FOCUS_ID, roles=[own_role], scopes=[own_scope], service_type=ServiceType.AGENT, enabled=False)
        other = _service(OTHER_ID, scopes=[_scope("other.read", service_id=OTHER_ID)])

        result = _resolve(ServiceType.AGENT, services=[focus, other], subjects=[])

        assert [r.name for r in result.own_roles] == ["focus.agent"]
        assert [s.name for s in result.own_scopes] == ["focus.read"]
        assert [s.name for s in result.other_scopes] == ["other.read"]
