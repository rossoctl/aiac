"""Unit tests for the Service Provision `provision_service` node (UC1, issue 4.3).

The idp-library `Configuration` is mocked via the `_config` seam — no service HTTP layer.
D31 adds the link of the shared subject scope `aiac-username-sub` to each onboarded client.
REJ-02: `TestProvisionServiceCreateRace` runs the real library on a fake wire of the IdP
Configuration Service (`_FakeIdP`), because the race is between the library's check and its create.
"""

from unittest.mock import MagicMock, call, patch

import pytest
from fastapi import HTTPException

from aiac.agent.uc.onboarding import orchestrator
from aiac.agent.uc.onboarding.provision import nodes
from aiac.agent.uc.onboarding.provision.state import OnboardingProvisionState, Trigger
from aiac.agent.uc.onboarding.provision.types import (
    RoleDefinition,
    ScopeDefinition,
    ServiceProvision,
)
from aiac.idp.configuration.api import Configuration
from aiac.idp.configuration.models import Role, Scope, Service, ServiceType

SERVICE_ID = "svc-123"
SUBJECT_SCOPE = "aiac-username-sub"


def _state(roles, scopes, service_type=ServiceType.AGENT, reasoning="r"):
    return OnboardingProvisionState(
        trigger=Trigger(entity_id=SERVICE_ID),
        service_id=SERVICE_ID,
        namespace="team-a",
        workload_name="weather",
        service_type=service_type,
        service_provision=ServiceProvision(roles=roles, scopes=scopes, reasoning=reasoning),
    )


def _service():
    return Service.model_validate({"id": SERVICE_ID, "clientId": SERVICE_ID, "enabled": True})


def _conf():
    """A mocked ``Configuration`` whose ``create_service_role`` / ``create_service_scope`` create
    each object: they return ``(object, True)``, the object named as the definition."""
    conf = MagicMock()
    conf.create_service_role.side_effect = lambda _sid, d: (Role(id=f"r-{d.name}", name=d.name, composite=False), True)
    conf.create_service_scope.side_effect = lambda _sid, d: (Scope(id=f"s-{d.name}", name=d.name), True)
    return conf


def _run(state, *, get_service_exc=None, conf=None):
    """Run ``provision_service`` with ``conf`` (``_conf()`` by default) as the ``Configuration``;
    return ``(result, conf)``."""
    with patch.object(nodes, "_config") as cfg:
        if conf is None:
            conf = _conf()
        if get_service_exc is not None:
            conf.get_service.side_effect = get_service_exc
        else:
            conf.get_service.return_value = _service()
        cfg.return_value = conf
        result = nodes.provision_service(state)
        return result, conf


class TestProvisionServiceWrites:
    def test_create_service_role_called_once_per_role(self):
        roles = [
            RoleDefinition(name="weather.agent", description="Agent role"),
            RoleDefinition(name="weather.admin", description="Admin role"),
        ]
        _, conf = _run(_state(roles, []))
        assert conf.create_service_role.call_count == 2
        conf.create_service_role.assert_has_calls([call(SERVICE_ID, roles[0]), call(SERVICE_ID, roles[1])])

    def test_create_service_scope_called_once_per_scope(self):
        scopes = [
            ScopeDefinition(name="weather.forecast", description="Forecast"),
            ScopeDefinition(name="weather.history", description="History"),
        ]
        _, conf = _run(_state([], scopes))
        assert conf.create_service_scope.call_count == 2
        conf.create_service_scope.assert_has_calls([call(SERVICE_ID, scopes[0]), call(SERVICE_ID, scopes[1])])

    def test_no_entries_makes_no_create_calls(self):
        _, conf = _run(_state([], []))
        conf.create_service_role.assert_not_called()
        conf.create_service_scope.assert_not_called()


class TestProvisionServicePersistsType:
    def test_set_service_type_called_with_resolved_service_type(self):
        _, conf = _run(_state([], [], service_type=ServiceType.TOOL))
        assert conf.set_service_type.call_count == 1
        passed_service, passed_type = conf.set_service_type.call_args.args
        assert passed_type is ServiceType.TOOL
        assert passed_service is conf.get_service.return_value

    def test_agent_type_persisted_as_capitalized_value(self):
        _, conf = _run(_state([], [], service_type=ServiceType.AGENT))
        assert conf.set_service_type.call_args.args[1] == "Agent"


class TestProvisionServiceLinksSubjectScope:
    """D31: Provision links the shared subject scope to the client of every onboarded service, so
    that a token exchanged by the agent client has ``sub`` = username."""

    @pytest.mark.parametrize("service_type", [ServiceType.AGENT, ServiceType.TOOL])
    def test_link_subject_scope_called_once_with_the_resolved_service(self, service_type):
        scopes = [ScopeDefinition(name="weather.forecast", description="Forecast")]
        _, conf = _run(_state([], scopes, service_type=service_type))
        assert conf.link_subject_scope.call_count == 1
        (passed_service,) = conf.link_subject_scope.call_args.args
        assert passed_service is conf.get_service.return_value

    def test_link_comes_before_set_service_type(self):
        # Every client that carries client.type then has the link.
        _, conf = _run(_state([], []))
        names = [c[0] for c in conf.mock_calls]
        assert names.index("get_service") < names.index("link_subject_scope")
        assert names.index("link_subject_scope") < names.index("set_service_type")

    def test_linked_also_with_no_roles_and_no_scopes(self):
        _, conf = _run(_state([], []))
        conf.link_subject_scope.assert_called_once()

    def test_subject_scope_is_not_in_the_created_manifest(self):
        # The UC-1 rollback deletes only the created-manifest. The subject scope is shared by all
        # managed clients, so it must never be in it; a scope that this run created is.
        conf = MagicMock()
        created = Scope(id="s-new", name="weather.x", attributes={"aiac.managed": "true"})
        conf.create_service_scope.return_value = (created, True)
        conf.link_subject_scope.return_value = Scope(id="s-sub", name=SUBJECT_SCOPE)

        result, _ = _run(_state([], [ScopeDefinition(name="weather.x", description="X")]), conf=conf)

        assert result["created_scopes"] == [created]
        assert SUBJECT_SCOPE not in {s.name for s in result["created_scopes"]}

    def test_link_failure_is_502_and_the_type_is_not_set(self):
        conf = MagicMock()
        conf.link_subject_scope.side_effect = RuntimeError("HTTP 502 from the IdP")
        with pytest.raises(HTTPException) as ei:
            _run(_state([], []), conf=conf)
        assert ei.value.status_code == 502
        assert SERVICE_ID in ei.value.detail
        conf.set_service_type.assert_not_called()


class TestProvisionServiceCreatedManifest:
    """The created-manifest has only what this run created, not what it reused by name (D32: services
    with the same workload name share a role or a scope). ``create_service_role`` /
    ``create_service_scope`` say which: they return ``(object, created)``. The rollback deletes only
    the manifest, so a shared role or scope that this run reused is never in it, but the run still
    maps it."""

    def test_a_role_that_this_run_created_is_in_the_manifest(self):
        roles = [
            RoleDefinition(name="weather.agent", description="d"),
            RoleDefinition(name="weather.admin", description="d"),
        ]

        result, _ = _run(_state(roles, []))

        assert [(r.id, r.name) for r in result["created_roles"]] == [
            ("r-weather.agent", "weather.agent"),
            ("r-weather.admin", "weather.admin"),
        ]
        assert result["created_scopes"] == []

    def test_a_scope_that_this_run_created_is_in_the_manifest(self):
        scopes = [ScopeDefinition(name="weather.forecast", description="d")]

        result, _ = _run(_state([], scopes, service_type=ServiceType.TOOL))

        assert [(s.id, s.name) for s in result["created_scopes"]] == [("s-weather.forecast", "weather.forecast")]
        assert result["created_roles"] == []

    def test_a_reused_role_is_mapped_but_is_not_in_the_created_manifest(self):
        shared = Role(id="r-shared", name="github-agent.source_operations", composite=False)
        new = Role(id="r-new", name="github-agent.review", composite=False)
        conf = _conf()
        conf.create_service_role.side_effect = (
            lambda _sid, role: (shared, False) if role.name == shared.name else (new, True)
        )
        roles = [RoleDefinition(name=shared.name, description="d"), RoleDefinition(name=new.name, description="d")]

        result, _ = _run(_state(roles, []), conf=conf)

        assert [c.args[1].name for c in conf.create_service_role.call_args_list] == [shared.name, new.name]
        assert result["created_roles"] == [new]

    def test_a_reused_scope_is_mapped_but_is_not_in_the_created_manifest(self):
        shared = Scope(id="s-shared", name="github-tool.source-read", attributes={"aiac.managed": "true"})
        new = Scope(id="s-new", name="github-tool.source-write", attributes={"aiac.managed": "true"})
        conf = _conf()
        conf.create_service_scope.side_effect = (
            lambda _sid, scope: (shared, False) if scope.name == shared.name else (new, True)
        )
        conf.link_subject_scope.return_value = Scope(id="s-sub", name=SUBJECT_SCOPE)
        scopes = [ScopeDefinition(name=shared.name, description="d"), ScopeDefinition(name=new.name, description="d")]

        result, _ = _run(_state([], scopes, service_type=ServiceType.TOOL), conf=conf)

        assert [c.args[1].name for c in conf.create_service_scope.call_args_list] == [shared.name, new.name]
        assert result["created_scopes"] == [new]


BASE = "http://127.0.0.1:7071"


def _response(body, status=200):
    resp = MagicMock()
    resp.ok, resp.status_code, resp.text = status < 400, status, str(body)
    resp.json.return_value = body
    return resp


class _FakeIdP:
    """The wire of the IdP Configuration Service for one service (``SERVICE_ID``), as the library
    sends it (``requests.get`` / ``post`` / ``delete``). ``POST /roles`` and ``POST /scopes`` answer
    ``409`` on a name that is taken, as Keycloak does. ``race`` holds the names that another run
    creates at the same time: that run commits its object after this run's check and just before
    this run's create, so this run's create gets the ``409``. The other run has not mapped its
    object yet, so the shared-safe delete of the service deletes it when this run unmaps it."""

    def __init__(self, race: set[str]) -> None:
        self.race = set(race)
        self.objects: dict[str, dict[str, dict]] = {"roles": {}, "scopes": {}}  # kind -> name -> raw
        self.mapped: dict[str, list[str]] = {"roles": [], "scopes": []}  # kind -> ids mapped to SERVICE_ID
        self.deletes: list[str] = []
        self.client = {"id": SERVICE_ID, "clientId": "team2/github-agent", "enabled": True}

    def _raw(self, kind: str, name: str, description: str, owner: str) -> dict:
        raw = {"id": f"{owner}-{name}", "name": name, "description": description}
        return {**raw, "composite": False} if kind == "roles" else {**raw, "attributes": {"aiac.managed": "true"}}

    def _by_id(self, kind: str) -> dict[str, dict]:
        return {raw["id"]: raw for raw in self.objects[kind].values()}

    def get(self, url, **_kwargs):
        path = url.removeprefix(BASE)
        if path in ("/roles", "/scopes"):
            return _response(list(self.objects[path[1:]].values()))
        if path == f"/services/{SERVICE_ID}":
            return _response(self.client)
        kind = path.removeprefix(f"/services/{SERVICE_ID}/")
        return _response([self._by_id(kind)[i] for i in self.mapped[kind] if i in self._by_id(kind)])

    def post(self, url, json=None, **_kwargs):
        path = url.removeprefix(BASE)
        if path in ("/roles", "/scopes"):
            kind, name = path[1:], json["name"]
            if name in self.race:  # the other run commits its create first
                self.objects[kind][name] = self._raw(kind, name, "the other run", owner="winner")
            if name in self.objects[kind]:
                return _response({"error": "409: Conflict"}, status=409)
            self.objects[kind][name] = self._raw(kind, name, json["description"], owner="mine")
            return _response(self.objects[kind][name], status=201)
        if path == f"/services/{SERVICE_ID}/subject-scope":
            return _response({"id": "s-sub", "name": SUBJECT_SCOPE})
        if path in (f"/services/{SERVICE_ID}/type", f"/services/{SERVICE_ID}/enabled"):
            return _response(self.client)
        kind, object_id = path.removeprefix(f"/services/{SERVICE_ID}/").split("/")
        self.mapped[kind].append(object_id)
        return _response({}, status=204)

    def delete(self, url, **_kwargs):
        path = url.removeprefix(BASE)
        self.deletes.append(path)
        kind, object_id = path.removeprefix(f"/services/{SERVICE_ID}/").split("/")
        self.mapped[kind].remove(object_id)
        # Shared-safe: the delete is only for an object that no other service holds. The other run
        # has not mapped its object yet, so here no other service holds any object.
        name = self._by_id(kind)[object_id]["name"]
        del self.objects[kind][name]
        return _response({}, status=204)


class TestProvisionServiceCreateRace:
    """REJ-02: two services with the same workload name provision the same new name at the same
    time. Both find no object, and Keycloak answers ``409`` to the second create. The library takes
    the ``409`` as reuse, so this run (the loser) maps the object of the other run (the winner).
    That object is not this run's: it must not be in the created-manifest, so the UC1 rollback of a
    failed build of this run does not delete it."""

    KINDS = {
        "role": ("roles", "created_roles", RoleDefinition, ServiceType.AGENT),
        "scope": ("scopes", "created_scopes", ScopeDefinition, ServiceType.TOOL),
    }

    @pytest.fixture(autouse=True)
    def _wire(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "1")

    def _provision_then_roll_back(self, kind, idp):
        objects, manifest, definition, service_type = self.KINDS[kind]
        shared, mine = "github-agent.source_operations", "github-agent.review"
        entries = [definition(name=shared, description="mine"), definition(name=mine, description="mine")]
        state = _state(entries, []) if objects == "roles" else _state([], entries, service_type=service_type)
        config = Configuration.for_realm("rossoctl")
        with (
            patch("aiac.idp.configuration.api.requests.get", side_effect=idp.get),
            patch("aiac.idp.configuration.api.requests.post", side_effect=idp.post),
            patch("aiac.idp.configuration.api.requests.delete", side_effect=idp.delete),
            patch.object(nodes, "_config", return_value=config),
        ):
            result = nodes.provision_service(state)
            mapped = list(idp.mapped[objects])
            # The build of this run fails: the Orchestrator rolls back the created-manifest.
            orchestrator._rollback(
                config, config.get_service(SERVICE_ID), result["created_roles"], result["created_scopes"]
            )
        return result[manifest], mapped, objects

    @pytest.mark.parametrize("kind", ["role", "scope"])
    def test_the_losers_manifest_does_not_hold_the_winners_object(self, kind):
        idp = _FakeIdP(race={"github-agent.source_operations"})
        manifest, mapped, objects = self._provision_then_roll_back(kind, idp)

        # This run mapped both objects: the winner's (reused after the 409) and its own.
        assert mapped == ["winner-github-agent.source_operations", "mine-github-agent.review"]
        # Only its own object is in the created-manifest.
        assert [(o.id, o.name) for o in manifest] == [("mine-github-agent.review", "github-agent.review")]
        # The rollback deletes only this run's own object; the winner's object stays.
        assert idp.deletes == [f"/services/{SERVICE_ID}/{objects}/mine-github-agent.review"]
        assert list(idp.objects[objects]) == ["github-agent.source_operations"]

    @pytest.mark.parametrize("kind", ["role", "scope"])
    def test_with_no_race_the_run_creates_both_and_rolls_both_back(self, kind):
        idp = _FakeIdP(race=set())
        manifest, mapped, objects = self._provision_then_roll_back(kind, idp)

        assert [o.id for o in manifest] == ["mine-github-agent.source_operations", "mine-github-agent.review"]
        assert idp.deletes == [f"/services/{SERVICE_ID}/{objects}/{object_id}" for object_id in mapped]
        assert idp.objects[objects] == {}


class TestProvisionServiceReturn:
    def test_returns_service_provision_and_service_type_to_orchestrator(self):
        roles = [RoleDefinition(name="weather.agent", description="Agent role")]
        state = _state(roles, [], service_type=ServiceType.AGENT)
        result, _ = _run(state)
        assert result["service_provision"] is state.service_provision
        assert result["service_type"] is ServiceType.AGENT


class TestProvisionService502:
    def test_idp_unavailable_is_502(self, monkeypatch):
        monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "1")
        roles = [RoleDefinition(name="weather.agent", description="Agent role")]
        state = _state(roles, [])
        with patch.object(nodes, "_config") as cfg:
            conf = MagicMock()
            conf.create_service_role.side_effect = RuntimeError("HTTP 503")
            cfg.return_value = conf
            with pytest.raises(HTTPException) as ei:
                nodes.provision_service(state)
        assert ei.value.status_code == 502
