"""Unit tests for aiac.idp.configuration."""

import copy
import logging
import pickle
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest
import requests

from aiac.idp.configuration.api import Configuration, IdPHTTPError
from aiac.idp.configuration.models import Role, RoleKind, Scope, Service, ServiceType, Subject

REALM = "rossoctl"
BASE = "http://127.0.0.1:7071"


@pytest.fixture(autouse=True)
def _single_attempt(monkeypatch):
    """Configuration now retries transient failures internally (``_request`` → ``run_upstream``),
    a ``5xx`` included (``IdPHTTPError`` keeps the status). Pin the budget to a single attempt so
    error-path unit tests stay fast and single-call. ``TestTransientRetry`` sets its own budget."""
    monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "1")


def _ok(json_data, status=200):
    resp = MagicMock()
    resp.ok = True
    resp.status_code = status
    resp.json.return_value = json_data
    return resp


def _err(status=500):
    resp = MagicMock()
    resp.ok = False
    resp.status_code = status
    resp.text = "internal error"
    return resp


# ---------------------------------------------------------------------------
# aiac.managed marker surfaced on Role / Scope (naming convention)
# ---------------------------------------------------------------------------


class TestAiacManagedMarker:
    def test_role_with_marker_is_managed(self):
        role = Role.model_validate(
            {"id": "r1", "name": "source-helper", "composite": False, "attributes": {"aiac.managed": ["true"]}}
        )
        assert role.aiac_managed is True

    def test_role_without_marker_is_not_managed(self):
        role = Role.model_validate({"id": "r1", "name": "default-roles-realm", "composite": False})
        assert role.aiac_managed is False

    def test_scope_with_marker_is_managed(self):
        scope = Scope.model_validate({"id": "s1", "name": "source-access", "attributes": {"aiac.managed": "true"}})
        assert scope.aiac_managed is True

    def test_scope_without_marker_is_not_managed(self):
        scope = Scope.model_validate({"id": "s1", "name": "profile"})
        assert scope.aiac_managed is False


# ---------------------------------------------------------------------------
# Factory method
# ---------------------------------------------------------------------------


class TestForRealm:
    def test_returns_configuration_bound_to_realm(self):
        cfg = Configuration.for_realm(REALM)
        assert isinstance(cfg, Configuration)
        assert cfg.realm == REALM

    def test_direct_init_sets_realm(self):
        cfg = Configuration(REALM)
        assert cfg.realm == REALM


# ---------------------------------------------------------------------------
# get_subjects
# ---------------------------------------------------------------------------


class TestGetSubjects:
    # Call order: GET /subjects, GET /roles (+ per-composite /composites), GET /subjects/{id}/assignments — per subject.

    def test_returns_list_of_subject(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "u1", "username": "alice", "enabled": True}]
        assignments = {"realmMappings": [], "serviceMappings": {}}
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(payload), _ok([]), _ok(assignments)],
        ) as m:
            result = Configuration.for_realm(REALM).get_subjects()
        assert isinstance(result[0], Subject)
        assert result[0].username == "alice"
        assert m.call_args_list[0] == ((f"{BASE}/subjects",), {"params": {"realm": REALM}})

    def test_roles_populated_from_keycloak_assignments(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "u1", "username": "alice", "enabled": True}]
        all_roles = [{"id": "r1", "name": "viewer", "composite": False}]
        assignments = {"realmMappings": [{"id": "r1", "name": "viewer"}], "serviceMappings": {}}
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(payload), _ok(all_roles), _ok(assignments)],
        ):
            result = Configuration.for_realm(REALM).get_subjects()
        assert len(result[0].roles) == 1
        assert result[0].roles[0].name == "viewer"

    def test_unassigned_roles_not_included(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "u1", "username": "alice", "enabled": True}]
        all_roles = [
            {"id": "r1", "name": "viewer", "composite": False},
            {"id": "r2", "name": "admin", "composite": False},
        ]
        assignments = {"realmMappings": [{"id": "r1"}], "serviceMappings": {}}
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(payload), _ok(all_roles), _ok(assignments)],
        ):
            result = Configuration.for_realm(REALM).get_subjects()
        assert len(result[0].roles) == 1
        assert result[0].roles[0].id == "r1"

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.get", return_value=_err()):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_subjects()

    def test_raises_when_assignments_call_fails(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "u1", "username": "alice", "enabled": True}]
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(payload), _ok([]), _err(502)],
        ):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_subjects()

    def test_realm_forwarded_on_all_calls(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "u1", "username": "alice", "enabled": True}]
        assignments = {"realmMappings": [], "serviceMappings": {}}
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(payload), _ok([]), _ok(assignments)],
        ) as m:
            Configuration.for_realm(REALM).get_subjects()
        for c in m.call_args_list:
            assert c[1].get("params") == {"realm": REALM}


# ---------------------------------------------------------------------------
# get_roles
# ---------------------------------------------------------------------------


class TestGetRoles:
    def test_returns_list_of_role(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "r1", "name": "admin", "composite": False}]
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(payload)) as m:
            result = Configuration.for_realm(REALM).get_roles()
        assert isinstance(result[0], Role)
        assert result[0].name == "admin"
        assert m.call_args_list[0][0][0] == f"{BASE}/roles"

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.get", return_value=_err()):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_roles()

    def test_non_composite_role_has_no_mappedScopes(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        roles = [{"id": "r1", "name": "viewer", "composite": False}]
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(roles)):
            result = Configuration.for_realm(REALM).get_roles()
        assert not hasattr(result[0], "mappedScopes")
        assert result[0].childRoles == []

    def test_non_composite_role_skips_composites_and_scopes_calls(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        roles = [{"id": "r1", "name": "viewer", "composite": False}]
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(roles)) as m:
            Configuration.for_realm(REALM).get_roles()
        urls = [c[0][0] for c in m.call_args_list]
        assert all("/composites" not in u for u in urls)
        assert all("/scopes" not in u for u in urls)

    def test_get_roles_never_calls_scopes_endpoint(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        roles = [
            {"id": "r1", "name": "admin", "composite": True},
            {"id": "r2", "name": "viewer", "composite": False},
        ]
        child_roles = [{"id": "r2", "name": "viewer", "composite": False}]
        with patch("aiac.idp.configuration.api.requests.get", side_effect=[_ok(roles), _ok(child_roles)]) as m:
            Configuration.for_realm(REALM).get_roles()
        urls = [c[0][0] for c in m.call_args_list]
        assert all("/scopes" not in u for u in urls)

    def test_composite_role_populates_child_roles(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        roles = [{"id": "r1", "name": "admin", "composite": True}]
        child_roles = [{"id": "r2", "name": "viewer", "composite": False}]
        with patch("aiac.idp.configuration.api.requests.get", side_effect=[_ok(roles), _ok(child_roles)]):
            result = Configuration.for_realm(REALM).get_roles()
        assert result[0].childRoles[0].name == "viewer"

    def test_composite_role_has_no_mappedScopes(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        roles = [{"id": "r1", "name": "admin", "composite": True}]
        child_roles = [{"id": "r2", "name": "viewer", "composite": False}]
        with patch("aiac.idp.configuration.api.requests.get", side_effect=[_ok(roles), _ok(child_roles)]):
            result = Configuration.for_realm(REALM).get_roles()
        assert not hasattr(result[0], "mappedScopes")

    def test_raises_if_composites_call_fails(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        roles = [{"id": "r1", "name": "admin", "composite": True}]
        with patch("aiac.idp.configuration.api.requests.get", side_effect=[_ok(roles), _err(502)]):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_roles()


# ---------------------------------------------------------------------------
# get_services
# ---------------------------------------------------------------------------


class TestGetServices:
    # Call order: GET /services, GET /roles (get_roles, + per-role secondary calls),
    #             GET /scopes (get_scopes), GET /services/{id}/roles, GET /services/{id}/scopes — per service.

    def test_returns_list_of_service(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "c1", "clientId": "my-app", "name": "my-app", "enabled": True}]
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(payload), _ok([]), _ok([]), _ok([]), _ok([])],
        ) as m:
            result = Configuration.for_realm(REALM).get_services()
        assert isinstance(result[0], Service)
        assert result[0].id == "c1"
        assert m.call_args_list[0] == (
            (f"{BASE}/services",),
            {"params": {"realm": REALM}},
        )

    def test_serviceId_populated_from_clientId(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "c1", "clientId": "mlflow", "enabled": True}]
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(payload), _ok([]), _ok([]), _ok([]), _ok([])],
        ):
            result = Configuration.for_realm(REALM).get_services()
        assert result[0].serviceId == "mlflow"

    def test_scope_descriptions_populated_from_get_scopes(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "c1", "clientId": "my-app", "name": "my-app", "enabled": True}]
        all_scopes = [{"id": "s1", "name": "read:data", "description": "Read access"}]
        service_scopes = [{"id": "s1", "name": "read:data"}]
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(payload), _ok([]), _ok(all_scopes), _ok([]), _ok(service_scopes)],
        ):
            result = Configuration.for_realm(REALM).get_services()
        assert result[0].scopes[0].description == "Read access"

    def test_role_details_populated_from_get_roles(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "c1", "clientId": "my-app", "name": "my-app", "enabled": True}]
        all_roles = [{"id": "r1", "name": "viewer", "composite": False}]
        service_roles = [{"id": "r1", "name": "viewer"}]
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(payload), _ok(all_roles), _ok([]), _ok(service_roles), _ok([])],
        ):
            result = Configuration.for_realm(REALM).get_services()
        assert result[0].roles[0].name == "viewer"

    def test_each_owner_of_a_shared_scope_gets_its_own_copy(self, monkeypatch):
        # A shared scope (D32): two clients link one aiac.managed scope. Each service gets its own
        # copy, with that owner's clientId as serviceId, so each copy routes to its owner's SPM.
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        services = [
            {"id": "uuid-1", "clientId": "team1/github-tool", "enabled": True},
            {"id": "uuid-2", "clientId": "team2/github-tool", "enabled": True},
        ]
        shared = {"id": "s-read", "name": "github-tool.source-read", "description": "Read source"}
        all_scopes = [{**shared, "attributes": {"aiac.managed": "true"}}]
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[
                _ok(services),  # GET /services
                _ok([]),  # GET /roles
                _ok(all_scopes),  # GET /scopes
                _ok([]),  # GET /services/uuid-1/roles
                _ok([{"id": "s-read", "name": shared["name"], "serviceId": "team1/github-tool"}]),
                _ok([]),  # GET /services/uuid-2/roles
                _ok([{"id": "s-read", "name": shared["name"], "serviceId": "team2/github-tool"}]),
            ],
        ):
            team1, team2 = Configuration.for_realm(REALM).get_services()
        assert team1.scopes == [Scope.model_validate({**all_scopes[0], "serviceId": "team1/github-tool"})]
        assert team2.scopes == [Scope.model_validate({**all_scopes[0], "serviceId": "team2/github-tool"})]
        assert team1.scopes[0].aiac_managed and team2.scopes[0].aiac_managed

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.get", return_value=_err()):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_services()


# ---------------------------------------------------------------------------
# get_service
# ---------------------------------------------------------------------------
# Call order: GET /services/{id}, GET /roles (+ per-role /scopes calls),
#             GET /scopes, GET /services/{id}/roles, GET /services/{id}/scopes


class TestGetService:
    SERVICE_ID = "svc-001"

    def test_returns_single_enriched_service(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        raw = {"id": self.SERVICE_ID, "clientId": self.SERVICE_ID, "name": "my-svc", "enabled": True}
        all_roles = [{"id": "r1", "name": "viewer", "composite": False}]
        all_scopes = [{"id": "s1", "name": "read:data", "description": "Read access"}]
        service_roles = [{"id": "r1"}]
        service_scopes = [{"id": "s1"}]
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[
                _ok(raw),  # GET /services/svc-001
                _ok(all_roles),  # GET /roles (no /scopes per role)
                _ok(all_scopes),  # GET /scopes
                _ok(service_roles),  # GET /services/svc-001/roles
                _ok(service_scopes),  # GET /services/svc-001/scopes
            ],
        ):
            result = Configuration.for_realm(REALM).get_service(self.SERVICE_ID)
        assert isinstance(result, Service)
        assert result.id == self.SERVICE_ID
        assert result.roles[0].name == "viewer"
        assert result.scopes[0].name == "read:data"

    def test_unmarked_subject_scope_kept_with_aiac_managed_false(self, monkeypatch):
        # D31: the shared aiac-username-sub scope has no aiac.managed marker. The library does not
        # filter on the marker: the scope stays in Service.scopes, and the consumers (the PCE, the
        # focal-entity resolver) drop it through Scope.aiac_managed.
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        raw = {"id": self.SERVICE_ID, "clientId": self.SERVICE_ID, "name": "my-svc", "enabled": True}
        all_scopes = [
            {"id": "s1", "name": "read:data", "attributes": {"aiac.managed": "true"}},
            {"id": "s-sub", "name": "aiac-username-sub", "attributes": {"include.in.token.scope": "false"}},
        ]
        service_scopes = [{"id": "s1"}, {"id": "s-sub"}]
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(raw), _ok([]), _ok(all_scopes), _ok([]), _ok(service_scopes)],
        ):
            result = Configuration.for_realm(REALM).get_service(self.SERVICE_ID)
        managed = {s.name: s.aiac_managed for s in result.scopes}
        assert managed == {"read:data": True, "aiac-username-sub": False}
        assert all(s.serviceId == self.SERVICE_ID for s in result.scopes)

    def test_type_resolved_from_client_type_attribute(self, monkeypatch):
        # Typing comes from the client.type attribute (via Service._resolve_keycloak_fields),
        # never from the description — the description-keyword fallback has been removed.
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        raw = {
            "id": self.SERVICE_ID,
            "clientId": self.SERVICE_ID,
            "name": "my-agent",
            "description": "An Agent service",  # keyword present but ignored
            "enabled": True,
            "attributes": {"client.type": "Tool"},
        }
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[
                _ok(raw),  # GET /services/svc-001
                _ok([]),  # GET /roles
                _ok([]),  # GET /scopes
                _ok([]),  # GET /services/svc-001/roles
                _ok([]),  # GET /services/svc-001/scopes
            ],
        ):
            result = Configuration.for_realm(REALM).get_service(self.SERVICE_ID)
        assert result.type == "Tool"

    def test_type_not_inferred_from_description(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        raw = {
            "id": self.SERVICE_ID,
            "clientId": self.SERVICE_ID,
            "name": "my-agent",
            "description": "An Agent service",  # no attribute → type stays None
            "enabled": True,
        }
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[
                _ok(raw),  # GET /services/svc-001
                _ok([]),  # GET /roles
                _ok([]),  # GET /scopes
                _ok([]),  # GET /services/svc-001/roles
                _ok([]),  # GET /services/svc-001/scopes
            ],
        ):
            result = Configuration.for_realm(REALM).get_service(self.SERVICE_ID)
        assert result.type is None

    def test_raises_when_primary_fetch_returns_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.get", return_value=_err(404)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_service(self.SERVICE_ID)

    def test_raises_when_service_roles_call_fails(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        raw = {"id": self.SERVICE_ID, "name": "my-svc", "enabled": True}
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[
                _ok(raw),  # GET /services/svc-001
                _ok([]),  # GET /roles
                _ok([]),  # GET /scopes
                _err(500),  # GET /services/svc-001/roles → error
            ],
        ):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_service(self.SERVICE_ID)

    def test_raises_when_service_scopes_call_fails(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        raw = {"id": self.SERVICE_ID, "name": "my-svc", "enabled": True}
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[
                _ok(raw),  # GET /services/svc-001
                _ok([]),  # GET /roles
                _ok([]),  # GET /scopes
                _ok([]),  # GET /services/svc-001/roles → ok
                _err(500),  # GET /services/svc-001/scopes → error
            ],
        ):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_service(self.SERVICE_ID)

    def test_realm_forwarded_on_every_request(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        raw = {"id": self.SERVICE_ID, "clientId": self.SERVICE_ID, "name": "my-svc", "enabled": True}
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[
                _ok(raw),
                _ok([]),
                _ok([]),
                _ok([]),
                _ok([]),
            ],
        ) as m:
            Configuration.for_realm(REALM).get_service(self.SERVICE_ID)
        for c in m.call_args_list:
            assert c[1].get("params") == {"realm": REALM}


# ---------------------------------------------------------------------------
# mint_discovery_token — fetches a tool-audienced bearer token from the config service
# ---------------------------------------------------------------------------


class TestMintDiscoveryToken:
    def test_returns_access_token(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = {"access_token": "tok", "client_id": "github-tool", "audience": ["github-tool"]}
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(payload)) as m:
            result = Configuration.for_realm(REALM).mint_discovery_token("svc-uuid")
        assert result == "tok"
        m.assert_called_once_with(f"{BASE}/services/svc-uuid/discovery-token", params={"realm": REALM})

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.get", return_value=_err(502)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).mint_discovery_token("svc-uuid")


# ---------------------------------------------------------------------------
# set_service_type — writes the client.type attribute
# ---------------------------------------------------------------------------


class TestSetServiceType:
    def _make_service(self, **kwargs):
        defaults = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        return Service.model_validate({**defaults, **kwargs})

    def test_returns_updated_service_with_type(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        updated = {
            "id": "svc-uuid",
            "clientId": "svc-uuid",
            "name": "my-svc",
            "enabled": True,
            "attributes": {"client.type": "Agent"},
        }
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(updated, 200)):
            result = Configuration.for_realm(REALM).set_service_type(service, "Agent")
        assert isinstance(result, Service)
        assert result.type == "Agent"

    def test_posts_to_correct_url_with_type_body(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        updated = {
            "id": "svc-uuid",
            "clientId": "svc-uuid",
            "name": "my-svc",
            "enabled": True,
            "attributes": {"client.type": "Tool"},
        }
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(updated, 200)) as m:
            Configuration.for_realm(REALM).set_service_type(service, "Tool")
        assert m.call_args[0][0] == f"{BASE}/services/svc-uuid/type"
        assert m.call_args[1].get("json") == {"type": "Tool"}

    def test_forwards_realm_as_query_param(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        updated = {
            "id": "svc-uuid",
            "clientId": "svc-uuid",
            "name": "my-svc",
            "enabled": True,
            "attributes": {"client.type": "Agent"},
        }
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(updated, 200)) as m:
            Configuration.for_realm(REALM).set_service_type(service, "Agent")
        assert m.call_args[1].get("params") == {"realm": REALM}

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        with patch("aiac.idp.configuration.api.requests.post", return_value=_err(502)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).set_service_type(service, "Agent")

    def test_accepts_service_type_enum(self, monkeypatch):
        # ServiceType is a str enum; set_service_type unwraps it to the plain "Agent"/"Tool" value.
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        updated = {
            "id": "svc-uuid",
            "clientId": "svc-uuid",
            "name": "my-svc",
            "enabled": True,
            "attributes": {"client.type": "Agent"},
        }
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(updated, 200)) as m:
            Configuration.for_realm(REALM).set_service_type(service, ServiceType.AGENT)
        assert m.call_args[1].get("json") == {"type": "Agent"}


# ---------------------------------------------------------------------------
# link_subject_scope — D31: links the shared, unmarked aiac-username-sub scope
#
# POST /services/{id}/subject-scope with no body → the service ensures the scope and
# its username -> sub mapper, and links it as a default scope of the client. Returns
# the Scope; it has no aiac.managed marker, so aiac_managed is False.
# ---------------------------------------------------------------------------


class TestLinkSubjectScope:
    SUBJECT_SCOPE = {
        "id": "subject-scope-id",
        "name": "aiac-username-sub",
        "description": "AIAC subject scope (D31): sets the token sub to the username",
        "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": "false", "display.on.consent.screen": "false"},
        "protocolMappers": [{"name": "username-to-sub", "protocolMapper": "oidc-usermodel-property-mapper"}],
    }

    def _make_service(self, **kwargs):
        defaults = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        return Service.model_validate({**defaults, **kwargs})

    def test_posts_to_subject_scope_endpoint(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(self.SUBJECT_SCOPE, 200)) as m:
            Configuration.for_realm(REALM).link_subject_scope(self._make_service())
        m.assert_called_once()
        assert m.call_args[0][0] == f"{BASE}/services/svc-uuid/subject-scope"

    def test_forwards_realm_as_query_param(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(self.SUBJECT_SCOPE, 200)) as m:
            Configuration.for_realm(REALM).link_subject_scope(self._make_service())
        assert m.call_args[1].get("params") == {"realm": REALM}

    def test_sends_no_body(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(self.SUBJECT_SCOPE, 200)) as m:
            Configuration.for_realm(REALM).link_subject_scope(self._make_service())
        assert "json" not in m.call_args[1]
        assert "data" not in m.call_args[1]

    def test_returns_scope_from_response(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(self.SUBJECT_SCOPE, 200)):
            result = Configuration.for_realm(REALM).link_subject_scope(self._make_service())
        assert isinstance(result, Scope)
        assert result.id == "subject-scope-id"
        assert result.name == "aiac-username-sub"

    def test_returned_scope_is_not_aiac_managed(self, monkeypatch):
        # The subject scope is shared by every managed client, so it never carries the marker:
        # a marked scope would become an own scope of each linked service.
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(self.SUBJECT_SCOPE, 200)):
            result = Configuration.for_realm(REALM).link_subject_scope(self._make_service())
        assert result.aiac_managed is False

    @pytest.mark.parametrize("status", [502, 409])
    def test_raises_on_non_2xx(self, status, monkeypatch):
        # 502: a Keycloak error; 409: the scope exists but carries the aiac.managed marker.
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.post", return_value=_err(status)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).link_subject_scope(self._make_service())


# ---------------------------------------------------------------------------
# create_service_role / create_service_scope — idempotent create-or-get + map
# (tested by patching the Configuration methods they compose)
# ---------------------------------------------------------------------------


class TestCreateServiceRole:
    def _svc(self):
        return Service.model_validate({"id": "svc-1", "clientId": "svc-1", "enabled": True})

    def test_creates_role_when_absent_then_maps_to_service(self):
        cfg = Configuration.for_realm(REALM)
        role_def = SimpleNamespace(name="app.agent", description="Agent role")
        created = Role(id="r-1", name="app.agent", description="Agent role", composite=False)
        svc = self._svc()
        with (
            patch.object(cfg, "get_roles", return_value=[]),
            patch.object(cfg, "create_role", return_value=created) as create,
            patch.object(cfg, "get_service", return_value=svc),
            patch.object(cfg, "map_role_to_service", return_value=svc) as mapper,
        ):
            result, was_created = cfg.create_service_role("svc-1", role_def)
        create.assert_called_once_with("app.agent", "Agent role")
        mapper.assert_called_once_with(svc, created)
        assert result is created
        assert was_created is True  # this call created the role: it goes into the created-manifest

    def test_reuses_existing_role_without_creating(self):
        cfg = Configuration.for_realm(REALM)
        role_def = SimpleNamespace(name="app.agent", description="Agent role")
        existing = Role(id="r-1", name="app.agent", description="Agent role", composite=False)
        svc = self._svc()
        with (
            patch.object(cfg, "get_roles", return_value=[existing]),
            patch.object(cfg, "create_role") as create,
            patch.object(cfg, "get_service", return_value=svc),
            patch.object(cfg, "map_role_to_service", return_value=svc) as mapper,
        ):
            result, was_created = cfg.create_service_role("svc-1", role_def)
        create.assert_not_called()
        mapper.assert_called_once_with(svc, existing)
        assert result is existing
        assert was_created is False  # a reuse is not in the created-manifest

    # A reused role is shared (D32): it keeps its first description, Keycloak is not updated, and a
    # different new description is logged as a WARNING (handoff 19 Bug 3).
    def _reuse(self, cfg, existing, role_def):
        svc = self._svc()
        with (
            patch.object(cfg, "get_roles", return_value=[existing]),
            patch.object(cfg, "create_role") as create,
            patch.object(cfg, "get_service", return_value=svc),
            patch.object(cfg, "map_role_to_service", return_value=svc),
            patch("aiac.idp.configuration.api.requests") as http,
        ):
            result, was_created = cfg.create_service_role("svc-1", role_def)
        create.assert_not_called()
        assert was_created is False
        # No update of the kept description: no request at all (``assert_not_called`` would see only a
        # call of the module mock itself, not ``http.put(...)`` or ``http.post(...)``).
        assert http.mock_calls == []
        return result

    def test_reuse_with_a_different_description_warns_and_keeps_the_first(self, caplog):
        cfg = Configuration.for_realm(REALM)
        existing = Role(id="r-1", name="app.agent", description="First agent", composite=False)
        with caplog.at_level(logging.WARNING, logger="aiac.idp.configuration.api"):
            result = self._reuse(cfg, existing, SimpleNamespace(name="app.agent", description="Second agent"))
        assert result.description == "First agent"
        [record] = caplog.records
        assert record.levelno == logging.WARNING
        assert all(text in record.getMessage() for text in ("app.agent", "First agent", "Second agent"))

    @pytest.mark.parametrize(("kept", "new"), [("Agent role", "Agent role"), (None, "")], ids=["same", "none-is-empty"])
    def test_reuse_with_the_same_description_does_not_warn(self, kept, new, caplog):
        cfg = Configuration.for_realm(REALM)
        existing = Role(id="r-1", name="app.agent", description=kept, composite=False)
        with caplog.at_level(logging.WARNING, logger="aiac.idp.configuration.api"):
            self._reuse(cfg, existing, SimpleNamespace(name="app.agent", description=new))
        assert caplog.records == []

    def test_new_role_does_not_warn(self, caplog):
        cfg = Configuration.for_realm(REALM)
        created = Role(id="r-1", name="app.agent", description="Agent role", composite=False)
        svc = self._svc()
        with (
            caplog.at_level(logging.WARNING, logger="aiac.idp.configuration.api"),
            patch.object(cfg, "get_roles", return_value=[]),
            patch.object(cfg, "create_role", return_value=created),
            patch.object(cfg, "get_service", return_value=svc),
            patch.object(cfg, "map_role_to_service", return_value=svc),
        ):
            cfg.create_service_role("svc-1", SimpleNamespace(name="app.agent", description="Agent role"))
        assert caplog.records == []

    # REJ-02: the check and the create are two requests. Two services with the same workload name
    # that provision at the same time both find no role, and Keycloak answers 409 to the second
    # create. A 409 from the create is reuse: read again by name, as the subject scope does (D31).
    def _race(self, cfg, reads, create_error):
        svc = self._svc()
        with (
            patch.object(cfg, "get_roles", side_effect=reads) as read,
            patch.object(cfg, "create_role", side_effect=create_error) as create,
            patch.object(cfg, "get_service", return_value=svc),
            patch.object(cfg, "map_role_to_service", return_value=svc) as mapper,
        ):
            try:
                result, self.created = cfg.create_service_role(
                    "svc-1", SimpleNamespace(name="app.agent", description="Second")
                )
                return result
            finally:
                self.reads, self.creates, self.maps = read.call_count, create.call_count, mapper.call_args_list

    def test_a_409_from_the_create_reuses_the_role_that_is_there_now(self, caplog):
        cfg = Configuration.for_realm(REALM)
        winner = Role(id="r-1", name="app.agent", description="First", composite=False)
        with caplog.at_level(logging.WARNING, logger="aiac.idp.configuration.api"):
            result = self._race(cfg, [[], [winner]], IdPHTTPError(409, "Conflict"))
        assert result is winner
        # The other run created the object, so it is not in this run's created-manifest (REJ-02).
        assert self.created is False
        assert (self.reads, self.creates) == (2, 1)
        assert self.maps == [call(self._svc(), winner)]
        # The same description rule as a reuse that the first read finds.
        [record] = caplog.records
        assert all(text in record.getMessage() for text in ("app.agent", "First", "Second"))

    def test_a_409_with_the_same_description_does_not_warn(self, caplog):
        # Also the case of a create that _request repeats after Keycloak committed the first attempt.
        cfg = Configuration.for_realm(REALM)
        mine = Role(id="r-1", name="app.agent", description="Second", composite=False)
        with caplog.at_level(logging.WARNING, logger="aiac.idp.configuration.api"):
            assert self._race(cfg, [[], [mine]], IdPHTTPError(409, "Conflict")) is mine
        # A 409 does not tell this run's committed first attempt from another run's create, so it
        # is reuse: the object is not in the created-manifest, and the rollback does not delete it.
        assert self.created is False
        assert caplog.records == []

    def test_a_409_that_the_read_again_does_not_explain_is_raised(self):
        cfg = Configuration.for_realm(REALM)
        with pytest.raises(IdPHTTPError) as ei:
            self._race(cfg, [[], []], IdPHTTPError(409, "Conflict"))
        assert ei.value.status == 409
        assert self.maps == []

    def test_an_error_other_than_409_from_the_create_is_raised_with_no_read_again(self):
        cfg = Configuration.for_realm(REALM)
        with pytest.raises(IdPHTTPError) as ei:
            self._race(cfg, [[], []], IdPHTTPError(502, "Bad gateway"))
        assert ei.value.status == 502
        assert (self.reads, self.maps) == (1, [])

    def test_a_concurrent_create_on_the_wire_is_reuse(self):
        # The wire of rej02_race.py: GET /roles misses the role, POST /roles answers 409, GET /roles
        # again finds it, and the role is mapped to the service.
        cfg = Configuration.for_realm(REALM)
        winner = {"id": "r-1", "name": "app.agent", "description": "Second", "composite": False}
        roles_reads = iter([[]])  # the check misses the role; each later read finds it
        posts = []

        def get(url, **_kwargs):
            path = url.removeprefix(BASE)
            if path == "/roles":
                return _ok(next(roles_reads, [winner]))
            if path == "/services/svc-1":
                return _ok({"id": "svc-1", "clientId": "svc-1", "enabled": True})
            return _ok([])  # /scopes and the service's own roles and scopes

        def post(url, **_kwargs):
            posts.append(url.removeprefix(BASE))
            if url == f"{BASE}/roles":
                return _err(409)
            return _ok({}, status=201)

        with (
            patch("aiac.idp.configuration.api.requests.get", side_effect=get),
            patch("aiac.idp.configuration.api.requests.post", side_effect=post),
        ):
            result, created = cfg.create_service_role("svc-1", SimpleNamespace(name="app.agent", description="Second"))
        assert (result.id, created) == ("r-1", False)
        assert posts == ["/roles", "/services/svc-1/roles/r-1"]


class TestCreateServiceScope:
    def _svc(self):
        return Service.model_validate({"id": "svc-1", "clientId": "svc-1", "enabled": True})

    def test_creates_scope_when_absent_then_maps_to_service(self):
        cfg = Configuration.for_realm(REALM)
        scope_def = SimpleNamespace(name="app.read", description="Read tool")
        created = Scope(id="s-1", name="app.read", description="Read tool")
        svc = self._svc()
        with (
            patch.object(cfg, "get_scopes", return_value=[]),
            patch.object(cfg, "create_scope", return_value=created) as create,
            patch.object(cfg, "get_service", return_value=svc),
            patch.object(cfg, "map_scope_to_service", return_value=svc) as mapper,
        ):
            result, was_created = cfg.create_service_scope("svc-1", scope_def)
        create.assert_called_once_with("app.read", "Read tool")
        mapper.assert_called_once_with(svc, created)
        assert result is created
        assert was_created is True  # this call created the scope: it goes into the created-manifest

    def test_reuses_existing_scope_without_creating(self):
        cfg = Configuration.for_realm(REALM)
        scope_def = SimpleNamespace(name="app.read", description="Read tool")
        existing = Scope(id="s-1", name="app.read", description="Read tool")
        svc = self._svc()
        with (
            patch.object(cfg, "get_scopes", return_value=[existing]),
            patch.object(cfg, "create_scope") as create,
            patch.object(cfg, "get_service", return_value=svc),
            patch.object(cfg, "map_scope_to_service", return_value=svc) as mapper,
        ):
            result, was_created = cfg.create_service_scope("svc-1", scope_def)
        create.assert_not_called()
        mapper.assert_called_once_with(svc, existing)
        assert result is existing
        assert was_created is False  # a reuse is not in the created-manifest

    # A reused scope is shared (D32): it keeps its first description, Keycloak is not updated, and a
    # different new description is logged as a WARNING (handoff 19 Bug 3).
    def _reuse(self, cfg, existing, scope_def):
        svc = self._svc()
        with (
            patch.object(cfg, "get_scopes", return_value=[existing]),
            patch.object(cfg, "create_scope") as create,
            patch.object(cfg, "get_service", return_value=svc),
            patch.object(cfg, "map_scope_to_service", return_value=svc),
            patch("aiac.idp.configuration.api.requests") as http,
        ):
            result, was_created = cfg.create_service_scope("svc-1", scope_def)
        create.assert_not_called()
        assert was_created is False
        # No update of the kept description: no request at all (``assert_not_called`` would see only a
        # call of the module mock itself, not ``http.put(...)`` or ``http.post(...)``).
        assert http.mock_calls == []
        return result

    def test_reuse_with_a_different_description_warns_and_keeps_the_first(self, caplog):
        cfg = Configuration.for_realm(REALM)
        existing = Scope(id="s-1", name="github-tool.source-read", description="Read the source")
        with caplog.at_level(logging.WARNING, logger="aiac.idp.configuration.api"):
            result = self._reuse(
                cfg, existing, SimpleNamespace(name="github-tool.source-read", description="Read a repository")
            )
        assert result.description == "Read the source"
        [record] = caplog.records
        assert record.levelno == logging.WARNING
        message = record.getMessage()
        assert all(text in message for text in ("github-tool.source-read", "Read the source", "Read a repository"))

    @pytest.mark.parametrize(("kept", "new"), [("Read tool", "Read tool"), (None, "")], ids=["same", "none-is-empty"])
    def test_reuse_with_the_same_description_does_not_warn(self, kept, new, caplog):
        cfg = Configuration.for_realm(REALM)
        existing = Scope(id="s-1", name="app.read", description=kept)
        with caplog.at_level(logging.WARNING, logger="aiac.idp.configuration.api"):
            self._reuse(cfg, existing, SimpleNamespace(name="app.read", description=new))
        assert caplog.records == []

    def test_new_scope_does_not_warn(self, caplog):
        cfg = Configuration.for_realm(REALM)
        created = Scope(id="s-1", name="app.read", description="Read tool")
        svc = self._svc()
        with (
            caplog.at_level(logging.WARNING, logger="aiac.idp.configuration.api"),
            patch.object(cfg, "get_scopes", return_value=[]),
            patch.object(cfg, "create_scope", return_value=created),
            patch.object(cfg, "get_service", return_value=svc),
            patch.object(cfg, "map_scope_to_service", return_value=svc),
        ):
            cfg.create_service_scope("svc-1", SimpleNamespace(name="app.read", description="Read tool"))
        assert caplog.records == []

    # REJ-02: the same race as for a role (see TestCreateServiceRole._race).
    def _race(self, cfg, reads, create_error):
        svc = self._svc()
        with (
            patch.object(cfg, "get_scopes", side_effect=reads) as read,
            patch.object(cfg, "create_scope", side_effect=create_error) as create,
            patch.object(cfg, "get_service", return_value=svc),
            patch.object(cfg, "map_scope_to_service", return_value=svc) as mapper,
        ):
            try:
                result, self.created = cfg.create_service_scope(
                    "svc-1", SimpleNamespace(name="app.read", description="Second")
                )
                return result
            finally:
                self.reads, self.creates, self.maps = read.call_count, create.call_count, mapper.call_args_list

    def test_a_409_from_the_create_reuses_the_scope_that_is_there_now(self, caplog):
        cfg = Configuration.for_realm(REALM)
        winner = Scope(id="s-1", name="app.read", description="First")
        with caplog.at_level(logging.WARNING, logger="aiac.idp.configuration.api"):
            result = self._race(cfg, [[], [winner]], IdPHTTPError(409, "Conflict"))
        assert result is winner
        # The other run created the object, so it is not in this run's created-manifest (REJ-02).
        assert self.created is False
        assert (self.reads, self.creates) == (2, 1)
        assert self.maps == [call(self._svc(), winner)]
        [record] = caplog.records
        assert all(text in record.getMessage() for text in ("app.read", "First", "Second"))

    def test_a_409_with_the_same_description_does_not_warn(self, caplog):
        cfg = Configuration.for_realm(REALM)
        mine = Scope(id="s-1", name="app.read", description="Second")
        with caplog.at_level(logging.WARNING, logger="aiac.idp.configuration.api"):
            assert self._race(cfg, [[], [mine]], IdPHTTPError(409, "Conflict")) is mine
        # A 409 does not tell this run's committed first attempt from another run's create, so it
        # is reuse: the object is not in the created-manifest, and the rollback does not delete it.
        assert self.created is False
        assert caplog.records == []

    def test_a_409_that_the_read_again_does_not_explain_is_raised(self):
        cfg = Configuration.for_realm(REALM)
        with pytest.raises(IdPHTTPError) as ei:
            self._race(cfg, [[], []], IdPHTTPError(409, "Conflict"))
        assert ei.value.status == 409
        assert self.maps == []

    def test_an_error_other_than_409_from_the_create_is_raised_with_no_read_again(self):
        cfg = Configuration.for_realm(REALM)
        with pytest.raises(IdPHTTPError) as ei:
            self._race(cfg, [[], []], IdPHTTPError(502, "Bad gateway"))
        assert ei.value.status == 502
        assert (self.reads, self.maps) == (1, [])

    def test_a_concurrent_create_on_the_wire_is_reuse(self):
        cfg = Configuration.for_realm(REALM)
        winner = {"id": "s-1", "name": "app.read", "description": "Second", "attributes": {"aiac.managed": "true"}}
        scopes_reads = iter([[]])  # the check misses the scope; each later read finds it
        posts = []

        def get(url, **_kwargs):
            path = url.removeprefix(BASE)
            if path == "/scopes":
                return _ok(next(scopes_reads, [winner]))
            if path == "/services/svc-1":
                return _ok({"id": "svc-1", "clientId": "svc-1", "enabled": True})
            return _ok([])  # /roles and the service's own roles and scopes

        def post(url, **_kwargs):
            posts.append(url.removeprefix(BASE))
            if url == f"{BASE}/scopes":
                return _err(409)
            return _ok({}, status=201)

        with (
            patch("aiac.idp.configuration.api.requests.get", side_effect=get),
            patch("aiac.idp.configuration.api.requests.post", side_effect=post),
        ):
            result, created = cfg.create_service_scope("svc-1", SimpleNamespace(name="app.read", description="Second"))
        assert (result.id, created) == ("s-1", False)
        assert posts == ["/scopes", "/services/svc-1/scopes/s-1"]


# ---------------------------------------------------------------------------
# get_scopes
# ---------------------------------------------------------------------------


class TestGetScopes:
    def test_returns_list_of_scope(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "s1", "name": "email"}]
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(payload)) as m:
            result = Configuration.for_realm(REALM).get_scopes()
        assert isinstance(result[0], Scope)
        assert result[0].name == "email"
        m.assert_called_once_with(f"{BASE}/scopes", params={"realm": REALM})

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.get", return_value=_err()):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_scopes()


# ---------------------------------------------------------------------------
# create_scope
# ---------------------------------------------------------------------------


class TestCreateScope:
    def test_returns_scope_instance(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        created = {"id": "sc1", "name": "read:data", "description": "Read access"}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(created, 201)):
            result = Configuration.for_realm(REALM).create_scope(
                scope_name="read:data", scope_description="Read access"
            )
        assert isinstance(result, Scope)
        assert result.name == "read:data"
        assert result.id == "sc1"

    def test_posts_to_correct_url(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        created = {"id": "sc1", "name": "write"}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(created, 201)) as m:
            Configuration.for_realm(REALM).create_scope("write", "Write access")
        url = m.call_args[0][0]
        assert url == f"{BASE}/scopes"

    def test_forwards_realm_as_query_param(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        created = {"id": "sc1", "name": "read"}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(created, 201)) as m:
            Configuration.for_realm(REALM).create_scope("read", "desc")
        params = m.call_args[1].get("params", {})
        assert params == {"realm": REALM}

    def test_json_body_contains_name_and_description(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        created = {"id": "sc1", "name": "read"}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(created, 201)) as m:
            Configuration.for_realm(REALM).create_scope("read", "Read access")
        body = m.call_args[1].get("json", {})
        assert body == {"name": "read", "description": "Read access"}

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.post", return_value=_err()):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).create_scope("read", "desc")

    def test_raises_on_409_conflict(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.post", return_value=_err(409)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).create_scope("dupe", "desc")


# ---------------------------------------------------------------------------
# map_scope_to_service
# ---------------------------------------------------------------------------


class TestMapScopeToService:
    def _make_service(self, **kwargs):
        defaults = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        return Service.model_validate({**defaults, **kwargs})

    def _make_scope(self, **kwargs):
        defaults = {"id": "scope-id", "name": "read:data"}
        return Scope.model_validate({**defaults, **kwargs})

    def test_returns_updated_service(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        scope = self._make_scope()
        updated = {
            "id": "svc-uuid",
            "clientId": "svc-uuid",
            "name": "my-svc",
            "enabled": True,
            "scopes": [{"id": "scope-id", "name": "read:data"}],
        }
        post_resp = _ok({}, 201)
        get_resp = _ok(updated)
        with (
            patch("aiac.idp.configuration.api.requests.post", return_value=post_resp),
            patch("aiac.idp.configuration.api.requests.get", return_value=get_resp) as get_m,
        ):
            result = Configuration.for_realm(REALM).map_scope_to_service(service, scope)
        assert isinstance(result, Service)
        assert result.id == "svc-uuid"
        get_m.assert_called_once_with(f"{BASE}/services/svc-uuid", params={"realm": REALM})

    def test_issues_post_to_correct_url(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        scope = self._make_scope()
        updated = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        with (
            patch("aiac.idp.configuration.api.requests.post", return_value=_ok({}, 201)) as post_m,
            patch("aiac.idp.configuration.api.requests.get", return_value=_ok(updated)),
        ):
            Configuration.for_realm(REALM).map_scope_to_service(service, scope)
        url = post_m.call_args[0][0]
        assert url == f"{BASE}/services/svc-uuid/scopes/scope-id"

    def test_raises_on_post_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        scope = self._make_scope()
        with patch("aiac.idp.configuration.api.requests.post", return_value=_err(409)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).map_scope_to_service(service, scope)

    def test_realm_forwarded_on_both_calls(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        scope = self._make_scope()
        updated = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        with (
            patch("aiac.idp.configuration.api.requests.post", return_value=_ok({}, 201)) as post_m,
            patch("aiac.idp.configuration.api.requests.get", return_value=_ok(updated)) as get_m,
        ):
            Configuration.for_realm(REALM).map_scope_to_service(service, scope)
        assert post_m.call_args[1].get("params") == {"realm": REALM}
        assert get_m.call_args[1].get("params") == {"realm": REALM}


# ---------------------------------------------------------------------------
# create_role
# ---------------------------------------------------------------------------


class TestCreateRole:
    def test_returns_role_instance(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        created = {"id": "r1", "name": "reader", "description": "Read-only", "composite": False}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(created, 201)):
            result = Configuration.for_realm(REALM).create_role("reader", "Read-only")
        assert isinstance(result, Role)
        assert result.name == "reader"
        assert result.id == "r1"

    def test_posts_to_correct_url(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        created = {"id": "r1", "name": "reader", "composite": False}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(created, 201)) as m:
            Configuration.for_realm(REALM).create_role("reader", "desc")
        url = m.call_args[0][0]
        assert url == f"{BASE}/roles"

    def test_forwards_realm_as_query_param(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        created = {"id": "r1", "name": "reader", "composite": False}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(created, 201)) as m:
            Configuration.for_realm(REALM).create_role("reader", "desc")
        assert m.call_args[1].get("params") == {"realm": REALM}

    def test_json_body_contains_name_and_description(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        created = {"id": "r1", "name": "reader", "composite": False}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(created, 201)) as m:
            Configuration.for_realm(REALM).create_role("reader", "Read-only")
        assert m.call_args[1].get("json") == {"name": "reader", "description": "Read-only"}

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.post", return_value=_err()):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).create_role("reader", "desc")

    def test_raises_on_409_conflict(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.post", return_value=_err(409)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).create_role("dupe", "desc")


# ---------------------------------------------------------------------------
# map_role_to_service
# ---------------------------------------------------------------------------


class TestMapRoleToService:
    def _make_service(self, **kwargs):
        defaults = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        return Service.model_validate({**defaults, **kwargs})

    def _make_role(self, **kwargs):
        defaults = {"id": "role-id", "name": "reader", "composite": False}
        return Role.model_validate({**defaults, **kwargs})

    def test_returns_updated_service(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        role = self._make_role()
        updated = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        with (
            patch("aiac.idp.configuration.api.requests.post", return_value=_ok({}, 201)),
            patch("aiac.idp.configuration.api.requests.get", return_value=_ok(updated)) as get_m,
        ):
            result = Configuration.for_realm(REALM).map_role_to_service(service, role)
        assert isinstance(result, Service)
        get_m.assert_called_once_with(f"{BASE}/services/svc-uuid", params={"realm": REALM})

    def test_issues_post_to_correct_url(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        role = self._make_role()
        updated = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        with (
            patch("aiac.idp.configuration.api.requests.post", return_value=_ok({}, 201)) as post_m,
            patch("aiac.idp.configuration.api.requests.get", return_value=_ok(updated)),
        ):
            Configuration.for_realm(REALM).map_role_to_service(service, role)
        url = post_m.call_args[0][0]
        assert url == f"{BASE}/services/svc-uuid/roles/role-id"

    def test_raises_on_post_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        role = self._make_role()
        with patch("aiac.idp.configuration.api.requests.post", return_value=_err(409)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).map_role_to_service(service, role)

    def test_realm_forwarded_on_both_calls(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        role = self._make_role()
        updated = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        with (
            patch("aiac.idp.configuration.api.requests.post", return_value=_ok({}, 201)) as post_m,
            patch("aiac.idp.configuration.api.requests.get", return_value=_ok(updated)) as get_m,
        ):
            Configuration.for_realm(REALM).map_role_to_service(service, role)
        assert post_m.call_args[1].get("params") == {"realm": REALM}
        assert get_m.call_args[1].get("params") == {"realm": REALM}


# ---------------------------------------------------------------------------
# realm forwarded as ?realm= on all methods
# ---------------------------------------------------------------------------


class TestRealmParameter:
    @pytest.mark.parametrize(
        "method,endpoint",
        [
            ("get_roles", "roles"),
            ("get_scopes", "scopes"),
        ],
    )
    def test_realm_forwarded_as_query_param(self, method, endpoint, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok([])) as m:
            getattr(Configuration.for_realm(REALM), method)()
        m.assert_called_once_with(f"{BASE}/{endpoint}", params={"realm": REALM})

    def test_get_subjects_realm_forwarded_as_query_param(self, monkeypatch):
        from unittest.mock import call

        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok([])) as m:
            Configuration.for_realm(REALM).get_subjects()
        assert call(f"{BASE}/subjects", params={"realm": REALM}) in m.call_args_list

    def test_get_services_realm_forwarded_as_query_param(self, monkeypatch):
        from unittest.mock import call

        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok([])) as m:
            Configuration.for_realm(REALM).get_services()
        assert call(f"{BASE}/services", params={"realm": REALM}) in m.call_args_list


# ---------------------------------------------------------------------------
# Default URL fallback
# ---------------------------------------------------------------------------


def test_default_base_url_used_when_env_unset(monkeypatch):
    monkeypatch.delenv("AIAC_PDP_CONFIG_URL", raising=False)
    with patch("aiac.idp.configuration.api.requests.get", return_value=_ok([])) as m:
        Configuration.for_realm(REALM).get_subjects()
    assert m.call_args[0][0].startswith("http://127.0.0.1:7071")


# ---------------------------------------------------------------------------
# get_services_by_role
# ---------------------------------------------------------------------------


class TestGetServicesByRole:
    """``get_services_by_role`` filters ``get_services()`` client-side by role ``id``."""

    def _make_role(self, **kwargs):
        defaults = {"id": "role-uuid", "name": "viewer", "composite": False}
        return Role.model_validate({**defaults, **kwargs})

    def _make_service(self, sid, role_ids):
        return Service.model_validate(
            {
                "id": sid,
                "clientId": sid,
                "name": sid,
                "enabled": True,
                "roles": [{"id": rid, "name": rid, "composite": False} for rid in role_ids],
            }
        )

    def test_returns_only_services_whose_roles_contain_role_id(self):
        role = self._make_role(id="r1")
        services = [
            self._make_service("svc1", ["r1"]),
            self._make_service("svc2", ["r2"]),
            self._make_service("svc3", ["r1", "r2"]),
        ]
        with patch.object(Configuration, "get_services", return_value=services):
            result = Configuration.for_realm(REALM).get_services_by_role(role)
        assert [s.id for s in result] == ["svc1", "svc3"]
        assert all(isinstance(s, Service) for s in result)

    def test_returns_empty_list_for_realm_level_role(self):
        role = self._make_role(id="r-nobody")
        services = [self._make_service("svc1", ["r1"]), self._make_service("svc2", ["r2"])]
        with patch.object(Configuration, "get_services", return_value=services):
            result = Configuration.for_realm(REALM).get_services_by_role(role)
        assert result == []

    def test_raises_on_non_2xx(self):
        role = self._make_role()
        with patch.object(Configuration, "get_services", side_effect=RuntimeError("HTTP 500")):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_services_by_role(role)


# ---------------------------------------------------------------------------
# get_services_by_scope
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# get_subjects_by_role (8.15)
# ---------------------------------------------------------------------------


class TestGetSubjectsByRole:
    def _make_role(self, **kwargs):
        defaults = {"id": "role-uuid", "name": "viewer", "composite": False}
        return Role.model_validate({**defaults, **kwargs})

    def test_returns_list_of_subject(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        role = self._make_role()
        payload = [{"id": "u1", "username": "alice", "enabled": True}]
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(payload)):
            result = Configuration.for_realm(REALM).get_subjects_by_role(role)
        assert isinstance(result[0], Subject)
        assert result[0].id == "u1"

    def test_issues_get_with_role_id_param(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        role = self._make_role(id="my-role-id")
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok([])) as m:
            Configuration.for_realm(REALM).get_subjects_by_role(role)
        assert m.call_args[0][0] == f"{BASE}/subjects"
        assert m.call_args[1]["params"] == {"role_id": "my-role-id", "realm": REALM}

    def test_returns_empty_list_when_no_subjects(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        role = self._make_role()
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok([])):
            result = Configuration.for_realm(REALM).get_subjects_by_role(role)
        assert result == []

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        role = self._make_role()
        with patch("aiac.idp.configuration.api.requests.get", return_value=_err(500)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_subjects_by_role(role)

    def test_realm_forwarded_as_query_param(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        role = self._make_role()
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok([])) as m:
            Configuration.for_realm(REALM).get_subjects_by_role(role)
        assert m.call_args[1]["params"]["realm"] == REALM

    def test_no_secondary_enrichment_calls(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        role = self._make_role()
        payload = [{"id": "u1", "username": "alice", "enabled": True}]
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(payload)) as m:
            Configuration.for_realm(REALM).get_subjects_by_role(role)
        assert m.call_count == 1

    # handoff 03 — actorIds consistency. The subject/username set this method
    # reports is the same set the IdP service uses to populate a user-kind role's
    # actorIds. Both come from the service, so they must agree and the library
    # must not recompute actorIds client-side.
    def test_subject_set_matches_user_role_actor_ids(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        role = self._make_role(kind="User", actorIds=["alice", "bob"])
        payload = [
            {"id": "u1", "username": "alice", "enabled": True},
            {"id": "u2", "username": "bob", "enabled": True},
        ]
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(payload)):
            result = Configuration.for_realm(REALM).get_subjects_by_role(role)
        assert {s.username for s in result} == set(role.actorIds)
        # The library surfaces the service's subject set as-is; it does not
        # mutate/recompute the role's actorIds.
        assert role.actorIds == ["alice", "bob"]

    def test_subject_fields_pass_through_unchanged(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        role = self._make_role()
        payload = [
            {
                "id": "u1",
                "username": "alice",
                "email": "alice@example.com",
                "firstName": "Alice",
                "enabled": True,
            }
        ]
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(payload)):
            result = Configuration.for_realm(REALM).get_subjects_by_role(role)
        assert result[0].email == "alice@example.com"
        assert result[0].firstName == "Alice"


# ---------------------------------------------------------------------------
# get_services_by_scope (unchanged)
# ---------------------------------------------------------------------------


class TestGetServicesByScope:
    """``get_services_by_scope`` filters ``get_services()`` client-side by scope ``id``."""

    def _make_scope(self, **kwargs):
        defaults = {"id": "scope-uuid", "name": "read:data"}
        return Scope.model_validate({**defaults, **kwargs})

    def _make_service(self, sid, scope_ids):
        return Service.model_validate(
            {
                "id": sid,
                "clientId": sid,
                "name": sid,
                "enabled": True,
                "scopes": [{"id": scid, "name": scid} for scid in scope_ids],
            }
        )

    def test_returns_only_services_whose_scopes_contain_scope_id(self):
        scope = self._make_scope(id="s1")
        services = [
            self._make_service("svc1", ["s1"]),
            self._make_service("svc2", ["s2"]),
            self._make_service("svc3", ["s1", "s2"]),
        ]
        with patch.object(Configuration, "get_services", return_value=services):
            result = Configuration.for_realm(REALM).get_services_by_scope(scope)
        assert [s.id for s in result] == ["svc1", "svc3"]
        assert all(isinstance(s, Service) for s in result)

    def test_returns_empty_list_when_no_service_exposes_scope(self):
        scope = self._make_scope(id="s-nobody")
        services = [self._make_service("svc1", ["s1"]), self._make_service("svc2", ["s2"])]
        with patch.object(Configuration, "get_services", return_value=services):
            result = Configuration.for_realm(REALM).get_services_by_scope(scope)
        assert result == []

    def test_raises_on_non_2xx(self):
        scope = self._make_scope()
        with patch.object(Configuration, "get_services", side_effect=RuntimeError("HTTP 500")):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).get_services_by_scope(scope)


# ---------------------------------------------------------------------------
# handoff 03 — SPM/APM field pass-through through the library deserialization
#
# handoff 01 declares Role.kind / Role.actorIds / Scope.serviceId; handoff 02
# makes the IdP *service* populate them. The Configuration library is a thin
# pass-through (model_validate), so these fields must survive onto the returned
# models with no hand-rolled mapping dropping them and no client-side derivation.
# These tests stub the HTTP layer with a service response carrying the new
# fields and assert they round-trip through the real read paths.
# ---------------------------------------------------------------------------


class TestFieldPassThrough:
    def test_get_roles_surfaces_role_kind(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "r1", "name": "agent-role", "composite": False, "kind": "Agent"}]
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(payload)):
            roles = Configuration.for_realm(REALM).get_roles()
        assert roles[0].kind == RoleKind.AGENT

    def test_get_roles_surfaces_actor_ids(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [
            {
                "id": "r1",
                "name": "viewer",
                "composite": False,
                "kind": "User",
                "actorIds": ["alice", "bob"],
            }
        ]
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(payload)):
            roles = Configuration.for_realm(REALM).get_roles()
        assert roles[0].actorIds == ["alice", "bob"]

    def test_get_scopes_surfaces_scope_service_id(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "s1", "name": "read:data", "serviceId": "mlflow"}]
        with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(payload)):
            scopes = Configuration.for_realm(REALM).get_scopes()
        assert scopes[0].serviceId == "mlflow"

    def test_get_services_surfaces_new_fields_on_nested_role_and_scope(self, monkeypatch):
        # get_services() enriches each service's roles/scopes from the get_roles()
        # / get_scopes() maps, so the new fields must survive that join too.
        # Call order: GET /services, GET /roles, GET /scopes, GET /services/{id}/roles,
        # GET /services/{id}/scopes.
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        services = [{"id": "c1", "clientId": "mlflow", "name": "mlflow", "enabled": True}]
        all_roles = [
            {
                "id": "r1",
                "name": "mlflow-agent",
                "composite": False,
                "kind": "Agent",
                "actorIds": ["mlflow"],
            }
        ]
        all_scopes = [{"id": "s1", "name": "read:data", "serviceId": "mlflow"}]
        service_roles = [{"id": "r1", "name": "mlflow-agent"}]
        service_scopes = [{"id": "s1", "name": "read:data"}]
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[
                _ok(services),
                _ok(all_roles),
                _ok(all_scopes),
                _ok(service_roles),
                _ok(service_scopes),
            ],
        ):
            result = Configuration.for_realm(REALM).get_services()
        assert result[0].roles[0].kind == RoleKind.AGENT
        assert result[0].roles[0].actorIds == ["mlflow"]
        assert result[0].scopes[0].serviceId == "mlflow"

    def test_role_kind_taken_from_response_not_rederived(self, monkeypatch):
        # Role.kind is authoritative — the library must not re-derive it by
        # classifying a role against the service list. Point get_services at a
        # spy and assert get_roles never touches it.
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        payload = [{"id": "r1", "name": "agent-role", "composite": False, "kind": "Agent"}]
        spy = MagicMock(side_effect=AssertionError("get_services must not be called to set Role.kind"))
        with patch.object(Configuration, "get_services", spy):
            with patch("aiac.idp.configuration.api.requests.get", return_value=_ok(payload)):
                roles = Configuration.for_realm(REALM).get_roles()
        assert roles[0].kind == RoleKind.AGENT
        spy.assert_not_called()


# ---------------------------------------------------------------------------
# delete_service_role — teardown of a role this service created
#
# The library issues a SINGLE DELETE to the unmap-then-delete endpoint; the
# service removes the role mapping from the service account first, then deletes
# the realm role (unmap-then-delete order + shared-object safety are enforced
# service-side — see idp-configuration-service.md / issue #177). At this seam we
# assert the correct single call, the None return, error propagation, and that
# an idempotent (already-gone) success does not raise.
# ---------------------------------------------------------------------------


class TestDeleteServiceRole:
    def _make_service(self, **kwargs):
        defaults = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        return Service.model_validate({**defaults, **kwargs})

    def _make_role(self, **kwargs):
        defaults = {"id": "role-id", "name": "reader", "composite": False}
        return Role.model_validate({**defaults, **kwargs})

    def test_issues_delete_to_unmap_then_delete_endpoint(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        role = self._make_role(id="role-id")
        with patch("aiac.idp.configuration.api.requests.delete", return_value=_ok({}, 204)) as m:
            result = Configuration.for_realm(REALM).delete_service_role(service, role)
        assert result is None
        assert m.call_args[0][0] == f"{BASE}/services/svc-uuid/roles/role-id"

    def test_forwards_realm_as_query_param(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        role = self._make_role()
        with patch("aiac.idp.configuration.api.requests.delete", return_value=_ok({}, 204)) as m:
            Configuration.for_realm(REALM).delete_service_role(service, role)
        assert m.call_args[1].get("params") == {"realm": REALM}

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        role = self._make_role()
        with patch("aiac.idp.configuration.api.requests.delete", return_value=_err(502)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).delete_service_role(service, role)

    def test_idempotent_already_gone_does_not_raise(self, monkeypatch):
        # The service treats an already-removed mapping / already-deleted role as
        # success (2xx); the library must not raise on that idempotent response.
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        role = self._make_role()
        with patch("aiac.idp.configuration.api.requests.delete", return_value=_ok({}, 204)):
            result = Configuration.for_realm(REALM).delete_service_role(service, role)
        assert result is None


# ---------------------------------------------------------------------------
# delete_service_scope — teardown of a scope this service created
#
# Same shape as delete_service_role: a single DELETE to the unmap-then-delete
# endpoint; the service removes the scope mapping from the client first, then
# deletes the client scope (ordering + shared-object safety enforced service-side).
# ---------------------------------------------------------------------------


class TestDeleteServiceScope:
    def _make_service(self, **kwargs):
        defaults = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        return Service.model_validate({**defaults, **kwargs})

    def _make_scope(self, **kwargs):
        defaults = {"id": "scope-id", "name": "read:data"}
        return Scope.model_validate({**defaults, **kwargs})

    def test_issues_delete_to_unmap_then_delete_endpoint(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        scope = self._make_scope(id="scope-id")
        with patch("aiac.idp.configuration.api.requests.delete", return_value=_ok({}, 204)) as m:
            result = Configuration.for_realm(REALM).delete_service_scope(service, scope)
        assert result is None
        assert m.call_args[0][0] == f"{BASE}/services/svc-uuid/scopes/scope-id"

    def test_forwards_realm_as_query_param(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        scope = self._make_scope()
        with patch("aiac.idp.configuration.api.requests.delete", return_value=_ok({}, 204)) as m:
            Configuration.for_realm(REALM).delete_service_scope(service, scope)
        assert m.call_args[1].get("params") == {"realm": REALM}

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        scope = self._make_scope()
        with patch("aiac.idp.configuration.api.requests.delete", return_value=_err(502)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).delete_service_scope(service, scope)

    def test_idempotent_already_gone_does_not_raise(self, monkeypatch):
        # The service treats an already-removed assignment / already-deleted scope
        # as success (2xx); the library must not raise on that idempotent response.
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        scope = self._make_scope()
        with patch("aiac.idp.configuration.api.requests.delete", return_value=_ok({}, 204)):
            result = Configuration.for_realm(REALM).delete_service_scope(service, scope)
        assert result is None


# ---------------------------------------------------------------------------
# set_service_enabled — the writer for Service.enabled
#
# POST /services/{id}/enabled with {"enabled": bool} → the service calls
# update_client(enabled=…). Returns the updated Service. Idempotent (disabling an
# already-disabled client is not an error). The round-trip block below proves the
# writer is wired and that get_service / get_services surface the current value.
# ---------------------------------------------------------------------------


class TestSetServiceEnabled:
    def _make_service(self, **kwargs):
        defaults = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        return Service.model_validate({**defaults, **kwargs})

    def test_returns_service_with_new_enabled_value(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service(enabled=True)
        updated = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": False}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(updated, 200)):
            result = Configuration.for_realm(REALM).set_service_enabled(service, False)
        assert isinstance(result, Service)
        assert result.enabled is False

    def test_posts_to_enabled_endpoint_with_enabled_body(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        updated = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": False}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(updated, 200)) as m:
            Configuration.for_realm(REALM).set_service_enabled(service, False)
        assert m.call_args[0][0] == f"{BASE}/services/svc-uuid/enabled"
        assert m.call_args[1].get("json") == {"enabled": False}

    def test_forwards_realm_as_query_param(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        updated = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": False}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(updated, 200)) as m:
            Configuration.for_realm(REALM).set_service_enabled(service, False)
        assert m.call_args[1].get("params") == {"realm": REALM}

    def test_raises_on_non_2xx(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service()
        with patch("aiac.idp.configuration.api.requests.post", return_value=_err(502)):
            with pytest.raises(RuntimeError):
                Configuration.for_realm(REALM).set_service_enabled(service, False)

    def test_idempotent_disabling_already_disabled_does_not_raise(self, monkeypatch):
        # Disabling an already-disabled client is a no-op the service reports as
        # success; the returned Service is still enabled=False and no error is raised.
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service(enabled=False)
        updated = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": False}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(updated, 200)):
            result = Configuration.for_realm(REALM).set_service_enabled(service, False)
        assert result.enabled is False

    def test_re_enable_returns_enabled_true(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        service = self._make_service(enabled=False)
        updated = {"id": "svc-uuid", "clientId": "svc-uuid", "name": "my-svc", "enabled": True}
        with patch("aiac.idp.configuration.api.requests.post", return_value=_ok(updated, 200)):
            result = Configuration.for_realm(REALM).set_service_enabled(service, True)
        assert result.enabled is True


class TestServiceEnabledRoundTrip:
    """Service.enabled round-trips: the writer (set_service_enabled) sets it and the
    read paths (get_service / get_services) surface the current value — not discarded
    after validation."""

    SERVICE_ID = "svc-uuid"

    def test_set_then_read_via_get_service_surfaces_disabled(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        # set_service_enabled(..., False) writes the disable...
        set_resp = _ok(
            {"id": self.SERVICE_ID, "clientId": self.SERVICE_ID, "name": "my-svc", "enabled": False},
            200,
        )
        service = Service.model_validate(
            {"id": self.SERVICE_ID, "clientId": self.SERVICE_ID, "name": "my-svc", "enabled": True}
        )
        with patch("aiac.idp.configuration.api.requests.post", return_value=set_resp):
            after_set = Configuration.for_realm(REALM).set_service_enabled(service, False)
        assert after_set.enabled is False

        # ...and a subsequent get_service reflects the disabled value from the service.
        raw = {"id": self.SERVICE_ID, "clientId": self.SERVICE_ID, "name": "my-svc", "enabled": False}
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(raw), _ok([]), _ok([]), _ok([]), _ok([])],
        ):
            read_back = Configuration.for_realm(REALM).get_service(self.SERVICE_ID)
        assert read_back.enabled is False

    def test_get_services_surfaces_enabled_value(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        services = [{"id": self.SERVICE_ID, "clientId": self.SERVICE_ID, "name": "my-svc", "enabled": False}]
        with patch(
            "aiac.idp.configuration.api.requests.get",
            side_effect=[_ok(services), _ok([]), _ok([]), _ok([]), _ok([])],
        ):
            result = Configuration.for_realm(REALM).get_services()
        assert result[0].enabled is False


# ---------------------------------------------------------------------------
# Transient retry — the error keeps the status, a 5xx is retried, a 4xx is not
#
# _check raises IdPHTTPError (a RuntimeError subclass) with the HTTP status and
# the response, so run_upstream (aiac.shared.upstream) retries a 5xx up to
# UPSTREAM_MAX_RETRIES with exponential backoff (1 s, 2 s, ...) and raises a 4xx
# at once. The fixture sets a budget of 3 attempts (it overrides _single_attempt)
# and records each backoff instead of sleeping: tenacity's default sleep calls
# time.sleep at run time, so patch time.sleep, not tenacity.nap.sleep.
# ---------------------------------------------------------------------------


def _real_response(status: int, text: str = "boom") -> requests.Response:
    """A real ``requests.Response`` (not a MagicMock), so ``.ok`` / ``.text`` / ``.status_code`` are
    the library's own."""
    resp = requests.Response()
    resp.status_code = status
    resp._content = text.encode()
    return resp


class TestTransientRetry:
    SERVICE_ID = "svc-001"

    @pytest.fixture(autouse=True)
    def waits(self, monkeypatch):
        monkeypatch.setenv("AIAC_PDP_CONFIG_URL", BASE)
        monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "3")
        recorded: list[float] = []
        monkeypatch.setattr("time.sleep", recorded.append)
        return recorded

    @pytest.mark.parametrize("status", [500, 502, 503])
    def test_5xx_is_retried_up_to_the_budget_then_raised(self, status, waits):
        with patch("aiac.idp.configuration.api.requests.get", return_value=_err(status)) as m:
            with pytest.raises(IdPHTTPError) as ei:
                Configuration.for_realm(REALM).get_scopes()
        assert m.call_count == 3  # UPSTREAM_MAX_RETRIES
        assert ei.value.status == status
        assert waits == [1, 2]  # exponential backoff, no real sleep

    def test_5xx_then_200_succeeds(self, waits):
        scopes = [{"id": "s1", "name": "read:data"}]
        with patch("aiac.idp.configuration.api.requests.get", side_effect=[_err(502), _ok(scopes)]) as m:
            result = Configuration.for_realm(REALM).get_scopes()
        assert [s.name for s in result] == ["read:data"]
        assert m.call_count == 2
        assert waits == [1]

    @pytest.mark.parametrize("status", [400, 404, 409])
    def test_4xx_is_not_retried(self, status, waits):
        with patch("aiac.idp.configuration.api.requests.get", return_value=_err(status)) as m:
            with pytest.raises(IdPHTTPError) as ei:
                Configuration.for_realm(REALM).get_service(self.SERVICE_ID)
        assert m.call_count == 1
        assert ei.value.status == status
        assert waits == []

    def test_real_response_5xx_is_retried_and_4xx_is_not(self, waits):
        with patch("aiac.idp.configuration.api.requests.get", return_value=_real_response(503)) as m:
            with pytest.raises(IdPHTTPError):
                Configuration.for_realm(REALM).get_scopes()
        assert m.call_count == 3
        with patch("aiac.idp.configuration.api.requests.get", return_value=_real_response(404)) as m:
            with pytest.raises(IdPHTTPError):
                Configuration.for_realm(REALM).get_service(self.SERVICE_ID)
        assert m.call_count == 1

    def test_write_5xx_is_retried_and_write_409_is_not(self, waits):
        # A write is retried at the same leaf (_request). library-idp.md ("Retry safety of the
        # writes") tells what a repeated write of each primitive does.
        with patch("aiac.idp.configuration.api.requests.post", return_value=_err(502)) as m:
            with pytest.raises(IdPHTTPError):
                Configuration.for_realm(REALM).create_scope("read:data", "Read access")
        assert m.call_count == 3
        with patch("aiac.idp.configuration.api.requests.post", return_value=_err(409)) as m:
            with pytest.raises(IdPHTTPError):
                Configuration.for_realm(REALM).create_scope("read:data", "Read access")
        assert m.call_count == 1

    def test_error_is_a_runtime_error_that_keeps_the_status_and_the_response(self):
        resp = _err(404)
        with patch("aiac.idp.configuration.api.requests.get", return_value=resp):
            with pytest.raises(RuntimeError) as ei:
                Configuration.for_realm(REALM).get_service(self.SERVICE_ID)
        assert isinstance(ei.value, IdPHTTPError)
        assert ei.value.status == 404
        assert ei.value.response is resp
        assert str(ei.value) == "HTTP 404: internal error"  # the message text does not change

    @pytest.mark.parametrize(
        "clone",
        [
            pytest.param(lambda e: pickle.loads(pickle.dumps(e)), id="pickle"),
            pytest.param(copy.copy, id="copy"),
            pytest.param(copy.deepcopy, id="deepcopy"),
        ],
    )
    @pytest.mark.parametrize("with_response", [True, False], ids=["response", "no-response"])
    def test_error_survives_pickle_and_copy(self, clone, with_response):
        # BaseException rebuilds a copy from ``self.args`` (the message only), which would call
        # IdPHTTPError(message) and fail with a TypeError. A checkpointer, a process pool or a log
        # handler that copies the error must get the same error back.
        resp = _real_response(502, "upstream down") if with_response else None
        err = IdPHTTPError(502, "upstream down", resp)
        err.add_note("first get_service")
        got = clone(err)
        assert type(got) is IdPHTTPError
        assert got.status == 502
        assert str(got) == "HTTP 502: upstream down"
        assert got.__notes__ == ["first get_service"]
        if with_response:
            assert got.response.status_code == 502
            assert got.response.text == "upstream down"
        else:
            assert got.response is None
