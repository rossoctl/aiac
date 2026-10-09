"""Unit tests for aiac/idp/service/configuration/keycloak/main.py FastAPI application."""

import base64
import json
import os
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from keycloak.exceptions import KeycloakError, KeycloakGetError

from aiac.idp.service.configuration.keycloak.main import _cache, app, get_admin

REALM = "rossoctl"


def _make_client(admin_mock: MagicMock) -> TestClient:
    app.dependency_overrides[get_admin] = lambda realm=None: admin_mock
    return TestClient(app)


def _make_jwt(payload: dict) -> str:
    """Encode a payload into a `header.payload.sig` JWT shape (unsigned — the endpoint only
    base64-decodes the payload to read iss/aud; it never verifies the signature)."""
    seg = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"h.{seg}.s"


# ---------------------------------------------------------------------------
# GET /subjects
# ---------------------------------------------------------------------------


class TestGetSubjects:
    def test_returns_json_array(self):
        admin = MagicMock()
        admin.get_users.return_value = [{"id": "u1", "username": "alice"}]
        resp = _make_client(admin).get(f"/subjects?realm={REALM}")
        assert resp.status_code == 200
        assert resp.json() == [{"id": "u1", "username": "alice"}]


# ---------------------------------------------------------------------------
# GET /roles
# ---------------------------------------------------------------------------


class TestGetRoles:
    def test_returns_json_array(self):
        admin = MagicMock()
        admin.get_realm_roles.return_value = [{"id": "r1", "name": "admin"}]
        resp = _make_client(admin).get(f"/roles?realm={REALM}")
        assert resp.status_code == 200
        # Realm roles are user roles (clientRole == false) -> kind=User (handoff 02).
        assert resp.json() == [{"id": "r1", "name": "admin", "kind": "User"}]

    def test_requests_full_representation_for_attributes(self):
        # The aiac.managed marker lives in role attributes, which Keycloak's brief
        # representation omits — the endpoint must ask for the full representation.
        admin = MagicMock()
        admin.get_realm_roles.return_value = []
        _make_client(admin).get(f"/roles?realm={REALM}")
        admin.get_realm_roles.assert_called_once_with(brief_representation=False)

    def test_populates_user_kind_on_all_realm_roles(self):
        admin = MagicMock()
        admin.get_realm_roles.return_value = [
            {"id": "r1", "name": "reader"},
            {"id": "r2", "name": "default-roles-rossoctl"},
        ]
        resp = _make_client(admin).get(f"/roles?realm={REALM}")
        # default-roles-rossoctl is the Keycloak default composite for this realm -> excluded.
        assert [r["kind"] for r in resp.json()] == ["User"]

    def test_excludes_default_roles_composite_for_realm(self):
        # The default composite (default-roles-{realm}) is the sole path to Keycloak's
        # built-ins (offline_access, uma_authorization, view-profile, account roles) --
        # it must never appear in the response, and its members must never be scanned.
        admin = MagicMock()
        admin.get_realm_roles.return_value = [
            {"id": "r1", "name": "reader"},
            {"id": "r2", "name": f"default-roles-{REALM}"},
        ]
        resp = _make_client(admin).get(f"/roles?realm={REALM}")
        names = [r["name"] for r in resp.json()]
        assert f"default-roles-{REALM}" not in names
        assert names == ["reader"]
        admin.get_realm_role_members.assert_not_called()

    def test_aiac_managed_role_gets_member_usernames_as_actor_ids(self):
        # For a user (realm) role, actorIds = the member usernames — resolved via the same
        # get_realm_role_members call that GET /subjects?role_id= uses (SPM/APM alignment).
        admin = MagicMock()
        admin.get_realm_roles.return_value = [
            {"id": "r1", "name": "invoicing", "attributes": {"aiac.managed": ["true"]}},
        ]
        admin.get_realm_role_members.return_value = [
            {"id": "u1", "username": "alice"},
            {"id": "u2", "username": "bob"},
        ]
        resp = _make_client(admin).get(f"/roles?realm={REALM}")
        role = resp.json()[0]
        assert role["kind"] == "User"
        assert role["actorIds"] == ["alice", "bob"]
        admin.get_realm_role_members.assert_called_once_with("invoicing")

    def test_non_managed_role_skips_member_query(self):
        # Built-ins / non-AIAC roles are not enriched with actorIds (no member scan).
        admin = MagicMock()
        admin.get_realm_roles.return_value = [{"id": "r1", "name": "admin"}]
        resp = _make_client(admin).get(f"/roles?realm={REALM}")
        assert "actorIds" not in resp.json()[0]
        admin.get_realm_role_members.assert_not_called()


# ---------------------------------------------------------------------------
# GET /services
# ---------------------------------------------------------------------------


class TestGetServices:
    def test_returns_json_array(self):
        admin = MagicMock()
        admin.get_clients.return_value = [{"id": "c1", "clientId": "my-app"}]
        resp = _make_client(admin).get(f"/services?realm={REALM}")
        assert resp.status_code == 200
        assert resp.json() == [{"id": "c1", "clientId": "my-app"}]


# ---------------------------------------------------------------------------
# GET /scopes
# ---------------------------------------------------------------------------


class TestGetScopes:
    def test_returns_json_array(self):
        admin = MagicMock()
        admin.get_client_scopes.return_value = [{"id": "s1", "name": "email"}]
        resp = _make_client(admin).get(f"/scopes?realm={REALM}")
        assert resp.status_code == 200
        assert resp.json() == [{"id": "s1", "name": "email"}]


# ---------------------------------------------------------------------------
# GET /subjects/{subject_id}/assignments
# ---------------------------------------------------------------------------


class TestGetSubjectAssignments:
    def test_returns_object_with_realm_and_service_mappings(self):
        admin = MagicMock()
        admin.get_all_roles_of_user.return_value = {
            "realmMappings": [{"id": "r1", "name": "admin"}],
            "clientMappings": {"account": {"id": "a1", "mappings": []}},
        }
        resp = _make_client(admin).get(f"/subjects/user-uuid/assignments?realm={REALM}")
        assert resp.status_code == 200
        body = resp.json()
        assert "realmMappings" in body
        assert "serviceMappings" in body


# ---------------------------------------------------------------------------
# GET /services/{service_id}/roles
# ---------------------------------------------------------------------------


class TestListServiceRoles:
    def test_sources_client_roles_and_service_account_realm_roles(self):
        # The endpoint returns both client roles (kind=Agent via clientRole=true) and
        # aiac-managed realm roles assigned to the service account (kind=Agent via the
        # provisioning path used by the Configuration library).
        admin = MagicMock()
        admin.get_client_roles.return_value = [{"id": "cr1", "name": "invoke", "clientRole": True}]
        admin.get_client.return_value = {"id": "svc-uuid", "clientId": "github-agent"}
        sa_user = {"id": "sa-uid"}
        admin.get_client_service_account_user.return_value = sa_user
        admin.get_realm_roles_of_user.return_value = []
        resp = _make_client(admin).get(f"/services/svc-uuid/roles?realm={REALM}")
        assert resp.status_code == 200
        admin.get_client_roles.assert_called_once_with("svc-uuid")
        admin.get_client_service_account_user.assert_called_once_with("svc-uuid")
        admin.get_realm_roles_of_user.assert_called_once_with(sa_user["id"])

    def test_populates_agent_kind_and_owner_actor_ids(self):
        # clientRole == true -> kind=Agent; actorIds = the owning client's serviceId,
        # resolved from the role's containerId -> client.
        admin = MagicMock()
        admin.get_client_roles.return_value = [
            {"id": "cr1", "name": "invoke", "clientRole": True, "containerId": "svc-uuid"},
        ]
        admin.get_client.return_value = {"id": "svc-uuid", "clientId": "github-agent"}
        admin.get_client_service_account_user.return_value = {"id": "sa-uid"}
        admin.get_realm_roles_of_user.return_value = []
        resp = _make_client(admin).get(f"/services/svc-uuid/roles?realm={REALM}")
        assert resp.status_code == 200
        role = resp.json()[0]
        assert role["kind"] == "Agent"
        assert role["actorIds"] == ["github-agent"]

    def test_returns_502_on_other_keycloak_error(self):
        # A Keycloak 404 gives 404 (see TestKeycloakNotFoundProduces404); any other error is a 502.
        admin = MagicMock()
        admin.get_client_roles.side_effect = KeycloakError(error_message="backend failure", response_code=500)
        resp = _make_client(admin).get(f"/services/svc-uuid/roles?realm={REALM}")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_missing_service_account_contributes_no_realm_roles(self):
        # A Keycloak 404 on the service-account lookup means "the client has no service account":
        # the client roles are returned. It is not the 404 of a missing client.
        admin = MagicMock()
        admin.get_client.return_value = {"id": "svc-uuid", "clientId": "github-agent"}
        admin.get_client_roles.return_value = [{"id": "cr1", "name": "invoke", "containerId": "svc-uuid"}]
        admin.get_client_service_account_user.side_effect = KeycloakGetError(
            error_message="Service account not enabled for the client", response_code=404
        )
        resp = _make_client(admin).get(f"/services/svc-uuid/roles?realm={REALM}")
        assert resp.status_code == 200
        assert [r["id"] for r in resp.json()] == ["cr1"]
        admin.get_realm_roles_of_user.assert_not_called()

    def test_returns_empty_list_when_client_has_no_client_roles(self):
        admin = MagicMock()
        admin.get_client_roles.side_effect = KeycloakError(error_message="Client not found", response_code=400)
        resp = _make_client(admin).get(f"/services/svc-uuid/roles?realm={REALM}")
        assert resp.status_code == 200
        assert resp.json() == []

    # The realm roles of the service account (the provisioning path of the Configuration library).
    # ``get_realm_roles_of_user`` gives stubs with no attributes, so the endpoint reads each full role
    # to find the aiac.managed marker.
    _MANAGED = {"id": "r-managed", "name": "github-agent.source_operations", "attributes": {"aiac.managed": ["true"]}}
    _BUILTIN = {"id": "r-builtin", "name": "offline_access", "attributes": {}}

    def _realm_admin(self, *, client_roles=(), stubs=()):
        admin = MagicMock()
        admin.get_client.return_value = {"id": "svc-uuid", "clientId": "team1/github-agent"}
        admin.get_client_roles.return_value = [dict(r) for r in client_roles]
        admin.get_client_service_account_user.return_value = {"id": "sa-uid"}
        admin.get_realm_roles_of_user.return_value = [dict(s) for s in stubs]
        full = {r["id"]: r for r in (self._MANAGED, self._BUILTIN)}
        admin.get_realm_role_by_id.side_effect = lambda role_id: dict(full[role_id])
        return admin

    def test_aiac_managed_realm_role_of_the_service_account_is_an_agent_role_of_the_service(self):
        stubs = [{"id": r["id"], "name": r["name"]} for r in (self._MANAGED, self._BUILTIN)]
        admin = self._realm_admin(stubs=stubs)

        resp = _make_client(admin).get(f"/services/svc-uuid/roles?realm={REALM}")

        assert resp.status_code == 200
        # The full role, as an agent role of this service (its clientId); the unmarked built-in is not listed.
        assert resp.json() == [{**self._MANAGED, "kind": "Agent", "actorIds": ["team1/github-agent"]}]

    def test_a_realm_role_that_is_also_a_client_role_of_the_service_is_listed_once(self):
        client_role = {"id": "r-managed", "name": "github-agent.source_operations", "containerId": "svc-uuid"}
        admin = self._realm_admin(client_roles=[client_role], stubs=[{"id": "r-managed", "name": "x"}])

        resp = _make_client(admin).get(f"/services/svc-uuid/roles?realm={REALM}")

        assert [r["id"] for r in resp.json()] == ["r-managed"]
        admin.get_realm_role_by_id.assert_not_called()

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Assumption 1 (no cross-kind role) — fail loud (handoff 02)
# ---------------------------------------------------------------------------


class TestCrossKindEnforcement:
    def test_role_held_by_users_and_service_accounts_returns_409(self):
        # A role held by *both* human users and agent service accounts cannot be represented
        # by a single actorIds list — fail loud rather than silently picking a side.
        admin = MagicMock()
        admin.get_realm_roles.return_value = [
            {"id": "r1", "name": "shared", "attributes": {"aiac.managed": ["true"]}},
        ]
        admin.get_realm_role_members.return_value = [
            {"id": "u1", "username": "alice"},
            {"id": "sa", "username": "service-account-github-agent"},
        ]
        resp = _make_client(admin).get(f"/roles?realm={REALM}")
        assert resp.status_code == 409
        assert "error" in resp.json()

    def test_role_held_only_by_users_is_ok(self):
        admin = MagicMock()
        admin.get_realm_roles.return_value = [
            {"id": "r1", "name": "readers", "attributes": {"aiac.managed": ["true"]}},
        ]
        admin.get_realm_role_members.return_value = [
            {"id": "u1", "username": "alice"},
            {"id": "u2", "username": "bob"},
        ]
        resp = _make_client(admin).get(f"/roles?realm={REALM}")
        assert resp.status_code == 200
        assert resp.json()[0]["actorIds"] == ["alice", "bob"]

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /services/{service_id}/scopes
# ---------------------------------------------------------------------------


class TestListServiceScopes:
    def test_returns_json_array_with_owner_service_id(self):
        # Scope.serviceId = the owner of this copy: the listed service, resolved to its serviceId
        # (clientId). A scope that more clients link is listed for each (see TestSharedScopes).
        admin = MagicMock()
        admin.get_client_default_client_scopes.return_value = [
            {"id": "sc1", "name": "profile"},
            {"id": "sc2", "name": "email"},
        ]
        admin.get_client.return_value = {"id": "svc-uuid", "clientId": "github-agent"}
        resp = _make_client(admin).get(f"/services/svc-uuid/scopes?realm={REALM}")
        assert resp.status_code == 200
        assert resp.json() == [
            {"id": "sc1", "name": "profile", "serviceId": "github-agent"},
            {"id": "sc2", "name": "email", "serviceId": "github-agent"},
        ]
        admin.get_client.assert_called_once_with("svc-uuid")

    def test_verifies_get_client_default_client_scopes_called(self):
        admin = MagicMock()
        admin.get_client_default_client_scopes.return_value = []
        _make_client(admin).get(f"/services/svc-uuid/scopes?realm={REALM}")
        admin.get_client_default_client_scopes.assert_called_once_with("svc-uuid")

    def test_returns_502_on_other_keycloak_error(self):
        # A Keycloak 404 gives 404 (see TestKeycloakNotFoundProduces404); any other error is a 502.
        admin = MagicMock()
        admin.get_client_default_client_scopes.side_effect = KeycloakError(
            error_message="backend failure", response_code=500
        )
        resp = _make_client(admin).get(f"/services/svc-uuid/scopes?realm={REALM}")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Shared scopes (D32): one copy for each owner; delete at the last owner
# ---------------------------------------------------------------------------


class _FakeDefaultScopesAdmin:
    """A small stateful stand-in for the Keycloak default-scope reads and writes, in the live shape:
    each item of ``get_client_default_client_scopes`` has only ``id`` and ``name`` (Keycloak never
    returns ``attributes`` there; live check on realm ``rossoctl``, 2026-10-06). ``links`` maps a
    client UUID to the scope ids it links as default scopes; an unmap changes it, so a later read
    sees the state after the unmap."""

    _NAMES = {"sc-shared": "github-tool.source-read", "sc-own": "github-tool.issue-read", "sc-profile": "profile"}

    def __init__(self, links: dict[str, list[str]]):
        self.client_ids = {"uuid-1": "team1/github-tool", "uuid-2": "team2/github-tool"}
        self.links = {uuid: list(scope_ids) for uuid, scope_ids in links.items()}
        self.deleted: list[str] = []

    def get_clients(self):
        return [{"id": uuid, "clientId": client_id} for uuid, client_id in self.client_ids.items()]

    def get_client(self, uuid):
        return {"id": uuid, "clientId": self.client_ids[uuid]}

    def get_client_default_client_scopes(self, uuid):
        return [{"id": scope_id, "name": self._NAMES[scope_id]} for scope_id in self.links.get(uuid, [])]

    def delete_client_default_client_scope(self, uuid, scope_id):
        self.links[uuid].remove(scope_id)

    def delete_client_scope(self, scope_id):
        self.deleted.append(scope_id)


class TestSharedScopes:
    _BOTH = {"uuid-1": ["sc-profile", "sc-shared"], "uuid-2": ["sc-shared", "sc-own"]}

    def test_scope_that_two_clients_link_is_listed_for_each_with_its_client_id(self):
        # A shared scope is valid (D32). Each client's listing gives its own copy, with that client's
        # clientId as serviceId, so each copy routes to its owner's SPM. No owner scan, no 409.
        admin = MagicMock(wraps=_FakeDefaultScopesAdmin(self._BOTH))
        client = _make_client(admin)
        team1 = client.get(f"/services/uuid-1/scopes?realm={REALM}")
        team2 = client.get(f"/services/uuid-2/scopes?realm={REALM}")
        assert team1.status_code == 200 and team2.status_code == 200
        assert team1.json() == [
            {"id": "sc-profile", "name": "profile", "serviceId": "team1/github-tool"},
            {"id": "sc-shared", "name": "github-tool.source-read", "serviceId": "team1/github-tool"},
        ]
        assert team2.json() == [
            {"id": "sc-shared", "name": "github-tool.source-read", "serviceId": "team2/github-tool"},
            {"id": "sc-own", "name": "github-tool.issue-read", "serviceId": "team2/github-tool"},
        ]
        admin.get_clients.assert_not_called()

    def test_delete_keeps_a_scope_that_another_client_links(self):
        fake = _FakeDefaultScopesAdmin(self._BOTH)
        resp = _make_client(fake).delete(f"/services/uuid-1/scopes/sc-shared?realm={REALM}")
        assert resp.status_code == 200
        assert fake.links == {"uuid-1": ["sc-profile"], "uuid-2": ["sc-shared", "sc-own"]}  # unmapped here only
        assert fake.deleted == []

    def test_delete_removes_a_scope_that_no_other_client_links(self):
        fake = _FakeDefaultScopesAdmin(self._BOTH)
        resp = _make_client(fake).delete(f"/services/uuid-2/scopes/sc-own?realm={REALM}")
        assert resp.status_code == 200
        assert fake.links == {"uuid-1": ["sc-profile", "sc-shared"], "uuid-2": ["sc-shared"]}
        assert fake.deleted == ["sc-own"]

    def test_delete_at_the_last_owner_removes_the_shared_scope(self):
        fake = _FakeDefaultScopesAdmin(self._BOTH)
        client = _make_client(fake)
        client.delete(f"/services/uuid-1/scopes/sc-shared?realm={REALM}")
        assert fake.deleted == []
        client.delete(f"/services/uuid-2/scopes/sc-shared?realm={REALM}")
        assert fake.deleted == ["sc-shared"]

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /roles/{role_name}/composites
# ---------------------------------------------------------------------------


class TestGetRoleComposites:
    def test_returns_json_array(self):
        admin = MagicMock()
        admin.get_composite_realm_roles_of_role.return_value = [{"id": "r2", "name": "viewer"}]
        resp = _make_client(admin).get(f"/roles/admin/composites?realm={REALM}")
        assert resp.status_code == 200
        assert resp.json() == [{"id": "r2", "name": "viewer"}]
        admin.get_composite_realm_roles_of_role.assert_called_once_with(role_name="admin")


# ---------------------------------------------------------------------------
# Realm query parameter: required, lazy per-realm cache
# ---------------------------------------------------------------------------


class TestRealmQueryParam:
    def test_missing_realm_returns_422(self):
        app.dependency_overrides.clear()
        resp = TestClient(app).get("/subjects")
        assert resp.status_code == 422

    def test_realm_param_creates_admin_with_admin_realm(self):
        _cache.clear()
        app.dependency_overrides.clear()
        admin_mock = MagicMock()
        admin_mock.get_users.return_value = []
        env = {
            "KEYCLOAK_URL": "http://keycloak:8080/",
            "KEYCLOAK_ADMIN_REALM": "master",
            "KEYCLOAK_ADMIN_USERNAME": "admin",
            "KEYCLOAK_ADMIN_PASSWORD": "admin",
        }
        with (
            patch.dict(os.environ, env),
            patch("aiac.idp.service.configuration.keycloak.main.KeycloakAdmin", return_value=admin_mock) as mock_cls,
        ):
            with TestClient(app) as client:
                resp = client.get(f"/subjects?realm={REALM}")
        assert resp.status_code == 200
        mock_cls.assert_called_once_with(
            server_url="http://keycloak:8080/",
            realm_name=REALM,
            user_realm_name="master",
            username="admin",
            password="admin",
        )

    def test_second_request_same_realm_hits_cache(self):
        _cache.clear()
        app.dependency_overrides.clear()
        admin_mock = MagicMock()
        admin_mock.get_users.return_value = []
        env = {
            "KEYCLOAK_URL": "http://keycloak:8080/",
            "KEYCLOAK_ADMIN_REALM": "master",
            "KEYCLOAK_ADMIN_USERNAME": "admin",
            "KEYCLOAK_ADMIN_PASSWORD": "admin",
        }
        with (
            patch.dict(os.environ, env),
            patch("aiac.idp.service.configuration.keycloak.main.KeycloakAdmin", return_value=admin_mock) as mock_cls,
        ):
            with TestClient(app) as client:
                client.get(f"/subjects?realm={REALM}")
                client.get(f"/subjects?realm={REALM}")
        assert mock_cls.call_count == 1

    def teardown_method(self):
        app.dependency_overrides.clear()
        _cache.clear()


# ---------------------------------------------------------------------------
# GET /health (readiness probe — pings Keycloak)
# ---------------------------------------------------------------------------


_HEALTH_ENV = {"KEYCLOAK_ADMIN_REALM": "master"}
_HEALTH_TARGET = "aiac.idp.service.configuration.keycloak.main._get_or_create_admin"


class TestHealth:
    def test_returns_200_when_keycloak_reachable(self):
        admin = MagicMock()
        with patch(_HEALTH_TARGET, return_value=admin), patch.dict(os.environ, _HEALTH_ENV):
            resp = TestClient(app).get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
        admin.get_server_info.assert_called_once()

    def test_returns_503_when_keycloak_unreachable(self):
        admin = MagicMock()
        admin.get_server_info.side_effect = KeycloakError(error_message="connection refused", response_code=503)
        with patch(_HEALTH_TARGET, return_value=admin), patch.dict(os.environ, _HEALTH_ENV):
            resp = TestClient(app).get("/health")
        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "unavailable"
        assert "error" in body

    def test_uses_admin_realm_env_var(self):
        admin = MagicMock()
        with (
            patch(_HEALTH_TARGET, return_value=admin) as mock_factory,
            patch.dict(os.environ, {"KEYCLOAK_ADMIN_REALM": "master"}),
        ):
            TestClient(app).get("/health")
        mock_factory.assert_called_once_with("master")


# ---------------------------------------------------------------------------
# POST /services/{service_id}/scopes
# ---------------------------------------------------------------------------


class TestCreateScope:
    def test_returns_201_with_scope_json(self):
        admin = MagicMock()
        admin.create_client_scope.return_value = "new-scope-id"
        admin.get_client_scope.return_value = {
            "id": "new-scope-id",
            "name": "read:data",
            "description": "Read access",
        }
        resp = _make_client(admin).post(
            f"/services/svc-uuid/scopes?realm={REALM}",
            json={"name": "read:data", "description": "Read access"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["id"] == "new-scope-id"
        assert body["name"] == "read:data"

    def test_assigns_scope_as_default_to_service(self):
        admin = MagicMock()
        admin.create_client_scope.return_value = "scope-id-42"
        admin.get_client_scope.return_value = {"id": "scope-id-42", "name": "write"}
        _make_client(admin).post(
            f"/services/svc-abc/scopes?realm={REALM}",
            json={"name": "write", "description": "Write access"},
        )
        admin.add_client_default_client_scope.assert_called_once_with("svc-abc", "scope-id-42", {})

    def test_creates_scope_with_openid_connect_protocol(self):
        admin = MagicMock()
        admin.create_client_scope.return_value = "sid"
        admin.get_client_scope.return_value = {"id": "sid", "name": "read"}
        _make_client(admin).post(
            f"/services/svc/scopes?realm={REALM}",
            json={"name": "read", "description": "desc"},
        )
        call_payload = admin.create_client_scope.call_args[0][0]
        assert call_payload["protocol"] == "openid-connect"
        assert call_payload["name"] == "read"
        assert call_payload["description"] == "desc"
        assert call_payload["attributes"] == {"aiac.managed": "true"}

    def test_returns_502_on_keycloak_error(self):
        admin = MagicMock()
        admin.create_client_scope.side_effect = KeycloakError(error_message="backend failure", response_code=500)
        resp = _make_client(admin).post(
            f"/services/svc/scopes?realm={REALM}",
            json={"name": "read", "description": "desc"},
        )
        assert resp.status_code == 502
        assert "error" in resp.json()

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /services/{service_id}
# ---------------------------------------------------------------------------


class TestGetService:
    def test_returns_200_with_client_json(self):
        admin = MagicMock()
        admin.get_client.return_value = {"id": "svc-uuid", "clientId": "my-app"}
        resp = _make_client(admin).get(f"/services/svc-uuid?realm={REALM}")
        assert resp.status_code == 200
        assert resp.json()["id"] == "svc-uuid"
        admin.get_client.assert_called_once_with("svc-uuid")

    def test_returns_502_on_other_keycloak_error(self):
        # A Keycloak 404 gives 404 (see TestKeycloakNotFoundProduces404); any other error is a 502.
        admin = MagicMock()
        admin.get_client.side_effect = KeycloakError(error_message="backend failure", response_code=500)
        resp = _make_client(admin).get(f"/services/svc-uuid?realm={REALM}")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /services/{service_id}/discovery-token
# ---------------------------------------------------------------------------


class TestMintDiscoveryToken:
    ISS = "http://keycloak.localtest.me:8080/realms/rossoctl"

    def _wire(self, admin, monkeypatch, *, aud, iss=None, mappers=None, secret="sek"):
        monkeypatch.setenv("KEYCLOAK_URL", "http://kc-internal:8080")
        monkeypatch.delenv("AIAC_KEYCLOAK_ISSUER", raising=False)
        admin.get_client.return_value = {"id": "svc-uuid", "clientId": "github-tool", "secret": secret}
        admin.get_mappers_from_client.return_value = mappers if mappers is not None else []
        oid = MagicMock()
        oid.token.return_value = {"access_token": _make_jwt({"aud": aud, "iss": iss or self.ISS})}
        return oid

    def test_returns_200_with_token_and_resolves_client_id(self, monkeypatch):
        admin = MagicMock()
        oid = self._wire(admin, monkeypatch, aud=["github-tool"])
        with patch("aiac.idp.service.configuration.keycloak.main.KeycloakOpenID", return_value=oid):
            resp = _make_client(admin).get(f"/services/svc-uuid/discovery-token?realm={REALM}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"]
        assert body["client_id"] == "github-tool"
        assert "github-tool" in body["audience"]
        admin.get_client.assert_called_once_with("svc-uuid")
        oid.token.assert_called_once_with(grant_type="client_credentials")

    def test_adds_audience_mapper_when_absent(self, monkeypatch):
        admin = MagicMock()
        oid = self._wire(admin, monkeypatch, aud=["github-tool"], mappers=[])
        with patch("aiac.idp.service.configuration.keycloak.main.KeycloakOpenID", return_value=oid):
            _make_client(admin).get(f"/services/svc-uuid/discovery-token?realm={REALM}")
        admin.add_mapper_to_client.assert_called_once()

    def test_idempotent_when_mapper_present(self, monkeypatch):
        admin = MagicMock()
        oid = self._wire(
            admin,
            monkeypatch,
            aud=["github-tool"],
            mappers=[{"name": "aiac-discovery-audience"}],
        )
        with patch("aiac.idp.service.configuration.keycloak.main.KeycloakOpenID", return_value=oid):
            _make_client(admin).get(f"/services/svc-uuid/discovery-token?realm={REALM}")
        admin.add_mapper_to_client.assert_not_called()

    def test_does_not_regenerate_secret(self, monkeypatch):
        admin = MagicMock()
        oid = self._wire(admin, monkeypatch, aud=["github-tool"])
        with patch("aiac.idp.service.configuration.keycloak.main.KeycloakOpenID", return_value=oid):
            _make_client(admin).get(f"/services/svc-uuid/discovery-token?realm={REALM}")
        admin.generate_client_secrets.assert_not_called()

    def test_502_when_aud_missing_client_id(self, monkeypatch):
        admin = MagicMock()
        oid = self._wire(admin, monkeypatch, aud=["account"])
        with patch("aiac.idp.service.configuration.keycloak.main.KeycloakOpenID", return_value=oid):
            resp = _make_client(admin).get(f"/services/svc-uuid/discovery-token?realm={REALM}")
        assert resp.status_code == 502
        assert "does not contain" in resp.json()["error"]

    def test_502_when_no_secret(self, monkeypatch):
        admin = MagicMock()
        oid = self._wire(admin, monkeypatch, aud=["github-tool"], secret=None)
        admin.get_client_secrets.return_value = {}  # no secret available via the secrets endpoint
        with patch("aiac.idp.service.configuration.keycloak.main.KeycloakOpenID", return_value=oid):
            resp = _make_client(admin).get(f"/services/svc-uuid/discovery-token?realm={REALM}")
        assert resp.status_code == 502
        assert "no readable secret" in resp.json()["error"]

    def test_hard_iss_assertion_when_env_set(self, monkeypatch):
        admin = MagicMock()
        oid = self._wire(admin, monkeypatch, aud=["github-tool"], iss="http://kc-internal:8080/realms/rossoctl")
        monkeypatch.setenv("AIAC_KEYCLOAK_ISSUER", self.ISS)
        with patch("aiac.idp.service.configuration.keycloak.main.KeycloakOpenID", return_value=oid):
            resp = _make_client(admin).get(f"/services/svc-uuid/discovery-token?realm={REALM}")
        assert resp.status_code == 502
        assert "iss" in resp.json()["error"]

    def test_502_on_other_keycloak_error(self, monkeypatch):
        # A Keycloak 404 gives 404 (see TestKeycloakNotFoundProduces404); any other error is a 502.
        monkeypatch.setenv("KEYCLOAK_URL", "http://kc-internal:8080")
        admin = MagicMock()
        admin.get_client.side_effect = KeycloakError(error_message="backend failure", response_code=500)
        resp = _make_client(admin).get(f"/services/svc-uuid/discovery-token?realm={REALM}")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /services/{service_id}/type
# ---------------------------------------------------------------------------


class TestSetServiceType:
    def test_returns_200_with_updated_client(self):
        admin = MagicMock()
        admin.get_client.side_effect = [
            {"id": "svc-uuid", "clientId": "my-app", "attributes": {}},
            {"id": "svc-uuid", "clientId": "my-app", "attributes": {"client.type": "Agent"}},
        ]
        resp = _make_client(admin).post(f"/services/svc-uuid/type?realm={REALM}", json={"type": "Agent"})
        assert resp.status_code == 200
        assert resp.json()["attributes"] == {"client.type": "Agent"}

    def test_sets_client_type_attribute_via_update_client(self):
        admin = MagicMock()
        admin.get_client.return_value = {"id": "svc-uuid", "attributes": {"existing": "keep"}}
        _make_client(admin).post(f"/services/svc-uuid/type?realm={REALM}", json={"type": "Tool"})
        # existing attributes preserved; client.type merged in (not clobbered)
        admin.update_client.assert_called_once_with(
            "svc-uuid", {"attributes": {"existing": "keep", "client.type": "Tool"}}
        )

    def test_stores_capitalized_plain_string_value(self):
        admin = MagicMock()
        admin.get_client.return_value = {"id": "svc-uuid", "attributes": {}}
        _make_client(admin).post(f"/services/svc-uuid/type?realm={REALM}", json={"type": "Agent"})
        payload = admin.update_client.call_args[0][1]
        assert payload["attributes"]["client.type"] == "Agent"  # plain string, not a list

    def test_rejects_invalid_type_with_422(self):
        admin = MagicMock()
        resp = _make_client(admin).post(f"/services/svc-uuid/type?realm={REALM}", json={"type": "agent"})
        assert resp.status_code == 422

    def test_empty_type_clears_client_type_attribute(self):
        # The #176 client sends {"type": ""} as the CLEAR signal. Clearing drops the client.type
        # key (read-merge update_client) while preserving other attributes; returns 200.
        admin = MagicMock()
        admin.get_client.return_value = {"id": "svc-uuid", "attributes": {"existing": "keep", "client.type": "Agent"}}
        resp = _make_client(admin).post(f"/services/svc-uuid/type?realm={REALM}", json={"type": ""})
        assert resp.status_code == 200
        admin.update_client.assert_called_once_with("svc-uuid", {"attributes": {"existing": "keep"}})

    def test_empty_type_is_idempotent_when_already_clear(self):
        # Clearing an already-clear type (no client.type attribute) is not an error — the
        # read-merge simply writes back the unchanged attributes and returns success.
        admin = MagicMock()
        admin.get_client.return_value = {"id": "svc-uuid", "attributes": {"existing": "keep"}}
        resp = _make_client(admin).post(f"/services/svc-uuid/type?realm={REALM}", json={"type": ""})
        assert resp.status_code == 200
        admin.update_client.assert_called_once_with("svc-uuid", {"attributes": {"existing": "keep"}})

    def test_missing_body_returns_422(self):
        admin = MagicMock()
        resp = _make_client(admin).post(f"/services/svc-uuid/type?realm={REALM}")
        assert resp.status_code == 422

    def test_returns_502_on_keycloak_error(self):
        admin = MagicMock()
        admin.get_client.side_effect = KeycloakError(error_message="not found", response_code=404)
        resp = _make_client(admin).post(f"/services/svc-uuid/type?realm={REALM}", json={"type": "Agent"})
        assert resp.status_code == 502
        assert "error" in resp.json()

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /services/{service_id}/enabled (UC1 rollback disable / re-enable)
# ---------------------------------------------------------------------------


class TestSetServiceEnabled:
    def test_disable_calls_update_client_and_returns_200(self):
        admin = MagicMock()
        admin.get_client.return_value = {"id": "svc-uuid", "clientId": "my-app", "enabled": False}
        resp = _make_client(admin).post(f"/services/svc-uuid/enabled?realm={REALM}", json={"enabled": False})
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False
        admin.update_client.assert_called_once_with("svc-uuid", {"enabled": False})

    def test_enable_calls_update_client_with_true(self):
        admin = MagicMock()
        admin.get_client.return_value = {"id": "svc-uuid", "clientId": "my-app", "enabled": True}
        resp = _make_client(admin).post(f"/services/svc-uuid/enabled?realm={REALM}", json={"enabled": True})
        assert resp.status_code == 200
        admin.update_client.assert_called_once_with("svc-uuid", {"enabled": True})

    def test_disable_is_idempotent_when_already_disabled(self):
        # Disabling an already-disabled client is not an error — update_client is issued and a
        # success status returned.
        admin = MagicMock()
        admin.get_client.return_value = {"id": "svc-uuid", "clientId": "my-app", "enabled": False}
        resp = _make_client(admin).post(f"/services/svc-uuid/enabled?realm={REALM}", json={"enabled": False})
        assert resp.status_code == 200

    def test_missing_body_returns_422(self):
        admin = MagicMock()
        resp = _make_client(admin).post(f"/services/svc-uuid/enabled?realm={REALM}")
        assert resp.status_code == 422

    def test_returns_502_on_keycloak_error(self):
        admin = MagicMock()
        admin.update_client.side_effect = KeycloakError(error_message="boom", response_code=500)
        resp = _make_client(admin).post(f"/services/svc-uuid/enabled?realm={REALM}", json={"enabled": False})
        assert resp.status_code == 502
        assert "error" in resp.json()

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /scopes
# ---------------------------------------------------------------------------


class TestCreateScopeEndpoint:
    def test_returns_201_with_scope_json(self):
        admin = MagicMock()
        admin.create_client_scope.return_value = "new-scope-id"
        admin.get_client_scope.return_value = {
            "id": "new-scope-id",
            "name": "read:data",
            "description": "Read access",
        }
        resp = _make_client(admin).post(
            f"/scopes?realm={REALM}",
            json={"name": "read:data", "description": "Read access"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["id"] == "new-scope-id"
        assert body["name"] == "read:data"

    def test_creates_scope_with_openid_connect_protocol(self):
        admin = MagicMock()
        admin.create_client_scope.return_value = "sid"
        admin.get_client_scope.return_value = {"id": "sid", "name": "read"}
        _make_client(admin).post(f"/scopes?realm={REALM}", json={"name": "read", "description": "desc"})
        payload = admin.create_client_scope.call_args[0][0]
        assert payload["protocol"] == "openid-connect"
        assert payload["name"] == "read"
        assert payload["description"] == "desc"
        assert payload["attributes"] == {"aiac.managed": "true"}

    def test_returns_409_on_duplicate_name(self):
        admin = MagicMock()
        admin.create_client_scope.side_effect = KeycloakError(error_message="Conflict", response_code=409)
        resp = _make_client(admin).post(f"/scopes?realm={REALM}", json={"name": "dupe", "description": ""})
        assert resp.status_code == 409

    def test_returns_502_on_keycloak_error(self):
        admin = MagicMock()
        admin.create_client_scope.side_effect = KeycloakError(error_message="backend failure", response_code=500)
        resp = _make_client(admin).post(f"/scopes?realm={REALM}", json={"name": "read", "description": "desc"})
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_realm_override_uses_per_realm_admin(self):
        _cache.clear()
        app.dependency_overrides.clear()
        admin_mock = MagicMock()
        admin_mock.create_client_scope.return_value = "s1"
        admin_mock.get_client_scope.return_value = {"id": "s1", "name": "x"}
        env = {
            "KEYCLOAK_URL": "http://keycloak:8080/",
            "KEYCLOAK_ADMIN_REALM": "master",
            "KEYCLOAK_ADMIN_USERNAME": "admin",
            "KEYCLOAK_ADMIN_PASSWORD": "admin",
        }
        with (
            patch.dict(os.environ, env),
            patch("aiac.idp.service.configuration.keycloak.main.KeycloakAdmin", return_value=admin_mock),
        ):
            with TestClient(app) as client:
                resp = client.post("/scopes?realm=other", json={"name": "x", "description": ""})
        assert resp.status_code == 201

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /services/{service_id}/scopes/{scope_id}
# ---------------------------------------------------------------------------


class TestAssignScopeToService:
    def test_returns_201_on_success(self):
        admin = MagicMock()
        resp = _make_client(admin).post(f"/services/svc-uuid/scopes/scope-id?realm={REALM}")
        assert resp.status_code == 201
        admin.add_client_default_client_scope.assert_called_once_with("svc-uuid", "scope-id", {})

    def test_returns_409_when_already_assigned(self):
        admin = MagicMock()
        admin.add_client_default_client_scope.side_effect = KeycloakError(error_message="Conflict", response_code=409)
        resp = _make_client(admin).post(f"/services/svc-uuid/scopes/scope-id?realm={REALM}")
        assert resp.status_code == 409

    def test_returns_502_on_keycloak_error(self):
        admin = MagicMock()
        admin.add_client_default_client_scope.side_effect = KeycloakError(error_message="failure", response_code=500)
        resp = _make_client(admin).post(f"/services/svc-uuid/scopes/scope-id?realm={REALM}")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /services/{service_id}/subject-scope (D31: sub = username on every leg)
# ---------------------------------------------------------------------------

_SUBJECT_SCOPE_ID = "subj-id"

# The exact Keycloak representations the D31 contract fixes for the shared subject scope and its
# mapper. The scope carries NO aiac.managed marker (it is linked to many clients).
_SUBJECT_SCOPE_PAYLOAD = {
    "name": "aiac-username-sub",
    "description": "AIAC subject scope (D31): sets the token sub to the username",
    "protocol": "openid-connect",
    "attributes": {"include.in.token.scope": "false", "display.on.consent.screen": "false"},
}
_SUBJECT_MAPPER_PAYLOAD = {
    "name": "username-to-sub",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-property-mapper",
    "config": {
        "user.attribute": "username",
        "claim.name": "sub",
        "jsonType.label": "String",
        "access.token.claim": "true",
        "id.token.claim": "true",
        "userinfo.token.claim": "true",
        "introspection.token.claim": "true",
    },
}

# The correct mapper as Keycloak returns it: the representation plus its id.
_SUBJECT_MAPPER_EXISTING = {**_SUBJECT_MAPPER_PAYLOAD, "id": "m1"}

# Admin calls whose first argument is a Keycloak client id (the link side of the endpoint).
_CLIENT_SCOPED_CALLS = {
    "get_client_optional_client_scopes",
    "delete_client_optional_client_scope",
    "add_client_default_client_scope",
    "add_client_optional_client_scope",
    "delete_client_default_client_scope",
    "get_client_default_client_scopes",
    "update_client",
}


class _FakeSubjectScopeAdmin:
    """A small stateful stand-in for the Keycloak admin API, so a test can call the endpoint more
    than once and assert the converged state. It models the Keycloak behaviours the endpoint
    relies on: a duplicate scope or mapper name is a 409, a client-scope link is skipped
    with no error when the scope is already linked to that client as default OR optional, and a
    mapper update (PUT) of an unknown mapper id is a 404 and replaces the type and the full config.
    Each mapper write is recorded in ``mapper_writes``."""

    def __init__(self):
        self.scopes: dict[str, dict] = {}
        self.mappers: dict[str, list[dict]] = {}
        self.default_links: dict[str, list[str]] = {}
        self.optional_links: dict[str, list[str]] = {}
        self.mapper_writes: list[str] = []
        self._next_mapper = 0

    def get_client_scopes(self):
        return [dict(s) for s in self.scopes.values()]

    def create_client_scope(self, payload):
        if any(s["name"] == payload["name"] for s in self.scopes.values()):
            raise KeycloakError(error_message="Conflict", response_code=409)
        scope_id = f"scope-{len(self.scopes) + 1}"
        self.scopes[scope_id] = {**json.loads(json.dumps(payload)), "id": scope_id}
        self.mappers[scope_id] = []
        return scope_id

    def get_client_scope(self, scope_id):
        return {**self.scopes[scope_id], "protocolMappers": list(self.mappers[scope_id])}

    def get_mappers_from_client_scope(self, scope_id):
        return list(self.mappers[scope_id])

    def add_mapper_to_client_scope(self, scope_id, payload):
        if any(m["name"] == payload["name"] for m in self.mappers[scope_id]):
            raise KeycloakError(error_message="Conflict", response_code=409)
        self.mapper_writes.append("add")
        self._next_mapper += 1
        self.mappers[scope_id].append({**json.loads(json.dumps(payload)), "id": f"mapper-{self._next_mapper}"})

    def _mapper(self, scope_id, mapper_id):
        mapper = next((m for m in self.mappers[scope_id] if m["id"] == mapper_id), None)
        if mapper is None:
            raise KeycloakError(error_message="Model not found", response_code=404)
        return mapper

    def update_mapper_in_client_scope(self, scope_id, mapper_id, payload):
        mapper = self._mapper(scope_id, mapper_id)
        if payload.get("id") != mapper_id:  # Keycloak 26.0 reads the mapper id from the payload
            raise KeycloakError(error_message="mapping with id None does not exist", response_code=500)
        self.mapper_writes.append("update")
        mapper["protocolMapper"] = payload["protocolMapper"]
        mapper["config"] = dict(payload["config"])  # Keycloak replaces the full config map

    def delete_mapper_from_client_scope(self, scope_id, mapper_id):
        self.mappers[scope_id].remove(self._mapper(scope_id, mapper_id))
        self.mapper_writes.append("delete")

    def get_client_optional_client_scopes(self, client_id):
        return [self.scopes[sid] for sid in self.optional_links.get(client_id, [])]

    def delete_client_optional_client_scope(self, client_id, scope_id):
        self.optional_links[client_id].remove(scope_id)

    def add_client_default_client_scope(self, client_id, scope_id, payload):
        linked = self.default_links.get(client_id, []) + self.optional_links.get(client_id, [])
        if scope_id not in linked:  # Keycloak skips an existing link with no error
            self.default_links.setdefault(client_id, []).append(scope_id)


class TestLinkSubjectScope:
    _URL = f"/services/svc-uuid/subject-scope?realm={REALM}"

    def _wire(self, admin, *, existing=None, mappers=(), optional=()):
        # Realm scopes: a built-in plus (optionally) an existing subject scope.
        realm_scopes = [{"id": "sc-profile", "name": "profile"}]
        if existing is not None:
            realm_scopes.append(existing)
        admin.get_client_scopes.return_value = realm_scopes
        admin.create_client_scope.return_value = _SUBJECT_SCOPE_ID
        admin.get_client_scope.return_value = {**_SUBJECT_SCOPE_PAYLOAD, "id": _SUBJECT_SCOPE_ID}
        admin.get_mappers_from_client_scope.return_value = list(mappers)
        admin.get_client_optional_client_scopes.return_value = list(optional)

    @staticmethod
    def _existing(attributes=None):
        attrs = attributes if attributes is not None else dict(_SUBJECT_SCOPE_PAYLOAD["attributes"])
        return {**_SUBJECT_SCOPE_PAYLOAD, "id": _SUBJECT_SCOPE_ID, "attributes": attrs}

    def test_absent_scope_is_created_without_marker(self):
        # The scope is created with its own, narrow payload — never through POST /scopes, which
        # always stamps aiac.managed (a marked subject scope would become an own scope of each linked service).
        admin = MagicMock()
        self._wire(admin)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        admin.create_client_scope.assert_called_once()
        payload = admin.create_client_scope.call_args[0][0]
        assert payload["name"] == "aiac-username-sub"
        assert payload["protocol"] == "openid-connect"
        assert payload["attributes"]["include.in.token.scope"] == "false"
        assert "aiac.managed" not in payload["attributes"]
        assert payload == _SUBJECT_SCOPE_PAYLOAD

    def test_create_does_not_use_skip_exists(self):
        # python-keycloak 7.x fails on the missing Location header when skip_exists=True gets a 409,
        # so the endpoint handles the 409 itself.
        admin = MagicMock()
        self._wire(admin)
        _make_client(admin).post(self._URL)
        assert "skip_exists" not in admin.create_client_scope.call_args.kwargs

    def test_adds_username_to_sub_mapper_with_exact_config(self):
        admin = MagicMock()
        self._wire(admin)
        _make_client(admin).post(self._URL)
        admin.get_mappers_from_client_scope.assert_called_once_with(_SUBJECT_SCOPE_ID)
        admin.add_mapper_to_client_scope.assert_called_once_with(_SUBJECT_SCOPE_ID, _SUBJECT_MAPPER_PAYLOAD)

    def test_existing_scope_with_mapper_is_noop(self):
        # Idempotent: the scope and its mapper exist, so nothing is created or added again.
        admin = MagicMock()
        self._wire(admin, existing=self._existing(), mappers=[_SUBJECT_MAPPER_EXISTING])
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        admin.create_client_scope.assert_not_called()
        admin.add_mapper_to_client_scope.assert_not_called()
        admin.update_mapper_in_client_scope.assert_not_called()
        admin.delete_mapper_from_client_scope.assert_not_called()

    def test_existing_scope_without_mapper_gets_the_mapper(self):
        # Self-healing: someone deleted the mapper, so the next onboarding adds it again.
        admin = MagicMock()
        self._wire(admin, existing=self._existing(), mappers=[{"id": "m9", "name": "other-mapper"}])
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        admin.create_client_scope.assert_not_called()
        admin.add_mapper_to_client_scope.assert_called_once_with(_SUBJECT_SCOPE_ID, _SUBJECT_MAPPER_PAYLOAD)

    def test_existing_scope_without_attributes_is_accepted(self):
        # An unmarked scope with no attributes map at all is not an invariant breach.
        admin = MagicMock()
        existing = {"id": _SUBJECT_SCOPE_ID, "name": "aiac-username-sub"}
        self._wire(admin, existing=existing, mappers=[_SUBJECT_MAPPER_EXISTING])
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        admin.add_client_default_client_scope.assert_called_once_with("svc-uuid", _SUBJECT_SCOPE_ID, {})

    def test_creating_it_twice_is_a_noop(self):
        # Against a stateful fake: two calls converge to exactly one scope, one mapper and one
        # default link on the service's client.
        admin = _FakeSubjectScopeAdmin()
        client = _make_client(admin)
        first = client.post(self._URL)
        second = client.post(self._URL)
        assert first.status_code == second.status_code == 200
        assert first.json() == second.json()
        assert [s["name"] for s in admin.scopes.values()] == ["aiac-username-sub"]
        (scope_id,) = admin.scopes
        assert [m["name"] for m in admin.mappers[scope_id]] == ["username-to-sub"]
        assert admin.default_links == {"svc-uuid": [scope_id]}
        assert "aiac.managed" not in admin.scopes[scope_id]["attributes"]

    def test_second_service_reuses_the_shared_scope(self):
        # Every managed client links the SAME scope: a second service gets a link, not a new scope.
        admin = _FakeSubjectScopeAdmin()
        client = _make_client(admin)
        assert client.post(self._URL).status_code == 200
        assert client.post(f"/services/svc-b/subject-scope?realm={REALM}").status_code == 200
        (scope_id,) = admin.scopes
        assert len(admin.mappers[scope_id]) == 1
        assert admin.default_links == {"svc-uuid": [scope_id], "svc-b": [scope_id]}

    def test_links_as_client_default_scope_only(self):
        # The link is a default scope of THIS client: never a realm default, never an optional
        # scope, and no call touches any other client (rossoctl included).
        admin = MagicMock()
        self._wire(admin)
        _make_client(admin).post(self._URL)
        admin.add_client_default_client_scope.assert_called_once_with("svc-uuid", _SUBJECT_SCOPE_ID, {})
        admin.add_default_default_client_scope.assert_not_called()
        admin.add_default_optional_client_scope.assert_not_called()
        admin.add_client_optional_client_scope.assert_not_called()
        admin.update_client.assert_not_called()
        client_ids = {c.args[0] for c in admin.mock_calls if c[0] in _CLIENT_SCOPED_CALLS}
        assert client_ids == {"svc-uuid"}

    def test_not_optional_link_is_not_deleted(self):
        admin = MagicMock()
        self._wire(admin, optional=[{"id": "sc-other", "name": "offline_access"}])
        _make_client(admin).post(self._URL)
        admin.get_client_optional_client_scopes.assert_called_once_with("svc-uuid")
        admin.delete_client_optional_client_scope.assert_not_called()

    def test_optional_link_is_moved_to_default(self):
        # Keycloak skips a default link of a scope that is already linked as optional, and an
        # optional scope's mapper runs only when the token request names it — so the endpoint
        # removes the optional link FIRST, then adds the default link.
        admin = MagicMock()
        self._wire(
            admin,
            existing=self._existing(),
            mappers=[_SUBJECT_MAPPER_EXISTING],
            optional=[{"id": _SUBJECT_SCOPE_ID, "name": "aiac-username-sub"}],
        )
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        admin.delete_client_optional_client_scope.assert_called_once_with("svc-uuid", _SUBJECT_SCOPE_ID)
        admin.add_client_default_client_scope.assert_called_once_with("svc-uuid", _SUBJECT_SCOPE_ID, {})
        names = [c[0] for c in admin.mock_calls]
        assert names.index("delete_client_optional_client_scope") < names.index("add_client_default_client_scope")

    def test_optional_link_ends_as_default_against_fake(self):
        # With the Keycloak skip modeled, a scope that starts as an optional link ends as a default
        # link (and no longer optional) — an optional link would silently leave sub = user ID.
        admin = _FakeSubjectScopeAdmin()
        scope_id = admin.create_client_scope(_SUBJECT_SCOPE_PAYLOAD)
        admin.optional_links["svc-uuid"] = [scope_id]
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        assert admin.default_links == {"svc-uuid": [scope_id]}
        assert admin.optional_links == {"svc-uuid": []}

    def test_concurrent_create_409_finds_the_scope_by_name(self):
        # Different services onboard concurrently: another onboarding created the scope between
        # the read and the create. The 409 is success; the next read finds the scope by name.
        admin = MagicMock()
        self._wire(admin)
        admin.get_client_scopes.side_effect = [
            [{"id": "sc-profile", "name": "profile"}],
            [{"id": "sc-profile", "name": "profile"}, self._existing()],
        ]
        admin.create_client_scope.side_effect = KeycloakError(error_message="Conflict", response_code=409)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        assert admin.get_client_scopes.call_count == 2
        admin.add_client_default_client_scope.assert_called_once_with("svc-uuid", _SUBJECT_SCOPE_ID, {})

    def test_concurrent_create_409_with_marked_scope_returns_409(self):
        # The re-read after a 409 still applies the marker check.
        admin = MagicMock()
        self._wire(admin)
        admin.get_client_scopes.side_effect = [[], [self._existing({"aiac.managed": "true"})]]
        admin.create_client_scope.side_effect = KeycloakError(error_message="Conflict", response_code=409)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 409
        admin.add_client_default_client_scope.assert_not_called()

    def test_concurrent_mapper_add_409_is_success(self):
        admin = MagicMock()
        self._wire(admin, existing=self._existing())
        admin.add_mapper_to_client_scope.side_effect = KeycloakError(error_message="Conflict", response_code=409)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        admin.add_client_default_client_scope.assert_called_once_with("svc-uuid", _SUBJECT_SCOPE_ID, {})

    def test_marked_existing_scope_returns_409_and_does_not_link(self):
        # A marked subject scope would become an own scope of every linked service (D31) — an
        # invariant breach, surfaced as 409.
        admin = MagicMock()
        self._wire(admin, existing=self._existing({"aiac.managed": "true"}))
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 409
        error = resp.json()["error"]
        assert "aiac-username-sub" in error
        assert "D31" in error
        assert "aiac.managed" in error
        admin.add_mapper_to_client_scope.assert_not_called()
        admin.delete_client_optional_client_scope.assert_not_called()
        admin.add_client_default_client_scope.assert_not_called()

    def test_returns_200_with_scope_json(self):
        admin = MagicMock()
        self._wire(admin)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        assert resp.json() == {**_SUBJECT_SCOPE_PAYLOAD, "id": _SUBJECT_SCOPE_ID}
        admin.get_client_scope.assert_called_once_with(_SUBJECT_SCOPE_ID)

    def test_returns_502_on_keycloak_error(self):
        admin = MagicMock()
        self._wire(admin)
        admin.get_client_scopes.side_effect = KeycloakError(error_message="backend failure", response_code=500)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_create_error_other_than_409_returns_502(self):
        admin = MagicMock()
        self._wire(admin)
        admin.create_client_scope.side_effect = KeycloakError(error_message="backend failure", response_code=500)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 502
        admin.add_client_default_client_scope.assert_not_called()

    def test_mapper_error_other_than_409_returns_502(self):
        admin = MagicMock()
        self._wire(admin, existing=self._existing())
        admin.add_mapper_to_client_scope.side_effect = KeycloakError(error_message="backend failure", response_code=500)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 502
        admin.add_client_default_client_scope.assert_not_called()

    def test_link_error_returns_502(self):
        admin = MagicMock()
        self._wire(admin)
        admin.add_client_default_client_scope.side_effect = KeycloakError(error_message="not found", response_code=404)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 502
        assert "error" in resp.json()

    # -- convergence of an existing username-to-sub mapper (D31) --------------------------------

    @staticmethod
    def _seeded_fake(protocol_mapper="oidc-usermodel-property-mapper", **config_changes):
        # A fake realm whose subject scope already has a mapper named username-to-sub with the
        # given type and the expected config changed by ``config_changes``.
        admin = _FakeSubjectScopeAdmin()
        scope_id = admin.create_client_scope(_SUBJECT_SCOPE_PAYLOAD)
        config = {**_SUBJECT_MAPPER_PAYLOAD["config"], **config_changes}
        admin.mappers[scope_id].append(
            {**_SUBJECT_MAPPER_PAYLOAD, "id": "m-old", "protocolMapper": protocol_mapper, "config": config}
        )
        return admin, scope_id

    def test_wrong_claim_name_is_updated_to_exact_config(self):
        # A mapper named username-to-sub that writes preferred_username leaves sub = user ID.
        admin, scope_id = self._seeded_fake(**{"claim.name": "preferred_username"})
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        assert admin.mapper_writes == ["update"]
        (mapper,) = admin.mappers[scope_id]
        assert mapper["id"] == "m-old"  # updated in place, not added again
        assert mapper["protocolMapper"] == "oidc-usermodel-property-mapper"
        assert mapper["config"] == _SUBJECT_MAPPER_PAYLOAD["config"]

    def test_update_payload_is_the_representation_with_the_mapper_id(self):
        admin = MagicMock()
        wrong = {**_SUBJECT_MAPPER_EXISTING, "config": {**_SUBJECT_MAPPER_PAYLOAD["config"], "claim.name": "x"}}
        self._wire(admin, existing=self._existing(), mappers=[wrong])
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        admin.update_mapper_in_client_scope.assert_called_once_with(
            _SUBJECT_SCOPE_ID, "m1", {**_SUBJECT_MAPPER_PAYLOAD, "id": "m1"}
        )
        admin.add_mapper_to_client_scope.assert_not_called()
        admin.delete_mapper_from_client_scope.assert_not_called()

    def test_wrong_token_claim_flag_is_updated(self):
        # access.token.claim=false: the access token (the one AuthBridge reads) keeps sub = user ID.
        admin, scope_id = self._seeded_fake(**{"access.token.claim": "false"})
        assert _make_client(admin).post(self._URL).status_code == 200
        assert admin.mapper_writes == ["update"]
        assert admin.mappers[scope_id][0]["config"] == _SUBJECT_MAPPER_PAYLOAD["config"]

    def test_missing_config_key_is_updated(self):
        admin, scope_id = self._seeded_fake()
        del admin.mappers[scope_id][0]["config"]["introspection.token.claim"]
        assert _make_client(admin).post(self._URL).status_code == 200
        assert admin.mapper_writes == ["update"]
        assert admin.mappers[scope_id][0]["config"] == _SUBJECT_MAPPER_PAYLOAD["config"]

    def test_extra_keycloak_config_keys_only_is_noop(self):
        # Keycloak can add keys of its own (e.g. lightweight.claim): only OUR keys are compared.
        admin, scope_id = self._seeded_fake(**{"lightweight.claim": "false"})
        assert _make_client(admin).post(self._URL).status_code == 200
        assert admin.mapper_writes == []
        assert admin.mappers[scope_id][0]["config"]["lightweight.claim"] == "false"

    def test_wrong_type_is_deleted_and_added_again(self):
        # A different mapper type is not changed in place: delete the old mapper, add the right one.
        admin, scope_id = self._seeded_fake(protocol_mapper="oidc-hardcoded-claim-mapper")
        assert _make_client(admin).post(self._URL).status_code == 200
        assert admin.mapper_writes == ["delete", "add"]
        (mapper,) = admin.mappers[scope_id]
        assert mapper["id"] != "m-old"
        assert {k: v for k, v in mapper.items() if k != "id"} == _SUBJECT_MAPPER_PAYLOAD

    def test_wrong_type_concurrent_delete_404_and_add_409_are_success(self):
        # A concurrent onboarding fixed the type first: our delete gets 404 and our add gets 409.
        admin = MagicMock()
        wrong = {**_SUBJECT_MAPPER_EXISTING, "protocolMapper": "oidc-hardcoded-claim-mapper"}
        self._wire(admin, existing=self._existing(), mappers=[wrong])
        admin.delete_mapper_from_client_scope.side_effect = KeycloakError(error_message="Not found", response_code=404)
        admin.add_mapper_to_client_scope.side_effect = KeycloakError(error_message="Conflict", response_code=409)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 200
        admin.delete_mapper_from_client_scope.assert_called_once_with(_SUBJECT_SCOPE_ID, "m1")
        admin.add_mapper_to_client_scope.assert_called_once_with(_SUBJECT_SCOPE_ID, _SUBJECT_MAPPER_PAYLOAD)
        admin.update_mapper_in_client_scope.assert_not_called()

    def test_wrong_type_delete_error_returns_502(self):
        admin = MagicMock()
        wrong = {**_SUBJECT_MAPPER_EXISTING, "protocolMapper": "oidc-hardcoded-claim-mapper"}
        self._wire(admin, existing=self._existing(), mappers=[wrong])
        admin.delete_mapper_from_client_scope.side_effect = KeycloakError(error_message="boom", response_code=500)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 502
        admin.add_mapper_to_client_scope.assert_not_called()
        admin.add_client_default_client_scope.assert_not_called()

    def test_converged_mapper_second_call_makes_no_write(self):
        admin, scope_id = self._seeded_fake(**{"claim.name": "preferred_username"})
        client = _make_client(admin)
        assert client.post(self._URL).status_code == 200
        writes_after_first = list(admin.mapper_writes)
        assert client.post(self._URL).status_code == 200
        assert admin.mapper_writes == writes_after_first == ["update"]

    def test_fresh_realm_second_call_makes_no_mapper_write(self):
        admin = _FakeSubjectScopeAdmin()
        client = _make_client(admin)
        assert client.post(self._URL).status_code == 200
        assert client.post(self._URL).status_code == 200
        assert admin.mapper_writes == ["add"]

    def test_update_error_returns_502(self):
        admin = MagicMock()
        wrong = {**_SUBJECT_MAPPER_EXISTING, "config": {**_SUBJECT_MAPPER_PAYLOAD["config"], "claim.name": "x"}}
        self._wire(admin, existing=self._existing(), mappers=[wrong])
        admin.update_mapper_in_client_scope.side_effect = KeycloakError(error_message="boom", response_code=500)
        resp = _make_client(admin).post(self._URL)
        assert resp.status_code == 502
        assert "error" in resp.json()
        admin.add_client_default_client_scope.assert_not_called()

    def test_other_sub_mapper_is_left_alone(self):
        # Another mapper (a different name) that also writes sub is not AIAC's: it is not changed,
        # not deleted, and it does not fail the onboarding.
        admin, scope_id = self._seeded_fake()
        other = {
            "id": "m-other",
            "name": "operator-sub",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "config": {"claim.name": "sub", "claim.value": "x", "access.token.claim": "true"},
        }
        admin.mappers[scope_id].append(json.loads(json.dumps(other)))
        assert _make_client(admin).post(self._URL).status_code == 200
        assert admin.mapper_writes == []
        assert admin.mappers[scope_id][1] == other

    def test_missing_realm_returns_422(self):
        app.dependency_overrides.clear()
        resp = TestClient(app).post("/services/svc-uuid/subject-scope")
        assert resp.status_code == 422

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /roles
# ---------------------------------------------------------------------------


class TestCreateRoleEndpoint:
    def test_returns_201_with_role_json(self):
        admin = MagicMock()
        admin.create_realm_role.return_value = "new-role-id"
        admin.get_realm_role.return_value = {
            "id": "new-role-id",
            "name": "reader",
            "description": "Read-only",
        }
        resp = _make_client(admin).post(
            f"/roles?realm={REALM}",
            json={"name": "reader", "description": "Read-only"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["id"] == "new-role-id"
        assert body["name"] == "reader"

    def test_creates_role_with_correct_payload(self):
        admin = MagicMock()
        admin.create_realm_role.return_value = "rid"
        admin.get_realm_role.return_value = {"id": "rid", "name": "reader"}
        _make_client(admin).post(f"/roles?realm={REALM}", json={"name": "reader", "description": "desc"})
        payload = admin.create_realm_role.call_args[0][0]
        assert payload == {
            "name": "reader",
            "description": "desc",
            "attributes": {"aiac.managed": ["true"]},
        }

    def test_returns_409_on_duplicate_name(self):
        admin = MagicMock()
        admin.create_realm_role.side_effect = KeycloakError(error_message="Conflict", response_code=409)
        resp = _make_client(admin).post(f"/roles?realm={REALM}", json={"name": "dupe", "description": ""})
        assert resp.status_code == 409

    def test_returns_502_on_keycloak_error(self):
        admin = MagicMock()
        admin.create_realm_role.side_effect = KeycloakError(error_message="backend failure", response_code=500)
        resp = _make_client(admin).post(f"/roles?realm={REALM}", json={"name": "reader", "description": "desc"})
        assert resp.status_code == 502
        assert "error" in resp.json()

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# POST /services/{service_id}/roles/{role_id}
# ---------------------------------------------------------------------------


class TestAssignRoleToService:
    def test_returns_201_on_success(self):
        admin = MagicMock()
        admin.get_client_service_account_user.return_value = {"id": "sa-user-id"}
        admin.get_realm_role_by_id.return_value = {"id": "role-id", "name": "src-helper"}
        resp = _make_client(admin).post(f"/services/svc-uuid/roles/role-id?realm={REALM}")
        assert resp.status_code == 201
        admin.get_client_service_account_user.assert_called_once_with("svc-uuid")
        admin.get_realm_role_by_id.assert_called_once_with("role-id")
        admin.assign_realm_roles.assert_called_once_with("sa-user-id", [{"id": "role-id", "name": "src-helper"}])

    def test_returns_409_when_already_assigned(self):
        admin = MagicMock()
        admin.get_client_service_account_user.return_value = {"id": "sa-user-id"}
        admin.assign_realm_roles.side_effect = KeycloakError(error_message="Conflict", response_code=409)
        resp = _make_client(admin).post(f"/services/svc-uuid/roles/role-id?realm={REALM}")
        assert resp.status_code == 409

    def test_returns_502_on_keycloak_error(self):
        admin = MagicMock()
        admin.get_client_service_account_user.return_value = {"id": "sa-user-id"}
        admin.assign_realm_roles.side_effect = KeycloakError(error_message="failure", response_code=500)
        resp = _make_client(admin).post(f"/services/svc-uuid/roles/role-id?realm={REALM}")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# DELETE /services/{service_id}/roles/{role_id} (unmap-then-delete, UC1 rollback)
# ---------------------------------------------------------------------------


class TestDeleteRoleFromService:
    def _wire(self, admin):
        admin.get_client_service_account_user.return_value = {"id": "sa-user-id"}
        admin.get_realm_role_by_id.return_value = {"id": "role-id", "name": "src-helper"}
        # Solely-owned: after the unmap, no other subject holds the role, so the shared-object
        # guard (#178) proceeds to delete — the behavior this test asserts.
        admin.get_realm_role_members.return_value = []

    def test_unmaps_role_from_service_account_then_deletes_realm_role(self):
        # Unmap-then-delete order: the role mapping is removed from the service account FIRST,
        # then the realm role is deleted (a still-mapped role cannot be deleted cleanly).
        from unittest.mock import call

        admin = MagicMock()
        self._wire(admin)
        resp = _make_client(admin).delete(f"/services/svc-uuid/roles/role-id?realm={REALM}")
        assert resp.status_code == 200
        # Unmap first, then the shared-object membership re-check (#178), then the delete since
        # no other subject holds the role.
        admin.assert_has_calls(
            [
                call.delete_realm_roles_of_user("sa-user-id", [{"id": "role-id", "name": "src-helper"}]),
                call.get_realm_role_members("src-helper"),
                call.delete_realm_role("src-helper"),
            ]
        )

    def test_shared_role_still_referenced_is_not_deleted(self):
        # Shared-object safety (#178): after unmapping the role from THIS service account, the
        # realm role is still held by ANOTHER subject (another agent's service account). The
        # shared role must be left intact — only the unmap happened, delete is NOT issued.
        admin = MagicMock()
        admin.get_client_service_account_user.return_value = {"id": "sa-user-id"}
        admin.get_realm_role_by_id.return_value = {"id": "role-id", "name": "shared-helper"}
        admin.get_realm_role_members.return_value = [
            {"id": "other-sa", "username": "service-account-other-agent"},
        ]
        resp = _make_client(admin).delete(f"/services/svc-uuid/roles/role-id?realm={REALM}")
        assert resp.status_code == 200
        admin.delete_realm_roles_of_user.assert_called_once_with(
            "sa-user-id", [{"id": "role-id", "name": "shared-helper"}]
        )
        admin.delete_realm_role.assert_not_called()

    def test_returns_502_on_keycloak_error(self):
        admin = MagicMock()
        admin.get_client_service_account_user.side_effect = KeycloakError(error_message="boom", response_code=500)
        resp = _make_client(admin).delete(f"/services/svc-uuid/roles/role-id?realm={REALM}")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_already_gone_role_404_is_idempotent_success(self):
        # Idempotent teardown: on a UC1 rollback retry the realm role is already gone, so
        # get_realm_role_by_id raises KeycloakGetError(404). This must be treated as success
        # (200), not 502 — otherwise the rollback aborts before the disable.
        admin = MagicMock()
        admin.get_client_service_account_user.return_value = {"id": "sa-user-id"}
        admin.get_realm_role_by_id.side_effect = KeycloakError(error_message="Could not find role", response_code=404)
        resp = _make_client(admin).delete(f"/services/svc-uuid/roles/role-id?realm={REALM}")
        assert resp.status_code == 200

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# DELETE /services/{service_id}/scopes/{scope_id} (unmap-then-delete, UC1 rollback)
# ---------------------------------------------------------------------------


class TestDeleteScopeFromService:
    def test_unmaps_scope_from_client_then_deletes_client_scope(self):
        # Unmap-then-delete order: the scope is removed from the client's default scopes FIRST,
        # then the client scope itself is deleted.
        from unittest.mock import call

        admin = MagicMock()
        # Solely-owned: after the unmap, no client exposes the scope, so the shared-object guard
        # (#178) proceeds to delete — the behavior this test asserts.
        admin.get_clients.return_value = []
        resp = _make_client(admin).delete(f"/services/svc-uuid/scopes/scope-id?realm={REALM}")
        assert resp.status_code == 200
        # Unmap first, then the shared-object owner rescan (#178, via get_clients), then the
        # delete since no other client exposes the scope.
        admin.assert_has_calls(
            [
                call.delete_client_default_client_scope("svc-uuid", "scope-id"),
                call.get_clients(),
                call.delete_client_scope("scope-id"),
            ]
        )

    def test_shared_scope_still_referenced_is_not_deleted(self):
        # Shared-object safety (#178): after unmapping the scope from THIS client, another client
        # still exposes it as a default scope. The shared client scope must be left intact —
        # only the unmap happened, delete is NOT issued.
        admin = MagicMock()
        admin.get_clients.return_value = [{"id": "other-svc"}]
        admin.get_client_default_client_scopes.return_value = [{"id": "scope-id", "name": "shared"}]
        resp = _make_client(admin).delete(f"/services/svc-uuid/scopes/scope-id?realm={REALM}")
        assert resp.status_code == 200
        admin.delete_client_default_client_scope.assert_called_once_with("svc-uuid", "scope-id")
        admin.delete_client_scope.assert_not_called()

    def test_returns_502_on_keycloak_error(self):
        admin = MagicMock()
        admin.delete_client_default_client_scope.side_effect = KeycloakError(error_message="boom", response_code=500)
        resp = _make_client(admin).delete(f"/services/svc-uuid/scopes/scope-id?realm={REALM}")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_already_gone_scope_404_is_idempotent_success(self):
        # Idempotent teardown: on a UC1 rollback retry the client scope (or its mapping) is
        # already gone, so the delete raises KeycloakDeleteError(404). This must be treated as
        # success (200), not 502 — otherwise the rollback aborts before the disable.
        admin = MagicMock()
        admin.delete_client_default_client_scope.side_effect = KeycloakError(
            error_message="Could not find client scope", response_code=404
        )
        resp = _make_client(admin).delete(f"/services/svc-uuid/scopes/scope-id?realm={REALM}")
        assert resp.status_code == 200

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /subjects?role_id= (filtered variant, 2.14)
# ---------------------------------------------------------------------------


class TestGetSubjectsByRole:
    def test_returns_enriched_subjects_for_role(self):
        admin = MagicMock()
        admin.get_realm_role_by_id.return_value = {"id": "rid", "name": "viewer"}
        admin.get_realm_role_members.return_value = [
            {"id": "u1", "username": "alice"},
            {"id": "u2", "username": "bob"},
        ]
        admin.get_all_roles_of_user.side_effect = [
            {"realmMappings": [{"id": "rid", "name": "viewer"}], "clientMappings": {}},
            {"realmMappings": [{"id": "rid", "name": "viewer"}], "clientMappings": {}},
        ]
        resp = _make_client(admin).get(f"/subjects?realm={REALM}&role_id=rid")
        assert resp.status_code == 200
        assert len(resp.json()) == 2
        admin.get_realm_role_by_id.assert_called_once_with("rid")
        admin.get_realm_role_members.assert_called_once_with("viewer")
        assert admin.get_all_roles_of_user.call_count == 2

    def test_returns_empty_list_when_no_members(self):
        admin = MagicMock()
        admin.get_realm_role_by_id.return_value = {"id": "rid", "name": "viewer"}
        admin.get_realm_role_members.return_value = []
        resp = _make_client(admin).get(f"/subjects?realm={REALM}&role_id=rid")
        assert resp.status_code == 200
        assert resp.json() == []
        admin.get_all_roles_of_user.assert_not_called()

    def test_returns_502_on_keycloak_error_in_get_role(self):
        admin = MagicMock()
        admin.get_realm_role_by_id.side_effect = KeycloakError(error_message="not found", response_code=404)
        resp = _make_client(admin).get(f"/subjects?realm={REALM}&role_id=rid")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_returns_502_on_keycloak_error_in_get_members(self):
        admin = MagicMock()
        admin.get_realm_role_by_id.return_value = {"id": "rid", "name": "viewer"}
        admin.get_realm_role_members.side_effect = KeycloakError(error_message="error", response_code=500)
        resp = _make_client(admin).get(f"/subjects?realm={REALM}&role_id=rid")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_returns_502_on_keycloak_error_during_enrichment(self):
        admin = MagicMock()
        admin.get_realm_role_by_id.return_value = {"id": "rid", "name": "viewer"}
        admin.get_realm_role_members.return_value = [{"id": "u1", "username": "alice"}]
        admin.get_all_roles_of_user.side_effect = KeycloakError(error_message="error", response_code=500)
        resp = _make_client(admin).get(f"/subjects?realm={REALM}&role_id=rid")
        assert resp.status_code == 502
        assert "error" in resp.json()

    def test_enrichment_shape_includes_realm_mappings(self):
        admin = MagicMock()
        admin.get_realm_role_by_id.return_value = {"id": "rid", "name": "viewer"}
        admin.get_realm_role_members.return_value = [{"id": "u1", "username": "alice"}]
        admin.get_all_roles_of_user.return_value = {
            "realmMappings": [{"id": "rid", "name": "viewer"}],
            "clientMappings": {"account": {"mappings": []}},
        }
        resp = _make_client(admin).get(f"/subjects?realm={REALM}&role_id=rid")
        assert resp.status_code == 200
        body = resp.json()
        assert "realmMappings" in body[0]
        assert body[0]["realmMappings"] == [{"id": "rid", "name": "viewer"}]

    def test_actor_ids_align_with_subjects_by_role(self):
        # SPM/APM alignment (1.12 / 2.14): the member usernames GET /subjects?role_id= returns
        # for a user (realm) role are exactly the Role.actorIds GET /roles populates for that
        # kind=User role — both resolve via admin.get_realm_role_members.
        admin = MagicMock()
        admin.get_realm_role_by_id.return_value = {"id": "rid", "name": "invoicing"}
        members = [{"id": "u1", "username": "alice"}, {"id": "u2", "username": "bob"}]
        admin.get_realm_role_members.return_value = members
        admin.get_all_roles_of_user.return_value = {"realmMappings": [], "clientMappings": {}}
        admin.get_realm_roles.return_value = [
            {"id": "rid", "name": "invoicing", "attributes": {"aiac.managed": ["true"]}},
        ]
        client = _make_client(admin)

        subjects = client.get(f"/subjects?realm={REALM}&role_id=rid").json()
        roles = client.get(f"/roles?realm={REALM}").json()

        subject_usernames = [s["username"] for s in subjects]
        actor_ids = roles[0]["actorIds"]
        assert subject_usernames == actor_ids == ["alice", "bob"]

    def test_missing_realm_returns_422(self):
        app.dependency_overrides.clear()
        resp = TestClient(app).get("/subjects?role_id=rid")
        assert resp.status_code == 422

    def test_unfiltered_still_works(self):
        admin = MagicMock()
        admin.get_users.return_value = [{"id": "u1", "username": "alice"}]
        resp = _make_client(admin).get(f"/subjects?realm={REALM}")
        assert resp.status_code == 200
        assert resp.json() == [{"id": "u1", "username": "alice"}]
        admin.get_users.assert_called_once()

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# KeycloakError → 502 on all endpoints
# ---------------------------------------------------------------------------


def _keycloak_error():
    return KeycloakError(error_message="connection refused", response_code=503)


class TestKeycloakErrorProduces502:
    def test_get_subjects(self):
        admin = MagicMock()
        admin.get_users.side_effect = _keycloak_error()
        assert _make_client(admin).get(f"/subjects?realm={REALM}").status_code == 502

    def test_get_roles(self):
        admin = MagicMock()
        admin.get_realm_roles.side_effect = _keycloak_error()
        assert _make_client(admin).get(f"/roles?realm={REALM}").status_code == 502

    def test_get_services(self):
        admin = MagicMock()
        admin.get_clients.side_effect = _keycloak_error()
        assert _make_client(admin).get(f"/services?realm={REALM}").status_code == 502

    def test_get_scopes(self):
        admin = MagicMock()
        admin.get_client_scopes.side_effect = _keycloak_error()
        assert _make_client(admin).get(f"/scopes?realm={REALM}").status_code == 502

    def test_get_subject_assignments(self):
        admin = MagicMock()
        admin.get_all_roles_of_user.side_effect = _keycloak_error()
        assert _make_client(admin).get(f"/subjects/u1/assignments?realm={REALM}").status_code == 502

    def test_get_service_permissions(self):
        admin = MagicMock()
        admin.get_client_roles.side_effect = _keycloak_error()
        assert _make_client(admin).get(f"/services/s1/roles?realm={REALM}").status_code == 502

    def test_get_service_scopes(self):
        admin = MagicMock()
        admin.get_client_default_client_scopes.side_effect = _keycloak_error()
        assert _make_client(admin).get(f"/services/s1/scopes?realm={REALM}").status_code == 502

    def test_get_role_composites(self):
        admin = MagicMock()
        admin.get_composite_realm_roles_of_role.side_effect = _keycloak_error()
        assert _make_client(admin).get(f"/roles/admin/composites?realm={REALM}").status_code == 502

    def test_mint_discovery_token(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_URL", "http://kc-internal:8080")
        admin = MagicMock()
        admin.get_client.side_effect = _keycloak_error()
        assert _make_client(admin).get(f"/services/s1/discovery-token?realm={REALM}").status_code == 502

    def teardown_method(self):
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Keycloak 404 → 404 on the reads of one service (the onboarding read path, handoff 20)
# ---------------------------------------------------------------------------


def _client_not_found():
    # What python-keycloak raises when Keycloak does not find the client, for example a new client
    # that a reader asks for before Keycloak commits it.
    return KeycloakGetError(error_message="Could not find client", response_code=404)


class TestKeycloakNotFoundProduces404:
    """A Keycloak ``404`` on a read of one service gives ``404`` with ``{"error": ...}``, not
    ``502``, so that the library and the onboarding can tell a client that is not there (or not
    there yet) from an IdP outage. Every other ``KeycloakError`` stays ``502`` (per-route tests)."""

    def test_get_service(self):
        admin = MagicMock()
        admin.get_client.side_effect = _client_not_found()
        resp = _make_client(admin).get(f"/services/s1?realm={REALM}")
        assert resp.status_code == 404
        assert resp.json() == {"error": "404: Could not find client"}

    def test_list_service_roles(self):
        admin = MagicMock()
        admin.get_client.side_effect = _client_not_found()
        resp = _make_client(admin).get(f"/services/s1/roles?realm={REALM}")
        assert resp.status_code == 404
        assert resp.json() == {"error": "404: Could not find client"}

    def test_list_service_scopes(self):
        admin = MagicMock()
        admin.get_client_default_client_scopes.side_effect = _client_not_found()
        resp = _make_client(admin).get(f"/services/s1/scopes?realm={REALM}")
        assert resp.status_code == 404
        assert resp.json() == {"error": "404: Could not find client"}

    def test_mint_discovery_token(self, monkeypatch):
        monkeypatch.setenv("KEYCLOAK_URL", "http://kc-internal:8080")
        admin = MagicMock()
        admin.get_client.side_effect = _client_not_found()
        resp = _make_client(admin).get(f"/services/s1/discovery-token?realm={REALM}")
        assert resp.status_code == 404
        assert resp.json() == {"error": "404: Could not find client"}

    def test_list_role_composites(self):
        # A sub-read of get_service: a composite role deleted between GET /roles and this read. A 404
        # is not retried by the library, and the onboarding reads get_service again (the role is then
        # not listed). A 502 would be retried for a failure that always repeats.
        admin = MagicMock()
        admin.get_composite_realm_roles_of_role.side_effect = KeycloakGetError(
            error_message="Could not find role", response_code=404
        )
        resp = _make_client(admin).get(f"/roles/gone/composites?realm={REALM}")
        assert resp.status_code == 404
        assert resp.json() == {"error": "404: Could not find role"}

    def teardown_method(self):
        app.dependency_overrides.clear()
