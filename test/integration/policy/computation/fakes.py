"""In-memory stand-ins for the external services behind the AIAC library seams (integration lane).

Each fake replaces one service that the real code reaches over HTTP. The AIAC code between the seams
stays real:

- ``FakeRealm`` — the Keycloak realm behind the IdP library ``Configuration``. It gives the real
  ``Service`` / ``Role`` / ``Scope`` / ``Subject`` models in the shapes that the IdP Configuration
  Service gives (``src/aiac/idp/service/configuration/keycloak/main.py``) and that the library merges
  (``src/aiac/idp/configuration/api.py``): ``GET /roles`` gives every realm role as ``kind=User``, with
  ``actorIds`` = the member usernames of an ``aiac.managed`` role; ``GET /services/{id}/roles`` gives
  each holder its own copy of a realm role held by its service account (``kind=Agent``, ``actorIds =
  [that holder's clientId]``); ``GET /services/{id}/scopes`` gives each owner its own copy of a client
  scope (``serviceId`` = that owner). It also records one role-members event for each role mapping
  (``REALM_ROLE_MAPPING`` create or delete, R5), as the SPI publishes it.
- ``FakeStore`` — the Policy Model Store service behind the store library: SPMs as JSON rows, a fresh
  empty SPM on a 404, the by-role scan over both inbound lists. It records every write.
- ``FakeCluster`` — the Kubernetes API behind the PDP Policy Writer: the ``AuthorizationPolicy`` CRs
  that the real writer app applies. ``FakePdp`` is the PDP library: it sends each policy model to the
  real writer app (``aiac.pdp.service.policy.opa.main``) in process, so the CRs hold the real Rego.
- ``FakeLlm`` — the PRB LLM seam (``_structured_call``): it decides each focal entity from a fixed
  table, approves every audit, and records every prompt text.
"""

import copy
import re
import uuid
from urllib.parse import quote

from fastapi.testclient import TestClient

from aiac.agent.policy_rules_builder.graph import AuditVerdict, RoleSelection, ScopeSelection
from aiac.idp.configuration.models import Role, Scope, Service, ServiceType, Subject
from aiac.pdp.service.policy.opa import main as writer
from aiac.pdp.service.policy.opa.rego import identity_ref
from aiac.policy.model.models import ServicePolicyModel

TRUST_DOMAIN = "rossoctl.io"
SERVICE_ACCOUNT_PREFIX = "service-account-"  # the service-account user of a client: service-account-<clientId>
SUBJECT_SCOPE = "aiac-username-sub"  # the shared D31 subject scope: linked to every client, no marker

_ROLE_MARKER = {"aiac.managed": ["true"]}  # realm-role attribute values are lists
_SCOPE_MARKER = {"aiac.managed": "true"}  # client-scope attribute values are plain strings


def client_id_of(namespace: str, workload: str) -> str:
    """The SPIFFE clientId that the operator registers for a workload."""
    return f"spiffe://{TRUST_DOMAIN}/ns/{namespace}/sa/{workload}"


def _uuid(kind: str, name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{kind}:{name}"))


# --------------------------------------------------------------------------- #
# IdP — the Keycloak realm behind the IdP library ``Configuration``           #
# --------------------------------------------------------------------------- #
class FakeRealm:
    """One Keycloak realm. The admin side (``provision``, ``grant``, ``revoke``) changes it as
    Provision or an admin would; the library side (``get_services`` ...) reads it as the IdP library
    ``Configuration`` does. Every read builds new model objects, so a caller cannot change the realm."""

    def __init__(self) -> None:
        self._clients: dict[str, dict] = {}  # clientId -> raw client, in creation order
        self._client_scopes: dict[str, list[str]] = {}  # clientId -> default client-scope ids
        self._roles: dict[str, dict] = {}  # role id -> raw realm role
        self._scopes: dict[str, dict] = {}  # scope id -> raw client scope
        self._members: dict[str, list[str]] = {}  # role id -> member usernames (users and service accounts)
        self._users: dict[str, str] = {}  # username -> user id
        self.events: list[str] = []  # one role id for each role mapping, in order (R5)

    # ---- admin side -------------------------------------------------------- #
    def add_user(self, username: str) -> None:
        self._users.setdefault(username, _uuid("user", username))

    def ensure_role(self, name: str, description: str) -> str:
        """Create the ``aiac.managed`` realm role ``name``, or reuse it by name (the library's
        ``create_service_role``: a reused role keeps its first description). Returns its id."""
        existing = next((rid for rid, raw in self._roles.items() if raw["name"] == name), None)
        if existing is not None:
            return existing
        role_id = _uuid("role", name)
        self._roles[role_id] = {
            "id": role_id,
            "name": name,
            "description": description,
            "composite": False,
            "clientRole": False,
            "attributes": dict(_ROLE_MARKER),
        }
        return role_id

    def ensure_scope(self, name: str, description: str, *, managed: bool = True) -> str:
        """Create the client scope ``name``, or reuse it by name (``create_service_scope``)."""
        existing = next((sid for sid, raw in self._scopes.items() if raw["name"] == name), None)
        if existing is not None:
            return existing
        scope_id = _uuid("scope", name)
        attributes = dict(_SCOPE_MARKER) if managed else {}
        self._scopes[scope_id] = {"id": scope_id, "name": name, "description": description, "attributes": attributes}
        return scope_id

    def register_client(self, namespace: str, workload: str) -> str:
        """The operator's client registration: an enabled client with no type yet. Returns its clientId."""
        client_id = client_id_of(namespace, workload)
        self._clients.setdefault(
            client_id,
            {
                "id": _uuid("client", client_id),
                "clientId": client_id,
                "name": f"{namespace}/{workload}",
                "enabled": True,
                "attributes": {},
            },
        )
        self._client_scopes.setdefault(client_id, [])
        return client_id

    def provision(self, namespace: str, workload: str, service_type: ServiceType, entries: dict[str, str]) -> str:
        """UC-1 Provision of one workload, as ``provision_service`` writes it. ``entries`` maps each
        agent skill id or tool name to its description. An agent gets the realm role and the client
        scope ``<workload>.<entry>`` for each skill; a tool gets the client scope for each tool. Both
        reuse an object by name. Then the subject scope is linked and the type is set. Returns the
        clientId."""
        client_id = self.register_client(namespace, workload)
        if service_type is ServiceType.AGENT:
            for entry, description in entries.items():
                self.ensure_role(f"{workload}.{entry}", description)
                self.grant(client_id, f"{workload}.{entry}")
        for entry, description in entries.items():
            self._map_scope(client_id, self.ensure_scope(f"{workload}.{entry}", description))
        self._map_scope(client_id, self.ensure_scope(SUBJECT_SCOPE, "", managed=False))
        self._clients[client_id]["attributes"]["client.type"] = service_type.value
        return client_id

    def grant(self, holder: str, role_name: str) -> None:
        """Map the realm role ``role_name`` to ``holder`` (a username, or a clientId for its service
        account), as Provision or an admin does in Keycloak. Records the role-members event."""
        role_id = self.role_id(role_name)
        members = self._members.setdefault(role_id, [])
        member = self._member(holder)
        if member not in members:
            members.append(member)
        self.events.append(role_id)

    def revoke(self, holder: str, role_name: str) -> None:
        """Unmap the realm role ``role_name`` from ``holder``. Records the role-members event."""
        role_id = self.role_id(role_name)
        self._members[role_id] = [m for m in self._members.get(role_id, []) if m != self._member(holder)]
        self.events.append(role_id)

    def role_id(self, role_name: str) -> str:
        return next(rid for rid, raw in self._roles.items() if raw["name"] == role_name)

    def service(self, client_id: str) -> Service:
        """The catalog entry of ``client_id`` (as ``get_services()`` gives it)."""
        return self._service(self._clients[client_id])

    def _member(self, holder: str) -> str:
        if holder in self._clients:
            return f"{SERVICE_ACCOUNT_PREFIX}{holder}"
        assert holder in self._users, f"no user or client {holder!r} in the realm"
        return holder

    def _map_scope(self, client_id: str, scope_id: str) -> None:
        if scope_id not in self._client_scopes[client_id]:
            self._client_scopes[client_id].append(scope_id)

    # ---- library side (the ``Configuration`` methods the real code calls) ---- #
    def get_roles(self) -> list[Role]:
        """``GET /roles``: every realm role as ``kind=User``; an ``aiac.managed`` role has
        ``actorIds`` = its member usernames (service accounts included, as Keycloak lists them)."""
        roles = []
        for role_id, raw in self._roles.items():
            role = Role.model_validate({**raw, "kind": "User"})
            if role.aiac_managed:
                role = role.model_copy(update={"actorIds": list(self._members.get(role_id, []))})
            roles.append(role)
        return roles

    def get_scopes(self) -> list[Scope]:
        """``GET /scopes``: every client scope, with an empty ``serviceId``."""
        return [Scope.model_validate(raw) for raw in self._scopes.values()]

    def get_subjects(self) -> list[Subject]:
        """``GET /subjects`` with the realm mappings of each user (service accounts are not users)."""
        roles = self.get_roles()
        return [
            Subject(
                id=user_id,
                username=username,
                enabled=True,
                roles=[role for role in roles if username in self._members.get(role.id, [])],
            )
            for username, user_id in self._users.items()
        ]

    def get_subjects_by_role(self, role: Role) -> list[Subject]:
        return [
            s.model_copy(update={"roles": []}) for s in self.get_subjects() if any(r.id == role.id for r in s.roles)
        ]

    def get_services(self) -> list[Service]:
        return [self._service(raw) for raw in self._clients.values()]

    def get_service(self, service_id: str) -> Service:
        """By the Keycloak internal client UUID (``Service.id``)."""
        return next(self._service(raw) for raw in self._clients.values() if raw["id"] == service_id)

    def get_services_by_role(self, role: Role) -> list[Service]:
        return [s for s in self.get_services() if any(r.id == role.id for r in s.roles)]

    def get_services_by_scope(self, scope: Scope) -> list[Service]:
        return [s for s in self.get_services() if any(sc.id == scope.id for sc in s.scopes)]

    def _service(self, raw: dict) -> Service:
        client_id = raw["clientId"]
        account = f"{SERVICE_ACCOUNT_PREFIX}{client_id}"
        # GET /services/{id}/roles: each aiac.managed realm role of the service account is an Agent role
        # of this service alone; the library merges kind + actorIds onto the GET /roles object.
        roles = [
            {**role.model_dump(), "kind": "Agent", "actorIds": [client_id]}
            for role in self.get_roles()
            if role.aiac_managed and account in self._members.get(role.id, [])
        ]
        # GET /services/{id}/scopes, joined to GET /scopes: this owner's own copy of each default scope.
        scopes = [
            {**raw_scope, "serviceId": client_id}
            for scope_id, raw_scope in self._scopes.items()
            if scope_id in self._client_scopes[client_id]
        ]
        return Service.model_validate({**copy.deepcopy(raw), "roles": roles, "scopes": scopes})


# --------------------------------------------------------------------------- #
# Policy Model Store — behind the store library                               #
# --------------------------------------------------------------------------- #
class FakeStore:
    """The Policy Model Store service: one JSON row per SPM, keyed by clientId."""

    def __init__(self) -> None:
        self._rows: dict[str, dict] = {}
        self.writes: list[tuple[str, str]] = []  # (op, service_id) for every apply and delete, in order

    def get_service_policy(self, service_id: str) -> ServicePolicyModel:
        if service_id in self._rows:
            return ServicePolicyModel.model_validate(self._rows[service_id])
        # The library's answer to a 404: a fresh empty SPM (the PCE re-seeds type and identity).
        return ServicePolicyModel(
            service_id=service_id, service_type=ServiceType.AGENT, owned_roles=[], owned_scopes=[]
        )

    def list_service_policies(self) -> list[ServicePolicyModel]:
        return [ServicePolicyModel.model_validate(row) for row in self._rows.values()]

    def get_service_policies_by_role(self, role: Role) -> list[ServicePolicyModel]:
        return [
            spm
            for spm in self.list_service_policies()
            if any(rule.role.id == role.id for rule in (*spm.inbound_allow_rules, *spm.inbound_deny_rules))
        ]

    def apply_service_policy(self, service_id: str, spm: ServicePolicyModel) -> None:
        self._rows[service_id] = spm.model_dump(mode="json")
        self.writes.append(("apply", service_id))

    def delete_service_policy(self, service_id: str) -> None:
        self._rows.pop(service_id, None)
        self.writes.append(("delete", service_id))

    def spm(self, service_id: str) -> ServicePolicyModel | None:
        """The stored SPM of ``service_id`` (for assertions), or ``None``."""
        row = self._rows.get(service_id)
        return None if row is None else ServicePolicyModel.model_validate(row)


# --------------------------------------------------------------------------- #
# PDP Policy Writer — the real writer app, on an in-memory Kubernetes API     #
# --------------------------------------------------------------------------- #
class FakeCluster:
    """The ``CustomObjectsApi`` calls the writer makes: the CRs by ``(namespace, name)``."""

    def __init__(self) -> None:
        self.crs: dict[tuple[str, str], dict] = {}

    def patch_namespaced_custom_object(self, *, namespace: str, name: str, body: dict, **_: object) -> None:
        self.crs[(namespace, name)] = copy.deepcopy(body)

    def delete_namespaced_custom_object(self, *, namespace: str, name: str, **_: object) -> None:
        self.crs.pop((namespace, name), None)

    def list_cluster_custom_object(self, *_: object, **__: object) -> dict:
        return {"items": [copy.deepcopy(body) for body in self.crs.values()]}

    def policies(self, client_id: str) -> dict[str, str] | None:
        """The two request packages of the CR of ``client_id`` (by path), or ``None`` if it has no CR."""
        cr = self.crs.get(identity_ref(client_id))
        return None if cr is None else {p["path"]: p["content"] for p in cr["spec"]["policies"]}


class FakePdp:
    """The PDP library: each call goes to the real writer app in process, as the HTTP call would."""

    def __init__(self) -> None:
        self._client = TestClient(writer.app)

    def apply_policy(self, model) -> None:
        self._check(self._client.post("/policy", json=model.model_dump(mode="json")))

    def replace_policy(self, model) -> None:
        self._check(self._client.put("/policy", json=model.model_dump(mode="json")))

    def delete_service_cr(self, service_id: str) -> None:
        self._check(self._client.delete(f"/policy/services/{quote(service_id, safe='')}"))

    @staticmethod
    def _check(resp) -> None:
        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")


# --------------------------------------------------------------------------- #
# LLM — the PRB ``_structured_call`` seam                                     #
# --------------------------------------------------------------------------- #
_FOCAL_RE = re.compile(r"^FOCAL ENTITY:\n(role|scope) name=([^:\n]*):", re.MULTILINE)
_CANDIDATE_RE = re.compile(r"^(?:role|scope) name=([^:\n]*):", re.MULTILINE)


def _candidate_block(prompt: str) -> str:
    return prompt.split("CANDIDATES:\n", 1)[1].split("\n\n", 1)[0]


class FakeLlm:
    """A deterministic PRB LLM. ``decisions`` maps ``(focal kind, focal name)`` — kind ``role`` (the
    role-focal pass) or ``scope`` (the scope-focal pass) — to ``(granted names, denied names)``. The
    proposer gives the names of the table that are candidates; the auditor approves. Every prompt
    text (the human message) is recorded in ``prompts``, in call order."""

    def __init__(self, decisions: dict[tuple[str, str], tuple[set[str], set[str]]]) -> None:
        self.decisions = decisions
        self.prompts: list[str] = []

    def __call__(self, schema, messages):
        prompt = messages[-1].content
        self.prompts.append(prompt)
        if schema is AuditVerdict:
            return AuditVerdict(approved=True)
        focal = _FOCAL_RE.search(prompt)
        assert focal is not None, f"no focal entity in the prompt:\n{prompt}"
        candidates = set(_CANDIDATE_RE.findall(_candidate_block(prompt)))
        granted, denied = self.decisions.get((focal[1], focal[2]), (set(), set()))
        granted, denied = sorted(granted & candidates), sorted(denied & candidates)
        if schema is RoleSelection:
            return RoleSelection(granted_scope_names=granted, denied_scope_names=denied, reasoning="table")
        if schema is ScopeSelection:
            return ScopeSelection(roles_with_access_names=granted, roles_denied_access_names=denied, reasoning="table")
        raise AssertionError(f"unexpected LLM call with schema {schema.__name__}")

    def prompts_for(self, kind: str, name: str) -> list[str]:
        """The recorded prompts (proposer and auditor) whose focal entity is ``kind`` ``name``."""
        return [p for p in self.prompts if (m := _FOCAL_RE.search(p)) and (m[1], m[2]) == (kind, name)]
