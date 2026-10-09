import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, TypeVar

import requests
from dotenv import load_dotenv

from aiac.idp.configuration.models import Role, Scope, Service, ServiceType, Subject
from aiac.shared.upstream import run_upstream

logger = logging.getLogger(__name__)


class IdPHTTPError(RuntimeError):
    """A non-OK response from the IdP Configuration Service. It keeps the HTTP ``status`` and the
    ``response``, so ``aiac.shared.upstream.is_transient`` retries a ``5xx`` and not a ``4xx``. It is
    a ``RuntimeError`` subclass, so the callers that catch ``RuntimeError`` do not change, and the
    message stays ``"HTTP {status}: {text}"``. A caller that must tell one status from another (for
    example a ``404`` for a client that Keycloak has not committed yet) reads ``.status``, not the
    message. A pickled or copied error keeps its status, text, response and notes."""

    def __init__(self, status: int, text: str, response=None) -> None:
        super().__init__(f"HTTP {status}: {text}")
        self.status = status
        self.response = response
        self._text = text

    def __reduce__(self):
        # BaseException rebuilds an error from ``self.args`` (the message only), which does not
        # match this ``__init__``. Rebuild from the three arguments, then restore ``__dict__``.
        return (type(self), (self.status, self._text, self.response), self.__dict__)


class _NamedDefinition(Protocol):
    """Structural type for a not-yet-persisted role/scope: just a name + description.
    Lets ``create_service_role`` / ``create_service_scope`` accept the agent layer's
    ``RoleDefinition`` / ``ScopeDefinition`` without the IdP library importing the agent."""

    name: str
    description: str


def _warn_on_dropped_description(kind: str, existing: Role | Scope, definition: _NamedDefinition) -> None:
    """Log a ``WARNING`` when a reused (shared, D32) role or scope keeps a description that is not
    the new definition's description. ``None`` counts as ``""``. The kept description is not
    updated in Keycloak, so a later owner cannot silently change the policy decision for the
    earlier owners; the warning makes the dropped text visible."""
    kept, dropped = existing.description or "", definition.description or ""
    if kept != dropped:
        logger.warning(
            "reused %s %r keeps its description %r; the new description %r is dropped (D32: Keycloak is not updated)",
            kind,
            existing.name,
            kept,
            dropped,
        )


_Named = TypeVar("_Named", Role, Scope)


def _get_or_create(
    kind: str,
    definition: _NamedDefinition,
    read: Callable[[], list[_Named]],
    create: Callable[[str, str], _Named],
) -> tuple[_Named, bool]:
    """Reuse the ``kind`` named ``definition.name`` that ``read()`` lists, or ``create`` it.

    Returns ``(object, created)``. ``created`` is ``True`` only when this call's ``create``
    returned the object, and ``False`` for each reuse, also a reuse after a ``409``. So a caller
    puts an object into its created-manifest only when this call made it.

    Reuse is by design (D32), and a reused object keeps its description
    (``_warn_on_dropped_description``). The check and the create are two requests, so two services
    with the same workload name that provision at the same time can both find no object; Keycloak
    then answers ``409`` to the second create (REJ-02). A ``409`` from the create is reuse too:
    ``read()`` again and reuse the object of that name that is there now, with the same description
    rule. That object is the other run's, so ``created`` is ``False``. A create that ``_request``
    repeats after Keycloak committed the first attempt also gets this ``409``, and reuses the object
    that the first attempt made. A ``409`` does not tell the two cases apart, so that object is not
    ``created`` either: a rollback keeps it (fail closed), and the next run reuses it by name. A
    ``409`` that the second read does not explain (no object of that name) and any other error are
    raised."""

    def by_name() -> _Named | None:
        return next((entity for entity in read() if entity.name == definition.name), None)

    existing = by_name()
    if existing is None:
        try:
            return create(definition.name, definition.description), True
        except IdPHTTPError as error:
            if error.status != 409:
                raise
            existing = by_name()
            if existing is None:
                raise
            logger.info("the create of %s %r answered 409: the name is taken now, so reuse it", kind, definition.name)
    _warn_on_dropped_description(kind, existing, definition)
    return existing, False


load_dotenv(Path(__file__).resolve().parent / ".env")


# Single source of truth for the Keycloak realm the whole AIAC pipeline operates on. Provisioning,
# the Service Policy Builder, and the Policy Computation Engine all resolve the realm through
# ``Configuration.for_default_realm()`` so they can never diverge onto different env vars.
REALM_ENV_VAR = "KEYCLOAK_REALM"


class Configuration:
    def __init__(self, realm: str) -> None:
        self.realm = realm

    @classmethod
    def for_realm(cls, realm: str) -> "Configuration":
        return cls(realm)

    @classmethod
    def for_default_realm(cls) -> "Configuration":
        """Build a ``Configuration`` for the realm named by ``$KEYCLOAK_REALM`` — the single source
        of truth shared by provisioning, the policy builder, and the computation engine.

        Fails fast if the env var is unset or empty: an empty realm would silently target the
        wrong Keycloak realm rather than surface the misconfiguration."""
        realm = os.getenv(REALM_ENV_VAR, "").strip()
        if not realm:
            raise RuntimeError(
                f"{REALM_ENV_VAR} is unset or empty; set it to the Keycloak realm the AIAC pipeline operates on"
            )
        return cls.for_realm(realm)

    def _base_url(self) -> str:
        return os.getenv("AIAC_PDP_CONFIG_URL", "http://127.0.0.1:7071")

    def _params(self) -> dict[str, str]:
        return {"realm": self.realm}

    def _check(self, resp) -> None:
        """Raise :class:`IdPHTTPError` (with the status and the response) on a non-OK response."""
        if not resp.ok:
            raise IdPHTTPError(resp.status_code, resp.text, resp)

    def _request(self, method: str, path: str, **kwargs):
        """Issue an HTTP request to the config service with bounded transport retries.

        Dispatches to the named ``requests.get`` / ``requests.post`` (not ``requests.request``)
        so callers and tests keep a stable, mockable surface. Retries transient failures via
        ``run_upstream``: a connection error, a timeout or a ``5xx`` is tried again up to
        ``UPSTREAM_MAX_RETRIES`` attempts (default 3) with exponential backoff (1 s, 2 s, …); a
        ``4xx`` is raised at once. A non-OK response raises :class:`IdPHTTPError` (``_check``), so
        callers just consume ``resp.json()``. Retrying at this leaf boundary means composite methods
        (``create_service_role`` / ``create_service_scope``) retry each sub-request without
        compounding. Writes are retried too: a repeated write makes no duplicate, but a repeated
        ``create_role`` / ``create_scope`` whose first attempt was committed answers ``409`` (see
        ``library-idp.md``); ``create_service_role`` / ``create_service_scope`` take that ``409`` as
        reuse (``_get_or_create``).
        """
        caller = getattr(requests, method.lower())

        def _do():
            resp = caller(f"{self._base_url()}{path}", **kwargs)
            self._check(resp)
            return resp

        return run_upstream(_do)

    def _build_subject(self, raw: dict, all_roles: dict[str, Role]) -> Subject:
        subject_id = raw["id"]
        assignments_resp = self._request("GET", f"/subjects/{subject_id}/assignments", params=self._params())
        realm_role_ids = {r["id"] for r in assignments_resp.json().get("realmMappings", [])}
        roles = [r.model_dump() for r in all_roles.values() if r.id in realm_role_ids]
        return Subject.model_validate({**raw, "roles": roles})

    def get_subjects(self) -> list[Subject]:
        resp = self._request("GET", "/subjects", params=self._params())
        all_roles = self._all_roles_map()
        return [self._build_subject(raw, all_roles) for raw in resp.json()]

    def get_roles(self) -> list[Role]:
        resp = self._request("GET", "/roles", params=self._params())
        roles = []
        for raw in resp.json():
            role_data = dict(raw)
            if raw.get("composite"):
                composites_resp = self._request("GET", f"/roles/{raw['name']}/composites", params=self._params())
                role_data["childRoles"] = composites_resp.json()
            roles.append(Role.model_validate(role_data))
        return roles

    def _build_service(self, raw: dict, all_roles: dict[str, Role], all_scopes: dict[str, Scope]) -> Service:
        service_id = raw["id"]
        roles_resp = self._request("GET", f"/services/{service_id}/roles", params=self._params())
        scopes_resp = self._request("GET", f"/services/{service_id}/scopes", params=self._params())
        # The per-service roles response carries the authoritative kind/actorIds for each role
        # (e.g. kind=Agent + actorIds=[serviceId] for agent-owned roles). Merge those fields into
        # the fully-validated all_roles objects (which carry composite/attributes/etc.) so Role
        # validation succeeds and kind/actorIds are not reverted to their defaults.
        service_roles_by_id = {r["id"]: r for r in roles_resp.json()}
        roles = []
        for role_id, svc_role in service_roles_by_id.items():
            base = all_roles.get(role_id)
            if base is not None:
                merged = {**base.model_dump(), **{k: v for k, v in svc_role.items() if k in ("kind", "actorIds")}}
            else:
                merged = svc_role  # not in all_roles (e.g. client role not in realm roles)
            roles.append(merged)
        client_id = raw.get("clientId") or raw.get("serviceId") or service_id
        service_scope_ids = {s["id"] for s in scopes_resp.json()}
        scopes = [{**s.model_dump(), "serviceId": client_id} for s in all_scopes.values() if s.id in service_scope_ids]
        # Type resolution is handled entirely by Service._resolve_keycloak_fields
        # (client.type attribute → None); the library does not infer it here.
        return Service.model_validate({**raw, "roles": roles, "scopes": scopes})

    def _all_roles_map(self) -> dict[str, Role]:
        return {r.id: r for r in self.get_roles()}

    def _all_scopes_map(self) -> dict[str, Scope]:
        return {s.id: s for s in self.get_scopes()}

    def get_services(self) -> list[Service]:
        resp = self._request("GET", "/services", params=self._params())
        all_roles = self._all_roles_map()
        all_scopes = self._all_scopes_map()
        return [self._build_service(raw, all_roles, all_scopes) for raw in resp.json()]

    def get_service(self, service_id: str) -> Service:
        resp = self._request("GET", f"/services/{service_id}", params=self._params())
        return self._build_service(resp.json(), self._all_roles_map(), self._all_scopes_map())

    def mint_discovery_token(self, service_id: str) -> str:
        """Mint a bearer token whose ``aud`` contains the tool's clientId, for authenticating UC-1
        tool discovery against the tool's AuthBridge sidecar. The config service (which holds the
        Keycloak admin) does the minting; this returns the raw ``access_token`` string. Raises
        ``IdPHTTPError`` (a ``RuntimeError``) on a non-OK response (via ``_check``)."""
        resp = self._request("GET", f"/services/{service_id}/discovery-token", params=self._params())
        return resp.json()["access_token"]

    def get_services_by_role(self, role: Role) -> list[Service]:
        """Services whose service-account holds ``role`` (client-side filter of get_services)."""
        return [s for s in self.get_services() if any(r.id == role.id for r in s.roles)]

    def get_subjects_by_role(self, role: Role) -> list[Subject]:
        resp = self._request("GET", "/subjects", params={"role_id": role.id, "realm": self.realm})
        return [Subject.model_validate(s) for s in resp.json()]

    def get_services_by_scope(self, scope: Scope) -> list[Service]:
        """Services exposing ``scope`` as a default client scope (client-side filter of get_services)."""
        return [s for s in self.get_services() if any(sc.id == scope.id for sc in s.scopes)]

    def get_scopes(self) -> list[Scope]:
        resp = self._request("GET", "/scopes", params=self._params())
        return [Scope.model_validate(s) for s in resp.json()]

    def create_scope(self, scope_name: str, scope_description: str) -> Scope:
        resp = self._request(
            "POST",
            "/scopes",
            json={"name": scope_name, "description": scope_description},
            params=self._params(),
        )
        return Scope.model_validate(resp.json())

    def map_scope_to_service(self, service: Service, scope: Scope) -> Service:
        self._request("POST", f"/services/{service.id}/scopes/{scope.id}", params=self._params())
        get_resp = self._request("GET", f"/services/{service.id}", params=self._params())
        return Service.model_validate(get_resp.json())

    def set_service_type(self, service: Service, service_type: ServiceType) -> Service:
        """Persist a service's type onto the Keycloak client as the ``client.type`` attribute.

        The value is stored capitalized (``Agent``/``Tool`` — ``ServiceType``'s values) so
        ``Service._resolve_keycloak_fields`` resolves it back on read. Returns the updated
        ``Service``. A bare ``"Agent"``/``"Tool"`` string is accepted too (``ServiceType`` is a
        ``str`` enum).
        """
        value = service_type.value if isinstance(service_type, ServiceType) else service_type
        resp = self._request(
            "POST",
            f"/services/{service.id}/type",
            json={"type": value},
            params=self._params(),
        )
        return Service.model_validate(resp.json())

    def link_subject_scope(self, service: Service) -> Scope:
        """Link the shared subject scope ``aiac-username-sub`` to a service's client (D31).

        Issues ``POST /services/{service.id}/subject-scope`` with no body. The config service
        ensures the client scope ``aiac-username-sub`` and its ``username`` → ``sub`` mapper, with
        **no** ``aiac.managed`` marker, and links it as a default client scope of this service's
        client. Exchanged tokens for the service then carry ``sub`` = username. Idempotent — an
        existing scope, mapper or link is not an error. Raises ``IdPHTTPError`` (a ``RuntimeError``)
        on a non-OK status.

        The scope is shared by every managed client, so UC-1 never puts it into the created-manifest
        (a rollback never deletes it). Returns the ``Scope``; its ``aiac_managed`` is ``False``.
        """
        resp = self._request("POST", f"/services/{service.id}/subject-scope", params=self._params())
        return Scope.model_validate(resp.json())

    def set_service_enabled(self, service: Service, enabled: bool) -> Service:
        """The **writer** for ``Service.enabled`` — consumed by the UC1 rollback (disable a failed
        service's client) and the success re-enable path.

        Issues ``POST /services/{service.id}/enabled`` with body ``{"enabled": <bool>}``; the config
        service calls ``update_client(enabled=…)`` on the Keycloak client. Idempotent — disabling an
        already-disabled client (or enabling an already-enabled one) is not an error. Raises
        ``IdPHTTPError`` (a ``RuntimeError``) on a non-OK status. Returns the updated ``Service`` with
        the new ``enabled`` value (``get_service`` / ``get_services`` surface it on subsequent reads).
        """
        resp = self._request(
            "POST",
            f"/services/{service.id}/enabled",
            json={"enabled": enabled},
            params=self._params(),
        )
        return Service.model_validate(resp.json())

    def create_service_role(self, service_id: str, role: _NamedDefinition) -> tuple[Role, bool]:
        """Idempotent create-or-get of a realm role by name, then map it to ``service_id``.

        If a realm role with ``role.name`` already exists it is reused (no duplicate create);
        otherwise it is created. Reuse is by design (D32): services with the same workload name
        share the role. A ``409`` from the create (another service created the role after the
        check) is reuse too: the role is read again by name (``_get_or_create``). A reused role keeps
        its description; when ``role.description`` is not the same (``None`` counts as ``""``), a
        ``WARNING`` names the role and both descriptions, and Keycloak is not updated. The role is
        then mapped to the service's service-account (``map_role_to_service`` is itself idempotent).
        Returns ``(role, created)``: the resolved ``Role``, and ``True`` only when this call created
        it (``False`` for a reuse, also after a ``409``). UC1 Provision puts the role into its
        created-manifest only when ``created`` is ``True``, so its rollback never deletes a role
        that another service created.
        """
        resolved, created = _get_or_create("role", role, self.get_roles, self.create_role)
        self.map_role_to_service(self.get_service(service_id), resolved)
        return resolved, created

    def create_service_scope(self, service_id: str, scope: _NamedDefinition) -> tuple[Scope, bool]:
        """Idempotent create-or-get of a client scope by name, then map it to ``service_id``.

        If a client scope with ``scope.name`` already exists it is reused; otherwise it is
        created. Reuse is by design (D32): services with the same workload name share the scope,
        and each owner gets its own copy in ``get_services()``. A ``409`` from the create (another
        service created the scope after the check) is reuse too: the scope is read again by name
        (``_get_or_create``). A reused scope keeps its description; when ``scope.description`` is
        not the same (``None`` counts as ``""``), a ``WARNING`` names the scope and both
        descriptions, and Keycloak is not updated. The scope is then mapped to the service as a
        default client scope (``map_scope_to_service`` is itself idempotent). Returns
        ``(scope, created)``: the resolved ``Scope``, and ``True`` only when this call created it
        (``False`` for a reuse, also after a ``409``), as for ``create_service_role``.
        """
        resolved, created = _get_or_create("client scope", scope, self.get_scopes, self.create_scope)
        self.map_scope_to_service(self.get_service(service_id), resolved)
        return resolved, created

    def create_role(self, role_name: str, role_description: str) -> Role:
        resp = self._request(
            "POST",
            "/roles",
            json={"name": role_name, "description": role_description},
            params=self._params(),
        )
        return Role.model_validate(resp.json())

    def map_role_to_service(self, service: Service, role: Role) -> Service:
        self._request("POST", f"/services/{service.id}/roles/{role.id}", params=self._params())
        get_resp = self._request("GET", f"/services/{service.id}", params=self._params())
        return Service.model_validate(get_resp.json())

    def delete_service_role(self, service: Service, role: Role) -> None:
        """Teardown of a role this service created — consumed by the UC1 rollback.

        Issues a single ``DELETE /services/{service.id}/roles/{role.id}``. The config service
        removes the role mapping from the service account **first**, then deletes the realm role
        (**unmap-then-delete** order — a still-mapped role cannot be deleted cleanly), and is
        shared-object safe: a role another service still references is at most unmapped, never
        deleted. Both are enforced service-side. Idempotent — the service treats an already-gone
        mapping / role as success, so this raises only on a genuine non-OK status (via ``_check``).
        Returns ``None``.
        """
        self._request("DELETE", f"/services/{service.id}/roles/{role.id}", params=self._params())

    def delete_service_scope(self, service: Service, scope: Scope) -> None:
        """Teardown of a scope this service created — consumed by the UC1 rollback.

        Issues a single ``DELETE /services/{service.id}/scopes/{scope.id}``. The config service
        removes the scope mapping from the client **first**, then deletes the client scope
        (**unmap-then-delete** order), and is shared-object safe: a scope another service still
        references is at most unmapped, never deleted. Both are enforced service-side. Idempotent —
        the service treats an already-gone assignment / scope as success, so this raises only on a
        genuine non-OK status (via ``_check``). Returns ``None``.
        """
        self._request("DELETE", f"/services/{service.id}/scopes/{scope.id}", params=self._params())
