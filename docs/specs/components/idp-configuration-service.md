# Component PRD: IdP Configuration Service

## Location
`src/aiac/idp/service/configuration/keycloak/`

## Description
A FastAPI web service that proxies Keycloak Admin REST API endpoints. Returns IdP (Keycloak) entity state in generic form for consumption by the AIAC Agent and library clients. Consolidates all Keycloak interactions into a single container. Stateless — no caching. Backed exclusively by Keycloak.

## Endpoints

| Method | Path | Keycloak Admin API call | Description |
|--------|------|------------------------|-------------|
| GET | `/subjects` | `GET /admin/realms/{realm}/users` | All subjects (users) in realm; filtered to subjects with a specific role when `role_id` query param is provided |
| GET | `/roles` | `GET /admin/realms/{realm}/roles` (full representation, `brief_representation=False`) | All realm-level roles, including attributes (so the `aiac.managed` marker is visible) |
| GET | `/subjects/{subject_id}/assignments` | `GET /admin/realms/{realm}/users/{subject_id}/role-mappings` | Realm and service permission assignments for a subject |
| GET | `/services` | `GET /admin/realms/{realm}/clients` | All services (clients) |
| GET | `/services/{service_id}` | `GET /admin/realms/{realm}/clients/{service_id}` | Single service by ID; `404` when Keycloak does not find the client |
| POST | `/services/{service_id}/type` | `admin.get_client(service_id)` → `admin.update_client(service_id, {"attributes": {...}})` | Set a service's type via the `client.type` client attribute; an empty `type` clears the attribute via read-merge (same pattern as set) |
| GET | `/scopes` | `GET /admin/realms/{realm}/client-scopes` | All scopes |
| GET | `/services/{service_id}/roles` | `admin.get_client_roles(service_id)` **+** `aiac.managed` realm roles on the service account | **An agent's own roles (`R_A`)** from **two** sources: this service's client roles, **plus** the `aiac.managed` realm roles assigned to its service account (the `Configuration` library's provisioning path). Both surfaced as `kind = Agent`. See "Agent roles are client roles" below. |
| GET | `/services/{service_id}/scopes` | `admin.get_client_default_client_scopes(service_id)` | Default client scopes assigned to a service, each with `serviceId` = this service. A scope that several services share is listed for each of them ([D32](../PRD.md#key-architectural-decisions)) |
| GET | `/roles/{role_name}/composites` | `GET /admin/realms/{realm}/roles/{role-name}/composites` | Current composite permissions assigned to a role; `404` when Keycloak does not find the role |
| POST | `/scopes` | `POST /admin/realms/{realm}/client-scopes` | Create realm-level scope |
| POST | `/services/{service_id}/scopes` | `admin.create_client_scope(...)` → `admin.add_client_default_client_scope(service_id, scope_id, {})` | Create an `aiac.managed` scope and assign it to the service as a default scope |
| POST | `/services/{service_id}/scopes/{scope_id}` | `PUT /admin/realms/{realm}/clients/{service_id}/default-client-scopes/{scope_id}` | Assign existing scope as default scope to service |
| POST | `/services/{service_id}/subject-scope` | `admin.get_client_scopes()` → (only if absent) `admin.create_client_scope(...)` → `admin.get_mappers_from_client_scope(scope_id)` → (only if absent) `admin.add_mapper_to_client_scope(scope_id, ...)`, or (only if the existing mapper is wrong) `admin.update_mapper_in_client_scope(...)` or `admin.delete_mapper_from_client_scope(...)` + add → `admin.get_client_scope(scope_id)` → `admin.get_client_optional_client_scopes(service_id)` → (only if linked as optional) `admin.delete_client_optional_client_scope(service_id, scope_id)` → `admin.add_client_default_client_scope(service_id, scope_id, {})` | Make sure that the shared subject scope `aiac-username-sub` and its `username-to-sub` mapper exist with the expected type and config (with **no** `aiac.managed` marker), and link the scope to the service as a default scope (D31) |
| POST | `/roles` | `POST /admin/realms/{realm}/roles` | Create realm-level role |
| POST | `/services/{service_id}/roles/{role_id}` | `admin.get_client_service_account_user(service_id)` → `admin.assign_realm_roles(user_id, ...)` | Assign existing realm role to service account |
| GET | `/services/{service_id}/discovery-token` | `admin.get_client(service_id)` → (idempotent) `add_mapper_to_client` → `KeycloakOpenID(...).token(grant_type="client_credentials")` | Mint a bearer token, minted **as the service's own client**, whose `aud` contains that client's client-id — for authenticating UC-1 tool discovery against the tool's AuthBridge sidecar |
| DELETE | `/services/{service_id}/roles/{role_id}` | `get_client_service_account_user` → `get_realm_role_by_id(role_id)` → `delete_realm_roles_of_user(user_id, [role])` → `get_realm_role_members(role_name)` → (only if no members are left) `delete_realm_role(role_name)` | Remove the role mapping from the service account, then delete the realm role (unmap-then-delete; shared-object safe: a shared role is deleted only at its last holder, D32) |
| DELETE | `/services/{service_id}/scopes/{scope_id}` | `delete_client_default_client_scope(service_id, scope_id)` → `_build_scope_owner_index(admin)` → (only if no other client links it) `delete_client_scope(scope_id)` | Remove the scope mapping from the client, then delete the client scope (unmap-then-delete; shared-object safe: a shared scope is deleted only at its last owner, D32) |
| POST | `/services/{service_id}/enabled` | `admin.update_client(service_id, {"enabled": <bool>})` → `admin.get_client(service_id)` (re-fetch) | Enable or disable a service's Keycloak client (the writer for `Service.enabled`) |
| GET | `/health` | `admin.get_server_info()` — uses `KEYCLOAK_ADMIN_REALM`; no `?realm=` param | Readiness and liveness probe; returns `503` on `KeycloakError` |

`GET /subjects?role_id={role_id}` (filtered variant):
1. Calls `admin.get_realm_role_by_id(role_id)` to resolve the role name from its ID.
2. Calls `admin.get_realm_role_members(role_name)` (`GET /admin/realms/{realm}/roles/{role-name}/users`) to retrieve users directly assigned to the role.
3. For each returned user, calls `admin.get_all_roles_of_user(user_id)` and merges `realmMappings` and `serviceMappings` into the user object. (The unfiltered `GET /subjects` returns the users without this enrichment.)
4. Returns `200 OK` with a JSON array of enriched user objects.
5. Returns `[]` (empty array) when no subject holds the role directly.
6. Returns `502 Bad Gateway` with `{"error": ...}` on `KeycloakError`.

`GET /services/{service_id}`:
1. Calls `admin.get_client(service_id)`.
2. Returns `200 OK` with the client JSON on success.
3. Returns `404 Not Found` with `{"error": ...}` when Keycloak answers `404` (python-keycloak raises `KeycloakGetError` with `response_code == 404`; the body is `{"error": str(e)}`). Keycloak's own body has no `message` key, so python-keycloak puts the raw Keycloak response in the error message, for example `{"error": "404: b'{\"error\":\"Could not find client\"}'"}`. Keycloak answers `404` when the client does not exist, and also when a reader asks for a new client before Keycloak commits it ([D33](../PRD.md#key-architectural-decisions)). The `404` lets the caller tell a missing client from an IdP outage: the `Configuration` library does not retry a `4xx`, and the UC1 onboarding waits a short time for a new client (see the AIAC Agent UC1 spec).
4. Returns `502 Bad Gateway` with `{"error": ...}` on every other `KeycloakError`.

All service reads (`GET /services`, `GET /services/{service_id}`) return the Keycloak client representation **unmodified**, so client `attributes` — including `client.type` — flow through verbatim for the library's generic-model mapping (`Service._resolve_keycloak_fields`) to resolve service type. The Keycloak attribute name is confined to this service (writes) and the library mapping layer (reads); it is never exposed to library callers.

`POST /services/{service_id}/type`:
Accepts JSON body `{"type": "Agent" | "Tool" | ""}` (`""` clears the type — see **Unset service type** below; any other value is rejected with `422`). It:
1. Calls `admin.get_client(service_id)` and copies its existing `attributes`.
2. Sets the **`client.type`** attribute to the (capitalized, plain-string) type value and calls `admin.update_client(service_id, {"attributes": {...}})`. The existing attributes are merged, not clobbered.
3. Returns `200 OK` with the updated client JSON (re-fetched via `admin.get_client`).
4. Returns `502 Bad Gateway` with `{"error": ...}` on `KeycloakError`.

`POST /scopes`:
Accepts JSON body `{"name": ..., "description": ...}`. It:
1. Calls `admin.create_client_scope({"name": ..., "description": ..., "protocol": "openid-connect", "attributes": {"aiac.managed": "true"}})` to create the scope at realm level. The `aiac.managed` attribute is the AIAC provisioning marker (client-scope attribute values are plain strings).
2. Returns `201 Created` with the created scope JSON (`{"id": ..., "name": ..., "description": ...}`).
3. Returns `409 Conflict` if a scope with that name already exists.
4. Returns `502 Bad Gateway` with `{"error": ...}` on `KeycloakError`.

`POST /services/{service_id}/scopes/{scope_id}`:
1. Calls `admin.add_client_default_client_scope(service_id, scope_id, {})` to assign the scope as a default scope to the service.
2. Returns `201 Created` on success. A repeat is also a success, with no second link: Keycloak skips a scope that is already linked to the client, as a default or as an optional scope, and gives no error (Keycloak 26.5.2, `JpaRealmProvider.addClientScopes`). A scope that is linked as an optional scope stays optional.
3. Returns `409 Conflict` with `{"error": ...}` only when Keycloak itself answers `409`. A scope that is already assigned does not give a `409`.
4. Returns `502 Bad Gateway` with `{"error": ...}` on other `KeycloakError`.

`POST /services/{service_id}/subject-scope` (the subject is the username on every leg — [D31](../PRD.md#key-architectural-decisions)):
Accepts no body. UC-1 Provision calls it at each onboarding, for agents and tools. It:
1. Makes sure that the shared client scope **`aiac-username-sub`** exists in the correct state (`_ensure_subject_scope`, idempotent):
   - Finds the scope by name in `admin.get_client_scopes()`. If it is absent, calls `admin.create_client_scope({"name": "aiac-username-sub", "description": "AIAC subject scope (D31): sets the token sub to the username", "protocol": "openid-connect", "attributes": {"include.in.token.scope": "false", "display.on.consent.screen": "false"}})`. The scope has **no** `aiac.managed` attribute (see the marker section below). A `KeycloakError` with `response_code == 409` (a concurrent onboarding of another service created the scope first) is not an error: it finds the scope by name again. It does not use `skip_exists=True` (in python-keycloak 7.x, a `409` then fails on the missing `Location` header).
   - If the existing scope carries the `aiac.managed` marker, it stops with `409` (step 5).
   - Calls `admin.get_mappers_from_client_scope(scope_id)`. If no mapper has the name **`username-to-sub`**, calls `admin.add_mapper_to_client_scope(scope_id, {...})` with an `oidc-usermodel-property-mapper`: `user.attribute` = `username`, `claim.name` = `sub`, `jsonType.label` = `String`, and `access.token.claim`, `id.token.claim`, `userinfo.token.claim` and `introspection.token.claim` all `true`. A `409` (a concurrent add) is not an error.
   - If a mapper with the name `username-to-sub` exists, makes it the same as this expected mapper (`_converge_subject_mapper`). It compares the mapper type and only the config keys above, so config keys that Keycloak adds do not cause a write. A correct mapper gets no write (idempotent). If only the config is wrong (for example `claim.name` = `preferred_username`, or `access.token.claim` = `false`), it calls `admin.update_mapper_in_client_scope(scope_id, mapper_id, {..., "id": mapper_id})` (a `PUT`; Keycloak replaces the full config, and Keycloak 26.0 reads the mapper ID from the payload). If the type is wrong, it calls `admin.delete_mapper_from_client_scope(scope_id, mapper_id)` and then adds the expected mapper; a `404` on the delete or a `409` on the add (a concurrent onboarding did the same fix) is not an error. Without this step, a wrong mapper keeps `sub` = the Keycloak user ID and the onboarding reports success.
   - It does not change, delete or fail on a mapper with a different name that also writes `sub`. AIAC did not make that mapper, and it can be the same mapping with a different name.
   - Reads the full scope representation with `admin.get_client_scope(scope_id)`.
2. If the scope is in `admin.get_client_optional_client_scopes(service_id)`, calls `admin.delete_client_optional_client_scope(service_id, scope_id)`. Keycloak does not add a default link for a scope that is already linked as optional (and gives no error), and the mapper of an optional scope runs only when the token request names that scope. So an optional link would silently leave `sub` = the user ID.
3. Calls `admin.add_client_default_client_scope(service_id, scope_id, {})`. Keycloak does not add a default link that already exists (and gives no error), so a second call changes nothing ("already linked" is success).
4. Returns `200 OK` with the scope JSON.
5. Returns `409 Conflict` with `{"error": ...}` if the existing `aiac-username-sub` carries the `aiac.managed` marker. The message names the scope, D31 and the fix (remove the attribute).
6. Returns `502 Bad Gateway` with `{"error": ...}` on `KeycloakError`.

Why the scope: the Keycloak standard token exchange (V2) applies only the scopes of the requester client (the agent). So the `username-to-sub` mapper of the login client (`rossoctl`) never gets into an exchanged token, but the mapper of a scope that is linked to the agent client does. The endpoint links the scope only to the client `service_id`. It never changes another client (the login client `rossoctl` keeps its own mapper and does not get the scope), and it never makes the scope a realm default scope. If the scope or its mapper is deleted, the next onboarding creates it again. If the mapper is changed, the next onboarding changes it back. See [the analysis](../../analysis/user-subject-across-token-exchange.md) (§1.5, §8.1).

`POST /roles`:
Accepts JSON body `{"name": ..., "description": ...}`. It:
1. Calls `admin.create_realm_role({"name": ..., "description": ..., "attributes": {"aiac.managed": ["true"]}})` to create the role at realm level. The `aiac.managed` attribute is the AIAC provisioning marker (realm-role attribute values are lists of strings).
2. Returns `201 Created` with the created role JSON (`{"id": ..., "name": ..., "description": ...}`).
3. Returns `409 Conflict` if a role with that name already exists.
4. Returns `502 Bad Gateway` with `{"error": ...}` on `KeycloakError`.

`GET /services/{service_id}/roles`: returns this service's agent roles (`R_A` in the PCE
derivation) from **two** sources, both stamped `kind = Agent`, `actorIds = [this client's
serviceId]`:
1. **Client roles** on the service's own client — `admin.get_client_roles(service_id)`. Each
   `RoleRepresentation` carries `clientRole: true` and `containerId` (the client UUID); the owner is
   resolved from `containerId` → `get_client(containerId)["clientId"]`.
2. **`aiac.managed` realm roles assigned to the service account** — `get_client_service_account_user(service_id)`
   → `get_realm_roles_of_user(user_id)`. This is how the `Configuration` library provisions an agent's
   roles (`POST /services/{id}/roles/{role_id}` → `assign_realm_roles` on the service account, below),
   so without it a library-onboarded agent would expose no roles. The role-of-user stub omits
   attributes, so each is re-fetched via `get_realm_role_by_id` to test the `aiac.managed` marker;
   non-managed realm roles (e.g. `default-roles-<realm>`) are skipped. The owner is this service's own
   `clientId`.
3. Returns `200 OK` with the merged JSON array (client-role ids dedup against the realm-role set).
4. Returns `[]` if `KeycloakError` has `response_code == 400` (service has no client roles — not an
   error); a missing service account (Keycloak answers `400` or `404` on the service-account lookup)
   is caught and simply contributes no realm roles.
5. Returns `404 Not Found` with `{"error": ...}` when Keycloak answers `404` for the client (the same
   rule as `GET /services/{service_id}`).
6. Returns `502 Bad Gateway` with `{"error": ...}` on other `KeycloakError`.

> **Redesign note (SPM/APM + provisioning reconciliation).** Under the original SPM/APM redesign this
> endpoint sourced roles **only** from the client's client roles (`admin.get_client_roles`), on the
> premise that an agent's role is always a Keycloak client role (Assumption 3). In practice the write
> path (`POST /services/{id}/roles/{role_id}`, used by the `Configuration` library) assigns a **realm
> role to the service account**, not a client role — so the read and write paths did not meet, and a
> library-provisioned agent exposed no roles (empty `agent_roles` → all-deny outbound Rego; surfaced by
> the 5.3 live pipeline). The endpoint now returns **both** sources so the two paths reconcile. The
> long-term option of making provisioning create true client roles instead is tracked with issue 1.7.

`GET /services/{service_id}/scopes`:
1. Calls `admin.get_client_default_client_scopes(service_id)` to return the realm-level client scopes assigned as defaults to the service.
2. Sets `serviceId` (this service's `clientId`) on each scope. A scope that several clients link as a default scope (a shared scope, [D32](../PRD.md#key-architectural-decisions)) is listed for each of them, each time with that client as `serviceId`. So each owner gets its own copy of the scope. The endpoint does no owner check.
3. Returns `200 OK` with a JSON array of client scope objects. The array has **every** default scope of the client, also the scopes that have no `aiac.managed` marker: the Keycloak built-ins (for example `profile`) and the shared subject scope `aiac-username-sub` (D31). The consumers keep only the marked scopes (the `Scope.aiac_managed` filter: the PCE `owned_scopes`, and the own and other scopes in the AIAC Agent `focal_entities`), so an unmarked scope never becomes an own scope of the service.
4. Returns `404 Not Found` with `{"error": ...}` when Keycloak answers `404` for the client (the same rule as `GET /services/{service_id}`).
5. Returns `502 Bad Gateway` with `{"error": ...}` on other `KeycloakError`.

The items of `admin.get_client_default_client_scopes(service_id)` have only `id` and `name` (live check on realm `rossoctl`, 2026-10-06). The full representation, with the `aiac.managed` marker and the description, comes from `GET /scopes`: the library joins the two by `id` (see [`library-idp.md`](library-idp.md) → `get_services()`).

`POST /services/{service_id}/roles/{role_id}`:
1. Calls `admin.get_client_service_account_user(service_id)` to get the service account user.
2. Extracts `user["id"]` from the result.
3. Resolves the role via `admin.get_realm_role_by_id(role_id)`, then calls `admin.assign_realm_roles(user_id, [role])` to assign the realm role to the service account.
4. Returns `201 Created` on success. A repeat is also a success, with no second mapping: Keycloak skips the grant of a role that the service account already has, and gives no error (Keycloak 26.5.2, `UserAdapter.grantRole`).
5. Returns `409 Conflict` with `{"error": ...}` only when Keycloak itself answers `409`. A role that is already assigned does not give a `409`.
6. Returns `502 Bad Gateway` with `{"error": ...}` on other `KeycloakError`.

`GET /services/{service_id}/discovery-token`:
1. Calls `admin.get_client(service_id)` to resolve `client_id = client["clientId"]`.
2. Reads the client's **existing** secret (`client.get("secret")` or `admin.get_client_secrets(service_id)`)
   — **never** calls `generate_client_secrets` (rotating the live secret would break the deployed
   workload). Returns `502 Bad Gateway` if no secret is present (e.g. a public client).
3. Idempotently ensures a self-audience `oidc-audience-mapper` named `aiac-discovery-audience` is
   attached to the client (`get_mappers_from_client` then `add_mapper_to_client` only if absent), so the
   minted token's `aud` includes `client_id`.
4. Mints via `KeycloakOpenID(server_url=..., realm_name=realm, client_id=client_id,
   client_secret_key=secret).token(grant_type="client_credentials")` — i.e. as the **service's own
   client**, not the realm admin.
5. Decodes the minted token's payload (no signature check needed — this endpoint trusts its own mint)
   and asserts `client_id in aud`; if `AIAC_KEYCLOAK_ISSUER` is set, also asserts `iss` matches it.
   Returns `502 Bad Gateway` if either assertion fails — this endpoint never returns a token the
   consuming AuthBridge sidecar's `jwt-validation` plugin would reject.
6. Returns `200 OK` with `{"access_token": ..., "client_id": ..., "issuer": ..., "audience": [...]}`.
7. Returns `404 Not Found` with `{"error": ...}` when Keycloak answers `404` (the same rule as
   `GET /services/{service_id}`), and `502 Bad Gateway` with `{"error": ...}` on other `KeycloakError`.

`DELETE /services/{service_id}/roles/{role_id}` (teardown — remove role mapping + delete realm role):
1. Calls `admin.get_client_service_account_user(service_id)` and extracts `user["id"]`.
2. Resolves the role via `admin.get_realm_role_by_id(role_id)`, then calls `admin.delete_realm_roles_of_user(user_id, [role])` to remove the mapping from the service account (**unmap first**).
3. **Shared-object safety.** Before it deletes the realm role, it calls `admin.get_realm_role_members(role_name)` to confirm no other subject (user or service account) still holds it. If another subject holds the role, it stops after the unmap and does **not** delete the role. So a shared role ([D32](../PRD.md#key-architectural-decisions)) is deleted only when its last holder goes.
4. Calls `admin.delete_realm_role(role_name)` to delete the realm role.
5. Idempotent — an already-removed mapping or already-deleted role is treated as success.
6. Returns `200 OK` on success; `502 Bad Gateway` with `{"error": ...}` on `KeycloakError`.

`DELETE /services/{service_id}/scopes/{scope_id}` (teardown — remove scope mapping + delete client scope):
1. Calls `admin.delete_client_default_client_scope(service_id, scope_id)` to remove the default-scope assignment from the client (**unmap first**).
2. **Shared-object safety.** Before it deletes the client scope, it builds the owner index (`_build_scope_owner_index`: one pass over the default scopes of every client; it uses only the scope `id`, so it works on the live shape) and confirms no other client still has the scope assigned. If another client references the scope, it stops after the unmap and does **not** delete the scope. So a shared scope ([D32](../PRD.md#key-architectural-decisions)) is deleted only when its last owner goes.
3. Calls `admin.delete_client_scope(scope_id)` to delete the client scope.
4. Idempotent — an already-removed assignment or already-deleted scope is treated as success.
5. Returns `200 OK` on success; `502 Bad Gateway` with `{"error": ...}` on `KeycloakError`.

**Unset service type** (`POST /services/{service_id}/type` with an empty/clear type):
1. Calls `admin.get_client(service_id)` and copies its existing `attributes`.
2. Removes (or empties) the **`client.type`** attribute and calls `admin.update_client(service_id, {"attributes": {...}})`. The remaining attributes are merged, not clobbered — the same read-merge pattern as setting the type.
3. Idempotent — clearing an already-clear type is not an error.
4. Returns `200 OK` with the updated client JSON (re-fetched via `admin.get_client`); `502 Bad Gateway` with `{"error": ...}` on `KeycloakError`.

`POST /services/{service_id}/enabled` (enable/disable the client — the writer for `Service.enabled`):
Accepts JSON body `{"enabled": true | false}` (rejected with `422` otherwise). It:
1. Calls `admin.update_client(service_id, {"enabled": <bool>})`. Keycloak merges a partial client representation, so no read is necessary first.
2. Idempotent — disabling an already-disabled client (or enabling an already-enabled one) is not an error.
3. Returns `200 OK` with the updated client JSON (re-fetched via `admin.get_client`); `502 Bad Gateway` with `{"error": ...}` on `KeycloakError`.

The UC1 compensating rollback (see the AIAC Agent UC1 spec) consumes the two deletes and the enable/disable: it deletes the roles and scopes Provision created, and then disables the client as a failed-service marker. The rollback keeps the client type. It also keeps the shared subject scope `aiac-username-sub` and its link: the scope is not in the created-manifest (D31). The empty-type clear on `POST /services/{id}/type` stays in the service, but no library primitive or rollback calls it.

All endpoints except `/health` require a `?realm=<realm>` query parameter specifying the Keycloak realm to operate in. Returns `422 Unprocessable Entity` if the parameter is absent. `/health` accepts no realm parameter — it calls `_get_or_create_admin(os.environ["KEYCLOAK_ADMIN_REALM"])` directly.

All GET endpoints return `200 OK` with a JSON array on success, except `/subjects/{subject_id}/assignments` (a JSON object with `realmMappings` and `serviceMappings` fields), `/services/{service_id}`, `/services/{service_id}/discovery-token` and `/health`, which return a JSON object. All endpoints return `502 Bad Gateway` with a JSON error body if the Keycloak Admin API call fails, with these exceptions:
- `/health` returns `503` with `{"status": "unavailable", "error": ...}`.
- `GET /roles` returns `409 Conflict` on an Assumption 1 violation (a cross-kind role). `GET /services/{service_id}/scopes` has no `409`: a shared scope is valid (D32).
- `POST /services/{service_id}/subject-scope` returns `409 Conflict` when the shared subject scope `aiac-username-sub` carries the `aiac.managed` marker (D31).
- `POST /roles`, `POST /scopes`, `POST /services/{service_id}/roles/{role_id}` and `POST /services/{service_id}/scopes/{scope_id}` return `409 Conflict` when Keycloak answers `409` (for the two creates: the name already exists).
- The two `DELETE` endpoints return `200 OK` when Keycloak answers `404` (idempotent teardown).
- `GET /services/{service_id}/roles` returns `[]` when Keycloak answers `400`.
- The four reads of one service (`GET /services/{service_id}`, `GET /services/{service_id}/roles`, `GET /services/{service_id}/scopes` and `GET /services/{service_id}/discovery-token`) and `GET /roles/{role_name}/composites` return `404 Not Found` with `{"error": ...}` when Keycloak answers `404` ([D33](../PRD.md#key-architectural-decisions)). They are the reads of the onboarding read path that name one entity. The composites read is a sub-read of the library's `get_service`: a `404` there means that a composite role was deleted during the read, and the next `get_service` does not list the role. The other endpoints keep `502` for a Keycloak `404`: the other reads (`/subjects`, `/subjects/{subject_id}/assignments`, `/roles`, `/scopes`, `/services`) do not read one entity, and the writes run only after a read found the client.

A Keycloak `4xx` that is not in this list also gives `502`: for example a `400` for a bad request, a `403` for a missing admin permission, or a `404` on a write for a client that was deleted. The IdP library retries every `5xx` (see [`library-idp.md` → Transport retries](library-idp.md)), so it also sends such a request up to `UPSTREAM_MAX_RETRIES` times in total, and it gets the same answer each time.

### AIAC provisioning marker (`aiac.managed`)

Every role and client scope this service creates, except the shared subject scope (below), is stamped with the Keycloak attribute `aiac.managed` = `true` — the AIAC naming convention that distinguishes AIAC-provisioned entities from Keycloak's own built-ins (default client scopes, the `default-roles-<realm>` composite). Attribute value shape differs by entity: realm-role attribute values are lists (`{"aiac.managed": ["true"]}`), client-scope attribute values are plain strings (`{"aiac.managed": "true"}`). Because Keycloak's brief role representation omits attributes, `GET /roles` requests the full representation so the marker survives the read. Downstream consumers (the Policy Computation Engine's P2 embed) filter on this marker to keep only domain entities.

**Exception — the shared subject scope `aiac-username-sub` has no marker ([D31](../PRD.md#key-architectural-decisions)).** `POST /services/{service_id}/subject-scope` creates it with no `aiac.managed` attribute, and gives `409` if a scope of that name has the attribute. The scope is not a domain entity of one service: it is shared by every AIAC-managed client, and it only sets the token `sub` to the username. A marked scope would become an own scope of each linked service: the library's `get_services()` joins the default scopes of each client with the full representations of `GET /scopes`, so the marker would put the scope into the policy model and into the PRB candidates. With no marker, the consumers drop it as they drop a Keycloak built-in. See [the analysis](../../analysis/user-subject-across-token-exchange.md) (§8.1).

### Agent roles are client roles, field population, and assumption enforcement (SPM/APM)

Under the SPM/APM policy-model redesign the Policy Computation Engine (PCE) performs **no IdP lookup for routing or classification** — it relies on entities being self-describing (`Role.kind`, `Role.actorIds`, `Scope.serviceId`; the fields are defined in the models spec). The IdP Configuration Service is the **only** layer that sees Keycloak's raw facts, so it is where these fields are populated and where the underlying assumptions are validated. Field definitions live with the models (library) spec; this service **populates** them.

**Assumption 3 — an agent's role is a Keycloak _client role_ (or an `aiac.managed` _realm role_ assigned to the agent's service account); a user's role is a plain Keycloak _realm role_.** In Keycloak a `RoleRepresentation` carries `clientRole: bool` and `containerId` (the client UUID for client roles, the realm id for realm roles). An agent role therefore has **two** valid representations — a client role on the agent's client, or an `aiac.managed` realm role held by the agent's service account (the provisioning path) — and both are classified `kind = Agent`; only a realm role **not** owned by any service account is a `kind = User` role. This service holds the invariant end-to-end:

- **Agent roles.** `GET /services/{service_id}/roles` returns an agent's own roles (`R_A`) from two sources: the client's client roles (`admin.get_client_roles`, `clientRole == true`), **and** the `aiac.managed` realm roles assigned to the service account (the provisioning path the `Configuration` library uses). Both are surfaced as `kind = Agent` owned by this service — see the endpoint description and its Redesign note above.
- **User roles are realm roles.** `GET /roles` continues to read realm-level roles (`kind = User`), excluding the Keycloak-generated `default-roles-<realm>` composite (exact-name match). That composite is the _only_ path to Keycloak's built-ins (`offline_access`, `uma_authorization`, `view-profile`, the `account` client roles) — no user holds them directly — so dropping it keeps AIAC policy free of Keycloak built-ins without a per-name blocklist.

**Field population** (in the Keycloak → generic-model mapping layer, from the raw facts above):

- **`Role.kind`** — a role read via `GET /services/{service_id}/roles` is always `kind = Agent` (whether it came from the client's client roles or from an `aiac.managed` realm role on the service account); a realm role read via `GET /roles` is `kind = User`. Equivalently: agent-context (`clientRole == true`, or `aiac.managed` realm role held by a service account) → `Agent`; plain realm role → `User`. Kind is **never** inferred from role naming.
- **`Role.actorIds` per kind:**
  - `Agent`: the owning agent's `serviceId` — resolved from the role's `containerId` → client (`clientId`) — and/or the agent service account(s) that hold the role. `GET /services/{service_id}/roles` gives `[this client's serviceId]`, also for a realm role that several service accounts share (D32). Each service gets its own copy of the role; the consumers merge the holders of all the copies (see below).
  - `User`: the **member usernames** of the role. This aligns with `GET /subjects?role_id=` / `get_subjects_by_role`, which already resolves a role → its member subjects; the usernames it returns are exactly `actorIds` for a user (realm) role. (Set only for `aiac.managed` roles; built-ins get no `actorIds`.) These are the **direct** members: a role that a user holds only through a group or a composite parent role is not in the list. The PCE reads them at each render to get the current holders (D32).
- **`Scope.serviceId`** = the client of this listing: the **owner of this copy** of the scope. A scope that several clients share has one copy for each owner (D32). (Set only by `GET /services/{service_id}/scopes`; `GET /scopes` does not set it.)

**Fail-loud enforcement at this boundary** (detectable here via membership queries; do not silently pick a side):

- **Assumption 1 — no cross-kind role.** A role held by _both_ human users and agent service accounts cannot be represented by a single `actorIds` list. On violation, **raise/log** rather than choosing one kind.
- There is no single-owner check for a scope. The former Assumption 2 (one owner for each `aiac.managed` scope) and its `409` are removed ([D32](../PRD.md#key-architectural-decisions)); see the next section.

### Shared roles and scopes (D32)

A realm is a tenant, and one policy covers all AIAC-managed services in the realm, across namespaces ([D32](../PRD.md#key-architectural-decisions)). So two services can share a role or a scope. For example, `team1/github-tool` and `team2/github-tool` share the scope `github-tool.source-read`, and `team1/github-agent` and `team2/github-agent` share the role `github-agent.source_operations`.

- **Reuse by name.** UC-1 Provision names each role and scope `<workload>.<tool|skill>`, with no namespace. The library's `create_service_role` / `create_service_scope` reuse an existing realm role or client scope of the same name, then map it to the service. This service only creates (`POST /roles`, `POST /scopes`, which give `409` on an existing name) and maps (`POST /services/{service_id}/roles/{role_id}`, `POST /services/{service_id}/scopes/{scope_id}`). The reuse logic and the description warning are in the library (see [`library-idp.md`](library-idp.md)).
- **A shared scope.** `GET /services/{service_id}/scopes` lists the scope for each client that links it, each time with that client as `serviceId`. The PCE routes each copy to the SPM of its owner. The endpoint makes no owner check and gives no `409`. The former check never fired on a live system (the default-scope list has only `id` and `name`), and if it fired, its `409` would stop every catalog read in the realm.
- **A shared role.** `GET /services/{service_id}/roles` lists a realm role that several service accounts hold for each of them, with `actorIds = [that client's serviceId]`. The current holders come from the catalog at render time (the PCE), not from one copy.
- **The delete at the last owner.** `DELETE /services/{service_id}/scopes/{scope_id}` deletes the client scope only when the owner index shows no other client. `DELETE /services/{service_id}/roles/{role_id}` deletes the realm role only when it has no other member. Before that, each delete only unmaps the object from the caller.
- **A role-mapping change.** A role mapping (`POST /services/{service_id}/roles/{role_id}`) or an unmap (`DELETE /services/{service_id}/roles/{role_id}`) is a Keycloak `REALM_ROLE_MAPPING` admin event. The Keycloak SPI publishes `aiac.apply.role-members.{role-id}` for it, and the Controller renders the CRs that use the role again (see [`keycloak-spi/README.md`](../../../keycloak-spi/README.md)).
- The shared subject scope `aiac-username-sub` (D31) is a different case: it is linked to every AIAC-managed client, but it has no `aiac.managed` marker, so it is never an own scope of a service.

## Configuration

Environment variables (injected via Kubernetes Deployment manifest):

| Variable | Required | Description |
|----------|----------|-------------|
| `KEYCLOAK_URL` | Yes | Keycloak base URL, e.g. `http://keycloak-service.keycloak.svc:8080` |
| `KEYCLOAK_ADMIN_REALM` | Yes | Realm where the admin credentials live, e.g. `master` |
| `KEYCLOAK_ADMIN_USERNAME` | Yes | Admin username (from `keycloak-admin-secret`) |
| `KEYCLOAK_ADMIN_PASSWORD` | Yes | Admin password (from `keycloak-admin-secret`) |
| `AIAC_KEYCLOAK_ISSUER` | No | If set, `GET /services/{service_id}/discovery-token` asserts that the minted token's `iss` equals this value |

## Runtime

- Framework: FastAPI
- Server: uvicorn
- Bind: `0.0.0.0:7071`
- Base image: `python:3.13-slim` (digest-pinned)
- Kubernetes ClusterIP Service: `aiac-pdp-config-service:7071`
- Deployment: co-located with PDP Policy Writer as a container in the **Rossoctl Interface Pod** (`pdp-interface-deployment.yaml`)
- Python library: `aiac.idp.configuration`

## Dependencies (`requirements.txt`)

```
fastapi
uvicorn[standard]
python-keycloak
python-dotenv
pydantic
```

## File structure

```
src/aiac/idp/service/
├── __init__.py
└── configuration/
    ├── __init__.py
    └── keycloak/
        ├── __init__.py
        ├── Dockerfile
        ├── keycloak_admin_methods.md
        ├── requirements.txt
        └── main.py
```

Build command (the build context is the component directory, because the Dockerfile copies `requirements.txt` and `main.py` from there):
```bash
docker build -f src/aiac/idp/service/configuration/keycloak/Dockerfile \
  -t localhost/aiac-pdp-config:local src/aiac/idp/service/configuration/keycloak/
```

## `main.py` behaviour notes

- Maintain a `dict[str, KeycloakAdmin]` cache keyed by realm name, protected by a `threading.Lock`.
- `get_admin(realm: str = Query(...))` is a FastAPI dependency. On each call it checks the cache; on a miss it acquires the lock, double-checks, and constructs a new `KeycloakAdmin(realm_name=realm, user_realm_name=KEYCLOAK_ADMIN_REALM, ...)`. FastAPI returns `422` automatically if `realm` is absent.
- All endpoints except `/health` declare `admin: KeycloakAdmin = Depends(get_admin)`. `/health` calls `_get_or_create_admin` directly with `os.environ["KEYCLOAK_ADMIN_REALM"]` — no FastAPI dependency, no realm query param.
- Each GET endpoint calls the corresponding `python-keycloak` method and returns the result (enriched where noted above). Errors are returned via `JSONResponse`.
- `GET /roles`: call `admin.get_realm_roles(brief_representation=False)`, then drop the role named `default-roles-{realm}` (the Keycloak-generated default composite for the realm) before enrichment.
- `GET /services/{service_id}/roles`: see the detailed contract above.
- `GET /services/{service_id}/scopes`: call `admin.get_client_default_client_scopes(service_id)`, then set `serviceId` = `admin.get_client(service_id)["clientId"]` on each scope. No owner check (D32).
- `GET /roles/{role_name}/composites`: call `admin.get_composite_realm_roles_of_role(role_name=role_name)`.
- `POST /services/{service_id}/roles/{role_id}`: call `admin.get_client_service_account_user(service_id)` → extract `user["id"]` → resolve the role via `admin.get_realm_role_by_id(role_id)` → call `admin.assign_realm_roles(user_id, [role])`.
- `DELETE /services/{service_id}/roles/{role_id}`: `get_client_service_account_user(service_id)` → `get_realm_role_by_id(role_id)` → `delete_realm_roles_of_user(user_id, [role])` (unmap first), then — only if `get_realm_role_members(role_name)` is empty (no other subject holds it) — `delete_realm_role(role_name)`.
- `DELETE /services/{service_id}/scopes/{scope_id}`: `delete_client_default_client_scope(service_id, scope_id)` (unmap first), then — only if `_build_scope_owner_index(admin)` shows no other client that has it assigned — `delete_client_scope(scope_id)`.
- Unset type (`POST /services/{service_id}/type` with an empty type): `get_client(service_id)` → drop the `client.type` attribute → `update_client(service_id, {"attributes": {...}})` (read-merge, same as set).
- `POST /services/{service_id}/subject-scope`: `_ensure_subject_scope(admin)` — find `aiac-username-sub` (`_SUBJECT_SCOPE`) by name in `get_client_scopes()` → `create_client_scope(...)` if it is absent (a `409` → find it by name again) → raise `_InvariantViolation` if it has the `aiac.managed` marker → `get_mappers_from_client_scope(scope_id)` → `add_mapper_to_client_scope(scope_id, ...)` if no mapper has the name `username-to-sub` (`_SUBJECT_MAPPER`; a `409` is success), or else `_converge_subject_mapper` makes the existing `username-to-sub` mapper the same as `_SUBJECT_MAPPER_REPRESENTATION` (it compares the type and only the keys of the expected config: no write if they agree; `update_mapper_in_client_scope(scope_id, mapper_id, {..., "id": mapper_id})` if only the config is wrong; `delete_mapper_from_client_scope` then add if the type is wrong, with `404`/`409` as success; other mappers that write `sub` are not changed) → `get_client_scope(scope_id)`. Then `delete_client_optional_client_scope(service_id, scope_id)` if the scope is in `get_client_optional_client_scopes(service_id)` → `add_client_default_client_scope(service_id, scope_id, {})`. `_InvariantViolation` → `409`; `KeycloakError` → `502`.
- `POST /services/{service_id}/enabled`: `update_client(service_id, {"enabled": <bool>})` → `get_client(service_id)` (re-fetch). This is the writer for `Service.enabled`; all service reads already return the client representation unmodified (see above), so `enabled` is surfaced on read for `get_service` / `get_services`.
- On `KeycloakError`, return HTTP 502 with `{"error": str(e)}`, with the exceptions in the error list above. The four reads of one service and `GET /roles/{role_name}/composites` return `_read_error(e)`: `404` when `e.response_code == 404`, else `502`, with the same body.
