# Component PRD: PDP Policy Writer (OPA)

## Location
`src/aiac/pdp/service/policy/opa/`

## Description
A FastAPI web service that translates a **policy model** into OPA Rego packages and, for each managed service (agent or tool), **server-side-applies** the two generated packages into a per-service `AuthorizationPolicy` Kubernetes Custom Resource (`agent.rossoctl.dev/v1alpha1`, `scope: client` — one CR per managed service). The policy model carries its **enforcement side** as a tag, and the writer renders the packages of that side (see [What each side renders](#what-each-side-renders)). The writer only renders Rego and deploys the CRs. It does no join: the PCE builds the policy model (D18, D18b). The `bundle-service` (operator repo) composes those per-service CRs into per-pod OPA bundles; the OPA plugin embedded in each AuthBridge instance polls the bundle relevant to its pod and evaluates it.

The service is deployed as a container in the **Rossoctl Interface Pod** alongside the IdP Configuration Service, behind the `aiac-pdp-policy-service:7072` ClusterIP.

The service has no dependency on Keycloak. All Keycloak operations (entity reads) are handled by the **IdP Configuration Service** and its library (`aiac.idp.configuration`). The legacy Keycloak composite / authorization-services policy writer has been **removed**; this OPA CR writer is the sole policy-writer surface.

---

## Pydantic models (`aiac.policy.model.models`)

The Policy Writer deserializes the **canonical** `AnyPolicyModel` / `ServicePolicyModel` / `AgentPolicyModel` / `PolicyRule` defined in [policy-model.md](policy-model.md) and imported from `aiac.policy.model.models`. This service does **not** define its own copies; the tables below summarize the fields the Rego generator consumes. (The former `aiac.pdp.library.models` module has been removed — see policy-model.md "Replaces".)

The input of `POST /policy` and `PUT /policy` is `AnyPolicyModel` (see [The policy model](#the-policy-model-anypolicymodel-d18a)). Pydantic parses the body into one subclass. The writer dispatches on the subclass, and it reads the enforcement side from the tag.

All models use `model_config = ConfigDict(extra='ignore')`.

### `PolicyRule`

A single access rule pairing a typed role with a typed scope. Used in both inbound and outbound rule sets.

| Field | Type |
|-------|------|
| `role` | `Role` |
| `scope` | `Scope` |
| `effect` | `RuleEffect` (`Allow` default / `Deny`) |

`Role` and `Scope` are the typed models from `aiac.idp.configuration.models`. The Rego generator emits their `.name` as the string literal OPA matches against. `effect` selects whether the rule contributes to an `*_allow_scopes` or `*_deny_scopes` map (see below).

### `ServicePolicyModel` (SPM) — target side

The stored policy of one service, agent or tool. Under target side it is the render input of the service's CR. Every edge that the callee checks on its inbound is already on its own SPM, because a rule is stored on the SPM of the service that owns the rule's scope. So the writer projects one SPM. It does no join.

| Field | Type | Use in the target-side rendering |
|-------|------|----------------------------------|
| `service_id` | `str` | The service's clientId (`<ns>/<name>` or a SPIFFE URI); `identity_ref` maps it to the CR's `(namespace, name)`. |
| `service_type` | `ServiceType` (`Agent` / `Tool`) | Selects the inbound package: the [agent inbound](#agent-inbound-package-authbridgeclientinboundrequest) (D26a) or the [tool inbound](#tool-inbound-package-target-side-authbridgeclientinboundrequest) (D26). |
| `owned_roles` | `list[Role]` | Not rendered. Under target side the outbound package is a pass-through (D24). |
| `owned_scopes` | `list[Scope]` | Agent: `agent_scopes` (full scope names). Tool: `owned_tools` (the bare MCP tool names, de-prefixed). |
| `inbound_allow_rules` / `inbound_deny_rules` | `list[PolicyRule]` | Every inbound edge on the owned scopes. The shared projection splits them into the user gate and the calling-agent gate. |

**Shared projection (D18b).** The target-side renderer calls `project_inbound(spm)` (`aiac.policy.model.projection`; pure, zero I/O). It splits the SPM's inbound edges by `role.kind` (User → subject, Agent → source) and by effect into `subject_allow_rules`, `subject_deny_rules`, `source_allow_rules` and `source_deny_rules`. It also builds the effect-agnostic identity maps `subject_roles` (username → roles) and `source_roles` (calling clientId → roles). The PCE's `_derive` builds the APM inbound with the same function. So, for one SPM, both sides give the same inbound gates.

### `AgentPolicyModel` (APM) — agent side

The derived policy of one agent, under agent side only. The PCE derives it in memory at each deploy (a join over the SPMs of the services that the agent calls) and never stores it. Contains two sets of `PolicyRule` entries plus supporting data maps used by the Rego packages.

| Field | Type | Description |
|-------|------|-------------|
| `agent_id` | `str` | The agent's clientId (`<ns>/<name>` or a SPIFFE URI); `identity_ref` maps it to the CR's `(namespace, name)`. Not the Keycloak UUID that the `aiac.apply.service.{id}` trigger carries. |
| `agent_roles` | `list[Role]` | Realm roles assigned to this agent. Effect-agnostic identity. |
| `agent_scopes` | `list[Scope]` | Scopes this agent exposes. Effect-agnostic identity. |
| `source_roles` | `dict[str, list[Role]]` | Inbound: source (calling service) **id** → roles held. Keyed by the inbound `input.identity.client_id`. **Optional** gate input — an absent `client_id`, or a platform bypass client, passes. Effect-agnostic; **includes deny-edge roles**. |
| `subject_roles` | `dict[str, list[Role]]` | Inbound + outbound: subject (end-user) **username** → roles held. Keyed by `input.identity.subject`, the JWT `sub`, which is the username on every leg (D31); on the agent-side outbound it comes from `delegation.origin`. Inbound gate: **mandatory**. Effect-agnostic; **includes deny-edge roles**. |
| `target_allow_scopes` | `dict[str, list[Scope]]` | Outbound: target service **id** → scopes this agent **may** request on it. Keys stay the **full** target service id (matching `input.identity.service_id`, a full SPIFFE ID); the scope **values** are de-prefixed to the bare MCP tool names carried in `input.mcp.params.name` (Q9). |
| `target_deny_scopes` | `dict[str, list[Scope]]` | Outbound: target service **id** → scopes this agent **must not** request on it. Same key/value shape as `target_allow_scopes` (full target service id keys, de-prefixed scope values). |
| `inbound_subject_allow_rules` / `inbound_subject_deny_rules` | `list[PolicyRule]` | Who may / must-not call this agent: `(subject_role, agent_scope)` tuples |
| `inbound_source_allow_rules` / `inbound_source_deny_rules` | `list[PolicyRule]` | Which calling services may / must-not call this agent: `(source_role, agent_scope)` tuples |
| `outbound_target_allow_rules` / `outbound_target_deny_rules` | `list[PolicyRule]` | What this agent may / must-not call: `(this_agent_role, target_scope)` tuples |
| `outbound_subject_allow_rules` / `outbound_subject_deny_rules` | `list[PolicyRule]` | Which users may / must-not reach the agent's targets: `(user_role, tool_scope)` tuples. Default `[]`. |

**`agent_roles` / `agent_scopes` provenance:** these carry the agent's **own** identity — the service-account realm roles it holds and the scopes it exposes. The Policy Computation Engine resolves them from the agent's IdP `Service` record (P2) and embeds them on every agent model it writes; a realm-level agent with no owning service keeps `[]`. Together with `subject_roles` / `source_roles` they are **effect-agnostic**: a role appearing only in a DENY rule is still listed here, so the Rego deny lookup can resolve it.

**Inbound rule semantics (deny-overrides):** a subject holding realm role `role` may invoke this agent for agent scope `scope` iff an allow edge grants it and no deny edge prohibits it. Grouped by role, the allow/deny lists become `subject_role_allow_scopes` / `subject_role_deny_scopes` (and `source_role_allow_scopes` / `source_role_deny_scopes`) that the inbound package evaluates.

**Outbound target rule semantics (deny-overrides):** this agent acting as realm role `role` may request target scope `scope` iff an allow edge grants it and no deny edge prohibits it. Grouped by role, the allow list becomes the single informational `agent_role_scopes` map, and the effective capability gate materializes into `target_allow_scopes` / `target_deny_scopes`.

**No default effect.** `AgentPolicyModel` has no default-effect field. A `(role, scope)` pair that no rule mentions is always denied (`default allow := false` in both packages). A legacy payload that still carries `default_effect` is accepted and the field is ignored (`extra='ignore'`).

**Outbound subject rule semantics (deny-overrides):** a subject holding realm role `role` (a **user** role) may reach a **tool** exposing scope `scope` iff an allow edge grants it and no deny edge prohibits it. Grouped by role, the lists become `subject_role_allow_scopes` / `subject_role_deny_scopes` (user role → tool scopes) that the **outbound** package's subject gate evaluates as `tool in subject_role_allow_scopes[role]` (the function `subject_allows(tool)`, mirrored by `subject_denies(tool)` against `subject_role_deny_scopes`; it is applied to `input.mcp.params.name` for `tools/call`, and to each tool of the target for the MCP session messages); their scope **values** are **de-prefixed** to the bare MCP tool name (Q9). This is distinct from the inbound subject rules (user → *agent* scope): the outbound subject gate answers "may this user reach the tool?", not "may this user call the agent?".

**Note on target-map direction:** `target_allow_scopes` / `target_deny_scopes` are keyed by **target service id → scopes** (the inverse of the former `scope_targets`, which was `scope → targets`). The outbound Rego generator emits the **full** target service id as the map key and evaluates `target_allow_scopes[input.identity.service_id]` / `target_deny_scopes[input.identity.service_id]` directly — there is no inversion (see below). Only the scope **values** are de-prefixed to bare MCP tool names; the **keys** stay the full target service id (Q9).

### The policy model (`AnyPolicyModel`, D18a)

`PolicyModel` is the base class. It has one field, the tag `enforcement_side: EnforcementSide` (`target-side` or `agent-side`). The base is never sent on its own. `AnyPolicyModel` is the discriminated union of the two subclasses on that tag:

| Class | `enforcement_side` | Fields |
|-------|--------------------|--------|
| `TargetSidePolicyModel` | `"target-side"` | `services: list[ServicePolicyModel]` — stored SPMs, one per callee |
| `AgentSidePolicyModel` | `"agent-side"` | `agents: list[AgentPolicyModel]` — the APMs; `pass_through: list[str]` (default `[]`) — the clientIds of the managed tools |

- In each subclass the tag is a `Literal` class constant with a default. Code never sets it by hand.
- Pydantic parses the body into one subclass by the tag. The models ignore unknown fields, so pydantic alone would drop the entry fields of the other side, and a `PUT` would then delete their CRs. So the writer adds two checks to the body of `POST /policy` and `PUT /policy` (`_one_side_only` and `_no_agent_pass_through` in `main.py`). Each one rejects the body with **422**, and nothing is written:
  - a body that has an entry field of the other side, also an empty one (for example `services` in an agent-side body, or `agents` or `pass_through` in a target-side body);
  - an agent-side model that has an agent also in `pass_through`. The writer writes the entries in order, so the pass-through CR would replace the agent CR and open the agent. The PCE never builds such a model.
- A body with a wrong or missing tag is rejected with **422**. The old shape `{"agents": [...]}` has no tag, so it is also a 422.
- The writer reads the enforcement side from the tag, never from an env var (D29).
- A policy model is partial or full. `POST /policy` gets only the affected services of one PCE run (D23). `PUT /policy` gets the full model of the current side (the resync, D28; the rebuild, D28a).

An **entry** is one CR to write:

| Side | Entries |
|------|---------|
| target side | each `services[]` SPM |
| agent side | each `agents[]` APM (the agent CR), and each `pass_through[]` clientId (a pass-through CR) |

### Usage

```python
from aiac.policy.model.models import (
    AgentPolicyModel,
    AgentSidePolicyModel,
    AnyPolicyModel,
    PolicyRule,
    ServicePolicyModel,
    TargetSidePolicyModel,
)
```

---

## Endpoints

No `?realm=` parameter — the service operates on a Kubernetes CR, not a Keycloak realm.

| Method | Path | Body | Operation |
|--------|------|------|-----------|
| `POST` | `/policy` | `AnyPolicyModel` | Upsert one CR per entry (no rollback on a partial failure) |
| `PUT` | `/policy` | `AnyPolicyModel` | Replace: upsert every entry, then delete every other CR that has the managed-by label |
| `DELETE` | `/policy/services/{service_id:path}` | — | Delete the CR of one service (the quarantine and the decommission); a k8s 404 is success |
| `DELETE` | `/policy` | — | Delete every CR that has the managed-by label, cluster-wide |
| `GET` | `/health` | — | Readiness probe |

Retired: `POST /policy/agents/{agent_id:path}` and `DELETE /policy/agents/{agent_id:path}`. They do not exist.

The callers:

- `POST /policy` — the PCE deploy stage, after each run (D23): the affected services only. Also the PCE `bootstrap`, before the Provision of a tool: the CR of that tool only (see [Tool inbound package](#tool-inbound-package-target-side-authbridgeclientinboundrequest)). Also the redeploy of the quarantine and the decommission, in one call after the CR delete (see [Quarantine and decommission](#quarantine-and-decommission--the-cr-delete-d20)). Also the PCE `rerender_role` (D32, the role-members event): under target side, the live stored SPMs that have an edge of the role; under agent side, every live stored agent (see [policy-computation-engine.md → Role re-render](policy-computation-engine.md#role-re-render-rerender_role)). There is no call when the set is empty.
- `PUT /policy` — the resync at every Controller start (D28), and the UC-2b rebuild (D28a; **Status: not built yet** — `rebuild_policy()` is a stub). Both send the full policy model of the current side. The rebuild does not start with `DELETE /policy`, so it has no deny window under D20.
- `DELETE /policy/services/{service_id:path}` — the PCE quarantine and decommission (D20).
- `DELETE /policy` — no AIAC caller (C1). It stays as an operator tool. Under D20 it denies every managed pod.

**`PUT /policy` (replace).** The writer upserts every entry. Then it lists every CR with the managed-by label, cluster-wide, and deletes each CR whose `(namespace, name)` is not an entry of the model. A CR without the label is never touched. An empty model deletes every AIAC CR. The delete step runs only after every upsert succeeded: if an upsert fails, the PUT returns the error and deletes nothing.

**`{service_id:path}`.** The id is a SPIFFE URI or `<ns>/<name>`, so it contains `/`. The server decodes the library's `%2F` back to `/` before routing, so a single-segment `{service_id}` never matches it (HTTP 404).

### Status codes

| Endpoint | Success | Error |
|----------|---------|-------|
| `POST /policy` | `204 No Content` | **400** `{"error": …}` for a malformed / namespace-less id (an SPM `service_id`, an APM `agent_id` or a `pass_through` id; the batch aborts, naming the bad id; entries already applied stay written — no rollback); **422** for a body with a wrong or missing tag (pydantic), a body that mixes the sides, or an agent-side model that has an agent also in `pass_through` (see [The policy model](#the-policy-model-anypolicymodel-d18a)); nothing is written; **502** `{"error": …}` for a Kubernetes API failure (or the additive dump's `OSError`) |
| `PUT /policy` | `204 No Content` | The same as `POST /policy`. An error in the upsert step stops the PUT before the delete step. A per-item 404 in the delete step is success (a concurrent delete) |
| `DELETE /policy/services/{service_id:path}` | `204 No Content` | **400** for a malformed id; **502** for a Kubernetes API failure. Deleting a **missing** CR is a no-op **204** (k8s 404 treated as success — idempotent) |
| `DELETE /policy` | `204 No Content` | **502** for a Kubernetes API failure |
| `GET /health` | `200 OK` `{"status": "ok"}` | `503 Service Unavailable` `{"status": "unavailable", "error": …}` if the bounded CR list fails |

`GET /health` performs a bounded (`limit=1`) cluster-wide list of the CRD: a successful list — **including an empty one** — is `200`; any failure (unreachable API, RBAC-forbidden, CRD not served) is `503`.

**400 vs 502 (Q11).** `400` is reserved strictly for a malformed / namespace-less id — the `identity_ref` `ValueError`, whose message names the bad id. `502` is strictly for Kubernetes API failures and the additive rego dump's `OSError`. The two are never conflated. **422** is a body that does not parse (FastAPI / pydantic validation, for example a wrong or missing `enforcement_side` tag) or that fails one of the two body checks (a body that mixes the sides, or an agent that is also in `pass_through`); a 400 is a parsed body with a bad id.

---

## Rego package structure

For each entry, the service generates **two Rego packages** — one for the inbound pipeline and one for the outbound pipeline — and server-side-applies them as the two `policies[]` entries of the service's `AuthorizationPolicy` CR. Every managed service gets both request packages (D20). There are no response packages.

**Fixed package names — no slug (Q2).** Both packages use **fixed** names, regardless of service and side:

| Tier | Package | CR `policies[].path` |
|------|---------|----------------------|
| inbound | `authbridge.client.inbound.request` | `inbound/request.rego` |
| outbound | `authbridge.client.outbound.request` | `outbound/request.rego` |

Each package begins with `import rego.v1`. The names never contain a slug: the `bundle-service` combiner requires the **exact** path `data.authbridge.client.<tier>`, so a per-service package name would break the composition. Per-service isolation is achieved at the **CR / bundle level** — bundle-service looks a CR up by namespace + name — not in the package name.

**`identity_ref` drives the CR metadata, not a package name (Q3).** `identity_ref(service_id) -> (namespace, name)` accepts a SPIFFE URI (`spiffe://<trust-domain>/ns/<ns>/sa/<name>`) or a plain `<ns>/<name>` clientId, validates both segments as DNS-1123 labels (`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`, ≤63 chars), and returns the `(namespace, name)` used for the CR's `metadata`. There is **no** fallback — a bare `github-agent` (no derivable namespace) or an invalid label raises `ValueError` (→ 400). This function replaces the former per-package slug: it feeds `metadata`, never a package name.

> **Two identifiers, two layers (no contradiction).** UC-1 onboarding and the Trigger use the internal Keycloak **client UUID** (`service.id` / `Trigger.entity_id`) purely to *look up* a service in the IdP — that UUID **never reaches this writer**. What flows down the policy pipeline into `PolicyRule.scope.serviceId` / `Role.actorIds` and lands as `ServicePolicyModel.service_id`, `AgentPolicyModel.agent_id` or a `pass_through` id is the **clientId** (the `<ns>/<name>` / SPIFFE form), which `identity_ref` maps to the CR's `(namespace, name)`. The UC-1 Orchestrator resolves the UUID to the clientId once (one `get_service()` read), before the policy model is ever built.

### What each side renders

The writer renders the packages of the side that the policy-model tag names. Every managed service gets a CR with both request packages under both sides (D20):

| Side | Entry | `inbound/request.rego` | `outbound/request.rego` |
|------|-------|------------------------|-------------------------|
| target side | SPM of a tool | [tool inbound](#tool-inbound-package-target-side-authbridgeclientinboundrequest) (D26) | [pass-through](#pass-through-package-d24) (D24) |
| target side | SPM of an agent | [agent inbound](#agent-inbound-package-authbridgeclientinboundrequest) (D26a) | [pass-through](#pass-through-package-d24) (D24) |
| agent side | APM (`agents[]`) | [agent inbound](#agent-inbound-package-authbridgeclientinboundrequest) | [agent outbound](#agent-outbound-package-agent-side-authbridgeclientoutboundrequest) (per-tool checks + the MCP session rule) |
| agent side | `pass_through[]` id (a managed tool) | [pass-through](#pass-through-package-d24) | [pass-through](#pass-through-package-d24) |

- **Target side.** Each callee checks the access to itself in its own inbound OPA, from its own CR. The render input is the stored SPM of the callee. The writer selects the tool inbound or the agent inbound from `service_type`. The outbound of every service, tools included, is a pass-through: the callee decides.
- **Agent side.** The agent CR is the legacy rendering: the agent inbound and the agent outbound, from the APM. Each managed tool gets a pass-through CR, because a pod that has no CR is denied (D20), also on its outbound.
- A side change replaces both packages of every CR in one write (`spec.policies` is atomic; see [the CR](#authorizationpolicy-custom-resource-q6)).

### Pass-through package (D24)

A pass-through package allows every request. The pass-throughs are the only ALLOW packages (D25):

```rego
package authbridge.client.outbound.request
import rego.v1

allow := true
```

The inbound pass-through is the same, with `package authbridge.client.inbound.request`. A **pass-through CR** has a pass-through package in both tiers.

### Live plugin input shape (Q4)

The Rego packages evaluate the `input` document the live AuthBridge OPA plugin populates — never IDs-plus-roles supplied per request. The fields the packages read:

| Input field | Meaning | Package |
|-------------|---------|---------|
| `input.identity.subject` | The delegated end-user **username**: the JWT `sub`, which is the username on every leg (D31). On the agent-side outbound, the plugin takes it from `delegation.origin` (the `sub` of the token that came into the agent) | agent inbound, tool inbound, agent outbound |
| `input.identity.client_id` | The calling client (the JWT `azp` claim). On an agent inbound: the source. On a tool inbound: the calling agent, or the tool itself for the UC-1 discovery token | agent inbound, tool inbound |
| `input.identity.service_id` | The downstream target audience the exchanged token was minted for — a **full SPIFFE id**. The inbound input has **no** `service_id` (cortex `core/plugins/opa/plugin.go`) | agent outbound |
| `input.mcp.method` | The MCP JSON-RPC method (`tools/call`, `tools/list`, `initialize`, …). The plugin always sets it (`buildMCPInput` in the cortex OPA plugin, `core/plugins/opa/plugin.go`) | tool inbound, agent outbound |
| `input.mcp.params.name` | The **bare** invoked MCP tool name (e.g. `source-read`). Only `tools/call` carries it | tool inbound, agent outbound |

On the agent outbound leg there is no validated JWT; the plugin synthesizes `input.identity` from the token-exchange delegation hop. An **absent** `input.identity.service_id` matches nothing in the maps and is therefore **denied**. A request with no tool name (for example `tools/list`) is allowed only as an MCP session message (see [Agent outbound package](#agent-outbound-package-agent-side-authbridgeclientoutboundrequest)).

On an inbound leg, `jwt-validation` sets `input.identity` from the validated token. When an agent calls a tool, that token is the one the agent's `token-exchange` minted for the tool's audience. So on the tool inbound, `subject` is the delegated user's username (D31: the agent client links the client scope `aiac-username-sub`, which sets `sub` to the username in the exchanged token) and `client_id` is the calling agent's clientId. The UC-1 discovery token is different: the IdP Configuration Service mints it as the tool's own client (client credentials), so its `azp`, and thus `client_id`, is the tool's own clientId. Its subject is not a user. `sub` is `service-account-<clientId>` when the tool's client links `aiac-username-sub`, or the user ID of the service account at the first onboarding (discovery runs before Provision links the scope). The user gate keys users by the usernames of the user-role holders, so this subject matches no key of `subject_roles`. Only the self-discovery rule (`input.identity.client_id == self_client_id`) allows its session messages (D26).

The agent packages embed these symbols. Under agent side they come from the APM. Under target side the agent inbound gets them from the projection of the agent's SPM: `agent_scopes` is `owned_scopes`, and the identity maps and the four inbound role maps come from `project_inbound(spm)`. The tool inbound symbols are in [their own table](#tool-inbound-package-target-side-authbridgeclientinboundrequest).

**Symmetric rename — no alias, no back-compat.** The single inbound `role_scopes` map splits into `subject_role_allow_scopes` / `subject_role_deny_scopes` / `source_role_allow_scopes` / `source_role_deny_scopes`; the outbound `subject_role_scopes` splits into `subject_role_allow_scopes` / `subject_role_deny_scopes`; `target_scopes` splits into `target_allow_scopes` / `target_deny_scopes`. Identity maps `subject_roles` / `source_roles` / `agent_roles` keep their names.

| Rego symbol | Source | Shape | De-prefixed? |
|-------------|--------|-------|--------------|
| `agent_scopes` | `model.agent_scopes` | `[scope.name, …]` — **inbound only** (the audience gate) | no — full scope names |
| `subject_roles` | `model.subject_roles` | username → `[role.name, …]` (effect-agnostic; includes deny-edge roles) | n/a (roles) |
| `source_roles` | `model.source_roles` | source client id → `[role.name, …]` — **inbound only** (effect-agnostic; includes deny-edge roles) | n/a (roles) |
| `subject_role_allow_scopes` / `subject_role_deny_scopes` | grouped `inbound_subject_{allow,deny}_rules` (inbound) / `outbound_subject_{allow,deny}_rules` (outbound) | role → `[scope name, …]` — inbound: agent scopes; outbound: tool names | inbound no; outbound **yes** |
| `source_role_allow_scopes` / `source_role_deny_scopes` | grouped `inbound_source_{allow,deny}_rules` | role → `[agent scope name, …]` — **inbound only** | no — full scope names |
| `agent_roles` | `model.agent_roles` | `[role.name, …]` — **outbound only** (informational) | n/a (roles) |
| `agent_role_scopes` | grouped `outbound_target_allow_rules` | agent role → `[tool name, …]` — **outbound only** (informational; single map, no deny variant emitted) | **yes** — bare tool names |
| `target_allow_scopes` / `target_deny_scopes` | `model.target_allow_scopes` / `model.target_deny_scopes` | full target service id → `[tool name, …]` — **outbound only** | **values yes, keys no** |

De-prefixing (Q9) applies to every package that compares a value with `input.mcp.params.name`: the agent outbound (agent side) and the tool inbound (target side). Provisioned scope names are prefixed with their owning workload (`github-tool.source-read`), but the value that arrives in `input.mcp.params.name` at runtime is the bare tool name (`source-read`), so those map **values** are stripped of a leading `"<owner>."` (where `owner = identity_ref(scope.serviceId).name`). The **keys** of `target_allow_scopes` / `target_deny_scopes` stay the full target service id (they match `input.identity.service_id`). The agent inbound `agent_scopes` and its `*_role_allow_scopes` / `*_role_deny_scopes` maps keep their **full** names — the agent inbound gate compares scopes internally, never against `input.mcp.params.name`.

### Always DENY by default

Each rules-based package ends with `default allow := false` and one or more `allow if { … }` rules (D25). A request that no rule allows is denied. There is no permissive default and there are no `allow := false` rules. The only exception is the [pass-through package](#pass-through-package-d24) (D24): it has `allow := true` and no rules. The agent inbound body and the agent outbound `tools/call` body carry inline `not …_deny_ok` guards (deny-overrides); the agent outbound session body and both tool inbound bodies apply the denies through `tool_ok(tool)`.

**The generator assumes disjoint allow/deny per `(role, scope)` and never reconciles an overlap.** A genuine grant/deny overlap on the same pair is a real policy conflict surfaced **upstream** as HTTP 422 (the PRB raises `PolicyContradictionError`); the PCE assumes a conflict-free model. The generator therefore adds **no** logic that silently reconciles an allow-vs-deny overlap — doing so would mask a conflict that is *supposed* to surface as a 422. The inline `not …_deny_ok` guards are **not** conflict reconciliation: they let a deny on **one** of a subject's several roles — or on **one** of the two gates of a per-tool check — beat an allow arriving from a *different* role / the *other* gate. Each individual `(role, scope)` stays allow-XOR-deny; the denies merely co-occur within a single request.

### Tool inbound package (target side): `authbridge.client.inbound.request`

Evaluated by the AuthBridge OPA plugin in the **inbound pipeline of a tool**, under target side — "who may call which tool of this service" (D26). The render input is the tool's stored SPM, through the shared projection (D18b). The package has two gates. Each gate is a pair of Rego functions over a bare tool name:

- **The user gate:** `input.identity.subject` → `subject_roles` → `subject_role_allow_scopes` / `subject_role_deny_scopes` (the user-role edges on the tool's scopes). Functions: `subject_allows(tool)` / `subject_denies(tool)`.
- **The calling-agent gate:** `input.identity.client_id` → `source_roles` → `source_role_allow_scopes` / `source_role_deny_scopes` (the agent-role edges on the tool's scopes). Functions: `source_allows(tool)` / `source_denies(tool)`.

`tool_ok(tool)` is the full per-tool check: the user gate allows the tool, the calling-agent gate allows the tool, and neither gate denies it (deny-overrides). The decision has three `allow` rules:

- **`tools/call` — per invoked tool:** `tool_ok(input.mcp.params.name)`.
- **MCP session messages:** `session_methods := {"initialize", "notifications/initialized", "ping", "tools/list"}`. These messages carry no tool name. A session message is allowed iff `some tool in owned_tools; tool_ok(tool)`. `owned_tools` is the bare names of the tool's own `owned_scopes`. An allow that a deny vetoes gives no session.
- **Self-discovery — the session messages for the tool's own client:** `self_client_id` is the tool's own clientId (the SPM `service_id`), rendered as a constant. A session message is allowed iff `input.identity.client_id == self_client_id`. This rule never allows `tools/call`. It lets UC-1 discovery (`analyze_tool`) send `tools/list` through the tool's own inbound (see [uc1-service-onboarding.md → Tool discovery and the bootstrap CR](aiac-agent/uc1-service-onboarding.md#tool-discovery-and-the-bootstrap-cr)). The check of `client_id` works because the discovery token is minted as the tool's own client (client credentials): its `azp` claim, which `jwt-validation` gives as `input.identity.client_id`, is the tool's clientId. A call from an agent carries the agent's clientId, so it never matches. Only Keycloak, the tool pod and AIAC hold the tool's client secret.

Every other MCP method, and a request with no MCP method, is denied. This is the agent-outbound logic of agent side (`tool_ok`, `session_methods`) moved to the callee. The callee itself is the key: the CR belongs to the tool, so the package needs no `target_*_scopes[input.identity.service_id]` map (the inbound input has no `service_id`).

Both gates are mandatory for every rule except the self-discovery rule, which allows no tool call. There is **no** platform-client bypass on a tool inbound (`PLATFORM_SOURCE_CLIENTS` applies to the agent inbound only). So a call with no calling agent is denied, and a user cannot call a tool directly with a `rossoctl` token: the call needs a calling agent that holds a granted role.

**The bootstrap CR.** At the first onboarding of a tool, the tool has no CR yet, so the changed combiner (D20) denies discovery. The PCE `bootstrap` writes the tool's CR before Provision (`POST /policy`, see [policy-computation-engine.md → Bootstrap CR (tool discovery)](policy-computation-engine.md#bootstrap-cr-tool-discovery)). Under target side, the CR is rendered from a zero-rule SPM (or the stored SPM), so its inbound allows only the self-discovery rule (plus any stored rules), and its outbound is a pass-through. Under agent side, the CR is a pass-through CR.

| Rego symbol | Source | Shape | De-prefixed? |
|-------------|--------|-------|--------------|
| `owned_tools` | `spm.owned_scopes` | `[tool name, …]` | **yes** |
| `self_client_id` | `spm.service_id` | the tool's own clientId (a string constant) | n/a |
| `subject_roles` | projection `subject_roles` | username → `[role.name, …]` (effect-agnostic; includes deny-edge roles) | n/a (roles) |
| `source_roles` | projection `source_roles` | calling agent clientId → `[role.name, …]` (effect-agnostic; includes deny-edge roles) | n/a (roles) |
| `subject_role_allow_scopes` / `subject_role_deny_scopes` | grouped projection `subject_{allow,deny}_rules` | user role → `[tool name, …]` | **yes** |
| `source_role_allow_scopes` / `source_role_deny_scopes` | grouped projection `source_{allow,deny}_rules` | agent role → `[tool name, …]` | **yes** |
| `session_methods` | constant | the four MCP session methods | n/a |

The block below is the package that the writer renders for the demo `github-tool` (users `dev-user` / `test-user` with roles `developer` / `tester`, the calling agent `github-agent`, and the four tools), annotated with `#` comments:

```rego
package authbridge.client.inbound.request
import rego.v1

# the bare MCP names of this service's own scopes
owned_tools := ["source-read", "source-write", "issues-read", "issues-write"]
# this tool's own clientId (the SPM service_id): the azp of the UC-1 discovery token
self_client_id := "spiffe://localtest.me/ns/team1/sa/github-tool"

subject_roles := {
    "dev-user": ["developer"],
    "test-user": ["tester"],
}
source_roles := {
    "spiffe://localtest.me/ns/team1/sa/github-agent": ["github-agent.issue_operations", "github-agent.source_operations"],
}

subject_role_allow_scopes := {
    "developer": ["issues-read", "source-write", "source-read"],
    "tester": ["issues-read", "issues-write"],
}
subject_role_deny_scopes := {}
source_role_allow_scopes := {
    "github-agent.issue_operations": ["issues-read", "issues-write"],
    "github-agent.source_operations": ["source-write", "source-read"],
}
source_role_deny_scopes := {}
# the MCP messages that carry no tool name (see the session rule below)
session_methods := {"initialize", "notifications/initialized", "ping", "tools/list"}

# user gate: the delegated user holds a role granted the tool
subject_allows(tool) if {
    some role in subject_roles[input.identity.subject]
    tool in subject_role_allow_scopes[role]
}
subject_denies(tool) if {
    some role in subject_roles[input.identity.subject]
    tool in subject_role_deny_scopes[role]
}
# calling-agent gate: the calling agent holds a role granted the tool
source_allows(tool) if {
    some role in source_roles[input.identity.client_id]
    tool in source_role_allow_scopes[role]
}
source_denies(tool) if {
    some role in source_roles[input.identity.client_id]
    tool in source_role_deny_scopes[role]
}
# the full per-tool check (both gates allow, no deny)
tool_ok(tool) if {
    subject_allows(tool)
    source_allows(tool)
    not subject_denies(tool)
    not source_denies(tool)
}
default allow := false
# tools/call: checked per invoked tool
allow if { input.mcp.method == "tools/call"; tool_ok(input.mcp.params.name) }
# session messages: allowed iff at least one tool of this service passes tool_ok
allow if { input.mcp.method in session_methods; some tool in owned_tools; tool_ok(tool) }
# self-discovery: the session messages (never tools/call) for the tool's own client
allow if { input.mcp.method in session_methods; input.identity.client_id == self_client_id }
```

A request with no identity is denied (D27): `subject_roles[input.identity.subject]` is undefined, so no tool passes `tool_ok`, and the request has no `client_id`, so the self-discovery rule does not match.

### Agent inbound package: `authbridge.client.inbound.request`

Evaluated by the AuthBridge OPA plugin in the **inbound pipeline of an agent** — "who may call this agent". Both sides render this package for an agent (D26a): under agent side from the APM, under target side from the projection of the agent's SPM. For one SPM both give the same package (D18b). `allow` requires `subject_allow_ok` **and** `source_allow_ok` and **neither** `subject_deny_ok` **nor** `source_deny_ok` (deny-overrides). `subject_allow_ok` passes when the subject (`input.identity.subject`) holds a role granting at least one of the agent's own `agent_scopes` via `subject_role_allow_scopes`; `subject_deny_ok` mirrors it against `subject_role_deny_scopes`. `source_allow_ok` passes when (a) there is no calling `input.identity.client_id` (pure end-user traffic), (b) the `client_id` is one of the **platform bypass clients** — `rossoctl` by default, from `PLATFORM_SOURCE_CLIENTS` (Q5); this bypass is **mandatory**, since end-user traffic carries the platform client and would otherwise be denied — or (c) that client holds a role granting an agent scope via `source_role_allow_scopes`; `source_deny_ok` mirrors it against `source_role_deny_scopes`.

The block below mirrors the current `generate_inbound_rego` output (`inbound/request.rego`), reproduced with light blank-line spacing for readability — every declaration map, gate, and the trailing decision block are identical to what the generator emits.

```rego
package authbridge.client.inbound.request
import rego.v1

agent_scopes := ["github-agent.issue_operations", "github-agent.source_operations"]

subject_roles := {
    "dev-user": ["developer"],
    "test-user": ["tester"],
}

source_roles := {}

subject_role_allow_scopes := {
    "developer": ["github-agent.issue_operations", "github-agent.source_operations"],
    "tester": ["github-agent.issue_operations"],
}
subject_role_deny_scopes := {}
source_role_allow_scopes := {}
source_role_deny_scopes := {}

subject_allow_ok if {
    some role in subject_roles[input.identity.subject]
    some scope in subject_role_allow_scopes[role]
    scope in agent_scopes
}
subject_deny_ok if {
    some role in subject_roles[input.identity.subject]
    some scope in subject_role_deny_scopes[role]
    scope in agent_scopes
}

source_allow_ok if { not input.identity.client_id }
source_allow_ok if { input.identity.client_id == "rossoctl" }
source_allow_ok if {
    some role in source_roles[input.identity.client_id]
    some scope in source_role_allow_scopes[role]
    scope in agent_scopes
}
source_deny_ok if {
    some role in source_roles[input.identity.client_id]
    some scope in source_role_deny_scopes[role]
    scope in agent_scopes
}

default allow := false
allow if { subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok }
```

**Deny-overrides:** `allow` fires only when both allow gates pass **and** neither deny gate matches. A subject or source barred by a deny edge is rejected even when an allow edge would otherwise admit it. (An absent `input.identity.client_id` makes `source_allow_ok` true and — because `source_roles[input.identity.client_id]` is undefined — leaves `source_deny_ok` false, so an absent source still passes.)

> **Security property — source-side deny reach.** The `source_allow_ok`
> bypass sets only the *allow* gate; `allow` still requires `not
> source_deny_ok` **and** `not subject_deny_ok`, so a bypassed source is
> **not** immune to a deny — a subject-side deny still applies, and a
> source-side deny applies too *when it can fire*. The limit is on the
> source deny gate specifically:
> - **Pure end-user traffic (no `client_id`)** is structurally
>   un-revokable on the **source** side: `source_roles[input.identity.client_id]`
>   is undefined, so `source_deny_ok` can never fire against it. Such
>   traffic can still be denied by a **subject**-side deny (it always
>   carries `input.identity.subject`).
> - A **platform bypass client** (`rossoctl` et al.) keeps
>   `source_allow_ok` unconditionally, but `source_deny_ok` *does* fire
>   if an explicit deny edge names a role that client holds. In normal
>   operation platform clients carry no authored rules, so their source
>   trust is effectively un-revokable — but it is not structurally
>   un-revokable, and no separate exemption shields them from a deny that
>   is actually authored against their role.
>
> Net: **DENY cannot revoke *source-side* trust for a caller that presents
> no `client_id`.** This is deliberate — dropping the bypass would deny
> the platform-fronted end-user traffic the mesh depends on (see
> `PLATFORM_SOURCE_CLIENTS`, Q5) — and is a property of the source gate,
> not a global "platform clients are always allowed" carve-out.

**Known limit (D26a) — the agent inbound is agent-level.** Under both sides, a caller that has an allow on any scope of the agent can call the agent. The package does not check which skill the call uses: the OPA input has no skill ID (the `a2a` input has only `method`, `session_id`, `task_id` and `role`), and A2A requests have no standard skill field.

A request with no identity is denied (D27): `subject_roles[input.identity.subject]` is undefined, so `subject_allow_ok` never passes. The bypass of an absent `client_id` sets only `source_allow_ok`.

### Agent outbound package (agent side): `authbridge.client.outbound.request`

Evaluated by the AuthBridge OPA plugin in the **outbound pipeline of an agent, under agent side only** — "what this agent may call". Under target side, the outbound package of every service is a [pass-through](#pass-through-package-d24) (D24), and the callee's inbound decides. The four outbound gates are Rego **functions over a bare tool name**: `subject_allows(tool)` (the delegated user's role admits the tool — `tool in subject_role_allow_scopes[role]`, de-prefixed values), `target_allows(tool)` (the target service, keyed by the full `input.identity.service_id`, admits the tool — `tool in target_allow_scopes[input.identity.service_id]`), and `subject_denies(tool)` / `target_denies(tool)`, which mirror them against `subject_role_deny_scopes` / `target_deny_scopes`. The named gates apply these functions to the invoked tool: `subject_allow_ok if { subject_allows(input.mcp.params.name) }`, and the same for `subject_deny_ok`, `target_allow_ok` and `target_deny_ok`. `tool_ok(tool)` is the full per-tool check: both allow functions pass and neither deny function matches (deny-overrides).

The decision has two `allow` rules:

- **`tools/call` — per invoked tool.** `input.mcp.method == "tools/call"` and both allow gates pass on the **same** `input.mcp.params.name` and neither deny gate matches.
- **MCP session messages.** `session_methods := {"initialize", "notifications/initialized", "ping", "tools/list"}`. These messages carry no tool name. A session message to a target is allowed iff at least one tool of that target (`some tool in target_allow_scopes[input.identity.service_id]`) passes `tool_ok(tool)` for this user. An allow that a deny vetoes gives no session.

Every other MCP method, and a request with no method, is denied. The caller sees the whole tool list of the target (`tools/list`), but it can call only its granted tools. `agent_roles` / `agent_role_scopes` are emitted for debugging but are **not** referenced by `allow` — `target_allow_scopes[input.identity.service_id]` already *is* the per-scope capability gate. This package emits neither `agent_scopes` nor the inbound subject gate: outbound decisions never consider the agent's own audience scopes.

The block below mirrors the current `generate_outbound_rego` output (`outbound/request.rego`), annotated with explanatory `#` comments for readability — the maps, gates, and trailing decision block are identical to what the generator emits (which itself emits only the single `# informational/debugging only` comment).

```rego
package authbridge.client.outbound.request
import rego.v1

agent_roles := ["github-agent.issue_operations", "github-agent.source_operations"]
subject_roles := {
    "dev-user": ["developer"],
    "test-user": ["tester"],
}
# The deployed github-tool (demo/assets/tools/github_tool) exposes
# exactly four MCP tools — source-read, source-write, issues-read,
# issues-write — one per skill. These names ARE the values that arrive in
# input.mcp.params.name when a specific tool is invoked, so the maps
# below key on them.
subject_role_allow_scopes := {
    "developer": ["issues-read", "source-write", "source-read"],
    "tester": ["issues-read", "issues-write"],
}
subject_role_deny_scopes := {}
# informational/debugging only — not referenced by allow
agent_role_scopes := {
    "github-agent.issue_operations": ["issues-read", "issues-write"],
    "github-agent.source_operations": ["source-write", "source-read"],
}
target_allow_scopes := {
    "spiffe://localtest.me/ns/team1/sa/github-tool": ["source-read", "source-write", "issues-read", "issues-write"],
}
target_deny_scopes := {}
# the MCP messages that carry no tool name (see the session rule below)
session_methods := {"initialize", "notifications/initialized", "ping", "tools/list"}

# user may reach the tool: holds a role granted the tool
subject_allows(tool) if {
    some role in subject_roles[input.identity.subject]
    tool in subject_role_allow_scopes[role]
}
subject_allow_ok if { subject_allows(input.mcp.params.name) }
subject_denies(tool) if {
    some role in subject_roles[input.identity.subject]
    tool in subject_role_deny_scopes[role]
}
subject_deny_ok if { subject_denies(input.mcp.params.name) }
# agent may reach the tool: the tool is one the target accepts (direct, per-scope)
target_allows(tool) if {
    tool in target_allow_scopes[input.identity.service_id]
}
target_allow_ok if { target_allows(input.mcp.params.name) }
target_denies(tool) if {
    tool in target_deny_scopes[input.identity.service_id]
}
target_deny_ok if { target_denies(input.mcp.params.name) }
# the full per-tool check (both allow gates, no deny)
tool_ok(tool) if {
    subject_allows(tool)
    target_allows(tool)
    not subject_denies(tool)
    not target_denies(tool)
}
default allow := false
# tools/call: checked per invoked tool
allow if { input.mcp.method == "tools/call"; subject_allow_ok; target_allow_ok; not subject_deny_ok; not target_deny_ok }
# session messages: allowed iff at least one tool of the target passes tool_ok
allow if { input.mcp.method in session_methods; some tool in target_allow_scopes[input.identity.service_id]; tool_ok(tool) }
```

**Known limit (agent side) — A2A and LLM calls through the outbound proxy are denied.** The agent outbound package allows only a granted `tools/call` and the MCP session messages. Every other request falls to `default allow := false`. An A2A call (`input.a2a`, for example `message/send`) and an LLM call (an OpenAI-shaped chat request) carry no MCP method, so the agent's outbound OPA denies them with HTTP `403` (`policy.forbidden`, `plugin: opa`). This applies to every call that crosses the agent's outbound proxy. The demo `github-agent` sends its LLM traffic through it (`HTTP_PROXY=http://127.0.0.1:8081`, plain-HTTP `LLM_API_BASE`). Checked on the Kind cluster (handoff 11, 2026-10-01): an A2A `message/send` and an LLM `/v1/chat/completions` request from the agent container both got `403` from OPA. Under agent side, until the agent outbound package has rules for A2A and inference traffic, wire the outbound OPA only where the agent's LLM endpoint does not cross the proxy (for example HTTPS passthrough, or `NO_PROXY`). Target side does not have this limit: the agent's outbound is a pass-through (but it has no egress check; see [Known limits](#known-limits)).

A worked example (agent `github-agent`, users `dev-user`/`test-user` with the roles `developer`/`tester`, tool `github-tool`) is kept next to the tests. `docs/examples/opa-team1-policy.yaml` is the **target-side CR pair** of that demo policy: the `github-agent` CR (the [agent inbound](#agent-inbound-package-authbridgeclientinboundrequest) + a pass-through outbound) and the `github-tool` CR (the [tool inbound](#tool-inbound-package-target-side-authbridgeclientinboundrequest) + a pass-through outbound). Each `content` block is the exact `render_target_side` output for the stored SPM of that service. Regenerate the example when the generator changes. The example has no agent-side CRs. Under agent side, the `github-agent` CR has the agent outbound package above (`generate_outbound_rego`), and `github-tool` gets a pass-through CR.

### No request without identity (D27)

No request without identity passes a rules-based inbound package. Both inbound packages need a subject that holds a role: the agent inbound through `subject_allow_ok`, the tool inbound through `subject_allows(tool)`. The one exception, the self-discovery rule of the tool inbound, needs the tool's own `client_id`, which also comes only from a validated token. `jwt-validation` skips its `bypass_paths` (default `/healthz`, `/readyz`, `/livez`, `/metrics`, `/.well-known/*`) and continues with no identity. OPA then denies the request. Known limits:

- A callee must use `tcpSocket` or `exec` probes. An `httpGet` probe through the proxy is denied. The onboarding check #6 (D30) stops the onboarding of a service whose app container has an `httpGet` probe.
- The A2A agent card (`/.well-known/agent-card.json`) and `/metrics` are denied through the proxy.

A pass-through inbound package (a managed tool under agent side) allows a request without identity.

### `AuthorizationPolicy` Custom Resource (Q6)

The two packages become the `policies[]` of a per-service CR — one CR per managed service, agent or tool, under both sides. The writer builds the body in `_build_cr`, keyed on `identity_ref(service_id)`:

```yaml
apiVersion: agent.rossoctl.dev/v1alpha1
kind: AuthorizationPolicy
metadata:
  name: github-tool             # identity_ref(service_id).name
  namespace: team1              # identity_ref(service_id).namespace
  labels:
    app.kubernetes.io/managed-by: aiac-pdp-policy-writer
spec:
  scope: client
  clientID: "github-tool"       # display / print-column only
  policies:
    - path: "inbound/request.rego"
      content: |
        # ... the inbound package of this side (see "What each side renders") ...
    - path: "outbound/request.rego"
      content: |
        # ... the outbound package of this side ...
```

- **Written via server-side apply.** The upsert of one CR calls `patch_namespaced_custom_object` with `_content_type="application/apply-patch+yaml"`, `field_manager="aiac-pdp-policy-writer"`, `force=True` — create-or-update in one idempotent call.
- **`spec.policies` is atomic under server-side apply.** The CRD gives `spec.policies` no `x-kubernetes-list-type`, so server-side apply treats the list as atomic: one write replaces the whole list. `spec.policies` always has exactly two entries, `inbound/request.rego` and `outbound/request.rego`. So a write of the other side (for example, an agent-side pass-through CR over a target-side tool CR) leaves no stale package. AIAC is the only manager of its CRs.
- **`metadata.labels["app.kubernetes.io/managed-by"] = "aiac-pdp-policy-writer"`** marks every CR the writer owns; `PUT /policy` and `DELETE /policy` select on it.
- **`spec.clientID` is display-only** — bundle-service looks the CR up by `metadata.name` + `metadata.namespace` (matched against the SPIFFE ServiceAccount segment), **never** by `clientID`. It must nonetheless be a valid DNS label (no `spiffe://`, no `/`); the writer sets it to the `name`.
- **One CR per ServiceAccount.** The client tier of a pod is the CR whose namespace and name are the namespace and the ServiceAccount of the pod's SPIFFE ID. Pods that share a ServiceAccount share one CR and one bundle (a known limit).
- **Delete-by-label vs per-service delete.** `DELETE /policy` lists every CR carrying the managed-by label **cluster-wide** and deletes each. `DELETE /policy/services/{service_id}` deletes the single `(name, namespace)` from `identity_ref` (a k8s 404 is treated as success — idempotent). `PUT /policy` deletes each labelled CR that is not an entry of its model.

### Both tiers always emitted; a missing CR denies (D20)

Every upsert writes **both** request tiers. A rules-based tier ends with `default allow := false`; a pass-through tier has `allow := true`. The global combiner (the `default` CR, `scope: global`, in the bundle-service namespace) allows a tier when a namespace CR sets `override`, or when `ns_ok AND client_ok`, where `client_ok` comes from this package's `allow`.

**The changed combiner (D20).** The stock combiner (`charts/operator/templates/bundleservice/default-policy.yaml` in the operator repo) has one more rule in each of its four packages: `client_ok if not <client package>` (for example `client_ok if not data.authbridge.client.inbound.request`). With it, a tier with **no** client CR falls back to allow. In an AIAC setup, the two **request** packages of the combiner do not have this rule:

```rego
# removed from package authbridge.inbound.request
client_ok if not data.authbridge.client.inbound.request
# removed from package authbridge.outbound.request
client_ok if not data.authbridge.client.outbound.request
```

So a pod that has no client CR is denied on both request legs. The two response packages keep the stock fallback. An AIAC CR has no response packages, so the responses are not checked. Other setups (no AIAC) keep the stock combiner.

- **The upstream chart value.** The operator chart gets an opt-in value, `bundleService.defaultPolicy.requireClientPolicy` (default `false`). When it is `true`, `default-policy.yaml` omits the two rules. Until the value exists, `k8s/opa-kind-enable.sh` applies a changed `default` CR after the install (see [`opa-kind-runbook.md`](../../../k8s/opa-kind-runbook.md#the-changed-combiner-d20)).
- **Drift.** A `helm upgrade` of the operator chart without the value brings back the stock combiner. The Controller start check #4 (D30) reads the `default` CR at every start. The Controller stops (see [aiac-agent.md](aiac-agent.md)) if the CR is missing or cannot be read, if a request package (`inbound/request.rego` or `outbound/request.rego`) is missing, or if a request package still has the fallback rule (a comment does not count).

Consequences:

- **A deleted CR denies.** In an AIAC setup, deleting a CR is lockdown, not off-boarding. So the quarantine and the decommission delete the CR (see below).
- **Every managed service has a CR, under both sides.** The managed set is the services that have a stored SPM (D21). Where AIAC has no rules for a direction, the CR has a pass-through package: the outbound of every service under target side, and both packages of every managed tool under agent side (D24).
- **A pod outside the managed set is denied** — a service that is not onboarded yet, a quarantined service, or a decommissioned service. The one exception is the bootstrap CR of a tool in its onboarding: it exists before the SPM is stored, and its inbound allows only the self-discovery rule (see [Tool inbound package](#tool-inbound-package-target-side-authbridgeclientinboundrequest)).
- **`DELETE /policy` denies every managed pod (C1).** It has no AIAC caller. The resync (D28) and the rebuild (D28a) use `PUT /policy`, which never removes the CR of a service in the model, so they have no deny window.

### Quarantine and decommission — the CR delete (D20)

When the build of a UC1 onboarding fails, the PCE `quarantine` deletes the service's CR (a failed precondition check does not quarantine, D30) (see [policy-computation-engine.md → Quarantine (failed onboarding)](policy-computation-engine.md#quarantine-failed-onboarding)). The decommission (a deleted client) also deletes the CR. Both call `delete_service_cr(service_id)` (`DELETE /policy/services/{service_id:path}`), for an agent and for a tool. There is no no-rules CR. Then the PCE deploys the affected live services of the current side in one `POST /policy` call (`X` is the removed service):

- **Target side:** the services whose SPM the footprint purge changed, and the services whose SPM keeps an edge of a role that `X` shares with another service. `X` is not a holder of that role any more, so the writer renders these CRs without `X`. The PCE does not write these SPMs, because their rules did not change (D32).
- **Agent side:** the agents that targeted `X`, the remaining holders of such a shared role, and the agents among the changed and the shared services.

See [policy-computation-engine.md → Decommission](policy-computation-engine.md#decommission-service-offboard) (steps 4b and 8).

**Why a delete.** With the changed combiner (D20), a pod that has no client CR is denied on both request legs. So a delete closes the service. A tool has a CR too (D20, D24), so a quarantined tool is closed in its own inbound, and not only through the outbound packages of its callers.

**The lift.** A successful re-onboarding stores the SPM (also with zero rules, D21) and writes the CR again. In the same `POST /policy` call, the PCE also deploys every live service whose SPM has an edge of a role of `X` (under agent side, the agents among them), with `X` as a holder again: the quarantine rendered these CRs without `X`. Their rules did not change, so the PCE writes only those whose stored holders are not the current ones (see [policy-computation-engine.md → Quarantine (failed onboarding)](policy-computation-engine.md#quarantine-failed-onboarding) and [Algorithm](policy-computation-engine.md#algorithm) step 3d). Known limit (C5): a quarantined tool cannot be lifted today (see [uc1-service-onboarding.md](aiac-agent/uc1-service-onboarding.md)).

**The poll delay.** The delete takes effect at the next poll of the OPA plugin. Until then the pod keeps its last bundle.

### Known limits

These limits concern the writer, the Rego and the bundle:

- **D26a — the agent inbound is agent-level.** See [Agent inbound package](#agent-inbound-package-authbridgeclientinboundrequest).
- **D27 — no request without identity passes a rules-based inbound.** Callees must use `tcpSocket` or `exec` probes. The A2A agent card and `/metrics` are denied through the proxy. See [No request without identity](#no-request-without-identity-d27).
- **D30 #3 — a direct path to the app port.** In reverse-proxy mode (the operator default), the AuthBridge proxy covers only the first port of the first container. The moved app port is reachable from other pods with no JWT and no OPA. Use transparent mode, or a NetworkPolicy for the app port. The onboarding checks do not check this; it is documented only.
- **The AgentCard sync.** When no `<agent>-card-signed` ConfigMap exists, the operator fetches the agent card over HTTP with no token from the first Service port. Only the optional `agentcard-signer` init container writes that ConfigMap. The demo reaches the moved app port directly (the D30 #3 hole). If that path is closed, D20 and D27 deny the fetch, and the agent onboarding fails: the card does not sync, so Provision gets no skills (see [uc1-service-onboarding.md](aiac-agent/uc1-service-onboarding.md), `analyze_agent`). Then use the signed-card ConfigMap. This is a known limit only.
- **Agent side — the agent outbound denies A2A and LLM calls** (`b435aa1`). See [Agent outbound package](#agent-outbound-package-agent-side-authbridgeclientoutboundrequest).
- **Agent side — the outbound subject maps have no target key** (D32). `subject_role_allow_scopes` and `subject_role_deny_scopes` of the agent outbound map a user role to bare tool names, for all targets of the agent. So a deny of `source-read` on one tool also blocks the same user's `source-read` on another target that has the same bare tool name. Also, a grant on one tool lets the user's call through on such a target when the user has no grant on that target's scope (the target gate of the agent must still allow the tool). For a shared scope, this agrees with the realm-wide policy. For two different scopes with the same bare tool name, it is a limit (see [PRD §6](../PRD.md#6-rossoctl--keycloak--opa-interfaces)).
- **Target side — no egress check.** The outbound of every service is a pass-through. Only the callee decides, so a call to a host that has no AIAC CR (for example, an external API) is not checked.
- **C1 — `DELETE /policy`** has no AIAC caller. Under D20 it denies every managed pod.
- **The poll delay.** A CR change takes effect at the next poll of the OPA plugin (`polling_min_delay` 10 s, `polling_max_delay` 120 s). So a side change does not reach all pods at the same time: until every pod has polled, a pod can still use the bundle of the old side.
- **503 before the first bundle.** Until the OPA plugin loads its first bundle, it answers every request with `503`.
- **A shared ServiceAccount.** Pods that share a ServiceAccount share one CR and one bundle.
- **UC-1 tool discovery — the self-discovery rule.** `analyze_tool` sends `tools/list` through the tool's AuthBridge inbound, with a discovery token minted as the tool's own client (see [uc1-service-onboarding.md → Tool discovery and the bootstrap CR](aiac-agent/uc1-service-onboarding.md#tool-discovery-and-the-bootstrap-cr)). The PCE `bootstrap` writes the tool's CR before Provision, so the changed combiner (D20) does not deny the call at the first onboarding. Under target side, the self-discovery rule of the tool inbound allows the four session methods for the tool's own client, never `tools/call`. Under agent side, the tool's pass-through CR allows the call. So a holder of the tool's client secret (Keycloak, the tool pod, AIAC) can open an MCP session with the tool and list its tools, but cannot call a tool. The bootstrap CR takes effect at the next poll of the tool's OPA plugin.

---

## Library: `aiac.pdp.policy.library.api`

HTTP client module wrapping the PDP Policy Writer REST API. Exposes four module-level functions. Service URL is read from the `AIAC_PDP_POLICY_URL` environment variable (default: `http://127.0.0.1:7072`). All functions raise `RuntimeError` on non-2xx response.

```python
def apply_policy(model: PolicyModel) -> None
    # POST /policy — a TargetSidePolicyModel or an AgentSidePolicyModel (the tag is sent)

def replace_policy(model: PolicyModel) -> None
    # PUT /policy — the full policy model of the current side (the resync, the rebuild)

def delete_service_cr(service_id: str) -> None
    # DELETE /policy/services/{service_id} — the clientId, URL-encoded (the quarantine, the decommission)

def delete_policy() -> None
    # DELETE /policy — no AIAC caller (C1)
```

`apply_agent_policy` and `delete_agent_policy` are removed. The name `delete_service_cr` does not clash with the store library's `delete_service_policy`.

### Dependencies

```
requests
pydantic
python-dotenv
```

### Usage

```python
from aiac.pdp.policy.library.api import apply_policy, delete_service_cr, replace_policy
from aiac.policy.model.models import TargetSidePolicyModel

apply_policy(TargetSidePolicyModel(services=changed_spms))    # the deploy of one PCE run
replace_policy(TargetSidePolicyModel(services=all_spms))      # the resync: also deletes stale AIAC CRs
delete_service_cr("spiffe://localtest.me/ns/team1/sa/github-tool")   # the quarantine
```

---

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PLATFORM_SOURCE_CLIENTS` | No | `rossoctl` | Comma-separated platform bypass clients, sourced from the `aiac-pdp-config` ConfigMap. Drives the agent inbound package's `source_allow_ok if { input.identity.client_id == "<c>" }` bypass rules (Q5). The tool inbound package has no bypass (D26). Blanks are dropped; an unset or all-blank value falls back to `rossoctl` (dropping the bypass would deny end-user traffic, which carries the platform client). |
| `POLICY_WRITER_DUMP_REGO` | No | off | When truthy (`1`/`true`/`yes`/`on`) enables the **additive** local rego dump (see below). Never gates the CR write. |
| `REGO_OUTPUT_DIR` | No | `/rego` | Destination for the additive dump — only consulted when `POLICY_WRITER_DUMP_REGO` is on. |

There are **no** CR-name or CR-namespace env vars — CR coordinates are derived per service from `identity_ref(service_id)`, and the group/version/plural/field-manager/label are code constants (Q8). There is **no** enforcement-side env var either: the writer reads the side from the policy-model tag (D29). `AIAC_ENFORCEMENT_SIDE` is read by the Controller only.

**Auth model.** The writer authenticates to the Kubernetes API as an **in-cluster ServiceAccount** (`aiac-pdp-policy-writer`), bound cluster-wide to a `ClusterRole` granting `get`, `list`, `create`, `update`, `patch`, `delete` on `authorizationpolicies.agent.rossoctl.dev` — **no `watch`** (the writer only creates/patches/deletes; bundle-service polls). `PUT /policy` and `DELETE /policy` need `list` (the cluster-wide list by the managed-by label). The `ServiceAccount`, `ClusterRole`, and `ClusterRoleBinding` are declared in `k8s/pdp-interface-deployment.yaml`. The binding is cluster-scoped (not a namespaced `RoleBinding`) because the writer creates CRs in arbitrary workload namespaces (`team1`, …), derived from each service's `identity_ref` namespace. For local development, the `kubernetes` client falls back to `~/.kube/config` automatically.

## Always-on CR write + additive debug dump

The **CR server-side-apply is always active** — it is never gated by an env var. The former filesystem-stub behaviour survives **only** as an additive debug/test aid, toggled by `POLICY_WRITER_DUMP_REGO` (default off). When on, each upsert **also** writes the same rego to `<REGO_OUTPUT_DIR>/<ns>/<name>/inbound/request.rego` and `<REGO_OUTPUT_DIR>/<ns>/<name>/outbound/request.rego`, mirroring the CR `policies[].path` so the on-disk output equals the CR content; each CR delete (the per-service delete, the delete step of `PUT /policy`, and `DELETE /policy`) clears the corresponding dumped tree. The dump is **never** a substitute for, or a switch away from, the CR write — production runs with it off (`k8s/pdp-interface-deployment.yaml` sets no `POLICY_WRITER_DUMP_REGO`). A dump `OSError` maps to 502, so a broken debug mount surfaces rather than silently dropping files.

---

## Runtime

- Framework: FastAPI
- Server: uvicorn
- Bind: `0.0.0.0:7072`
- Base image: `python:3.13-slim` (digest-pinned)
- Kubernetes ClusterIP Service: `aiac-pdp-policy-service:7072`
- Deployment: co-located with IdP Configuration Service as a container in the **Rossoctl Interface Pod** (`pdp-interface-deployment.yaml`)

---

## Dependencies (`requirements.txt`)

```
fastapi
uvicorn[standard]
kubernetes>=36.0.3,<37
pydantic
```

---

## File structure

```
src/aiac/pdp/service/
├── __init__.py
└── policy/
    ├── __init__.py
    └── opa/
        ├── __init__.py
        ├── Dockerfile
        ├── requirements.txt
        ├── rego.py         # identity_ref + the generators of both sides: the agent inbound,
                            # the agent outbound, the tool inbound, the pass-through
        └── main.py         # the always-on CR writer (with optional additive dump)

src/aiac/pdp/policy/
├── __init__.py
└── library/
    ├── __init__.py
    └── api.py          # apply_policy, replace_policy, delete_service_cr, delete_policy
                        # (models now imported from aiac.policy.model.models)
```

There is **no** `stub.py` and no separate filesystem-writer module: `main.py` is the single, always-on CR writer (rego rendering lives in `rego.py`; the optional dump is a branch inside `main.py`, not a distinct mode).

Build command:
```bash
docker build -f src/aiac/pdp/service/policy/opa/Dockerfile \
  -t localhost/aiac-pdp-policy-opa:local src/
```

---

## `main.py` behaviour notes

- **Kube config at import:** `_load_kube_config()` tries `config.load_incluster_config()`, falling back to `config.load_kube_config()` (local dev). Both failing is non-fatal — the module stays importable and API calls surface as 502/503 until real config exists. A module-level `client.CustomObjectsApi` handles all CR operations.
- **Code constants (never env vars):** `_GROUP = "agent.rossoctl.dev"`, `_VERSION = "v1alpha1"`, `_PLURAL = "authorizationpolicies"`, `_MANAGED_BY_LABEL = {"app.kubernetes.io/managed-by": "aiac-pdp-policy-writer"}`, `_FIELD_MANAGER = "aiac-pdp-policy-writer"` (Q8).
- **`identity_ref(service_id) -> (namespace, name)`** (in `rego.py`): SPIFFE or `<ns>/<name>` → DNS-1123-validated `(namespace, name)`; raises `ValueError` (→ 400) when no namespace is derivable or a segment is an invalid label — no fallback.
- **The generators** (in `rego.py`) render four package kinds: the agent inbound (both sides), the agent outbound (agent side), the tool inbound (target side) and the pass-through (both sides). See [What each side renders](#what-each-side-renders).
- **The tool inbound generator** renders the target-side tool package from the projection of one SPM (D26): `owned_tools`, `self_client_id` (the SPM `service_id`), `subject_roles` / `source_roles`, the four de-prefixed role maps, `session_methods`, the gate functions (`subject_allows` / `subject_denies` / `source_allows` / `source_denies`), `tool_ok(tool)`, `default allow := false`, and the three `allow` rules (`tools/call`; the session messages over `owned_tools`; the session messages for `self_client_id`). It emits no platform-client bypass.
- **The pass-through generator** `generate_pass_through_rego(tier)` renders one pass-through package: the package header, `import rego.v1` and `allow := true` (D24), for either tier.
- **The CR renderers** (in `rego.py`; `_entries` in `main.py` calls them, one per entry). Each one returns the two packages of one CR:
  - `render_target_side(spm, platform_clients)`: the tool inbound, or the agent inbound from `project_inbound(spm)` through the private `_agent_inbound_rego` (the renderer that `generate_inbound_rego` also uses, D18b); and a pass-through outbound.
  - `render_agent_side(apm, platform_clients)`: the agent inbound (`generate_inbound_rego`) and the agent outbound (`generate_outbound_rego`).
  - `render_pass_through()`: a pass-through in both tiers.
- **`generate_inbound_rego(model, platform_clients)` / `generate_outbound_rego(model)`** (in `rego.py`): render the two agent packages of an APM (agent side) under the ALLOW/DENY model (always DENY by default). Both take only an `AgentPolicyModel`. The inbound generator emits `subject_roles` / `source_roles` (effect-agnostic) plus the grouped `subject_role_allow_scopes` / `subject_role_deny_scopes` (from `inbound_subject_{allow,deny}_rules`) and `source_role_allow_scopes` / `source_role_deny_scopes` (from `inbound_source_{allow,deny}_rules`), one `source_allow_ok` bypass rule per `platform_clients` entry (plus the no-`client_id` and role-based rules), and the mirrored `subject_deny_ok` / `source_deny_ok` gates; `allow` applies deny-overrides. The outbound generator emits `subject_role_allow_scopes` / `subject_role_deny_scopes` (from `outbound_subject_{allow,deny}_rules`), the single informational `agent_role_scopes` (from `outbound_target_allow_rules`), and `target_allow_scopes` / `target_deny_scopes`, de-prefixing its map values; the four outbound gates are functions over a bare tool name (`subject_allows` / `subject_denies` / `target_allows` / `target_denies`), with `tool_ok(tool)` and `session_methods`; `allow` is a per-tool AND with deny-overrides for `tools/call`, plus the MCP session rule. Both generators emit `default allow := false` and `allow if { … }` rule(s) only — there is no default-effect branch. The generator never reconciles an allow-vs-deny overlap (a genuine overlap is an upstream 422; see [Always DENY by default](#always-deny-by-default)).

- **`_build_cr`:** assemble the CR body of one entry — `metadata.name`/`.namespace` from `identity_ref`, the managed-by label, `spec.scope: client`, `spec.clientID` = the display name, and `policies[]` = exactly the two rendered packages of the entry's side (`inbound/request.rego`, `outbound/request.rego`). Raises `ValueError` (via `identity_ref`) on a malformed id.
- **The upsert of one CR:** server-side apply via `patch_namespaced_custom_object` (`_content_type="application/apply-patch+yaml"`, `field_manager=_FIELD_MANAGER`, `force=True`); then, if the dump is enabled, `_dump_cr`.
- **The per-service delete:** `delete_namespaced_custom_object` for the single `(name, namespace)`; a k8s **404 is swallowed** (idempotent → 204); then dump-clear the service's tree if enabled.
- **`_delete_all()`:** `list_cluster_custom_object` filtered by the managed-by label selector, then delete each item (per-item 404 tolerated for concurrent-delete races); then clear the dumped tree if enabled.
- **`_run_write(op)`** maps outcomes to responses: success → **204**; `ValueError` → **400** `{"error": …}`; `ApiException` → **502** `{"error": …}`; `OSError` (the additive dump) → **502**. A body that does not parse, or that fails a body check (`_one_side_only`, `_no_agent_pass_through`), never reaches `_run_write`: FastAPI returns **422**.
- **`POST /policy`:** dispatch on the subclass. `TargetSidePolicyModel`: upsert one CR per `services[]` SPM — the tool inbound or the agent inbound (by `service_type`), and the pass-through outbound. `AgentSidePolicyModel`: upsert one agent CR per `agents[]` APM, and one pass-through CR per `pass_through[]` id. A malformed id aborts the batch with a 400 naming it (entries already applied before that point stay written — no rollback).
- **`PUT /policy`:** the same upserts as `POST /policy`; then list the CRs by the managed-by label and delete each one whose `(namespace, name)` is not an entry (per-item 404 tolerated). An upsert error stops the PUT before the delete step.
- **`DELETE /policy/services/{service_id}`:** the per-service delete.
- **`DELETE /policy`:** `_delete_all()`.
- **`GET /health`:** a bounded `list_cluster_custom_object(..., limit=1)` — a successful list (even empty) → `200 {"status": "ok"}`; any failure (unreachable API, RBAC-forbidden, CRD not served) → `503 {"status": "unavailable", "error": …}`. The dump dir is not part of this signal.
