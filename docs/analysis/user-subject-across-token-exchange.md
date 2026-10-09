# User Subject Across Token Exchange: Options

> **Status:** decided: B-AIAC (D31), 2026-10-06; changed on 2026-10-09 (the scope is the one
> source, also for the login clients; see the status note in §8.1). See
> [PRD D31](../specs/PRD.md#key-architectural-decisions) and the implementation note in §8.1. **Date:**
> 2026-10-06. **Branch:** `target-side-ac`.
>
> The analysis below stays as the decision used it. Dated status notes in §8.1 and §9 record the
> decision and its implementation. The `file:line` references are for the code before D31
> (`50d61a8`); the D31 change (`33b0bef`) moved some of these lines.
>
> The AuthBridge and operator facts come from their source code (§1.4). The Keycloak facts come
> from the Keycloak 26.5.2 source and docs (§1.5). Statements marked **To verify** are not
> confirmed yet. The live evidence is for the target side; §1.7 covers the agent side.

---

## 1. Problem

Under the target side (D23), the inbound OPA of a tool does the user gate (D26). The gate reads
`input.identity.subject`. AuthBridge's `jwt-validation` plugin fills that field from the `sub` claim
of the token that reaches the tool. The agent's `token-exchange` plugin gets that token from
Keycloak (RFC 8693).

In that exchanged token, `sub` is the user's Keycloak **user ID** (a UUID). The policy that AIAC
renders keys users by **username**. So the user gate never passes, and the tool denies every
`tools/call` that comes through the agent.

The inbound of the agent does not have this problem, because the login token of the user has
`sub` = username. So one user has two different subject values on the two legs of one call.

The agent side has the same cause, but it fails later: at the second agent of an agent chain, not at
the first exchange (§1.7).

### 1.1 Requirement

A user must have **one** subject value on every leg. An agent can get a call directly (with a login
token) or through another agent (with an exchanged token). Agents and tools must use the same
solution.

### 1.2 Evidence

Live checks on 2026-10-05, Kind cluster `kind-rossoctl`, Keycloak 26.5.2, realm `rossoctl`,
enforcement side `target-side`:

| Fact | Evidence |
|---|---|
| UC-1 rung 2 (agent, then tool) fails: the inbound to the agent is correct for all users, and every agent → tool call is denied | 3 of 4 runs; the other run failed earlier for a different cause. A 900 s convergence wait did not help |
| The `github-tool` CR is correct | The captured CR: the user gate and the agent gate agree with the oracle |
| The tool's OPA has the current bundle | bundle-service log: the tool bundle was built again at 19:15:15; the denies continued until 19:30:58 |
| The tool's OPA input has a UUID as subject | Decision log, `path=authbridge/inbound/request`: `identity.subject: 2a4e729b-de9f-4989-b4d0-bf6d158a6fb7`, `identity.client_id: spiffe://localtest.me/ns/team1/sa/github-agent`, `mcp.params.name: source-read`, `result: allow: false` |
| That UUID is `dev-user` | Admin API: `GET users/2a4e729b-…` → `username: dev-user` |
| The login token has `sub` = username | Password grant through client `rossoctl`: `sub: dev-user`, `azp: rossoctl`, `preferred_username: dev-user` |
| Only the `rossoctl` client has a `sub` mapper | `rossoctl` → mapper `username-to-sub` (`oidc-usermodel-property-mapper`, `user.attribute=username`, `claim.name=sub`, access + ID + userinfo). No client scope and no other client has a `sub` mapper |
| The realm has no `basic` client scope | Admin API: no client scope named `basic`. In Keycloak 25+ that scope holds the standard `sub` mapper |
| Without the mapper, login tokens have no `sub` | rossoctl `docs/_internal/authbridge/opa-migration-guide.md:285-289`: the mapper exists because tokens "ship without a `sub` claim" |
| The exchanged token gets `sub` = user ID, and the `rossoctl` mapper does not apply to it | The decision log above. V2 applies only the agent client's scopes (§1.5). **To verify:** which code sets `sub` = user ID, because no scope in this realm has the standard Subject mapper |
| The exchange accepts a subject token whose `sub` is the username | Every exchange in the 4 runs succeeded |
| Realm `rossoctl` has `editUsernameAllowed: false` | Admin API: `GET /realms/rossoctl` → `editUsernameAllowed: false`. This is why the username field is greyed out in the admin console |
| Keycloak enforces username uniqueness only against currently-existing users, not against history | Live test: creating a second user named `dev-user` while the original exists is rejected (`409: "User exists with same username"`); nothing checks whether that username was ever used before. Delete-then-recreate with the same username is not independently tested, but the live-row-only check makes it very likely to succeed |
| The operator's realm template does not set `editUsernameAllowed`, and it sets `registrationAllowed: false` | `operator/internal/bootstrap/keycloak.go:632`; no `editUsernameAllowed` key in the template, so a new realm gets the Keycloak default `false` (as realm `rossoctl` shows). Only an admin can create users |
| AIAC's IdP service can link a client scope to a client as a default scope | `POST /services/{id}/scopes/{scope_id}` calls `add_client_default_client_scope` (`src/aiac/idp/service/configuration/keycloak/main.py:484-492`) |
| The realm also hosts clients that AIAC does not manage | Admin API: the standard Keycloak clients (`account`, `admin-cli`, `broker`, …) and other applications (for example `mlflow`). They are outside the evaluation scope (§1.6) |

### 1.3 The current path of the subject

```
User ──password grant, client rossoctl──► token₁   sub = "dev-user"   (mapper username-to-sub)
  │
  ▼
github-agent inbound   jwt-validation: input.identity.subject = token₁.sub = "dev-user"
                       policy keyed by username ............................ match ✓
  │
  │  outbound token-exchange: requester = github-agent client,
  │  subject_token = token₁, audience = github-tool, scope = "openid agent-team1-github-tool-aud"
  ▼
token₂   sub = "2a4e729b-…" (user ID),  azp = spiffe://…/sa/github-agent
  │
  ▼
github-tool inbound    jwt-validation: input.identity.subject = token₂.sub = "2a4e729b-…"
                       policy keyed by username ............................ no match ✗
```

How AIAC keys users today:

- The IdP configuration service sets `actorIds` of each AIAC-managed user role to the member
  **usernames** (`src/aiac/idp/service/configuration/keycloak/main.py:540-546`). Keycloak also
  returns each member's `id`, but the service does not keep it.
- The PCE copies `actorIds` into `subject_roles` (`src/aiac/policy/model/projection.py:71`,
  `src/aiac/policy/computation/engine.py:952`).
- The PDP writer renders `subject_roles[input.identity.subject]` in each subject gate (agent
  inbound, tool inbound, agent outbound) (`src/aiac/pdp/service/policy/opa/rego.py`).

### 1.4 AuthBridge and operator facts

From the source code. `cortex/` is the AuthBridge repo, `operator/` is the rossoctl operator repo.

| Fact | Source |
|---|---|
| `jwt-validation` sets the subject from `sub`, and `client_id` from `azp`. The subject claim is not configurable | `cortex/core/plugins/jwtvalidation/validation/jwks.go:85-112`; config struct `jwtvalidation/plugin.go:32-107` |
| The plugin config rejects unknown keys (`DisallowUnknownFields`) | `jwtvalidation/plugin.go:243-244` |
| `jwt-validation` parses all claims (`preferred_username` goes to `Claims.Extra`), but `Extra` is private. The public claims carrier gives only `issuer`, `audience` and `exp`, by design | `jwks.go:108-112`; `jwtvalidation/identity.go:22-50`; `cortex/core/capabilities/identity.go:74-98` |
| The OPA input has only `identity{subject, client_id, scopes}` from `jwt-validation`. No claims, no token. Credential headers are removed. The `include` option covers only MCP, A2A and inference data | `cortex/core/plugins/opa/plugin.go:520-563`, `:758-778`, `:32-67` |
| A CR can ship only `.rego` files (`data.json` is not possible), so policy data must be Rego constants | `operator/api/v1alpha1/authorizationpolicy_types.go:75` |
| The token exchange authenticates the agent with a SPIFFE JWT-SVID (`client_assertion`, Keycloak `federated-jwt`), or with the client secret when the plugin's `identity.type` is `client-secret` (the setting of `k8s/opa-kind-enable.sh`). It sends `audience`, and `scope` only when the route has `token_scopes`. It sends no `actor_token`, and nothing forwards the user downstream | `cortex/core/plugins/tokenexchange/exchange/client.go:77-107`, `exchange/auth.go:28-43`; `cortex/core/auth/auth.go:441-443` |
| On the agent's outbound leg, `delegation.origin` is the `sub` of the incoming token (parsed without verification). This is why the agent side sees `dev-user` | `cortex/core/plugins/tokenexchange/plugin.go:785-832` |
| The operator creates workload clients with no protocol mappers and no explicit client scopes. Keycloak gives a new client the realm default scopes | `operator/internal/keycloak/admin.go:181-231` |
| The operator creates `agent-<ns>-<workload>-aud` with one audience mapper. It attaches that scope to the workload's own client and to each platform client (for example `rossoctl`), and makes it a realm default scope. It already has the code to add a protocol mapper to a scope | `operator/internal/keycloak/audience.go:62-104`, `:205-235` |
| The operator's realm template has a `profile` scope with a `username → preferred_username` mapper, and `profile` is a realm default scope. It has no `basic` scope and no `sub` mapper. This explains why the realm has no `basic` | `operator/internal/bootstrap/keycloak.go:725-738`, `:821` |
| The `username → sub` mapper on `rossoctl` comes from manual setup steps and a demo script, not from the operator | `k8s/opa-kind-runbook.md:95-122`; `rossoctl/docs/_internal/authbridge/opa-migration-guide.md:315-321`; `rossoctl/rossoctl/examples/app-demo/keycloak/register_client.py:112-119` |

### 1.5 Keycloak facts (26.5.2)

From the Keycloak source and docs at tag `26.5.2`. `GH/` = `github.com/keycloak/keycloak/blob/26.5.2/`.

| Fact | Source |
|---|---|
| The standard token exchange (V2) handles the AuthBridge request: the operator turns on `standard.token.exchange.enabled` on each client, and AuthBridge sends `subject_token_type`. V2 declines a request that has `requested_subject` / `requested_issuer` / `subject_issuer`, or that comes from a client with the switch off; the legacy V1 (feature `token-exchange`, on in this realm) then takes it without an error | `GH/docs/documentation/upgrading/topics/changes/changes-26_2_0.adoc` L95-103; `GH/services/…/tokenexchange/StandardTokenExchangeProvider.java` L72-117 |
| V2 builds the token for the **requester** (the agent). It applies the agent's default client scopes, the agent's own mappers, and the agent's optional scopes named in `scope`. It does not apply the mappers of the target client, or of the client of the subject token (`rossoctl`). **This is why `username-to-sub` does not reach the exchanged token** | `changes-26_2_0.adoc` L116 ("based on the client triggering the token exchange request rather than the 'target' client"); `GH/services/…/TokenManager.java` L640-677 |
| A mapper with claim name `sub` overrides `sub`: Keycloak calls `token.setSubject()`. Its default priority (0) runs after the standard Subject mapper (-10), so its value wins | `GH/services/…/mappers/OIDCAttributeMapperHelper.java` (the `sub` property setter and `mapClaim`); `changes-25_0_0.adoc` L304-306 |
| Keycloak finds the user from the session (`sid`), not from `sub`: subject-token validation, userinfo, introspection, refresh and Authorization Services. This is why the exchange accepts a subject token whose `sub` is the username. A token with no `sid` falls back to `sub` as the user ID, then to `preferred_username` | `GH/services/…/managers/AuthenticationManager.java` L1512-1596; `GH/services/…/util/UserSessionUtil.java` L60-127, L219-237 |
| A backchannel logout token always has `sub` = user ID | `GH/services/…/jose/jws/DefaultTokenManager.java` L351-376 |
| The built-in `username` mapper (`preferred_username`) is in the `profile` scope, so a V2 token has `preferred_username` when the agent has `profile` as a default scope. A lightweight access token omits it; in 26.5.2 the lightweight executor does not act on token exchange, but it does act on the password grant | `GH/services/…/OIDCLoginProtocolFactory.java` L166-170, L268-282; `UseLightweightAccessTokenExecutor.java` |
| Realm default client scopes link only to clients created later. For an existing client: `PUT /admin/realms/{realm}/clients/{id}/default-client-scopes/{scopeId}`. A scope that is already linked (default or optional) is skipped with no error | `proc-updating-default-scopes.adoc`; `GH/services/…/admin/ClientResource.java` L408-482; `JpaRealmProvider.addClientScopes` |
| The mappers of an optional scope run only when `scope` names it. `audience` never adds a scope | `TokenManager.java` L662-676; `token-exchange.adoc` L156-170 |
| 26.5.2 has no delegation (`act`, `may_act`). The feature `token-exchange-delegation` is experimental in 26.7 and preview in 26.8 | `GH/docs/guides/securing-apps/token-exchange.adoc` L290-291, L327 |

**The Keycloak gates on the exchange.** Before OPA decides anything, Keycloak itself limits which
agent can exchange a token toward which tool:

| Gate | What Keycloak checks | Failure |
|---|---|---|
| 1 — requester allowed | The requester (agent) client has `standard.token.exchange.enabled` | V2 declines the request. In this realm the legacy V1 then takes it (§1.5); with V1 off, `400` "Standard token exchange is not enabled for the requested client" |
| 2 — target reachable | The tool's audience scope (`agent-<ns>-<tool>-aud`) is linked to the requester client. V2 checks `scope` only against the requester's scopes (`StandardTokenExchangeProvider.java` L183-204) | A requested scope that is not linked: `400 invalid_scope`. No `scope` and no linked scope that gives the requested `audience`: `400` "Requested audience not available" |

Gate 2 is a topological boundary (which agent may reach which tool), separate from the per-user and
per-tool decisions in OPA. **To verify:** whether it still separates agents. The operator makes
each audience scope a realm default scope (§1.4), so a client that is created after a tool's
audience scope exists may get that scope by default, and then pass gate 2 for that tool.

The earlier reference `docs/analysis/keycloak-access-control-analysis.md` (removed; see git history)
also described a Keycloak-native RBAC model (composite roles, scope-to-role gating,
`fullScopeAllowed=false`). AIAC does not use it: OPA is the PDP (`docs/specs/PRD.md:70-76`).

### 1.6 Evaluation scope

This analysis covers only **AIAC-managed agents and tools**: the services that AIAC onboards, whose
access is controlled by token exchange and the OPA PEP of AuthBridge. The realm can tell them
apart from other clients:

- AIAC onboarding tags each managed client with the Keycloak client attribute `client.type` =
  `Agent` or `Tool` (`src/aiac/agent/uc/onboarding/provision/nodes.py:470` →
  `POST /services/{id}/type`; the value comes from the pod label `rossoctl.io/type`). Clients that
  AIAC does not manage have no `client.type`.
- The roles and client scopes that AIAC creates carry the attribute `aiac.managed=true`
  (`src/aiac/idp/service/configuration/keycloak/main.py:475,561,595`).
- The Controller's managed set is the set of services that have a stored SPM
  (`src/aiac/policy/computation/engine.py:454-460`).

A service has no CR before it is onboarded, and the global combiner denies a pod that has no CR.

The tokens in scope are the tokens that reach those services:

- the **login token** of the user, from the login client that calls AIAC agents (`rossoctl`);
- the **exchanged token**, minted for an AIAC-managed agent client.

Other clients of the realm (the standard Keycloak clients, `mlflow`, …) are out of scope. Their
tokens do not go through the AIAC token exchange or the OPA PEP. Where an option changes a client
that other consumers share (the login client), the file says so in a boundary note, but it does
not score that effect.

### 1.7 Enforcement sides

The live evidence (§1.2) is for the **target side**. The **agent side** (D23) has the same cause:
the first check that reads the subject of an exchanged token fails. Which check that is depends on
the side and on the number of hops.

Where each user check gets its subject:

| Check | Side | Subject comes from | One hop: user → agent → tool | Two hops: user → agent A → agent B → tool |
|---|---|---|---|---|
| Agent inbound user gate (`rego.py:256`) | Both | `sub` of the incoming token (`jwt-validation`) | Login token: username ✓ | Agent A: username ✓. Agent B: the token from A's exchange, user ID ✗ |
| Agent outbound per-tool gate (`rego.py:323`) | Agent side | `delegation.origin` = the `sub` of the token that came **into** the agent (`tokenexchange/plugin.go:785-832`) | Login token: username ✓ | Agent A: username ✓. Agent B: the exchanged token, user ID ✗ |
| Tool inbound user gate | Target side | `sub` of the exchanged token | User ID ✗ (the UC-1 failure) | User ID ✗ |
| Tool inbound | Agent side | — (pass-through) | Not checked | Not checked |

So:

- **Target side:** it fails at one hop. This is the UC-1 rung-2 failure.
- **Agent side:** one hop works, which is why the runbook's agent-side example (B.5) shows
  `dev-user`. It fails at the second agent of a chain, in both that agent's inbound and its
  outbound. AIAC models such a chain: the delegation scenario `dispatch-agent` → `customs-agent`
  (`test/system/scenario_eval_agent_delegation.py`).

The agent-side rows come from the code paths. They are not run live (§9).

---

## 2. Option A — `sub` = user ID everywhere; AIAC keys users by user ID

**Target state.** Each token for a user has `sub` = the Keycloak user ID, from each client and on
each path (login or token exchange). Each CR that AIAC renders keys users by that ID. The Rego does
not change: it already reads `subject_roles[input.identity.subject]`.

| Layer | Change | Where |
|---|---|---|
| Login client (one time) | On `rossoctl`, replace `username-to-sub` with a mapper that writes the user ID to `sub`: the standard Subject mapper (`oidc-sub-mapper`), or the standard `basic` scope that holds it. Removing the mapper alone is **not** sufficient: then login tokens have no `sub`, and every user is denied. This is a manual setup step today, so the change is in the setup docs, not in code | The realm setup in `k8s/opa-kind-enable.sh` / `k8s/opa-kind-driver.sh` / the runbook prerequisites; the rossoctl guide |
| AIAC-managed agent and tool clients | No change: the exchange already gives `sub` = user ID (§1.2) | — |
| Realm template (operator) | Not needed inside the scope. Optional hardening: add `basic` to the template so that each new client gets the standard `sub` | `operator/internal/bootstrap/keycloak.go` (other team) |
| IdP configuration service | `actorIds` of user roles = member `id`, not `username`: `[m["id"] for m in members]` | `src/aiac/idp/service/configuration/keycloak/main.py:540-546`; docstrings in `src/aiac/idp/configuration/models.py:23,79` |
| PCE / policy model | No logic change: both read `role.actorIds`. Rename variables and comments (`username` → `user_id`) | `projection.py:31,71`, `engine.py:952` |
| PDP writer | No change. Optional: render the username as a comment next to each user-ID key. That needs the username on `Role` (for example a new `actorNames` field) | `rego.py` |
| Stored SPMs | SPM rules store whole `Role` objects, so stored SPMs keep username `actorIds`. The Controller resync (`engine.py:454`) uses the SPMs as stored and does not read the IdP again. Migration: clear the store and onboard again, or do a full rebuild. **To verify:** whether `build_policy()` (subject `aiac.apply.policy.build`) does a full rebuild from the IdP | Model store; deploy procedure |
| Test harness | `verify_subject_mapper` expects `sub` = the user's ID. The oracles can stay keyed by username; the checks of CR maps convert username → ID | `test/system/uc1_onboard.py:1073`, `test/system/launcher.py:925-942`, `test/system/scenario_uc1.py`, `k8s/opa-kind-driver.sh:419-420` |
| Docs | Change the examples that show `identity.subject = dev-user` | `k8s/opa-kind-runbook.md`, `docs/examples/opa-team1-policy.yaml`, `docs/specs/components/pdp-policy-writer-opa.md`, `docs/testing/*.md` |

**Gains.**

- The same subject on each path: a direct call and a call through another agent.
- Stable: a username rename or reuse cannot move grants to a different person. A rename needs no
  re-render.
- New workload clients need no setup: the exchange path already gives the user ID.
- Standard Keycloak behaviour: no override of `sub`.

**Costs and risks.**

- CR keys and decision logs show UUIDs. Comments in the rendered Rego help (see §6).
- Boundary note (§1.6): `rossoctl` is a shared login client, so its `sub` changes also for its
  other consumers, for example the rossoctl OPA examples that key on `alice` / `bob`.
- A login client without `basic` gives tokens without `sub`. The result is a deny for all users
  (fail closed), but it is silent. A harness check of the login token and of the exchanged token
  finds it.

---

## 3. Option B — `sub` = username everywhere

**Target state.** Each token for a user has `sub` = username, from each client and on each path.
AIAC keeps the username keys. The Rego does not change.

| Layer | Change | Where |
|---|---|---|
| Keycloak realm, realm-default placement (one time; not recommended inside the scope) | Create one client scope (for example `aiac-username-sub`) with the user-property mapper `username → sub` (access, ID, userinfo, introspection). Make it a realm default client scope. This also reaches clients that AIAC does not manage (§1.6). Assign it as a default scope to each existing client that mints user tokens: each login client (`rossoctl`) and each agent client that does a token exchange. Then delete the per-client `username-to-sub` on `rossoctl`, so that there is one source | The realm setup scripts; the runbook; the rossoctl guide (other team) |
| Alternative placement | Put the mapper on each audience scope (`agent-<ns>-<workload>-aud`). The operator creates these scopes and already has the code to add a protocol mapper to a scope, so a second mapper is a small change. Note: the operator attaches each audience scope also to the platform clients and makes it a realm default scope (§1.4), so the mapper reaches login tokens too, not only exchanged tokens | `operator/internal/keycloak/audience.go` (other team) |
| Operator | New workload clients get the realm default scopes, because the operator sets no explicit scopes (§1.4). So the realm-default placement covers new clients with no operator change | — |
| AIAC-owned placement (B-AIAC, recommended in §8.1) | The scope is **not** a realm default. AIAC links it as a default scope to each service's client at onboarding, with the existing IdP call `POST /services/{id}/scopes/{scope_id}`, in the same provisioning step that tags the client with `client.type` (§1.6). It changes only AIAC-managed clients (§1.6) and needs no operator change. The login client `rossoctl` keeps its own `username-to-sub` mapper, for backward compatibility (§8.1) | `src/aiac/agent/uc/onboarding/` (the onboarding flow); the IdP service already has the endpoint |
| AIAC source | Realm-default placement: no change. B-AIAC: one call in the onboarding flow | — |
| Test harness | Extend the precondition check to the exchanged token. A practical form: after registration, check with the admin API that the agent client has the scope with the mapper | `test/system/uc1_onboard.py:1073`, `test/system/launcher.py` |
| Docs | Add the realm prerequisite. The runbook text that says the tool leg has `subject = dev-user` becomes true | Runbook, specs |

**Feasibility: confirmed (§1.5).** A mapper with claim name `sub` overrides `sub`, also in an
exchanged token. But V2 runs only the mappers of the **agent** client, so the mapper must be in a
scope that the agent client has. A mapper on the login client (as today) or on the tool's client
does not reach the exchanged token. Two placements work:

- a realm default scope that is also linked to each existing agent client (new clients get it
  automatically);
- the optional audience scope `agent-<ns>-<workload>-aud`, but only when the route sends
  `token_scopes`. The routes that the operator generates send no `scope` (§1.4); only the
  hand-written UC-1 route does.

**Gains.**

- No change to AIAC source.
- Policies and decision logs show readable names.
- The runbook examples stay valid.

**Costs and risks.**

- Not stable, for two separate reasons:
  - **Rename.** Live check (2026-10-06): realm `rossoctl` has `editUsernameAllowed: false`, so a
    username cannot be renamed through the console or self-service, as configured today. But
    this is itself a realm setting that can be turned on later with no code change. The
    operator's realm template does not set it, so each new realm gets the Keycloak default
    `false` (§1.2).
  - **Reuse.** `editUsernameAllowed` does not block this. Live check (2026-10-06): Keycloak rejects
    a *second* user with an existing username (`409`), but it enforces uniqueness only against
    users that exist right now, not against a history of retired usernames. So the exposure is
    narrower than ambient "usernames get recycled": it needs a deliberate two-step admin action
    (delete `dev-user`, then create a *new* user also named `dev-user`), not something that
    happens through normal renaming, typos, or self-service. The sequence itself was not run live
    (it would destroy and recreate a real test-realm user); the live-row-only uniqueness check
    makes it very likely to succeed. If that sequence occurs, a stale CR key gives the new person
    the old user's grants until AIAC re-renders — AIAC does not listen for create/delete events.
    This is a process risk (an admin runbook can forbid username reuse) rather than something
    Keycloak prevents structurally.
  - OIDC Core §5.7: only `sub` together with `iss` is a stable identifier. An override with a
    value that can be reused removes that guarantee for the AIAC-managed services.
- Coverage: each AIAC-managed agent client must have the mapper in its own scopes. With a manual
  setup, one client without it gives a UUID, and every user on that path is denied without a clear
  error (the same failure class as the current problem). With B-AIAC the risk is low: onboarding
  links the scope, and a service has no CR before onboarding (§1.6).
- Keycloak itself keeps working, because it finds the user from the session (`sid`), not from
  `sub` (§1.5). But:
  - backchannel logout tokens keep `sub` = user ID. AIAC-managed agents and tools are resource
    servers behind AuthBridge and do not receive logout tokens (**to verify**);
  - ID tokens and logout tokens keep other `sub` values, but they do not reach AIAC-managed
    services. The access tokens in scope (login and exchanged) both get the username;
  - introspection needs the mapper's "Add to token introspection" switch;
  - a token with no `sid` depends on the `preferred_username` fallback.
- The override is a deliberate Keycloak feature, but no Keycloak document supports `sub` =
  username. It goes against OIDC Core and RFC 9068 §2.2, which define `sub` as the stable
  identifier of the user.

---

## 4. Option C — AuthBridge takes the subject from `preferred_username`

**Target state.** Tokens keep the standard Keycloak `sub`. AuthBridge fills
`input.identity.subject` from the `preferred_username` claim. All agents and tools run the same
AuthBridge plugins, so the subject is the same on each path. AIAC keeps the username keys.

Three variants:

None of the variants exists today: the subject claim is not configurable, and no claim other than
`sub`, `azp` and `scope` reaches OPA (§1.4).

| Variant | Description | Size | Owner |
|---|---|---|---|
| C1 — `jwt-validation` option | Add an option such as `subject_claim` (default `sub`) to the config struct (`jwtvalidation/plugin.go:32-107`), and apply it where the plugin sets the identity (`plugin.go:439`). Set it to `preferred_username` in the AIAC namespaces. The plugin rejects unknown keys, so deploy the new image before the new configuration | Smallest code change | AuthBridge (`cortex`) |
| C2 — claim in the OPA input | Extend the OPA input (`opa/plugin.go:520-563`) with a selected claim, for example `input.identity.username`. The AIAC writer renders the subject from it. The full claim set is private by design (the claims carrier gives only `issuer`, `audience`, `exp`), so the AuthBridge owners must agree which claims to expose | Medium | AuthBridge + AIAC writer |
| C3 — claims-mapper plugin | A new plugin after `jwt-validation` that sets `identity.subject`. It cannot read the private claims, so it must decode the already verified `Authorization` header again. It also needs a build tag, a profile entry and an operator preset order entry | Largest | AuthBridge |

| Layer | Change | Where |
|---|---|---|
| AuthBridge | One of C1–C3. **For the agent side, a second change is required:** the outbound identity uses `delegation.origin`, which the token-exchange plugin takes from the identity subject when one is set, otherwise from the raw `sub` of the incoming bearer (`tokenexchange/plugin.go:785-832`). It must use the same claim. C1 alone fixes only the inbound checks. If `username-to-sub` is removed, the agent-side outbound check fails even at one hop without this change (§1.7) | `cortex` repo (other team) |
| AuthBridge configuration | Set the claim in the pipeline configuration. The operator builds each workload's `config.yaml` from the namespace `authbridge-runtime-config` | `k8s/opa-kind-enable.sh`; `operator/internal/webhook/injector/pod_mutator.go:1103-1220` |
| Keycloak | Each token must have `preferred_username`. Login tokens have it (observed). A V2 token has it when the agent client has `profile` as a default scope (§1.5). The operator's realm template makes `profile` a realm default scope (§1.4), and the exchanged token's scope list includes `profile` (decision log). So exchanged tokens have it, unless the token is a lightweight access token. **To verify** once with a decoded exchanged token. AIAC no longer needs `username-to-sub`. If it is removed, login tokens have no `sub`. **To verify:** does `jwt-validation` accept a token without `sub`? | Realm |
| AIAC source | C1 and C3: no change. C2: the subject expression in each gate of the writer | `rego.py` |
| Test harness | The precondition checks `preferred_username` in the login token and in the exchanged token, not `sub` | `uc1_onboard.py`, `launcher.py` |
| Docs | The runbook says that `subject` is the JWT `sub` claim; this changes to `preferred_username` | Runbook, specs |

**Gains.**

- Keycloak `sub` stays standard.
- Policies and decision logs show readable names.
- No change to AIAC source (C1, C3).
- One setting controls all services.

**Costs and risks.**

- Not stable: the same rename and reuse risk as option B. OIDC Core §5.7 says that a relying party
  must not use `preferred_username` as a unique identifier. In Keycloak a username is unique in a
  realm at one time, but it can change.
- Ownership: a change in AuthBridge, a component of another team. Its default must stay `sub`.
- Coverage: a token without `preferred_username` (a client without the `profile` scope, or a
  lightweight access token) gives no subject, and every user on that path is denied.

---

## 5. Considered, not preferred: a UUID → username map in the Rego

**Description.** The writer renders a map from user ID to username into each CR as a Rego
constant, for example `subject_usernames := {"2a4e729b-…": "dev-user"}`. A CR can ship only
`.rego` files, so a separate `data.json` is not possible (§1.4). Each subject gate first resolves the subject:
`subject := object.get(subject_usernames, input.identity.subject, input.identity.subject)`, then
reads `subject_roles[subject]`. The data comes from the IdP (`Subject{id, username}`,
`GET /subjects?role_id=`).

**Why it is not preferred.**

- It hides an identity problem in the policy. Two subject forms stay in the system.
- It copies IdP data into each CR. Each new user and each rename needs a re-render of all CRs, and
  AIAC does not listen for rename events.
- Collision: a user whose username is equal to the ID of a different user resolves to that user.

---

## 6. Comparison

| Criterion | A — user ID | B — username in `sub` | C — `preferred_username` |
|---|---|---|---|
| Same subject on each path | Yes | Yes, if each client has the mapper | Yes, if each token has `preferred_username` |
| Stable when a username changes or is used again | Yes, structurally — Keycloak user IDs are never reused | Renaming is currently blocked (`editUsernameAllowed: false`); reuse needs a deliberate delete-then-recreate, not confirmed live but likely to work | Same as B — a username is unique only among current users, not over time |
| Risk of a silent gap when a client has no setup | Low: the exchange path gives the ID with no setup; only the login client changes | Low with B-AIAC (onboarding links the scope); high with a manual setup | Low: `profile` is a realm default scope |
| Standard Keycloak behaviour | Yes | No: an override of `sub`. Keycloak works with it, but logout tokens keep the user ID | Yes |
| What changes | The login client's `sub` mapper, AIAC IdP service, harness, docs, store migration | Existing realm (or the operator's audience scopes), harness, docs | AuthBridge code and its configuration, harness, docs (and the AIAC writer for C2) |
| Owners outside AIAC | None in code (the login-client setup step is documented) | None with B-AIAC | AuthBridge team |
| Readable policies and logs | No (UUIDs; comments help) | Yes | Yes |
| Feasible with configuration only | Yes | Yes, if the mapper is in the agent client's scopes (§3) | No (an AuthBridge change) |

---

## 7. Combinations

- **A and B exclude each other:** `sub` holds one value.
- **B and C are alternatives** for one goal (the username as the subject). C keeps `sub` standard,
  so C is the better end state.
- **B now, then C (the path of §8.1):** B gives the username as the subject today with no other
  team. When AuthBridge gets a `subject_claim` option, switch to C and remove the `sub` mapper.
  The policies do not change, because both give the same subject value.
- **A + C2, for readability only:** key users by user ID, and also give `preferred_username` in the
  OPA input, so that decision logs show the name. The policy does not use the name.
- **A + Rego comments:** the writer renders the username as a comment next to each user-ID key.
  No component outside AIAC changes.
- **A transition with two keys:** render both the user ID and the username for a short time, then
  remove the username keys. While both exist, the collision risk of §5 applies.
- **Later: Keycloak delegation.** Keycloak 26.7+ (experimental; preview in 26.8) can add an `act`
  claim that names the calling agent. It does not change `sub`, so it does not solve this problem.
  But it is relevant to agent chains, and it works with each of A, B and C.

---

## 8. Assessment

The decision is open. The best option depends on one assumption about usernames, so this section
gives two assessments.

### 8.1 If usernames are unique, cannot change, and are never reused (stated assumption)

**Recommendation: option B now, with an AIAC-owned placement (B-AIAC below). Option C later, if
the AuthBridge team accepts a `subject_claim` option. Option A is no longer preferred.**

The assumption is realistic for this platform:

- Keycloak enforces a unique username among current users (§1.2, live `409`).
- The operator's realm template does not set `editUsernameAllowed`, so each realm gets the
  Keycloak default `false` (as in realm `rossoctl`, §1.2). Usernames cannot change.
- The template sets `registrationAllowed: false`, so only an admin can create users. Reuse can
  happen only when an admin deletes a user and then creates the same username again. A written
  admin rule ("never create a deleted username again") closes that gap.

With the assumption, the main gain of option A (a stable identifier) is gone: a username is as
stable as a user ID. The criteria that are left:

| Criterion | A — user ID | B — username in `sub` | C — `preferred_username` |
|---|---|---|---|
| Stable identifier | Yes | Yes (by the assumption) | Yes (by the assumption) |
| Work in AIAC | IdP service change, SPM store migration, harness, docs | One-time scope + a link at onboarding; harness check | Harness and docs (C1); writer (C2) |
| Work for other teams | None in code. Boundary note: the shared login client's `sub` changes for its other consumers | None (B-AIAC) | AuthBridge code change and release |
| Readable policies and logs | No | Yes | Yes |
| Fits the current conventions (runbook, rossoctl examples, generated policies, agent-side outbound `delegation.origin`) | No — all change to UUIDs | Yes — the same convention, extended to the exchange path | Yes |
| Setup gap on the exchange path | None (observed) | None: onboarding links the scope, and a service has no CR before onboarding (§1.6) | None (`profile` is a realm default) |
| Standard Keycloak `sub` | Yes | No (override; logout tokens keep the user ID) | Yes |
| Available now | Needs the operator team | **Yes** | Needs the AuthBridge team |

**B-AIAC — the recommended placement of option B:**

1. AIAC creates, idempotently, a client scope `aiac-username-sub` with one user-property mapper
   (`username` → claim `sub`; access token, ID token, userinfo, introspection). The scope must
   **not** carry the `aiac.managed` marker, for two reasons:
   - it is linked to many clients, and a marked scope with more than one owner is an Assumption 2
     violation: `GET /services/{id}/scopes` returns `409`, so the catalog read fails
     (`docs/specs/components/idp-configuration-service.md:107,197`); *D32 (2026-10-07) removed
     Assumption 2 and its check, so this reason no longer applies; see the status note below*;
   - a marked scope would become an own scope of each linked service and enter the policy model
     and the PRB candidates.

   The login client `rossoctl` does **not** change. It keeps its own `username-to-sub` mapper,
   which has the same mapping. That mapper runs only for tokens issued for `rossoctl` (the login
   token), and the scope covers the tokens issued for the AIAC-managed agents (the exchanged
   tokens). So the rossoctl guide, its examples, the runbook prerequisite and the other users of
   `rossoctl` keep working, and AIAC never modifies a shared client. *Changed on 2026-10-09: AIAC
   now links the scope to `rossoctl` too, and the manual mapper step is gone; see the status note
   below.*
2. At onboarding, AIAC links `aiac-username-sub` as a default scope to the onboarded service's
   client. Do it in the provisioning step that tags the client with `client.type`
   (`provision/nodes.py:470`), so it happens before `compute_and_apply` writes the CR. The scope
   then belongs to exactly the clients that carry `client.type`. The IdP service already has this
   call (`POST /services/{id}/scopes/{scope_id}` → `add_client_default_client_scope`). V2 then
   applies the mapper to each exchange that this agent requests (§1.5).
3. Link the scope only to AIAC-managed clients (the evaluation scope, §1.6). Do not make it a
   realm default.
4. A check: the Controller (or the harness) verifies that the onboarded agent client has the
   scope, and the system test decodes one exchanged token and checks `sub` = username.
5. Turn off the legacy token exchange (V1). V1 uses the scopes of the *target* client, so a
   request that falls back to V1 would not get the mapper (§1.5, §9 side findings). *Corrected on
   2026-10-07: this is true only for a target without the link; see the status note.*

> **Status (2026-10-06): decided, D31.** The user chose B-AIAC, with the username precondition and
> with `rossoctl` unchanged. The steps above are implemented as follows:
>
> 1. The scope: an idempotent ensure-step in the IdP Configuration Service, inside the new link call
>    `POST /services/{service_id}/subject-scope`. It creates `aiac-username-sub` and its
>    `username-to-sub` mapper with no `aiac.managed` marker, so a deleted scope comes back at the next
>    onboarding. It runs at each onboarding, not in the Controller start sequence (PRD §7.7 does not
>    change). `rossoctl` does not change: it keeps its own mapper, and AIAC never links the scope to
>    it. *Changed on 2026-10-09: AIAC now links the scope to `rossoctl`; see the status note below
>    the risks.*
> 2. The link: Provision calls `link_subject_scope` before `set_service_type`, for agents and tools,
>    so before `compute_and_apply` writes the CR. It uses the new endpoint, not
>    `POST /services/{id}/scopes/{scope_id}`: the new endpoint also moves an optional link to a
>    default link. The link is not in the created-manifest, so the rollback, the quarantine and the
>    offboarding never delete the scope. A service onboarded before D31 gets the link at its next
>    onboarding (no backfill).
> 3. Only AIAC-managed clients: the endpoint changes only the client of the onboarded service, and
>    never makes the scope a realm default.
> 4. The check is in the system harness, not in the Controller: `require_subject_scope` (each
>    onboarded client links the scope; a failure, not a skip), `verify_subject_mapper` (the login
>    token, unchanged), and the rung-2 test `test_exchanged_token_subject_is_username` (it decodes an
>    exchanged token).
> 5. Optional, and not done here: `KC_FEATURES` is in the Keycloak deployment of the rossoctl
>    platform, not in this repo. Correction (2026-10-07): AIAC does not depend on it. V1 handles a
>    request only when V2 declines it (the requester has no `standard.token.exchange.enabled`, or
>    the request has `requested_subject` / `requested_issuer` / `subject_issuer`); the AuthBridge
>    requests meet none of these conditions. If V1 handles a request, it uses the target client's
>    scopes, and AIAC links the scope to each managed agent **and** tool, so an onboarded target
>    still gets `sub` = the username. A target without the link is not onboarded, so it has no CR and
>    the global combiner denies it (D20). A wrong subject can only cause a deny (usernames are the
>    only keys, and each rules-based package denies by default, D25). Turning V1 off makes a request
>    that V2 declines fail loudly (`400`); Keycloak recommends it.
>
> Two facts found during the implementation:
>
> - `GET /services/{id}/scopes` returns **every** default scope of a client, the Keycloak built-ins
>   (`profile`, `email`, …) too, so it also lists `aiac-username-sub`. The scope does not pollute the
>   policy model or the PRB candidates because it has no marker: the consumers keep only
>   `Scope.aiac_managed` scopes (`policy/computation/engine.py`, `agent/shared/focal_entities.py`).
>   That is how the handoff criterion "`list_service_scopes` does not return it" is met in intent.
> - The Assumption-2 owner scan does not work on a live system, before and after D31: Keycloak's
>   `GET /clients/{id}/default-client-scopes` returns only `id` and `name` (live check, 2026-10-06),
>   so `list_service_scopes` never sees the `aiac.managed` attribute and never builds the owner index.
>   A marked shared scope would therefore not give a live `409`; it would become an own scope of each
>   linked service. This is a separate defect (record it as its own issue); the "no marker" rule of
>   D31 does not depend on it.
> - Status (2026-10-07): D32 (PRD §5) removed Assumption 2 and its check, so this defect is closed.
>   A realm is a tenant and one policy covers the realm, so a shared `aiac.managed` scope is valid:
>   `GET /services/{id}/scopes` lists it for each owner, with that owner as `serviceId`, and gives no
>   `409`. The "no marker" rule of D31 stays, for the second reason in step 1: a marked
>   `aiac-username-sub` would become an own scope of each linked service.

Risks that are left with B-AIAC:

- The `sub` override is not documented as supported for usernames. Logout tokens keep the user
  ID, but they do not reach AIAC-managed services (**to verify**).
- The assumption must stay true. Record it as a platform precondition in the spec: keep
  `editUsernameAllowed: false`, keep `registrationAllowed: false`, and never create a deleted
  username again.
- A client is AIAC-managed only after onboarding, and before that the global combiner denies its
  pod (no CR). So a failed link shows as a deny, and the check in step 4 finds it.
- Two sources of one rule: the `rossoctl` mapper (login tokens) and `aiac-username-sub`
  (exchanged tokens). They must stay equal (username → `sub`). The harness checks both: the login
  token (`verify_subject_mapper`) and the scope link (step 4).
- The `rossoctl` mapper stays a manual prerequisite (the runbook), as today. Any other login
  client that calls AIAC agents directly needs the same mapper.

> **Status (2026-10-09): the decision changed.** The client scope `aiac-username-sub` is now the
> one source of `sub` = the username, also for the login token. The two risks above about the two
> sources and the manual `rossoctl` mapper are closed. The changes:
>
> - AIAC links `aiac-username-sub` as a default scope to the platform login clients
>   (`PLATFORM_SOURCE_CLIENTS`, default `rossoctl`; the same setting as the platform bypass
>   clients of the PDP Policy Writer, from the ConfigMap `aiac-pdp-config`). The IdP Configuration
>   Service makes this link at its startup (when `KEYCLOAK_REALM` is set; a failure does not stop
>   the service) and again at each `POST /services/{service_id}/subject-scope`. A login client that
>   is not in the realm is not an error.
> - The manual `username-to-sub` client mapper step on `rossoctl` is removed from the runbook. AIAC
>   adds no client mapper to a login client. The scope is still not a realm default, still has no
>   `aiac.managed` marker, and is still not in the created-manifest.
> - Fresh installs only: AIAC does not remove an old manual mapper on `rossoctl`.
> - The harness: `verify_subject_mapper` is now `verify_login_subject`. It skips when it cannot
>   mint the login token (Direct Access Grants), and fails when `sub` is not the username, because
>   the link is an AIAC step. `require_subject_scope` and the rung-2 test `test_subject_scope_linked`
>   now require the default link on `rossoctl`, and no `rossoctl` client mapper that writes `sub`.
> - Open: AIAC now writes to a client that the rossoctl chart owns, so the rossoctl team must agree.
>   Option C (§4, AuthBridge `subject_claim`) is still the end state, and it removes the scope too.

**Both enforcement sides (§1.7).** B-AIAC fixes both sides with one setup. Each exchanged token for
a managed agent then has `sub` = username, so the inbound of a second agent sees the username, and
its outbound `delegation.origin` (taken from that token) is the username too. One hop does not
change. A switch of the enforcement side (`AIAC_ENFORCEMENT_SIDE`) needs no identity change. The
urgency differs: the target side needs the fix now (UC-1 fails at one hop); the agent side needs
it for agent chains.

**Why option C later:** C keeps `sub` standard and needs no per-client link, because `profile` is
already a realm default. On the agent side, C needs two AuthBridge changes (`jwt-validation` and
the delegation origin of the token-exchange plugin), not one (§4). When AuthBridge has a `subject_claim` option (C1), AIAC can remove
`aiac-username-sub` with no change to policies, because both B and C give the same username as
the subject.

### 8.2 If the assumption cannot be guaranteed

**Recommendation: option A**, with Rego comments for readability. It is the only option whose
identifier is structurally stable: Keycloak never reuses a user ID. The safety of B and C would
depend on a realm setting (`editUsernameAllowed`) and on an admin rule (no username reuse), not on
the platform. A also needs no setup on the exchange path. Its costs (the AIAC IdP change, the SPM
migration, UUIDs in logs, the change of the shared login client) are the price of that guarantee. Of B and
C, C is better, because it keeps `sub` standard.

A is valid on both enforcement sides: after the login-client change, the login token, each exchanged
token and `delegation.origin` all carry the user ID (§1.7).

---

## 9. Open questions (To verify)

Open:

1. Whether `jwt-validation` accepts a token without `sub` (option C, if `username-to-sub` is
   removed).
2. Whether the exchanged token has `preferred_username` (option C). Very probable (§4); confirm
   once with a decoded token.
3. Whether `build_policy()` rebuilds all SPMs from the IdP (migration for option A).
4. Which Keycloak code sets `sub` = user ID in the exchanged token, because no scope in this realm
   has the standard Subject mapper (§1.2). The observed behaviour is clear; only the cause is
   unknown.
5. Whether any AIAC-managed agent or tool receives backchannel logout tokens, which keep
   `sub` = user ID (option B). Expected: no, because they are resource servers behind AuthBridge.
6. *Closed on 2026-10-06; see Closed.*
7. *Closed on 2026-10-07; see Closed.*
8. The agent-side two-hop result of §1.7 (fails at the second agent) on the live cluster. It is
   inferred from the code paths only.
9. Added 2026-10-08. Check D31 again when AuthBridge starts to send an `actor_token`. On cortex
   `main` (`00cd25be`, 2026-10-07) the exchange client can send `actor_token` /
   `actor_token_type` (`core/plugins/tokenexchange/exchange/client.go`), but no plugin sets it
   (`core/auth/auth.go`: "actor-token chaining is not yet wired by any plugin"). Keycloak 26.5.2's
   standard exchange (V2) has no delegation support (§1.5), so a request with an `actor_token` could
   fail or go to another engine. On the same commit, `jwt-validation` still takes the subject only
   from `sub` (`validation/jwks.go`), so option C still needs an AuthBridge change.

Closed:

- V2 handles the exchange, and it applies only the agent client's scopes (§1.5).
- A `sub` mapper in the agent client's scopes changes the `sub` of an exchanged token (§1.5).
- Keycloak finds the user by `sid`, not by `sub`; the risks of an override are in §3 (§1.5).
- `jwt-validation` takes the subject only from `sub`; no option exists (§1.4).
- The operator gives new clients the realm default scopes (it sets no explicit scopes) (§1.4).
- The `rossoctl` mapper comes from manual setup steps and a demo script, for the OPA examples that
  key on usernames (§1.4).
- Usernames cannot be edited in realm `rossoctl`, and the operator's template keeps the Keycloak
  default (`editUsernameAllowed: false`) (§1.2).
- Keycloak rejects a second user with an existing username (§1.2).
- AIAC's IdP service can link a scope to a client as a default scope (§1.2).
- Question 6 (closed on 2026-10-06): the username precondition of §8.1 (no rename, no reuse) is a
  written rule. Decided with the user on 2026-10-06, and recorded as a platform prerequisite in PRD
  §8 (D31).
- Question 7 (closed on 2026-10-07): the agent side works at one hop on the live cluster. With D31
  deployed, rung 7 (the side switch) passed (40 tests): the verdicts are the same under target side
  and under agent side, and the deny comes from the enforcement point of each side.
- D31 works on the live cluster (2026-10-07, `kind-rossoctl`, target side). Rung 2 (agent, then tool)
  passed (23 tests), also the new `test_subject_scope_linked` and
  `test_exchanged_token_subject_is_username`: a standard token exchange as the agent client gives
  `sub` = the username for each user. The decision log of github-tool's inbound OPA shows
  `subject: dev-user` and `subject: test-user` for the agent → tool calls (§1.2 showed the user ID).
  Its self-discovery calls, which run before the tool's own Provision links the scope, still show
  the user ID of the tool's service account; the self-discovery rule keys on `client_id`, so this
  has no effect. Rungs 1 and 3 passed too (5 and 19 tests).

Side findings, not part of the decision:

- The realm has the legacy feature `token-exchange` (V1) on. A request that V2 declines (for
  example from a client with the standard switch off) goes to V1 with no error. Keycloak
  recommends that you turn V1 off (`changes-26_2_0.adoc` L95-103).
- The repo links `agent-team1-github-tool-aud` to the agent in two ways: as optional
  (`k8s/opa-kind-driver.sh`) and as default (`demo/use-cases/uc1-onboarding/lib/setup_keycloak.py`,
  `ensure_default_audience_scope`). Keycloak skips a second link, so the script that runs first
  wins.
- If the client policy executor `downscope-assertion-grant-enforcer` is turned on, the exchange
  fails, because the user token does not carry the tool's audience scope.

---

## 10. References

| Item | Location |
|---|---|
| Mapper reason (rossoctl) | `rossoctl/docs/_internal/authbridge/opa-migration-guide.md:285-289` |
| Expected tool inbound input (subject = `dev-user`) | `k8s/opa-kind-runbook.md` (B.4, B.5) |
| User-role `actorIds` | `src/aiac/idp/service/configuration/keycloak/main.py` (`list_roles`) |
| Inbound projection | `src/aiac/policy/model/projection.py` |
| Subject gates | `src/aiac/pdp/service/policy/opa/rego.py` |
| Harness subject check | `verify_login_subject` in `test/system/launcher.py` (called by `onboarded_stack` in `test/system/uc1_onboard.py`); the scope link (D31): `require_subject_scope` in `test/system/uc1_onboard.py` |
| Decision D31 (B-AIAC) | `docs/specs/PRD.md` §5 *Key architectural decisions*; `docs/handoffs/18-option-b-aiac-username-sub.md` (gitignored; local only) |
| Captured CRs of the failing runs | `test/system/artifacts/cr-captures/` (gitignored; local only) |
| AuthBridge identity, OPA input, token exchange | `cortex/core/plugins/{jwtvalidation,opa,tokenexchange}/` (see §1.4) |
| Operator clients, audience scopes, realm template | `operator/internal/keycloak/{admin,audience}.go`, `operator/internal/bootstrap/keycloak.go` |
| Keycloak token exchange (26.5.2) | `github.com/keycloak/keycloak/blob/26.5.2/docs/guides/securing-apps/token-exchange.adoc`; `…/docs/documentation/upgrading/topics/changes/changes-26_2_0.adoc` (see §1.5) |
| `sub` semantics | OpenID Connect Core 1.0 §2, §5.7; RFC 9068 §2.2 |
| OPA as PDP, AuthBridge as PEP | `docs/specs/PRD.md:70-76` |
| Routes, exchange scope, OPA input (runbook) | `k8s/opa-kind-runbook.md` (B.1, B.2, B.5) |
