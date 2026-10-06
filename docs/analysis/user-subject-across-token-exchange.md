# User Subject Across Token Exchange: Options

> **Status:** analysis, open for decision. **Date:** 2026-10-06. **Branch:** `target-side-ac`.
>
> The AuthBridge and operator facts come from their source code (§1.4). The Keycloak facts come
> from the Keycloak 26.5.2 source and docs (§1.5). Statements marked **To verify** are not
> confirmed yet.

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
| The token exchange authenticates the agent with a SPIFFE JWT-SVID (`client_assertion`, Keycloak `federated-jwt`). It sends `audience`, and `scope` only when the route has `token_scopes`. It sends no `actor_token`, and nothing forwards the user downstream | `cortex/core/plugins/tokenexchange/exchange/client.go:77-107`, `exchange/auth.go:28-43`; `cortex/core/auth/auth.go:441-443` |
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
| AIAC-owned placement (B-AIAC, recommended in §8.1) | The scope is **not** a realm default. AIAC links it as a default scope to each service's client at onboarding, with the existing IdP call `POST /services/{id}/scopes/{scope_id}`, in the same provisioning step that tags the client with `client.type` (§1.6). It changes only AIAC-managed clients (§1.6) and needs no operator change | `src/aiac/agent/uc/onboarding/` (the onboarding flow); the IdP service already has the endpoint |
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
| AuthBridge | One of C1–C3. For the agent side, the outbound identity uses `delegation.origin`, which is the `sub` of the incoming bearer (`tokenexchange/plugin.go:785-832`). It must use the same claim | `cortex` repo (other team) |
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

1. One-time realm step: create a client scope `aiac-username-sub` with one user-property mapper
   (`username` → claim `sub`; access token, ID token, userinfo, introspection). Link it as a
   default scope to `rossoctl`, and delete the per-client `username-to-sub` mapper, so that there
   is one source.
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
   request that falls back to V1 would not get the mapper (§1.5, §9 side findings).

Risks that are left with B-AIAC:

- The `sub` override is not documented as supported for usernames. Logout tokens keep the user
  ID, but they do not reach AIAC-managed services (**to verify**).
- The assumption must stay true. Record it as a platform precondition in the spec: keep
  `editUsernameAllowed: false`, keep `registrationAllowed: false`, and never create a deleted
  username again.
- A client is AIAC-managed only after onboarding, and before that the global combiner denies its
  pod (no CR). So a failed link shows as a deny, and the check in step 4 finds it.

**Why option C later:** C keeps `sub` standard and needs no per-client link, because `profile` is
already a realm default. When AuthBridge has a `subject_claim` option (C1), AIAC can remove
`aiac-username-sub` with no change to policies, because both B and C give the same username as
the subject.

### 8.2 If the assumption cannot be guaranteed

**Recommendation: option A**, with Rego comments for readability. It is the only option whose
identifier is structurally stable: Keycloak never reuses a user ID. The safety of B and C would
depend on a realm setting (`editUsernameAllowed`) and on an admin rule (no username reuse), not on
the platform. A also needs no setup on the exchange path. Its costs (the AIAC IdP change, the SPM
migration, UUIDs in logs, the change of the shared login client) are the price of that guarantee. Of B and
C, C is better, because it keeps `sub` standard.

---

## 9. Open questions (To verify)

Open:

1. Whether `jwt-validation` accepts a token without `sub` (option C, if `username-to-sub` is
   removed).
2. Whether the exchanged token has `preferred_username` (option C). Very probable (§4); confirm
   once with a decoded token.
3. Whether `build_policy()` rebuilds all SPMs from the IdP (migration for option A).
5. Which Keycloak code sets `sub` = user ID in the exchanged token, because no scope in this realm
   has the standard Subject mapper (§1.2). The observed behaviour is clear; only the cause is
   unknown.
6. Whether any AIAC-managed agent or tool receives backchannel logout tokens, which keep
   `sub` = user ID (option B). Expected: no, because they are resource servers behind AuthBridge.
7. Whether the platform owners accept the username precondition of §8.1 (no rename, no reuse) as
   a written rule.

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
| User-role `actorIds` | `src/aiac/idp/service/configuration/keycloak/main.py:540-546` |
| Inbound projection | `src/aiac/policy/model/projection.py` |
| Subject gates | `src/aiac/pdp/service/policy/opa/rego.py` |
| Harness subject check | `test/system/uc1_onboard.py:1073`, `test/system/launcher.py:925-942` |
| Captured CRs of the failing runs | `test/system/artifacts/cr-captures/` (gitignored; local only) |
| AuthBridge identity, OPA input, token exchange | `cortex/core/plugins/{jwtvalidation,opa,tokenexchange}/` (see §1.4) |
| Operator clients, audience scopes, realm template | `operator/internal/keycloak/{admin,audience}.go`, `operator/internal/bootstrap/keycloak.go` |
| Keycloak token exchange (26.5.2) | `github.com/keycloak/keycloak/blob/26.5.2/docs/guides/securing-apps/token-exchange.adoc`; `…/docs/documentation/upgrading/topics/changes/changes-26_2_0.adoc` (see §1.5) |
| `sub` semantics | OpenID Connect Core 1.0 §2, §5.7; RFC 9068 §2.2 |
| Related reference | `docs/analysis/keycloak-access-control-analysis.md` |
