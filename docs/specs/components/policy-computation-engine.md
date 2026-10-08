# Component PRD: Policy Computation Engine (`aiac.policy.computation`)

## Problem Statement

AIAC Agent sub-agents produce `list[PolicyRule]` objects representing partial policy updates — a new onboarding event may produce a handful of rules covering one agent's inbound and outbound access. `compute_and_apply(rules, override)` merges those rules into persisted policy.

The **original design persisted only per-agent `AgentPolicyModel` (APM) records**, storing rules denormalised onto the agent that reaches or is reached. Because a rule was only ever attached to an agent that already existed in the store, the merge outcome depended on the **order** in which services were onboarded.

### The order-dependence bug (repro)

Let:

- `UR` = a user (realm) role, mapped to agent `A`'s scope `AS` **and** tool `T`'s scope `TS`.
- `AR` = agent `A`'s (client) role, mapped to `TS`.

Onboarding **A then T** yields `APM(A)` outbound `{AR→TS, UR→TS}` — correct. Onboarding **T then A** **loses `UR→TS`**: at T-onboarding no agent yet targets `TS`, so the `(UR → TS)` outbound-subject rule has nowhere to attach and is dropped; at A-onboarding it is never re-emitted. The two orders diverge.

The same shape produces a **latent sibling bug**: a user role added *later* (UC3) to an already-onboarded agent+tool pair could not be reconstructed onto the agent, because nothing re-derived the agent's gates from durable facts.

## Solution

A **two-layer** model (see the policy-model component spec, handoff 01):

- **`ServicePolicyModel` (SPM)** — one per service, **persistent**, the **source of truth**. It carries the service's own identity (`owned_roles` / `owned_scopes` / `service_type`) and its inbound edges — split by effect into `inbound_allow_rules` + `inbound_deny_rules`: every `(role → scope)` rule whose `scope` this service owns, routed to the allow or deny list by `rule.effect`. `UR→TS` lives durably on `SPM(T)`.

**Two-sided rules (ALLOW / DENY).** Rules carry a `RuleEffect` (`Allow` / `Deny`; see the policy-model spec, handoff 01). The PCE treats effect as a routing/derivation dimension throughout: routing files each rule into the owning SPM's allow or deny list; `override`, reconcile, and `decommission` operate on **both** lists; and derivation classifies each inbound edge by `role.kind` **and** `effect` into the matching APM bucket while still registering deny-edge roles into the effect-agnostic identity maps. Under the no-conflict assumption the PCE applies **no** precedence logic — the two lists are carried through independently and deny-overrides is enforced downstream in generated Rego. There is no default effect: the deployed Rego always denies a `(role, scope)` pair that no rule mentions (always DENY).
- **`AgentPolicyModel` (APM)** — under **agent side** only, **derived on demand** from the relevant SPMs and **partial-upserted** to the PDP. Never persisted as source of truth.

`compute_and_apply` routes each incoming rule to the effect-appropriate list of `SPM(scope.serviceId)` (`inbound_allow_rules` / `inbound_deny_rules`), persists the changed SPMs, computes the set of **affected services** of the current enforcement side, builds the **policy model** of that side for them, and partial-upserts it to the PDP in a single `apply_policy` call (the policy-model stage, D23):

- Under **target side**, the affected services are the services whose SPM changed in this run (and, when the run lifts a quarantine, the services whose SPM has an edge of a role of the focus service; see [Algorithm](#algorithm) step 3d). The policy model (`TargetSidePolicyModel`) carries their stored SPMs, each with the [current role holders](#role-holders-at-render-time-d32). Each callee's own CR is rendered from its own SPM.
- Under **agent side**, the affected services are the affected agents, plus the focus service when it is a tool. The PCE re-derives each affected agent's APM **entirely from SPMs** (with the current role holders). The policy model (`AgentSidePolicyModel`) carries the APMs and the pass-through of a focus tool.

Because `UR→TS` is durable on `SPM(T)`, both onboarding orders converge. Under agent side, `UR→TS` is reconstructed onto `A` whenever `A` is derived, so both orders give the same `APM(A)` = inbound `{UR→AS}`, outbound `{AR→TS, UR→TS}`. Under target side, no join is necessary: `T`'s own CR is rendered from `SPM(T)`, which holds `UR→TS` and `AR→TS`. The latent sibling bug is fixed too: a late UC3 user role routes to `SPM(T)`. Under agent side it marks `A` affected and re-derives `A`'s subject gate. Under target side it changes `SPM(T)`, so `T` gets a new CR.

The module is pure Python (`aiac.policy.computation`), imported directly into the calling sub-agent's process. No FastAPI service, no Kubernetes deployment, no container image.

---

## Assumptions

These AIAC invariants (1 and 3, from the [policy-model spec](policy-model.md#assumptions), handoff 01; the former Assumption 2 is removed, D32) are relied on by the PCE and are **enforced upstream at the Keycloak IdP boundary** (handoff 02), not re-checked here:

1. **No role spans both kinds.** A role is held by users *or* by agent service accounts, never both. This is what lets `Role.actorIds` be a single list and lets the PCE split inbound rules cleanly by `role.kind`. AIAC invariant, *not* a Keycloak guarantee.
2. **Removed by D32** (it was: no scope shared across services). A shared scope is valid (D32: one policy for the whole realm, so `team1/github-tool` and `team2/github-tool` share `github-tool.source-read`). Keycloak links one client scope to many clients, and the IdP gives each owner its own copy, with `Scope.serviceId` = that owner. So `SPM(scope.serviceId)` is unambiguous for each copy, and the PRB emits one rule for each owner's copy. A role can be shared too (one realm role on the service accounts of several agents); the PCE resolves its holders at render time (see [Role holders at render time (D32)](#role-holders-at-render-time-d32)). So a rule can map a role onto a scope that one of the holders of the role owns (a self-mapping). D32 allows it, and the PCE has no filter for it: the CR then lets that holder call its own scope, as the realm-wide policy grants ([D32](../PRD.md#key-architectural-decisions) (h)).
3. **Agent role ⇔ a client role on the agent's client, or an `aiac.managed` realm role on its service account; user role ⇔ a realm role held by users.** The IdP config service sets `Role.kind`: `GET /services/{id}/roles` marks agent roles `Agent`, and `GET /roles` marks realm roles `User`. Agent roles come from `Service.roles`.

---

## User Stories

1. As an AIAC Agent sub-UC agent, I want to submit a list of `PolicyRule` objects and have them durably recorded on the right service and reflected in the CR of every affected service, without implementing routing or storage merge logic myself.
2. As an AIAC Agent sub-UC agent, I want to submit the rules and get no return value to unpack on success, so I stay decoupled from routing, storage, and derivation — while a failure still surfaces to me (US 7).
3. As the Policy Computation Engine, I want each rule recorded on the SPM of the service that **owns the rule's scope**, so the fact survives regardless of which services already exist.
4. As the Policy Computation Engine, I want to build the policy model purely from the persisted SPMs (under agent side, to derive an affected agent's APM from them), so the result is **independent of onboarding order**.
5. As the Policy Computation Engine, I want to skip duplicate rules on append, so re-processing the same event does not create redundant entries.
6. As the Policy Computation Engine, I want to partial-upsert only the affected services' CRs to the PDP, so the CRs of unaffected services are left untouched.
7. As a developer, I want exceptions from the computation logged **and re-raised**, so a failed IdP / store / PDP interaction surfaces to the caller (the Controller returns HTTP 500; the NATS consumer does not ack the message, so NATS redelivers it after `AckWait` and moves it to `aiac.apply.dlq` after the 5th failed delivery; see [`aiac-agent.md` → Ack contract](aiac-agent.md#ack-contract)) instead of being silently dropped while nothing is applied.
8. As a developer, I want a stable import path, so the calling convention does not change as the module grows.
9. As the Policy Computation Engine, I want one run at a time to change the SPMs, so two concurrent onboardings that route rules into one shared SPM do not lose the rules of one run.
10. As the UC1 Orchestrator, I want to quarantine a failed onboarding by its clientId, so its policy footprint is removed, its CR is deleted (a pod that has no CR is denied), and no later run writes rules back into that footprint.
11. As an operator, I want one switch to select the enforcement side for every callee, so that the two sides never exist together.
12. As the Controller, I want a resync at every start, so that every managed service has the CR of the current side, and no AIAC CR stays for a service that has no SPM.
13. As a test or an operator, I want to read the policy model of one service, so that I can see what the PCE deploys for it.
14. As the Policy Computation Engine, I want a successful onboarding to store the focus SPM also when it has zero rules, so that the focus service joins the managed set and gets a CR.
15. As the UC1 Orchestrator, I want the CR of a tool written before its Provision, so that UC-1 discovery through the tool's own inbound OPA passes D20 at the first onboarding.
16. As the Controller, I want to re-render the CRs that use a role when its members change, with no PRB run, so that a user or an agent that gets or loses the role gets or loses its grants at once.
17. As the Policy Computation Engine, I want every holder of a shared role in each CR that grants or denies the role, independent of the onboarding order, so that all holders get the same allow and deny.

---

## Implementation Decisions

### Module Identity

**Namespace:** `aiac.policy.computation`

**Location:** `src/aiac/policy/computation/`

```
src/aiac/policy/
└── computation/
    ├── __init__.py   # exports compute_and_apply, decommission, quarantine, resync,
    │                 #         bootstrap, rerender_role, policy_model_for, enforcement_side
    └── engine.py     # the same eight functions
```

The PCE uses the pure module `aiac.policy.model.holders` (`RoleHolders`) for the [role holders at render time](#role-holders-at-render-time-d32).

No FastAPI. No Kubernetes deployment. No container image. Imported as a library by AIAC Agent sub-UC agents.

### Public API

Six entry points change the deployed policy — an incremental fold, an authoritative offboard, the teardown of a failed onboarding, the resync at the Controller start, the bootstrap CR of a tool before its Provision, and the re-render of the CRs that use a role. Two entry points only read — the read model and the side:

```python
def compute_and_apply(
    rules: list[PolicyRule],
    override: bool = False,
    focus_service: ClientId | None = None,   # clientId of the service this onboarding builds
) -> None
def decommission(service_id: ClientId) -> None
def quarantine(service_id: ClientId, deleted_roles: Iterable[Role] = ()) -> None   # deleted_roles = roles the rollback deleted
def resync() -> None                                              # D28: at every Controller start
def bootstrap(service_id: ClientId, service_type: ServiceType) -> None   # the focus tool's CR, before Provision
def rerender_role(role_id: str) -> None                           # D32: the role-members event
def policy_model_for(service_id: ClientId) -> PolicyModel | None  # D18: read-only, no lock
def enforcement_side() -> EnforcementSide                         # D29: reads AIAC_ENFORCEMENT_SIDE
```

**Service ids: the PCE takes only the clientId.** Keycloak gives every client two ids: the internal UUID (`Service.id`, type `ServiceUuid`) and the `clientId` (`Service.serviceId`, a SPIFFE ID, type `ClientId`; both `NewType`s of `str` in `aiac.idp.configuration.models`). Every service id the PCE takes is the clientId — the SPM key, `PolicyRule.scope.serviceId`, and OPA `input.identity.service_id`. The UUID is only for finding the service in the IdP. The asymmetry stays at the HTTP/NATS boundary: an onboarding comes in with a UUID (`/apply/service/{uuid}`, `aiac.apply.service.<uuid>`), and the UC1 Orchestrator resolves the clientId once, before Provision, while the client still exists; an offboard comes in with the clientId, because after the client is deleted UUID→clientId resolution is impossible.

- **No return value; failures propagate:** on success the caller receives no return value. The six functions that change policy log exceptions and **re-raise** them — a failure in IdP resolution, Policy Model Store I/O, or PDP Policy Writer push surfaces to the caller rather than being silently swallowed while nothing is applied. The Controller returns HTTP 500. The NATS consumer does not ack the message: NATS redelivers it after `AckWait` (600 s), and after the 5th failed delivery (`MAX_DELIVER`) the consumer moves it to `aiac.apply.dlq`. Only a `ServiceNotVisibleError` of the UC1 Orchestrator gets a nak with a delay (D33), and the PCE does not raise it. See [`aiac-agent.md` → Ack contract](aiac-agent.md#ack-contract).
- **`override`:** selects the merge mode (see [Merge Semantics](#merge-semantics)). `False` (default) appends additively at the SPM layer; `True` authoritatively replaces every input role's mappings **across all SPMs** (role-level revocation). Set by the caller (the Controller) from the producing UC's choice — UC1 = `False`, UC3 = `True`, UC2 Rebuild = `True`, UC2 Build = TBD.
- **`focus_service`:** the clientId (`Service.serviceId`) of the service that this onboarding builds — not its Keycloak UUID. The [routing guard](#routing-guard-disabled-services) does not drop the rules of this service while its client is disabled. The onboarding route (`POST /apply/service/{uuid}`) and the NATS consumer (`aiac.apply.service.<uuid>`) pass the clientId that `onboard_service` returns. Other callers pass nothing.
- **No default effect:** there is no default-effect parameter. A `(role, scope)` pair that no rule mentions is always DENY.
- **`decommission`:** the authoritative service **offboard** — tears down a decommissioned service's entire policy footprint (see [Decommission (service offboard)](#decommission-service-offboard)). Keyed by the **clientId (SPM key)**, since an offboarded client is gone from `get_services()` and its UUID can no longer be resolved.
- **`quarantine`:** the UC1 failure-path teardown of a failed onboarding (see [Quarantine (failed onboarding)](#quarantine-failed-onboarding)). Keyed by the **clientId (SPM key)**, as `decommission` is. The failed service stays in the catalog (disabled).
- **`resync`:** the full redeploy at every Controller start (D28; see [Resync (Controller start)](#resync-controller-start)). It writes the CR of every live managed service (in the IdP catalog and not disabled) in the current side, deletes every other AIAC CR, and quarantines each disabled service that still has an SPM.
- **`bootstrap`:** writes the CR of the focus tool before its Provision, so that UC-1 discovery passes D20 at the first onboarding (see [Bootstrap CR (tool discovery)](#bootstrap-cr-tool-discovery)). Keyed by the clientId. It stores no SPM.
- **`rerender_role`:** re-renders the CRs that use one role, with its current holders, after a change of its members (D32; see [Role re-render (`rerender_role`)](#role-re-render-rerender_role)). Keyed by the Keycloak role id. It makes no PRB call and writes no SPM.
- **`policy_model_for`:** the read model of one service (D18; see [Read model (`policy_model_for`)](#read-model-policy_model_for)). It changes nothing.
- **`enforcement_side`:** the current enforcement side (D29; see [Enforcement side and the managed set](#enforcement-side-and-the-managed-set)).
- **Serialization:** `compute_and_apply`, `decommission`, `quarantine`, `resync`, `bootstrap` and `rerender_role` hold one PCE lock for their whole body (see [Serialization (the PCE lock)](#serialization-the-pce-lock)). `policy_model_for` and `enforcement_side` take no lock.
- Import path: `from aiac.policy.computation import compute_and_apply, decommission, quarantine, resync, bootstrap, rerender_role, policy_model_for, enforcement_side`

### Rule-builder input contract (upstream)

Each incoming `PolicyRule` arrives with `scope.serviceId`, `role.kind`, and `role.actorIds` **already populated**, and with roles **already flattened** to their closure (role + descendants, dedup by `role.id`). The PCE performs **no IdP lookup for routing or classification** and **no role flattening** — it treats each rule's `scope`, `role.id` and `role.kind` as-is. The `role.actorIds` of a rule is only a snapshot of the holders at build time: the PCE replaces it with the current holders before the routing guard (see [Role holders at render time (D32)](#role-holders-at-render-time-d32)).

- The boundary that **derives** `scope.serviceId` / `role.kind` / `role.actorIds` from Keycloak facts is the **Keycloak IdP config service (handoff 02)**.
- The rule-builder (the Policy Rules Builder, `src/aiac/agent/policy_rules_builder/graph.py`) merely **carries those fields through** on the IdP `Role` / `Scope` that it puts in each `PolicyRule`; it does not compute them. The focal resolver (`src/aiac/agent/shared/focal_entities.py`) gives one candidate for each role id, with every current holder (the same `RoleHolders` rule as the PCE).

### Role holders at render time (D32)

**The problem.** A stored edge keeps a copy of `Role.actorIds` from the run that built it: a snapshot. The snapshot goes stale in two ways:

- **A shared role** (handoff 19, Bug 1). Two agents can hold one realm role: across namespaces, Provision reuses a role by name (`team1/github-agent` and `team2/github-agent` share `github-agent.source_operations`); in one namespace, an admin assigns the role to a second service account. `GET /services/{id}/roles` gives each service's copy with `actorIds` = only that service, and append-dedup (`role.id + scope.id + effect`) drops the edge of the second holder. So the CR of the tool named only the first holder, and the other holder was denied, although the policy grants it.
- **The members of a user role** (Bug 4). `GET /roles` gives all current members of an `aiac.managed` user role, but the stored edge keeps the members of build time. A user who gets the role later is denied; a user who loses the role keeps access.

A membership change does not change the policy (role → scope). It changes only who holds the role. So the PCE resolves the holders at render time, from current IdP data, and not from the stored copy. One seam (the pure module `aiac.policy.model.holders`, class `RoleHolders`) does this for both bugs. The focal resolver uses the same module.

**Who is a holder.**

- **An `Agent`-kind role:** each **live** service in the `get_services()` catalog whose `roles` contain the role id (its `serviceId`). Live = in the catalog and enabled; the focus service of a run counts as live. A quarantined or deleted service is not a holder.
- **A `User`-kind role:** the `actorIds` that `get_roles()` (`GET /roles`) gives for the role id now — the direct members of an `aiac.managed` realm role. A role that `get_roles()` does not list (deleted) has no holder (fail closed).
- The kind of the role in the edge selects the source. The holders are sorted, so the result does not depend on the order that the IdP gives.
- **Known limits (unchanged):** a role held through a group or through a composite parent role is not resolved; an unmarked user role has no `actorIds` in `GET /roles`, so it has no holder.

**The read rule (relaxed by D32).** Each operation reads the IdP one time, under the PCE lock: `Configuration.get_services()` (the catalog: the identity seed, the live check, and the holders of each agent role) and `Configuration.get_roles()` (the current members of each user role). The PCE **never** reads `get_subjects()`. Before D32 the only runtime IdP read was `get_services()`; user roles are not in that catalog, so a render could not see a membership change. The read model reads the IdP too, because it must show what the PCE deploys (D18).

**Where the holders apply.** The PCE builds one `RoleHolders` for each operation, and applies it in memory:

- to every input rule of `compute_and_apply`, before the routing guard;
- to every SPM that it reads from the store: the SPM cache (`get_service_policy`), the stored SPMs of the resync (`list_service_policies`), the stored SPM of the read model and of the bootstrap, and the SPMs that `get_service_policies_by_role` finds (the outbound derivation reads them through the cache; the role re-render refreshes them).

So the routing guard, the targeters, the affected agents, the agent-side derivation and the writer's `project_inbound` all see the current holders.

**The store.** The store schema does not change. The stored `actorIds` are not authoritative: they are a snapshot that the PCE refreshes when it writes the SPM. A touched SPM whose stored holders are not the current ones is in the `changed` set (see [Algorithm](#algorithm) step 3c): so the onboarding of the second holder of a shared role, whose rule is a duplicate, still writes and deploys the callee's SPM with both holders. An SPM that a run does not touch keeps its snapshot in the store until a later write; its CR gets the current holders at the next role re-render or resync. When `quarantine` or `decommission` removes one holder of a shared role, they redeploy (but do not write) the SPMs that have an edge of the role, so the removed holder leaves those CRs at once (see [Decommission](#decommission-service-offboard) step 4b). After a quarantine, these SPMs keep the snapshot of the removed holder, so a later stale-holders check cannot find them. The lift of the quarantine deploys them again with that holder, and writes those whose snapshot is stale (see [Quarantine](#quarantine-failed-onboarding) → The lift).

**Known limits (the snapshot).** The stale-holders check ([Algorithm](#algorithm) step 3c) compares the current holders with the stored snapshot, not with the CR. So when the snapshot names the current holders, a run does not find a CR that names other holders:

- **A render with no store write.** `rerender_role`, the resync, and the redeploy of the shared SPMs of a quarantine or a decommission render each CR with the current holders, but do not write its SPM. After such a render, the stored snapshot can be different from the CR. If the holders later go back to those of the snapshot with no role-members event (for example a holder that `rerender_role` added loses the role, and the event is lost), a run that touches the SPM finds its holders current. It does not deploy the SPM, so the CR keeps the old holders until the next render: a role-members event of the role, a run that changes the rules of the SPM, or the resync. The lift is different: it also writes each lifted SPM whose snapshot is stale ([Algorithm](#algorithm) step 3d).
- **A decommission is not lifted.** A new client with the clientId of a decommissioned service is an enabled focus service, so its onboarding is not a lift ([Algorithm](#algorithm) step 3d). When it holds a shared role of the old service, the shared SPMs of the decommission can still have a snapshot that names that clientId, so the stale-holders check does not find them. Their CRs get the new holder at the next role-members event of the role, at the resync, or when a run changes their rules.
- **A render between the lift and the re-enable.** The PCE lock covers `compute_and_apply`, not the `reenable_service` call that comes after it. So another PCE operation can run between the two. On the HTTP route `POST /apply/service/{service_id}` the NATS consumer is free, so the role-members event of Provision's own mapping can come in this window. The operation sees `X` disabled, so `X` is not a holder, and the operation renders the CRs of the shared roles of `X` without `X`. When it writes no SPM (`rerender_role`, or the shared SPMs of the quarantine or the decommission of another holder of the role), the lifted snapshots already name `X`. So after the re-enable, a run finds their holders current, and the CRs keep `X` out (fail closed) until the next role-members event of the role, a run that changes the rules of the SPM, or the resync. The window is short: the PRB build comes before `compute_and_apply`, so the event of Provision's own mapping comes mostly during the build, and a render then does no harm. On the NATS path the consumer handles one message at a time, so the event of Provision's own mapping comes after the re-enable, and only an HTTP route (for example `POST /apply/role-members/{role_id}`) can run in the window.

**The interface** (`aiac.policy.model.holders`, pure, no I/O):

```python
class RoleHolders:
    def __init__(self, services: Iterable[Service], roles: Iterable[Role], *, focus_service: str | None = None)
    def of(self, role: Role) -> list[str]                                    # the current holders
    def refresh_role(self, role: Role) -> Role                               # a copy with actorIds = holders
    def refresh_rule(self, rule: PolicyRule) -> PolicyRule                   # a copy; scope and effect unchanged
    def refresh_model(self, model: ServicePolicyModel) -> ServicePolicyModel # a deep copy; every edge refreshed
```

`services` is the `get_services()` catalog, `roles` the `get_roles()` realm roles, and `focus_service` the clientId of the service that a run builds. `roles` is required (it has no default): with no roles, no `User`-kind role has a holder, so a missing argument must not pass silently. `refresh_model` keeps the order of the edges and the identity (`owned_roles`, `owned_scopes`).

#### Role re-render (`rerender_role`)

`rerender_role(role_id)` is the entry point for a change of role members: the Controller calls it for the role-members event (`aiac.apply.role-members.{role-id}`, which the SPI publishes when a user or a service account gets or loses a realm role; see [`event-broker.md`](event-broker.md)) and for the operator route `POST /apply/role-members/{role_id}`. A membership change does not change the policy, so it makes **no PRB call and writes no SPM**: the stored rules stay, and only the CRs change.

Steps (under the PCE lock):

1. **IdP once** (`get_services()` and `get_roles()`), and build `RoleHolders`.
2. **Deploy** in one `apply_policy` call (the policy-model stage, D23):
   - **target side:** `TargetSidePolicyModel(services=[...])` with the live stored SPMs that `get_service_policies_by_role(role_id)` finds, each with the current holders. No call when there is none (for example a new role, which has no edge yet).
   - **agent side** (the legacy method): `AgentSidePolicyModel(agents=[...])` with the APM of every live stored agent, re-derived from the store. An agent that lost the role is not a holder any more, so the PCE cannot find it from the holders; it re-derives every live stored agent. No call when there is no live stored agent.

A deleted role still re-renders: its edges get no holder (fail closed). A failure is logged and re-raised. The [resync](#resync-controller-start) repairs a missed event, because it renders with the current holders.

### Enforcement side and the managed set

**The side (D16, D29).** `enforcement_side()` reads the env var `AIAC_ENFORCEMENT_SIDE` and returns an `EnforcementSide`: `target-side` (the default, also when the var is unset) or `agent-side`. An unknown value raises `ValueError`. The Controller calls it at start, so an unknown value stops the Controller before it serves. The var comes from the `aiac-agent-config` ConfigMap, so it does not change while the process runs. Each PCE operation builds the policy model of this side. The two sides never exist together.

- **Target side.** Each callee, agent or tool, checks the access to itself in its own inbound OPA, from its own CR. The render input is the stored SPM of the callee (`TargetSidePolicyModel`). The outbound package of every CR is a pass-through: the callee decides (D24).
- **Agent side** (the legacy method). Each agent's CR checks the agent's calls to tools on its outbound. The render input is the APM, which the PCE derives in memory (`AgentSidePolicyModel.agents`). Each managed tool gets a pass-through CR (`AgentSidePolicyModel.pass_through`), because a pod that has no CR is denied (D20, D24).

A side change is a ConfigMap patch and a Controller restart. The [resync](#resync-controller-start) then writes every CR in the new side, so no mixed state stays.

**The managed set (D21).** The managed set is the services that have a stored SPM. Every managed service has a CR, under both sides (D20): the global combiner denies a pod that has no client CR. A service leaves the set only through the quarantine or the decommission, which delete its SPM and its CR. A successful onboarding stores the focus SPM also when it has zero rules (see [Algorithm](#algorithm) step 2b), so the focus service always joins the set. The [bootstrap CR](#bootstrap-cr-tool-discovery) of a tool is the one CR outside the managed set: it exists from the bootstrap until the onboarding stores the SPM, or until a quarantine or the resync deletes it.

### Algorithm

Given `rules: list[PolicyRule]`, an `override` flag and an optional `focus_service`, `compute_and_apply` executes these steps under the [PCE lock](#serialization-the-pce-lock):

1. **IdP once.** Call `Configuration.get_services()` (the catalog) and `Configuration.get_roles()` (the current members of each user role) — the **only** runtime IdP reads (D32; never `get_subjects()`). Build the [role holders](#role-holders-at-render-time-d32) from them. For every service touched this batch, seed its SPM's `service_type` / `owned_roles` / `owned_scopes` from its catalog `Service` record, keeping only **AIAC-provisioned** entities (the `aiac.managed` marker on `Role.aiac_managed` / `Scope.aiac_managed`; Keycloak built-ins — the default client scopes `profile`, `email`, `roles`, `web-origins`, `acr`, `basic`, `service_account`, and the `default-roles-<realm>` composite — are dropped; so is the shared subject scope `aiac-username-sub`, which AIAC provisions with no marker, D31). This seed drives **P2** identity and the service type (under target side, the inbound render of the CR). Under agent side, the rule [only agents get an APM](#p2--p5b-reconciliation-and-the-agent-side-rule) does not use the seeded type: it reads the catalog type directly. It is a seed, **not** a per-derive dependency.

1a. **Current holders.** Give each input rule the current holders of its role (`RoleHolders.refresh_rule`). The rule's own `actorIds` are a snapshot of build time.

1b. **Routing guard.** Drop every rule whose scope owner is disabled (except the focus service) or absent from the catalog, or whose Agent-kind role has no live holder now (see [Routing guard (disabled services)](#routing-guard-disabled-services)).

2. **Route each rule to its owning service's SPM, by effect.** For each rule `(role, scope, effect)`, append it to `SPM(scope.serviceId).inbound_allow_rules` (if `effect == Allow`) or `.inbound_deny_rules` (if `effect == Deny`) — fetch the SPM via `get_service_policy(scope.serviceId)`; the SPM cache gives each of its edges the current holders. **Append-dedup by `role.id + scope.id + effect`.** There is **no** write-time 3-way P5b classification (the old (user,agent-scope)/(user,tool-scope)/(agent,tool-scope) routing table is gone) — a rule always lands on the effect-appropriate list of the SPM that owns its scope, whatever the kinds.

2b. **Focus SPM (D21).** When `focus_service` is set and the focus service is in the catalog, the run loads `SPM(focus)` (seeded from the catalog) and adds it to the `changed` set, also when it has zero rules. So step 4 always stores the focus SPM, and the focus service joins the managed set and gets a CR. A re-onboarding with zero rules also stores the SPM and redeploys the CR.

3. **Override (`override=True`) — role-level revocation.** *Before* appending, purge the **distinct input-role set** (taken from the input **before** the routing guard, so a role whose every new rule the guard drops still loses its old grants) from **both** lists (`inbound_allow_rules` + `inbound_deny_rules`) of **every** SPM that contains any of them: one up-front pass using `get_service_policies_by_role` per distinct input role, removing every stored rule (allow or deny) whose `role.id` matches. Then append the fresh rules. Purging once, up-front, ensures a role shared across the input is not wiped after being added. The old algorithm's `target_scopes` reconciliation is **deleted** — the target maps (`target_allow_scopes` / `target_deny_scopes`) are derived, never-stored quantities.

3b. **Reconcile (drift GC) — after routing/override, before persist.** Prune each **touched** SPM against the step-1 `get_services()` catalog (no additional IdP read) so drift cannot accumulate across re-onboarding. Runs under **both** merge modes and is order-independent (drops only edges whose entity no longer exists). See [Reconcile (drift GC)](#reconcile-drift-gc) under Merge Semantics for the keep rules.

3c. **Stale holders.** Add to the `changed` set each touched SPM whose stored holders are not the current ones (a holder came or went since the SPM was written). Step 4 then writes it (this refreshes the snapshot), and step 6 deploys it with the current holders. Without this step, the onboarding of the second holder of a shared role, whose rule is a duplicate of the first holder's rule, would leave the callee's CR without the second holder.

3d. **The lift (D32).** When `focus_service` is in the catalog and disabled, the run lifts the quarantine of that service (see [Quarantine (failed onboarding)](#quarantine-failed-onboarding) → The lift). For each role in `SPM(focus).owned_roles`, find the SPMs that have an edge of the role (`get_service_policies_by_role`). Each of these SPMs whose service is live (the focus excluded) is **lifted**: the SPM cache gives it with the current holders, and the focus is a holder again. Step 6 deploys the lifted SPMs (under agent side, the agents among them, step 5). Their rules did not change, so step 4 writes a lifted SPM only when its stored holders are not the current ones (for example, a run wrote it while the focus was quarantined, so its snapshot does not name the focus). Its snapshot then names the holders that its CR names, so a later stale-holders check (step 3c) sees a later change of the holders. A lifted SPM does not join the `changed` set, so under agent side it does not make more agents affected. In every other run the `lifted` set is empty: an enabled focus service is already a holder in those CRs.

4. **Persist** each changed SPM, and each lifted SPM whose stored holders are stale (step 3d), via `apply_service_policy`.

5. **Compute the affected set of the current side (D23)** — from the batch, **not** by scanning all services:
   - **Target side:** the affected set is the `changed` set (the services whose SPM changed in this run: routed, override-purged, reconciled, stale holders, and the focus SPM of step 2b; a zero-rule focus SPM counts) and the `lifted` set of step 3d. Only these CRs change, because each CR is rendered from the callee's own SPM.
   - **Agent side:** the affected agents, from the batch's roles/scopes:
     - For each input (or purged) role `r` with `r.kind == Agent`: the current holders in `r.actorIds` are affected (their outbound changed).
     - For each touched owner `X` (the scope owner of each routed rule, plus every SPM in the `changed` set: override-purged, reconciled, stale holders, and the focus SPM):
       - if `X` is an **Agent**, `X` is affected (its inbound changed); **and**
       - every agent **targeting** `SPM(X)` is affected — namely the current holders (`actorIds`) of every **Agent-kind** inbound rule (allow and deny) on `SPM(X)`, for any scope (a superset of the exact-scope match).
     - Plus the focus service when it is a **tool**: it gets its pass-through CR.
     - Each agent in the `lifted` set of step 3d is affected: its inbound `source_roles` names the focus again. A lifted tool keeps its pass-through. The outbound of another holder does not change, because an outbound does not name the holders of its own role.

6. **The policy-model stage (D23).** After the store writes and before the deploy, build the policy model of the current side for the affected **live** services (in the catalog and not disabled; the focus service counts as live), and **partial-upsert** it via `aiac.pdp.policy.library.apply_policy` **at most once** (no call when the model is empty). This stage replaces the former derive-only stage (`_apply_derived`). It is inside `compute_and_apply`, so the UC1 Orchestrator is not involved.
   - **Target side:** `TargetSidePolicyModel(services=[SPM(x) for x in changed ∪ lifted if x is live])`, each SPM with the current holders. No APM is derived.
   - **Agent side:** derive the APM of each affected live agent of step 5, also each agent in `lifted`, then `AgentSidePolicyModel(agents=…, pass_through=[focus] if the focus service is a tool)`.

   Exceptions are logged and re-raised (they propagate to the caller). A stale or missing CR stays until its service is affected again, or until the [resync](#resync-controller-start). A CR change takes effect at the next poll of the OPA plugin in the pod (10 s min, up to 120 s), not when `apply_policy` returns.

### Derivation of `APM(A)` — 100% from SPMs (agent side)

The PCE derives an APM only under agent side. Let `R_A = SPM(A).owned_roles` (A's own `aiac.managed` roles, from `Service.roles`) and `S_A = SPM(A).owned_scopes`. The derivation makes no IdP read of its own: it reads every SPM through the SPM cache of the operation, so each edge carries the [current holders](#role-holders-at-render-time-d32) of its role.

- **Identity (P2):** `agent_roles` ← `R_A`; `agent_scopes` ← `S_A`.
- **No default effect:** the APM carries no default effect. The generated Rego always denies a pair that no rule mentions.
- **Inbound:** project `SPM(A)` with the shared `project_inbound` (D18b, `aiac.policy.model.projection`; see [`policy-model.md`](policy-model.md)). The target-side renderer uses the same function, so for one SPM both sides give the same inbound gates. The projection iterates **both** of `SPM(A)`'s inbound lists. It splits each edge by `role.kind` **and** `effect` into the matching APM bucket:
  - `User` + `Allow` → `inbound_subject_allow_rules`; `User` + `Deny` → `inbound_subject_deny_rules`;
  - `Agent` + `Allow` → `inbound_source_allow_rules`; `Agent` + `Deny` → `inbound_source_deny_rules`.
  - **Identity registration is effect-agnostic:** for **every** inbound edge (allow *or* deny), register the role into the identity map — `User` → `subject_roles[username] += role` (usernames from `role.actorIds`); `Agent` → `source_roles[serviceId] += role` (serviceIds from `role.actorIds`). A role seen only in a DENY edge must still land in these maps, or the Rego deny lookup cannot resolve it.
- **Outbound:** for each `r ∈ R_A`, find the SPMs with `r`-rules (`get_service_policies_by_role(r)`), and read each one through the SPM cache, so it has the current holders. Take the `r`-rules across **both** lists. For each such `(r → s)`: route by effect — `Allow` → `outbound_target_allow_rules` and `target_allow_scopes[s.serviceId] += s`; `Deny` → `outbound_target_deny_rules` and `target_deny_scopes[s.serviceId] += s`.
- **Outbound subject gate:** for each target `(X, s)` in the target maps — where `X` is the callee, a **tool or another agent**, or `A` itself when a role of `A` is mapped onto a scope of `A` (a self-mapping of a shared role, D32) — take the **User**-kind inbound rules `(u → s)` on `SPM(X)`, route each by effect into `outbound_subject_allow_rules` / `outbound_subject_deny_rules`, and register `subject_roles += u.actorIds` (effect-agnostic). The gate's range is tool ∪ agent scopes.

**Relevance is directional.** An SPM contributes to `A` **iff** it *is* `SPM(A)` (contributes inbound) **or** it contains a rule whose role is one of A's **agent** roles `R_A` (contributes outbound). A merely *shared user role* never confers relevance — this is what prevents a **false outbound edge** to a target (a tool or another agent) `A` does not actually target. This is a **derivation-layer** relevance rule: it does **not** imply the outbound user gate is empty. When the agent holds a per-skill operator role that the PRB maps (by capability-match) to a target's scope, the agent *does* target that callee, and the nested derivation then surfaces the shared-user edges.

### P2 / P5b reconciliation, and the agent-side rule

- **P2 (identity embed):** copy `owned_roles` / `owned_scopes` from `SPM(A)` onto the APM's `agent_roles` / `agent_scopes`. AIAC-managed filter applied at catalog-seed time. Without the embed the inbound gate would deny-all (inbound `subject_allow_ok` needs a non-empty `agent_scopes`), and outbound derivation would find no edges (it iterates `R_A`). The outbound Rego emits `agent_roles` for debugging only; its `allow` does not use it. Under target side, no embed is necessary: the writer reads the same identity (`owned_scopes`) from the SPM itself.
- **Agent side — only agents get an APM:** under agent side, derive an APM only for a live service whose catalog `Service.type == Agent`. An agent-side deploy uses only the catalog type: a live service with no catalog type is not an agent and not a tool, so it gets no CR, and D20 denies it. Under agent side, only the [read model](#read-model-policy_model_for) and the [bootstrap](#bootstrap-cr-tool-discovery) use the `service_type` of the SPM (the bootstrap uses the given type for a new SPM). A managed tool keeps its SPM (durable `inbound_allow_rules` / `inbound_deny_rules`) but gets no APM. It gets a pass-through CR instead (its clientId in `pass_through`, D24). Under target side, the PCE derives no APM: every managed service, agent or tool, gets a CR rendered from its stored SPM. So every managed service has a CR under both sides (D20).
- **P5b (classification):** now expressed purely as `role.kind` + `scope.serviceId`. The write-time 3-way routing table is gone; classification happens at **derive** time by splitting inbound rules on `role.kind`.

### Agent → agent access — in scope, for free

An agent-to-agent edge `AR→BS` (agent A's role → agent B's scope) is stored on `SPM(B)` and handled uniformly, with **no target-type branching anywhere**:

- A's derivation: `AR ∈ R_A`, so `get_service_policies_by_role(AR)` finds `AR→BS` on `SPM(B)` → (assuming `Allow`) `outbound_target_allow_rules += AR→BS`, `target_allow_scopes[B] += BS`, plus B's user gates as `outbound_subject_allow_rules` (a `Deny` edge routes to the deny counterparts identically).
- B's derivation: `AR→BS ∈ SPM(B).inbound_allow_rules`, `AR.kind == Agent` → `inbound_source_allow_rules += AR→BS` and `source_roles[A] += AR` (effect-agnostic identity).

The two bullets above are the agent-side derivation. Under target side, `B`'s own inbound checks `AR→BS`: `B`'s CR is rendered from `SPM(B)`, so `source_roles[A]` holds `AR`. `A`'s outbound is a pass-through.

Add a test for this.

**Future-optimization note (document, do NOT build now):** a shared edge like `AR→BS` is stored **once** canonically on `SPM(B)` but **projected into two APMs** (A's `outbound_target_allow_rules` and B's `source_roles`), so the generated Rego duplicates it across two packages. This is acceptable; a future optimization could share the representation.

### Two implementation-time verification gates

Both gates are confirmed (they gate correctness of the whole approach):

1. **`apply_policy` must be a partial (per-service) upsert.** The PCE upserts only the affected services. Confirmed: `POST /policy` server-side-applies one CR per entry in the batch, so the CRs of the other services stay. (Only `PUT /policy`, the resync, deletes the other AIAC CRs.)
2. **Rego must consume `source_roles`** for the inbound gate (not only `subject_roles`), or agent→agent inbound is *modelled but not enforced*. Confirmed: the inbound source gate reads `source_roles[input.identity.client_id]`.

### Merge Semantics

The `override` flag (set by the caller from the producing UC's choice) selects the merge mode, applied at the **SPM layer**:

- **`override=False` (default — additive append):** each rule is appended to the effect-appropriate list — `SPM(scope.serviceId).inbound_allow_rules` or `.inbound_deny_rules` — if not already present (dedup by `role.id + scope.id + effect`). Existing SPM rules are preserved. Incremental path (e.g. UC1 Service Onboarding, where existing roles must not lose their other access).
- **`override=True` (authoritative role-keyed replace):** before appending, the engine purges the distinct input-role set from **both** lists of **every** SPM containing them (`get_service_policies_by_role`), once, up-front, so the fresh rules become each role's complete mapping. Because the purge is keyed on `role.id` alone (not effect), it clears a role's allow **and** deny edges together before re-appending whatever the input carries. Used by role-scoped recomputes (UC3 Role Update) and full rebuilds (UC2 Rebuild).

`override=True` provides **role-level** revocation. Finer-grained single-rule revocation (removing one `PolicyRule` without replacing its whole role) is still **TBD**.

#### Reconcile (drift GC)

SPM edges key on Keycloak role/scope UUIDs, which **churn on delete/recreate**. Because append-dedup keys on `role.id + scope.id + effect`, a re-onboarded service whose Keycloak roles/scopes were recreated presents *new* UUIDs, so its edges are treated as new and pile up **beside** the superseded generations — nothing removes the old ones. (`override=True` does not close this: it purges by the *input* role's id, so a role whose UUID already churned out of the batch is never matched.) A live diagnostic once found a single agent SPM carrying 53 inbound edges across two role-id generations, retired `*-aud` scopes, a self-reference of a retired agent role, and duplicate same-name roles — all replayed into every regenerated APM/Rego.

**Reconcile** closes this. After routing (step 2) and any override purge (step 3), and **before** persist (step 4), each **touched** SPM is pruned against the step-1 catalog. It **reuses that same `get_services()` result** — no additional IdP read. It runs under **both** merge modes and is **order-independent** — it removes *only* edges whose entity genuinely no longer exists, never a live edge, so both onboarding orders still converge. "Touched SPMs only": at that point the SPM cache holds exactly the routed, override-purged and focus SPMs (the lifted SPMs of step 3d and the agent-derive SPMs are not loaded yet).

The prune runs over **both** `inbound_allow_rules` and `inbound_deny_rules` — the keep rules below are applied per edge in each list identically (a dangling deny edge is GC'd exactly as a dangling allow edge). For each touched `SPM(X)` whose owner `X` **is present in the catalog** (a catalog **miss ⇒ skip pruning**, never wipe on a transient outage), an inbound edge is kept iff:

1. **Scope still exists** — `edge.scope.id ∈ {s.id for s in owned_scopes}` (X's current `aiac.managed` scopes, seeded from the catalog). Drops retired/churned scopes (kills the `*-aud` species and scope-model cruft).
2. **Agent role still exists** — for `role.kind == Agent`, `edge.role.id ∈` the catalog's `aiac.managed` role ids (all services). Drops retired/churned agent client roles (kills agent-role UUID churn, and the self-reference of a retired role). A self-mapping of a live role stays: D32 allows it.
3. **User-role churn collapse** — user realm roles are membership-derived and absent from the catalog (the PCE reads `get_roles()` only for the [holders at render time](#role-holders-at-render-time-d32), and never reads `get_subjects()`); so among surviving `User` edges grouped by `(scope.id, role.name)`, a stale edge is dropped only when **this batch** carries a *different* id for that same `(scope, name)` (the fresh id supersedes the old generation). Two *co-existing* same-name realm roles both currently held are both kept (realm hygiene, not accumulation — out of scope).

#### Decommission (service offboard)

Reconcile is passive and catalog-anchored: it prunes only **touched** SPMs and skips any whose owner is absent from `get_services()`. That leaves the **onboard→offboard** drift species uncovered — once a service `X` is decommissioned (its Keycloak client + roles/scopes deleted), `X` is gone from the catalog forever, so (1) `SPM(X)`'s own inbound edges linger; (2) `X`'s **outbound footprint** (`X_role → other_scope` edges on *other* SPMs) is never pruned; (3) `X`'s **CR stays in the PDP**. `decommission(service_id)` is the **authoritative** teardown for exactly this — it acts on an explicit offboard signal, not the catalog-miss guard.

**Keyed by the clientId, not the UUID.** An offboarded client is gone from `get_services()`, so UUID→clientId resolution is impossible; the offboard contract carries the clientId (`Service.serviceId`, the SPM key) directly. The asymmetry with onboard's `/apply/service/{uuid}` is only at the boundary: the PCE takes the clientId in both cases (see [Public API](#public-api)).

Steps:

1. **IdP once** (`get_services()` and `get_roles()`, D32; `X` is absent from the catalog, so it is not a holder; the catalog seeds and classifies the still-live services redeployed in step 8).
2. **Load `SPM(X)`.** **Content guard:** a 404 fresh-empty SPM (never onboarded / already removed) is a **no-op** — no spurious PDP delete.
3. **Targeters** (agent side) — agents whose *outbound* loses `X`: the current holders (`actorIds`) of every **Agent**-kind inbound edge on `SPM(X)`, scanning **both** `inbound_allow_rules` and `inbound_deny_rules` (they held `their_role → X_scope` on `SPM(X)`, deleted in step 5). Under target side a targeter's CR does not change: its outbound is a pass-through.
4. **Purge `X`'s outbound footprint.** For each `r ∈ SPM(X).owned_roles` that no other catalog service holds, find the SPMs referencing it via `get_service_policies_by_role(r)`; on each such SPM `B` (skip `X`), drop edges where `edge.role.id == r.id` from **both** lists; mark `B` changed. Under target side, every changed `B` is affected (its CR is rendered from `SPM(B)`). Under agent side, `B` is affected if it is an agent (its inbound `source_roles[X]` vanished). **Shared role:** an `aiac.managed` realm role can be on the service accounts of several services (a role reused by name). The edges are keyed by `role.id`, so a purge of such a role would also remove the grants of the other services. The purge skips it. `X` stays denied: its CR is deleted (step 7), and the combiner denies a pod that has no client CR (D20). Also, an offboarded client cannot authenticate.

4b. **Re-render the callees of a shared role.** For each role of `X` that the purge skips (another service holds it), find the SPMs that have an edge of the role (`get_service_policies_by_role(r)`, `X` excluded). `X` is not a [holder](#role-holders-at-render-time-d32) any more (it is absent or disabled), so the SPM cache gives these SPMs with the remaining holders only. Mark them **shared**: step 8 redeploys them, but step 6 does not write them, because their rules did not change. Under agent side, the remaining holders of the role (the holders on those edges) are affected too: their outbound carries those edges. A client delete gives no role-mapping event, so without this step `X` stays in `source_roles` of those CRs until the [resync](#resync-controller-start).
5. **Delete `SPM(X)`** (`delete_service_policy`) — removes every user→X and agent→X inbound edge at once — and evict it from the SPM cache so re-derive can't resurrect it. `X` leaves the managed set.
6. **Persist** each changed (footprint-purged) SPM (`apply_service_policy`).
7. **Delete the CR of `X`** (`delete_service_cr(X)`, D20), for an agent and for a tool. A 404 counts as success.
8. **Redeploy the affected services** of the current side (the policy-model stage, D23), `X` excluded, filtered to live services (in the catalog and not disabled — a stored SPM of a deleted service must not bring its CR back, and a quarantined service stays with no CR); one `apply_policy` call if the model is non-empty:
   - **target side:** `TargetSidePolicyModel(services=…)` with the footprint-purged SPMs and the shared SPMs of step 4b, with the current holders;
   - **agent side:** `AgentSidePolicyModel(agents=…)` with the re-derived APMs of `(targeters ∪ remaining holders of a shared role ∪ the agents among the purged and the shared SPMs) − {X}`. Derivation is reused unchanged — it reads the freshly-persisted, `X`-deleted store with the current holders, so the outbound rule lists / `target_allow_scopes` / `target_deny_scopes` / `source_roles` referencing `X` drop automatically.

**Invariants preserved:** still one IdP read (`get_services()` and `get_roles()`); still a per-service partial upsert. A role that another service still holds keeps its edges; the redeployed SPMs name only its current holders. A shared SPM of step 4b keeps the snapshot of `X` in the store (it is not written), but its CR no longer names `X`; the next write of the SPM refreshes the snapshot. After a quarantine (not after a decommission), the lift deploys these SPMs again with `X` (see [Quarantine](#quarantine-failed-onboarding) → The lift). A new client with the clientId of a decommissioned `X` is not a lift (see [Role holders at render time](#role-holders-at-render-time-d32) → Known limits (the snapshot)). **Not covered** (follow-ups): NATS `aiac.apply.offboard.{id}` consumer wiring; dropped-target GC where the source service survives (via `override=True` re-onboard); batch offboard.

#### Quarantine (failed onboarding)

`quarantine(service_id, deleted_roles)` is the UC1 failure-path counterpart of `decommission`. The UC1 Orchestrator calls it after the compensating rollback and before it re-raises the build error (see [`aiac-agent/uc1-service-onboarding.md` → Failure & Rollback](aiac-agent/uc1-service-onboarding.md#failure--rollback)). The Orchestrator never calls the PDP library itself. The PCE owns the PDP.

**Keyed by the clientId, not the UUID.** Like `decommission`, `quarantine` takes the clientId (the SPM key). The UC1 Orchestrator resolves it from the onboarding's UUID once, before Provision. The rollback disables the client. It does not delete it. So the failed service `X` is still in the catalog.

Steps (under the PCE lock):

1. **IdP once** (`get_services()` and `get_roles()`, D32). `X` is disabled, so it is not a holder of its roles. A `service_id` that is not a catalog key (for example a UUID passed by mistake) is a logged no-op.
2. **Targeters** (agent side) — the agents that targeted `X` (the current holders of every Agent-kind inbound edge on `SPM(X)`, allow and deny).
3. **Remove `X`'s roles from the other SPMs** — the same purge as decommission step 4. `X`'s SPM is seeded from the catalog, so this removes the roles that `X` still has. The catalog does not list the roles that the rollback deleted, so the Orchestrator passes them in `deleted_roles` (the run's created-manifest), and this step removes their edges too. A role that another service also holds is skipped (see decommission step 4); the SPMs that have an edge of it are re-rendered without `X` and are not written (see decommission step 4b). Without this, a grant that a concurrent onboarding stored for a deleted role (for example `X_role → B_scope` on `SPM(B)`) would keep allowing `X` in `B`'s inbound policy until a later run [reconciles](#reconcile-drift-gc) `SPM(B)`.
4. **Delete `SPM(X)`** and persist each changed SPM. `X` leaves the managed set.
5. **Delete the CR of `X`** (`delete_service_cr(X)`, D20), for an agent and for a tool. In an AIAC setup the global combiner denies a pod that has no client CR, so the delete denies every request to and from `X` (see [`pdp-policy-writer-opa.md`](pdp-policy-writer-opa.md)). There is no no-rules CR. A 404 counts as success.
6. **Redeploy the affected live services** of the current side (`X` excluded) in one `apply_policy` call (the policy-model stage, D23), with the current role holders. Under target side, these are the services whose SPMs lost `X`'s roles, and the services whose SPMs keep an edge of a shared role of `X`. Under agent side, these are the targeters, the remaining holders of a shared role of `X`, and the agents whose SPMs lost `X`'s roles or keep an edge of a shared role of `X`.

Steps 2–6 are the steps that `decommission` also runs (the shared helper `_remove_footprint`, the CR delete, and the policy-model stage). `quarantine` is idempotent: a second call finds no SPM and no edges, and deletes the CR again (a 404 counts as success). The delete takes effect at the next poll of the OPA plugin in the pod (10 s min, up to 120 s).

**The lift.** Only a successful re-onboarding lifts a quarantine. Its PRB rebuilds the rules, and `compute_and_apply` runs with `focus_service` = `X` while the client of `X` is still disabled. It stores `SPM(X)` (also with zero rules, D21) and writes a new CR for `X` with the same SSA field manager (`aiac-pdp-policy-writer`). In the same `apply_policy` call it deploys every live SPM that has an edge of a role of `X` (under agent side, the agents among them; [Algorithm](#algorithm) steps 3d and 5), with `X` as a holder again. The quarantine rendered the CRs of these SPMs without `X` but did not write the SPMs (step 3), so their stored holders can still name `X`. Thus the stale-holders check (Algorithm step 3c) does not find them, and the rebuilt rules need not touch them. Without Algorithm step 3d, `X` stays out of those CRs until a role-members event or the resync. The lift does not wait for a role-members event. Provision maps the kept role again, and Keycloak records a `REALM_ROLE_MAPPING` event also for a mapping that is already there. But the platform Keycloak does not publish that subject yet, and on the NATS path the event comes only after the onboarding (see [`aiac-agent/uc1-service-onboarding.md` → Failure & Rollback](aiac-agent/uc1-service-onboarding.md#failure--rollback)). The lift writes only those of these SPMs whose stored holders are stale (a run wrote them while `X` was quarantined), so their snapshot names `X` again, as their CR does. If the lift did not write them and `X` later loses the role with no role-members event, the next run that touches such an SPM finds its holders current and does not deploy it, and the CR keeps allowing `X` until the resync. Then `reenable_service` re-enables the client. The lift of a service that holds no shared role deploys nothing more than its `changed` set: the quarantine purged the edges of the roles of the service, so each SPM that gets a rebuilt edge is in the `changed` set. The UC2 rebuild route is a stub, so it does not lift a quarantine. For the renders that write no SPM, and for a decommission (which has no lift), see [Role holders at render time](#role-holders-at-render-time-d32) → Known limits (the snapshot).

**Known limit (C5) — a quarantined tool cannot be lifted.** The re-onboarding of a disabled tool fails in Provision, before the build (see [`aiac-agent/uc1-service-onboarding.md` → Failure & Rollback](aiac-agent/uc1-service-onboarding.md#failure--rollback)). A failed onboarding precondition check (D30) does not quarantine and does not disable the client, so it does not cause this limit. The limit stays until handoff 14 (offboarding through Keycloak) is built.

#### Resync (Controller start)

`resync()` (D28) is the full redeploy of the current side. The Controller calls it at every start, after the start check of the combiner and before the NATS consumer starts (see [`aiac-agent.md`](aiac-agent.md)). It holds the PCE lock for its whole body, so onboardings wait on the lock.

Steps (under the PCE lock):

1. **IdP once** (`get_services()` and `get_roles()`, D32), and **list every stored SPM** (`list_service_policies()`, C3). The stored SPMs are the managed set.
2. **Replace every AIAC CR** with one `replace_policy(model)` call (`PUT /policy`). `model` is the full policy model of the current side, for the live services of the managed set (in the catalog and enabled), with the [current role holders](#role-holders-at-render-time-d32):
   - **target side:** `TargetSidePolicyModel(services=[every live stored SPM])`;
   - **agent side:** `AgentSidePolicyModel(agents=[the APM of every live stored agent SPM], pass_through=[every live stored tool SPM])`.

   The `PUT` upserts one CR per entry. Then it deletes every other CR that has the managed-by label, so no AIAC CR stays for a service that is not in the model. A disabled service is not in the model: step 3 removes it, and it must not get its rules back, even for a moment. The resync calls `replace_policy` also when the model is empty: then the `PUT` deletes every AIAC CR.
3. **Quarantine each disabled service that still has an SPM** (C2), with the steps of [Quarantine (failed onboarding)](#quarantine-failed-onboarding), under the same lock hold. There are no `deleted_roles`.

A service that has a stored SPM but is absent from the catalog (deleted, not decommissioned) is not in the model, so it gets no CR. Its SPM stays: removing it is `decommission`'s job.

If the resync fails, it re-raises, and the Controller stops. The pod restarts, and the resync runs again.

The resync is also the path for these changes:

- **A side change.** The operator patches `AIAC_ENFORCEMENT_SIDE` in the `aiac-agent-config` ConfigMap and restarts the Controller. The resync then writes every CR in the new side. Without it, a partial change is open: for example, an agent gets a pass-through outbound (target side) while a tool keeps a pass-through inbound (agent side), and then nothing checks the calls.
- **An upgrade.** The resync replaces the per-agent CRs of an older release.
- **A stale or missing CR.** A run deploys only the affected services (D23). The resync rewrites every CR.
- **A missed role-members event.** The resync renders every CR with the current role holders, so a user or an agent that got or lost a role while no event reached the Controller gets the right CR.

#### Bootstrap CR (tool discovery)

`bootstrap(service_id, service_type)` writes the CR of the focus tool before its Provision. UC-1 discovery (`analyze_tool`) sends `tools/list` through the tool's own inbound OPA. At the first onboarding the tool has no CR, so without the bootstrap the changed combiner (D20) denies that call. The UC1 Orchestrator calls `bootstrap` for an enabled tool only: after the precondition checks, and before Provision. A disabled (quarantined) tool gets no bootstrap: its discovery fails at the token mint anyway (C5), and a bootstrap CR would then stay until the next resync (see [`aiac-agent/uc1-service-onboarding.md` → Tool discovery and the bootstrap CR](aiac-agent/uc1-service-onboarding.md#tool-discovery-and-the-bootstrap-cr)). An agent gets no bootstrap, because AIAC does not call an agent at onboarding.

Steps (under the PCE lock):

1. **IdP once** (`get_services()` and `get_roles()`, D32; the tool is the focus, so it counts as live), and **load the stored `SPM(service_id)`** (`list_service_policies`, C3), with the current role holders. If the store has no SPM, use a zero-rule SPM with the given `service_type`, its identity seeded from the catalog. The type comes from the pod label (`rossoctl.io/type`), because the catalog type is not set before Provision.
2. **Write the CR** with one `apply_policy` call (`POST /policy`):
   - **target side:** `TargetSidePolicyModel(services=[that SPM])`. The tool inbound then allows only the self-discovery rule (plus any stored rules), and the outbound is a pass-through (see [`pdp-policy-writer-opa.md` → Tool inbound package](pdp-policy-writer-opa.md#tool-inbound-package-target-side-authbridgeclientinboundrequest));
   - **agent side:** `AgentSidePolicyModel(agents=[], pass_through=[service_id])`, a pass-through CR. If the type of that SPM is `Agent` (the stored type, else the given type; a mistake of the caller), the CR is the APM derived from that SPM, never a pass-through: a pass-through would allow every request.

`bootstrap` stores no SPM, so the tool does not join the managed set. The bootstrap CR then has one of these ends:

- A successful onboarding stores the SPM of the tool (D21) and writes its CR again.
- A build failure runs the [quarantine](#quarantine-failed-onboarding), which deletes the CR.
- If the onboarding stops in a different way (for example, a retryable failure in Provision), the CR stays until the next onboarding of the tool, or until the [resync](#resync-controller-start): the tool has no SPM, so the `PUT` deletes its CR.

The CR takes effect at the next poll of the OPA plugin of the tool (10 s min, up to 120 s). So discovery waits for it: it treats a `403` from the tool as not ready and polls again, until `AIAC_MCP_DISCOVERY_READY_TIMEOUT` ends (default 180 s).

#### Read model (`policy_model_for`)

`policy_model_for(service_id)` (D18) returns the policy model of the current side with only the entry of that service. It is for tests and debugging. The Controller serves it on the read-only route `GET /policy/services/{service_id:path}` (200 with the policy model JSON, or 404).

- **target side:** `TargetSidePolicyModel(services=[SPM(service_id)])`, the stored SPM with the current role holders;
- **agent side:** `AgentSidePolicyModel(agents=[APM(service_id)])` for an agent (derived from the store, as at a deploy), else `AgentSidePolicyModel(agents=[], pass_through=[service_id])` for a tool.

It returns `None` when the store has no SPM for the service (the route then gives 404). It takes no lock and writes nothing. It shows what the PCE deploys for the service from the current store. It does not read the CR in the cluster, which can be stale (D23). When the store has the SPM of an entry that it renders (any service under target side, an agent under agent side), it reads the IdP as a deploy does (`get_services()` and `get_roles()`, D32), because the PCE deploys the [current role holders](#role-holders-at-render-time-d32), not the stored `actorIds`. Under agent side, a service whose stored `service_type` is not `Agent` gets its pass-through at once, with no IdP read. The identity of an APM is the one stored on the SPM.

#### Routing guard (disabled services)

A disabled client is a failed (quarantined) service. Under the PCE lock, after the IdP read, `compute_and_apply` gives each rule the [current holders](#role-holders-at-render-time-d32) of its role, and then drops every rule that:

- has a scope whose owner (`scope.serviceId`) is disabled, or
- has an Agent-kind role that has no current live holder (every service that holds the role is disabled or absent).

**A shared role (D32).** A shared role is also the grant of its other holders. So a rule of a shared role is kept when at least one holder is live: the routed edge then names only the live holders. Before D32 the guard needed **every** `role.actorIds` owner to be live, so one disabled holder dropped the grant of all the others. A rule is dropped when the role's only holder is disabled, also when the stale `actorIds` of the rule name a live service that does not hold the role now.

The focus service is the exception. A re-onboarding applies while its client is still disabled, because `reenable_service` runs after the apply. So the focus service counts as live: its scopes and its roles are kept. Without a `focus_service`, the guard drops every rule whose scope owner is disabled, and a disabled service is not a holder.

**Deleted services.** A service that is absent from the catalog is deleted (its client was removed, for example offboarded while its onboarding was still building). The guard also drops every rule whose scope owner is absent from the catalog; an absent service is not a holder of an Agent-kind role. There is no focus exception for this case. The run also deploys only live services — in the catalog and not disabled (except the focus service). A disabled service stays with no CR (the quarantine deleted it). A service must be in the catalog because the store returns a placeholder SPM typed `Agent` on a 404, so without this check a late onboarding of a deleted tool wrote a CR for it, and a run that touched the stored SPM of a deleted service wrote its CR again. Removing a deleted service's footprint is `decommission`'s job.

The guard prevents a build that started before a quarantine or an offboard from writing its rules back into the removed footprint. The focal resolver applies the disabled-service rule on the build side (see [`aiac-agent/uc1-service-onboarding.md` → Service Policy Builder](aiac-agent/uc1-service-onboarding.md#sub-agent-service-policy-builder)).

**Known limit (C2) — a client that is disabled by hand.** The quarantine runs only after a failed onboarding. A client that an operator disables by hand keeps its SPM and its CR. The routing guard drops every new rule that touches it, so it gets no new rules. Its CR stays until the [resync](#resync-controller-start) at the next Controller start quarantines it.

### Serialization (the PCE lock)

Each public operation reads SPMs, changes them, and writes them back (a read-modify-write). The store has no versions, and its write lock protects one write, not a read-modify-write. Thus two onboardings that route rules into one shared SPM (for example, two agents granted on one tool's scope) both read the old SPM, and the second write removes the rules of the first run.

One module-level `threading.Lock` (`_pce_lock`) is held for the whole body of `compute_and_apply`, `decommission`, `quarantine`, `resync`, `bootstrap` and `rerender_role` (D22). The IdP read of an operation (the catalog and the role holders) is under the lock too. The resync at the Controller start therefore finishes before an onboarding can apply. The read model `policy_model_for` takes no lock. The PRB (the LLM work) runs before `compute_and_apply`, outside the lock. So concurrent onboardings still do their LLM work in parallel. The part under the lock makes no LLM call.

Known limits:

- **One Controller replica only.** The lock serializes one process, like the Orchestrator's per-service lock. More replicas need store versions or a distributed lock.
- **The lock does not cover the re-enable.** The Controller calls `reenable_service` after `compute_and_apply` returns, outside the lock. A render with no store write in that window can keep a lifted service out of the shared CRs (see [Role holders at render time](#role-holders-at-render-time-d32) → Known limits (the snapshot)).
- **Overlapping onboardings can leave a pair unjudged.** When two onboardings overlap, the resolver of each service reads the catalog before the Provision of the other service. So a pair between the two new services can stay unjudged. That pair gives no grant (fail closed).

### Dependencies

| Module | Purpose |
|--------|---------|
| `aiac.policy.model` | `PolicyRule`, `RuleEffect`, `ServicePolicyModel`, `AgentPolicyModel`, `EnforcementSide`, `PolicyModel`, `TargetSidePolicyModel`, `AgentSidePolicyModel`; `project_inbound` (`aiac.policy.model.projection`, the APM inbound); `RoleHolders` (`aiac.policy.model.holders`, the role holders at render time) |
| `aiac.idp.configuration` | `Configuration.get_services` (catalog: `service_type` + own roles/scopes for the P2 seed, the live check, the holders of each agent role) and `Configuration.get_roles` (the current members of each user role, D32) — the **only** runtime IdP reads, one time for each operation. Never `get_subjects`. |
| `aiac.policy.model_store.library` | `get_service_policy` (fetch SPM), `get_service_policies_by_role` (SPMs containing a role — override purge, outbound derivation, the role re-render), `list_service_policies` (every SPM — the resync, the read model, the bootstrap, the agent-side role re-render), `apply_service_policy` (persist SPM), `delete_service_policy` (offboard, quarantine) |
| `aiac.pdp.policy.library` | `apply_policy` — partial-upsert the policy model of the affected services (each run, the redeploy in `quarantine` / `decommission`, and `rerender_role`), and the CR of the focus tool (`bootstrap`); `replace_policy` — replace every AIAC CR (the resync); `delete_service_cr` — delete the CR of one service (`quarantine`, `decommission`). The PCE never calls `delete_policy`. |
| Env | `AIAC_ENFORCEMENT_SIDE` — `target-side` (default) or `agent-side`; read by `enforcement_side()` |

Note: the PCE no longer calls `get_services_by_role` / `get_services_by_scope` / `get_subjects_by_role` at routing or classification time — those facts arrive on the rules (input contract) and derivation reads SPMs. The IdP reads are `get_services()` and `get_roles()`, for the identity seed, the live check and the [role holders](#role-holders-at-render-time-d32).

### Not Called By

- PDP Policy Writer — the downstream consumer, not a caller.
- Policy Model Store — pure CRUD, no computation.
- IdP Configuration Service — no awareness of this module.

### Not Responsible For

- Rule revocation beyond role-level `override=True` replace (single-rule revocation is TBD).
- Bootstrapping SPM records for brand-new services (the store returns 404; the engine seeds a fresh SPM from the catalog).
- Translating the policy model → Rego packages (responsibility of `aiac.pdp.policy.library` / PDP Policy Writer). The writer also picks the CR name and namespace (`identity_ref`).

---

## Testing Decisions

Good tests assert external behavior — what the engine writes to the Policy Model Store (SPMs) and pushes to the PDP (the policy model of the current side) — not internal merge logic directly.

**Seam:** mock all downstream dependencies at their module-level import boundary:

- `aiac.idp.configuration` — mock `Configuration.get_services` (the catalog: `service_type` + each service's own roles/scopes for the P2 seed) and `Configuration.get_roles` (the current members of each user role). The unit harness answers `get_roles` with the user roles that the test gives (the realm agrees with each snapshot), unless the test gives other members to model a membership change.
- `aiac.policy.model.holders` — `RoleHolders` is pure; its own tests (`test/unit/policy/model/test_holders.py`) give it a catalog and the realm roles.
- `aiac.policy.model_store.library` — mock `get_service_policy`, `get_service_policies_by_role`, `list_service_policies`, `apply_service_policy`, `delete_service_policy`.
- `aiac.pdp.policy.library` — mock `apply_policy`, `replace_policy`, `delete_service_cr`.
- The side — set `AIAC_ENFORCEMENT_SIDE` (monkeypatch the env). Run the side-specific behaviors under each side.

**`test/unit/policy/computation/` runs in the unit lane.** The suite runs under the default `pytest` (marker-only selection; the unit lane is untagged).

Key behaviors to assert:

- **Original repro, both orders → identical `APM(A)`.** Onboard **A then T** and **T then A**; assert the derived `APM(A)` is identical (inbound `{UR→AS}`, outbound `{AR→TS, UR→TS}`), compared as order-independent `(role, scope)` sets. This is the headline regression guard (agent side). Under target side, both orders give the same stored `SPM(T)` (`{UR→TS, AR→TS}`) and the same target-side policy model of `T`.
- **Latent sibling bug (late UC3 user role).** After A+T exist, a later user-role rule `(UR2 → TS)` routes to `SPM(T)`. Under agent side it marks A affected, and A's re-derived subject gate includes `UR2`. Under target side, `T` is in the `changed` set, and its entry in the policy model includes `UR2`.
- **Agent → agent (`AR→BS`).** Stored on `SPM(B)`. Under agent side, A's derived APM has `AR→BS` in `outbound_target_allow_rules` + `target_allow_scopes[B]`; B's derived APM has `source_roles[A] += AR`. Under target side, `SPM(B)` (with `AR→BS`) is B's entry in the policy model, and A's SPM does not change.
- **Override role-level purge across SPMs.** `override=True` with an input role already present on multiple SPMs → that role is purged from **every** SPM (via `get_service_policies_by_role`) once, up-front, before the fresh rules are appended; a role shared across the input is not wiped after being added.
- **Append dedup.** A rule already present on the target SPM (same `role.id + scope.id`) is not appended twice; map list entries (same `id`) are not duplicated.
- **No flattening.** Rules arrive pre-flattened; the PCE issues at most one `get_service_policies_by_role` call **per distinct role** — a rule carrying a composite role does not trigger per-child calls inside the PCE.
- **Agent side: a tool gets an SPM and a pass-through, but no APM.** A Tool service accrues durable inbound edges (`inbound_allow_rules` / `inbound_deny_rules`) on its SPM but is never emitted as an APM; the agent→tool `target_allow_scopes` edge still appears on the agent's derived APM. A focus tool is in `pass_through`.
- **Target side: every changed SPM is an entry.** A tool and an agent whose SPMs changed are both in `TargetSidePolicyModel.services`, as stored (no APM is derived). A disabled service (not the focus) and a service absent from the catalog are not in the model.
- **The side (D29).** `enforcement_side()` returns `target-side` when `AIAC_ENFORCEMENT_SIDE` is unset, `agent-side` for `agent-side`, and raises `ValueError` for an unknown value.
- **The zero-rule focus SPM (D21).** A run with a `focus_service` and zero rules stores `SPM(focus)` (seeded from the catalog) and deploys it: under target side it is in `services`; under agent side its APM is in `agents` (an agent) or its clientId is in `pass_through` (a tool).
- **P2 identity from `owned_*`.** Each derived APM's `agent_roles` / `agent_scopes` come from `SPM(A).owned_roles` / `owned_scopes`, AIAC-managed-filtered; an agent with no AIAC-managed catalog roles/scopes keeps `[]`.
- **Directional relevance — no false outbound edge.** A user role shared between `AS` and `TS` does **not** by itself make A "target" T; A's outbound edge to T appears only if one of A's **agent** roles maps to a T scope.
- **Affected set from the batch, not a full scan.** Under target side the affected set is the `changed` set (and, at a lift, the `lifted` set). Under agent side the affected-agent set is computed from the batch roles/scopes. Services unrelated to the batch are never derived or upserted.
- **`apply_policy` called exactly once** after all `apply_service_policy` writes complete (partial upsert of only the affected services, with the policy model of the current side), and not called when the model is empty.
- **Reconcile (drift GC).** A touched SPM carrying dangling edges (retired scope, churned scope UUID, churned/duplicate user role, retired agent-role self-reference) is pruned against the catalog on re-onboarding; live edges survive and the pass is idempotent; a catalog miss (owner absent) leaves the SPM untouched.
- **Decommission (service offboard).** Onboard an agent A targeting tool T, then `decommission(T)`: `SPM(T)` is deleted and `delete_service_cr(T)` is called. Under agent side, A is re-derived with an empty outbound while its inbound survives. Under target side, A's CR is not redeployed (its SPM did not change). `decommission(A)`: `SPM(A)` deleted, `delete_service_cr(A)` called, A's outbound footprint (`AR→TS` on `SPM(T)`) purged while T keeps its user grant, and no entry for the deleted agent in the policy model. Under target side, the purged `SPM(T)` is redeployed. A never-onboarded / 404 service is a no-op (no `delete_service_cr` call).
- **Effect routing.** A `Deny` rule routes to `SPM(scope.serviceId).inbound_deny_rules`; an `Allow` rule to `inbound_allow_rules`. Append-dedup keys on `role.id + scope.id + effect`, so the same `(role, scope)` can be present once in each list.
- **Effect-aware derivation.** A subject DENY edge on `SPM(A)` derives into `inbound_subject_deny_rules`, and its role still appears in the effect-agnostic `subject_roles`; an agent-role → target-scope DENY edge derives into `outbound_target_deny_rules` + `target_deny_scopes[target]`.
- **Override purges both lists.** `override=True` with an input role present in a target SPM's allow **and** deny lists purges it from both before re-appending.
- **Reconcile prunes both lists.** A dangling deny edge (retired scope / churned role) is GC'd exactly as a dangling allow edge; a live deny edge survives; the pass is idempotent.
- **Decommission clears both lists.** Offboard tears down the target's own inbound (allow + deny) and its outbound footprint (allow + deny edges keyed by its roles on other SPMs).
- **PCE lock.** Two concurrent runs that route rules into one shared SPM keep the rules of both runs. `compute_and_apply`, `decommission`, `quarantine`, `resync`, `bootstrap` and `rerender_role` each hold the PCE lock.
- **Routing guard.** A rule whose scope owner is disabled, or whose agent role has no live holder, is dropped. A shared role with one disabled holder and one live holder is routed, with the live holder only; a role whose only holder is disabled is dropped. The rules of the focus service are kept while it is disabled. Without a focus service, every rule that touches a disabled service is dropped. When all services are enabled, every rule is kept. Under override, a role whose every new rule the guard drops still loses its old grants.
- **Role holders at render time (D32).** Two agents in `team1` and `team2` share a role; the stored edge names only one. Both onboarding orders give the tool a CR whose `source_roles` (the writer's `project_inbound`) names both agents, and the same stored `SPM(T)`. A holder added later is in the next render with no PRB run (`rerender_role`, `resync`, and an unrelated `compute_and_apply` on the tool); a disabled, deleted or unassigned holder is gone. A duplicate rule whose holders are current writes and deploys nothing. A user who gets a user role after the rule was stored is in `subject_roles` after `rerender_role` and after `resync`; a user who loses the role is not; a role that `get_roles()` does not list has no holder.
- **Role re-render.** Under target side, `rerender_role(id)` calls `apply_policy` once with only the live stored SPMs that have the role, with the current holders, and calls no store write function; it makes no call when no SPM has the role. Under agent side, it re-derives every live stored agent in one call, and makes no call when there is none. It holds the lock, and a failure re-raises.
- **Quarantine.** For an agent and for a tool: `SPM(X)` is deleted, its roles are removed from the other SPMs, `delete_service_cr(X)` is called (no no-rules CR is written), and the affected services of the current side are redeployed in one call (target side: the SPMs that lost X's roles; agent side: the targeters and the agents whose SPMs lost X's roles). A second call gives the same result. An unknown UUID is a no-op. `quarantine` and `decommission` keep the grants of a role that another service also holds, and never deploy a service that is absent from the catalog or disabled. When the removed service shares a role with a live agent, the callees that have an edge of the role are redeployed in the same call without the removed holder (the live holder stays in `source_roles`), and the store write set does not change; under agent side, the remaining holder and the agent callees are re-derived.
- **The lift (D32).** A successful re-onboarding of a quarantined service (the focus, still disabled) deploys, in the same call, every live SPM that has an edge of a role of the service, with the service in `source_roles` again. This is also true when the rebuilt rules route no rule, or only a duplicate rule, to that SPM. A lifted SPM is written only when its stored holders are stale. Then its snapshot names the lifted service, and a later loss of the role with no event takes the service out of the CR at the next run that touches the SPM. A disabled or deleted callee is not deployed and not written. Under agent side, the agents among the lifted SPMs are re-derived, and the tools keep their pass-through. When every other holder of the shared role is quarantined, the role goes to the lifted service only. The lift of a service that holds no shared role, and an onboarding of an enabled service, deploy only the `changed` set. A second lift run gives the same deploy and writes only the focus SPM. A resync after the lift gives the same CRs (unit tests in `test/unit/policy/computation/test_engine.py`; the integration lane in `test/integration/policy/computation/test_quarantine_lift.py`).
- **Resync (D28).** Under the PCE lock, `resync` calls `replace_policy` once with the full policy model of the current side: under target side, every live stored SPM; under agent side, the APMs of the live stored agent SPMs and `pass_through` = the live stored tool SPMs. A disabled service with an SPM is not in the model and is then quarantined (its SPM is deleted and `delete_service_cr` is called). A service absent from the catalog is not in the model, and its SPM stays. An empty store gives one `replace_policy` call with an empty model. A failure re-raises.
- **Bootstrap.** For a tool with no stored SPM, `bootstrap(id, Tool)` calls `apply_policy` once: under target side with a zero-rule SPM of type `Tool` (its CR then allows only the self-discovery rule); under agent side with `pass_through=[id]` and no agents. With a stored SPM, the target-side entry is the stored SPM. It calls no store write function, so the tool has no SPM after it. Under agent side, `bootstrap(id, Agent)` pushes the APM of its zero-rule SPM, with no pass-through, and stores nothing.
- **Read model (D18).** `policy_model_for(id)` returns a target-side model with only `SPM(id)`, with the current holders, under target side. Under agent side it returns the APM of an agent, or `pass_through=[id]` for a tool. It returns `None` when the store has no SPM for `id`. It takes no lock and calls no write function.
- **Failures propagate.** An exception from any dependency is logged and **re-raised** (it propagates to the caller, which surfaces it — e.g. the Controller returns HTTP 500, or stops at start for `resync`); on success `compute_and_apply` / `decommission` / `quarantine` / `resync` / `bootstrap` / `rerender_role` return `None`.

---

## Out of Scope

- **Fine-grained rule revocation:** removing an individual `PolicyRule` without replacing its whole role. `override=True` covers role-level replace at the SPM layer (see [Merge Semantics](#merge-semantics)); single-rule revocation is not yet designed — **TBD**. (Full-service **decommission / package deletion** *is* now designed and implemented — see [Decommission (service offboard)](#decommission-service-offboard).)
- **Full policy rebuild orchestration:** the PCE handles incremental updates; full rebuilds are driven by higher-level orchestration outside this module. The UC-2b rebuild reapplies every rule with `override=True`, and ends with `PUT /policy` (`replace_policy`, through the PCE, as the resync does) (D28a). It does not start with `DELETE /policy`, so there is no deny window under D20. **Status: not built yet** — UC2 Rebuild (`src/aiac/agent/uc/policy_update/rebuild.py`) is a stub that returns `([], True)`.
- **Direct Keycloak calls:** all IdP access goes through `aiac.idp.configuration.Configuration` (only `get_services()` and `get_roles()`). The PCE never calls Keycloak directly.
- **Group and composite-parent holders:** a role held through a group or through a composite parent role is not resolved at render time (a known limit; see [Role holders at render time (D32)](#role-holders-at-render-time-d32)).
- **Persistence of `PolicyRule` inputs:** the PCE persists SPMs (source of truth); the policy model (and, under agent side, its APMs) is built and pushed, never persisted (D18). The raw input rule list is not stored.
- **Model field definitions** (handoff 01), **IdP service / library** (handoffs 02/03), **store CRUD** (handoff 04).

---

## Further Notes

- The PCE is the **only** caller of `aiac.pdp.policy.library` (`apply_policy`, `replace_policy`, `delete_service_cr`) from AIAC Agent sub-agents. Sub-agents call `compute_and_apply`, not the PDP Policy Library directly. No AIAC code calls `delete_policy` (C1).
