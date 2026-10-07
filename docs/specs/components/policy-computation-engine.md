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

- Under **target side**, the affected services are the services whose SPM changed in this run. The policy model (`TargetSidePolicyModel`) carries their stored SPMs as they are. Each callee's own CR is rendered from its own SPM.
- Under **agent side**, the affected services are the affected agents, plus the focus service when it is a tool. The PCE re-derives each affected agent's APM **entirely from SPMs (zero IdP)**. The policy model (`AgentSidePolicyModel`) carries the APMs and the pass-through of a focus tool.

Because `UR→TS` is durable on `SPM(T)`, both onboarding orders converge. Under agent side, `UR→TS` is reconstructed onto `A` whenever `A` is derived, so both orders give the same `APM(A)` = inbound `{UR→AS}`, outbound `{AR→TS, UR→TS}`. Under target side, no join is necessary: `T`'s own CR is rendered from `SPM(T)`, which holds `UR→TS` and `AR→TS`. The latent sibling bug is fixed too: a late UC3 user role routes to `SPM(T)`. Under agent side it marks `A` affected and re-derives `A`'s subject gate. Under target side it changes `SPM(T)`, so `T` gets a new CR.

The module is pure Python (`aiac.policy.computation`), imported directly into the calling sub-agent's process. No FastAPI service, no Kubernetes deployment, no container image.

---

## Assumptions

These AIAC invariants (from the policy-model spec, handoff 01) are relied on by the PCE and are **enforced upstream at the Keycloak IdP boundary** (handoff 02), not re-checked here:

1. **No role spans both kinds.** A role is held by users *or* by agent service accounts, never both. This is what lets `Role.actorIds` be a single list and lets the PCE split inbound rules cleanly by `role.kind`. AIAC invariant, *not* a Keycloak guarantee.
2. **No scope shared across services.** A scope has exactly one owner, so `Scope.serviceId` is single-valued and `SPM(scope.serviceId)` is unambiguous. (Keycloak client scopes are realm-level and assignable to many clients; for AIAC-managed scopes the owner set is always length 1.)
3. **Agent role ⇔ a client role on the agent's client, or an `aiac.managed` realm role on its service account; user role ⇔ a realm role held by users.** The IdP config service sets `Role.kind`: `GET /services/{id}/roles` marks agent roles `Agent`, and `GET /roles` marks realm roles `User`. Agent roles come from `Service.roles`.

---

## User Stories

1. As an AIAC Agent sub-UC agent, I want to submit a list of `PolicyRule` objects and have them durably recorded on the right service and reflected in the CR of every affected service, without implementing routing or storage merge logic myself.
2. As an AIAC Agent sub-UC agent, I want to submit the rules and get no return value to unpack on success, so I stay decoupled from routing, storage, and derivation — while a failure still surfaces to me (US 7).
3. As the Policy Computation Engine, I want each rule recorded on the SPM of the service that **owns the rule's scope**, so the fact survives regardless of which services already exist.
4. As the Policy Computation Engine, I want to build the policy model purely from the persisted SPMs (under agent side, to derive an affected agent's APM from them), so the result is **independent of onboarding order**.
5. As the Policy Computation Engine, I want to skip duplicate rules on append, so re-processing the same event does not create redundant entries.
6. As the Policy Computation Engine, I want to partial-upsert only the affected services' CRs to the PDP, so the CRs of unaffected services are left untouched.
7. As a developer, I want exceptions from the computation logged **and re-raised**, so a failed IdP / store / PDP interaction surfaces to the caller (the Controller returns HTTP 500; a NATS consumer nacks → at-least-once redelivery) instead of being silently dropped while nothing is applied.
8. As a developer, I want a stable import path, so the calling convention does not change as the module grows.
9. As the Policy Computation Engine, I want one run at a time to change the SPMs, so two concurrent onboardings that route rules into one shared SPM do not lose the rules of one run.
10. As the UC1 Orchestrator, I want to quarantine a failed onboarding by its clientId, so its policy footprint is removed, its CR is deleted (a pod that has no CR is denied), and no later run writes rules back into that footprint.
11. As an operator, I want one switch to select the enforcement side for every callee, so that the two sides never exist together.
12. As the Controller, I want a resync at every start, so that every managed service has the CR of the current side, and no AIAC CR stays for a service that has no SPM.
13. As a test or an operator, I want to read the policy model of one service, so that I can see what the PCE deploys for it.
14. As the Policy Computation Engine, I want a successful onboarding to store the focus SPM also when it has zero rules, so that the focus service joins the managed set and gets a CR.
15. As the UC1 Orchestrator, I want the CR of a tool written before its Provision, so that UC-1 discovery through the tool's own inbound OPA passes D20 at the first onboarding.

---

## Implementation Decisions

### Module Identity

**Namespace:** `aiac.policy.computation`

**Location:** `src/aiac/policy/computation/`

```
src/aiac/policy/
└── computation/
    ├── __init__.py   # exports compute_and_apply, decommission, quarantine, resync,
    │                 #         bootstrap, policy_model_for, enforcement_side
    └── engine.py     # the same seven functions
```

No FastAPI. No Kubernetes deployment. No container image. Imported as a library by AIAC Agent sub-UC agents.

### Public API

Five entry points change the deployed policy — an incremental fold, an authoritative offboard, the teardown of a failed onboarding, the resync at the Controller start, and the bootstrap CR of a tool before its Provision. Two entry points only read — the read model and the side:

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
def policy_model_for(service_id: ClientId) -> PolicyModel | None  # D18: read-only, no lock
def enforcement_side() -> EnforcementSide                         # D29: reads AIAC_ENFORCEMENT_SIDE
```

**Service ids: the PCE takes only the clientId.** Keycloak gives every client two ids: the internal UUID (`Service.id`, type `ServiceUuid`) and the `clientId` (`Service.serviceId`, a SPIFFE ID, type `ClientId`; both `NewType`s of `str` in `aiac.idp.configuration.models`). Every service id the PCE takes is the clientId — the SPM key, `PolicyRule.scope.serviceId`, and OPA `input.identity.service_id`. The UUID is only for finding the service in the IdP. The asymmetry stays at the HTTP/NATS boundary: an onboarding comes in with a UUID (`/apply/service/{uuid}`, `aiac.apply.service.<uuid>`), and the UC1 Orchestrator resolves the clientId once, before Provision, while the client still exists; an offboard comes in with the clientId, because after the client is deleted UUID→clientId resolution is impossible.

- **No return value; failures propagate:** on success the caller receives no return value. The five functions that change policy log exceptions and **re-raise** them — a failure in IdP resolution, Policy Model Store I/O, or PDP Policy Writer push surfaces to the caller (the Controller returns HTTP 500; a NATS consumer nacks → at-least-once redelivery) rather than being silently swallowed while nothing is applied.
- **`override`:** selects the merge mode (see [Merge Semantics](#merge-semantics)). `False` (default) appends additively at the SPM layer; `True` authoritatively replaces every input role's mappings **across all SPMs** (role-level revocation). Set by the caller (the Controller) from the producing UC's choice — UC1 = `False`, UC3 = `True`, UC2 Rebuild = `True`, UC2 Build = TBD.
- **`focus_service`:** the clientId (`Service.serviceId`) of the service that this onboarding builds — not its Keycloak UUID. The [routing guard](#routing-guard-disabled-services) does not drop the rules of this service while its client is disabled. The onboarding route (`POST /apply/service/{uuid}`) and the NATS consumer (`aiac.apply.service.<uuid>`) pass the clientId that `onboard_service` returns. Other callers pass nothing.
- **No default effect:** there is no default-effect parameter. A `(role, scope)` pair that no rule mentions is always DENY.
- **`decommission`:** the authoritative service **offboard** — tears down a decommissioned service's entire policy footprint (see [Decommission (service offboard)](#decommission-service-offboard)). Keyed by the **clientId (SPM key)**, since an offboarded client is gone from `get_services()` and its UUID can no longer be resolved.
- **`quarantine`:** the UC1 failure-path teardown of a failed onboarding (see [Quarantine (failed onboarding)](#quarantine-failed-onboarding)). Keyed by the **clientId (SPM key)**, as `decommission` is. The failed service stays in the catalog (disabled).
- **`resync`:** the full redeploy at every Controller start (D28; see [Resync (Controller start)](#resync-controller-start)). It writes the CR of every live managed service (in the IdP catalog and not disabled) in the current side, deletes every other AIAC CR, and quarantines each disabled service that still has an SPM.
- **`bootstrap`:** writes the CR of the focus tool before its Provision, so that UC-1 discovery passes D20 at the first onboarding (see [Bootstrap CR (tool discovery)](#bootstrap-cr-tool-discovery)). Keyed by the clientId. It stores no SPM.
- **`policy_model_for`:** the read model of one service (D18; see [Read model (`policy_model_for`)](#read-model-policy_model_for)). It changes nothing.
- **`enforcement_side`:** the current enforcement side (D29; see [Enforcement side and the managed set](#enforcement-side-and-the-managed-set)).
- **Serialization:** `compute_and_apply`, `decommission`, `quarantine`, `resync` and `bootstrap` hold one PCE lock for their whole body (see [Serialization (the PCE lock)](#serialization-the-pce-lock)). `policy_model_for` and `enforcement_side` take no lock.
- Import path: `from aiac.policy.computation import compute_and_apply, decommission, quarantine, resync, bootstrap, policy_model_for, enforcement_side`

### Rule-builder input contract (upstream)

Each incoming `PolicyRule` arrives with `scope.serviceId`, `role.kind`, and `role.actorIds` **already populated**, and with roles **already flattened** to their closure (role + descendants, dedup by `role.id`). The PCE performs **no IdP lookup for routing or classification** and **no role flattening** — it treats each rule's `role` and `scope` as-is.

- The boundary that **derives** `scope.serviceId` / `role.kind` / `role.actorIds` from Keycloak facts is the **Keycloak IdP config service (handoff 02)**.
- The rule-builder (the Policy Rules Builder, `src/aiac/agent/policy_rules_builder/graph.py`) merely **carries those fields through** on the IdP `Role` / `Scope` that it puts in each `PolicyRule`; it does not compute them.

### Enforcement side and the managed set

**The side (D16, D29).** `enforcement_side()` reads the env var `AIAC_ENFORCEMENT_SIDE` and returns an `EnforcementSide`: `target-side` (the default, also when the var is unset) or `agent-side`. An unknown value raises `ValueError`. The Controller calls it at start, so an unknown value stops the Controller before it serves. The var comes from the `aiac-agent-config` ConfigMap, so it does not change while the process runs. Each PCE operation builds the policy model of this side. The two sides never exist together.

- **Target side.** Each callee, agent or tool, checks the access to itself in its own inbound OPA, from its own CR. The render input is the stored SPM of the callee (`TargetSidePolicyModel`). The outbound package of every CR is a pass-through: the callee decides (D24).
- **Agent side** (the legacy method). Each agent's CR checks the agent's calls to tools on its outbound. The render input is the APM, which the PCE derives in memory (`AgentSidePolicyModel.agents`). Each managed tool gets a pass-through CR (`AgentSidePolicyModel.pass_through`), because a pod that has no CR is denied (D20, D24).

A side change is a ConfigMap patch and a Controller restart. The [resync](#resync-controller-start) then writes every CR in the new side, so no mixed state stays.

**The managed set (D21).** The managed set is the services that have a stored SPM. Every managed service has a CR, under both sides (D20): the global combiner denies a pod that has no client CR. A service leaves the set only through the quarantine or the decommission, which delete its SPM and its CR. A successful onboarding stores the focus SPM also when it has zero rules (see [Algorithm](#algorithm) step 2b), so the focus service always joins the set. The [bootstrap CR](#bootstrap-cr-tool-discovery) of a tool is the one CR outside the managed set: it exists from the bootstrap until the onboarding stores the SPM, or until a quarantine or the resync deletes it.

### Algorithm

Given `rules: list[PolicyRule]`, an `override` flag and an optional `focus_service`, `compute_and_apply` executes these steps under the [PCE lock](#serialization-the-pce-lock):

1. **Catalog once.** Call `Configuration.get_services()` — the **only** runtime IdP read. For every service touched this batch, seed its SPM's `service_type` / `owned_roles` / `owned_scopes` from its catalog `Service` record, keeping only **AIAC-provisioned** entities (the `aiac.managed` marker on `Role.aiac_managed` / `Scope.aiac_managed`; Keycloak built-ins — the default client scopes `profile`, `email`, `roles`, `web-origins`, `acr`, `basic`, `service_account`, and the `default-roles-<realm>` composite — are dropped; so is the shared subject scope `aiac-username-sub`, which AIAC provisions with no marker, D31). This seed drives **P2** identity and the service type (under target side, the inbound render of the CR; under agent side, the rule [only agents get an APM](#p2--p5b-reconciliation-and-the-agent-side-rule)). It is a seed, **not** a per-derive dependency.

1b. **Routing guard.** Drop every rule that touches a disabled service (except the focus service) or a service absent from the catalog (see [Routing guard (disabled services)](#routing-guard-disabled-services)).

2. **Route each rule to its owning service's SPM, by effect.** For each rule `(role, scope, effect)`, append it to `SPM(scope.serviceId).inbound_allow_rules` (if `effect == Allow`) or `.inbound_deny_rules` (if `effect == Deny`) — fetch the SPM via `get_service_policy(scope.serviceId)`. **Append-dedup by `role.id + scope.id + effect`.** There is **no** write-time 3-way P5b classification (the old (user,agent-scope)/(user,tool-scope)/(agent,tool-scope) routing table is gone) — a rule always lands on the effect-appropriate list of the SPM that owns its scope, whatever the kinds.

2b. **Focus SPM (D21).** When `focus_service` is set and the focus service is in the catalog, the run loads `SPM(focus)` (seeded from the catalog) and adds it to the `changed` set, also when it has zero rules. So step 4 always stores the focus SPM, and the focus service joins the managed set and gets a CR. A re-onboarding with zero rules also stores the SPM and redeploys the CR.

3. **Override (`override=True`) — role-level revocation.** *Before* appending, purge the **distinct input-role set** (taken from the input **before** the routing guard, so a role whose every new rule the guard drops still loses its old grants) from **both** lists (`inbound_allow_rules` + `inbound_deny_rules`) of **every** SPM that contains any of them: one up-front pass using `get_service_policies_by_role` per distinct input role, removing every stored rule (allow or deny) whose `role.id` matches. Then append the fresh rules. Purging once, up-front, ensures a role shared across the input is not wiped after being added. The old algorithm's `target_scopes` reconciliation is **deleted** — the target maps (`target_allow_scopes` / `target_deny_scopes`) are derived, never-stored quantities.

3b. **Reconcile (drift GC) — after routing/override, before persist.** Prune each **touched** SPM against the step-1 `get_services()` catalog (no additional IdP read) so drift cannot accumulate across re-onboarding. Runs under **both** merge modes and is order-independent (drops only edges whose entity no longer exists). See [Reconcile (drift GC)](#reconcile-drift-gc) under Merge Semantics for the keep rules.

4. **Persist** each changed SPM via `apply_service_policy`.

5. **Compute the affected set of the current side (D23)** — from the batch, **not** by scanning all services:
   - **Target side:** the affected set is the `changed` set — the services whose SPM changed in this run (routed, override-purged, reconciled, and the focus SPM of step 2b; a zero-rule focus SPM counts). Only these CRs change, because each CR is rendered from the callee's own SPM.
   - **Agent side:** the affected agents, from the batch's roles/scopes:
     - For each input (or purged) role `r` with `r.kind == Agent`: the owning agents in `r.actorIds` are affected (their outbound changed).
     - For each touched owner `X` (the scope owner of each routed rule, plus every SPM in the `changed` set: override-purged, reconciled, and the focus SPM):
       - if `X` is an **Agent**, `X` is affected (its inbound changed); **and**
       - every agent **targeting** `SPM(X)` is affected — namely the owners (`actorIds`) of every **Agent-kind** inbound rule (allow and deny) on `SPM(X)`, for any scope (a superset of the exact-scope match).
     - Plus the focus service when it is a **tool**: it gets its pass-through CR.

6. **The policy-model stage (D23).** After the store writes and before the deploy, build the policy model of the current side for the affected **live** services (in the catalog and not disabled; the focus service counts as live), and **partial-upsert** it via `aiac.pdp.policy.library.apply_policy` **at most once** (no call when the model is empty). This stage replaces the former derive-only stage (`_apply_derived`). It is inside `compute_and_apply`, so the UC1 Orchestrator is not involved.
   - **Target side:** `TargetSidePolicyModel(services=[SPM(x) for x in changed if x is live])`. No APM is derived.
   - **Agent side:** derive each affected live agent's APM (see below), then `AgentSidePolicyModel(agents=…, pass_through=[focus] if the focus service is a tool)`.

   Exceptions are logged and re-raised (they propagate to the caller). A stale or missing CR stays until its service is affected again, or until the [resync](#resync-controller-start). A CR change takes effect at the next poll of the OPA plugin in the pod (10 s min, up to 120 s), not when `apply_policy` returns.

### Derivation of `APM(A)` — 100% from SPMs, zero IdP (agent side)

The PCE derives an APM only under agent side. Let `R_A = SPM(A).owned_roles` (A's own `aiac.managed` roles, from `Service.roles`) and `S_A = SPM(A).owned_scopes`.

- **Identity (P2):** `agent_roles` ← `R_A`; `agent_scopes` ← `S_A`.
- **No default effect:** the APM carries no default effect. The generated Rego always denies a pair that no rule mentions.
- **Inbound:** project `SPM(A)` with the shared `project_inbound` (D18b, `aiac.policy.model.projection`; see [`policy-model.md`](policy-model.md)). The target-side renderer uses the same function, so for one SPM both sides give the same inbound gates. The projection iterates **both** of `SPM(A)`'s inbound lists. It splits each edge by `role.kind` **and** `effect` into the matching APM bucket:
  - `User` + `Allow` → `inbound_subject_allow_rules`; `User` + `Deny` → `inbound_subject_deny_rules`;
  - `Agent` + `Allow` → `inbound_source_allow_rules`; `Agent` + `Deny` → `inbound_source_deny_rules`.
  - **Identity registration is effect-agnostic:** for **every** inbound edge (allow *or* deny), register the role into the identity map — `User` → `subject_roles[username] += role` (usernames from `role.actorIds`); `Agent` → `source_roles[serviceId] += role` (serviceIds from `role.actorIds`). A role seen only in a DENY edge must still land in these maps, or the Rego deny lookup cannot resolve it.
- **Outbound:** for each `r ∈ R_A`, find the `r`-rules across **both** lists in `get_service_policies_by_role(r)`. For each such `(r → s)`: route by effect — `Allow` → `outbound_target_allow_rules` and `target_allow_scopes[s.serviceId] += s`; `Deny` → `outbound_target_deny_rules` and `target_deny_scopes[s.serviceId] += s`.
- **Outbound subject gate:** for each target `(X, s)` in the target maps — where `X` is the callee, a **tool or another agent** — take the **User**-kind inbound rules `(u → s)` on `SPM(X)`, route each by effect into `outbound_subject_allow_rules` / `outbound_subject_deny_rules`, and register `subject_roles += u.actorIds` (effect-agnostic). The gate's range is tool ∪ agent scopes.

**Relevance is directional.** An SPM contributes to `A` **iff** it *is* `SPM(A)` (contributes inbound) **or** it contains a rule whose role is one of A's **agent** roles `R_A` (contributes outbound). A merely *shared user role* never confers relevance — this is what prevents a **false outbound edge** to a target (a tool or another agent) `A` does not actually target. This is a **derivation-layer** relevance rule: it does **not** imply the outbound user gate is empty. When the agent holds a per-skill operator role that the PRB maps (by capability-match) to a target's scope, the agent *does* target that callee, and the nested derivation then surfaces the shared-user edges.

### P2 / P5b reconciliation, and the agent-side rule

- **P2 (identity embed):** copy `owned_roles` / `owned_scopes` from `SPM(A)` onto the APM's `agent_roles` / `agent_scopes`. AIAC-managed filter applied at catalog-seed time. Without the embed the inbound gate would deny-all (inbound `subject_allow_ok` needs a non-empty `agent_scopes`), and outbound derivation would find no edges (it iterates `R_A`). The outbound Rego emits `agent_roles` for debugging only; its `allow` does not use it. Under target side, no embed is necessary: the writer reads the same identity (`owned_scopes`) from the SPM itself.
- **Agent side — only agents get an APM:** under agent side, derive an APM only for a live service whose catalog `Service.type == Agent` (the SPM's `service_type` is used only for a service that is absent from the catalog). A managed tool keeps its SPM (durable `inbound_allow_rules` / `inbound_deny_rules`) but gets no APM. It gets a pass-through CR instead (its clientId in `pass_through`, D24). Under target side, the PCE derives no APM: every managed service, agent or tool, gets a CR rendered from its stored SPM. So every managed service has a CR under both sides (D20).
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

SPM edges key on Keycloak role/scope UUIDs, which **churn on delete/recreate**. Because append-dedup keys on `role.id + scope.id + effect`, a re-onboarded service whose Keycloak roles/scopes were recreated presents *new* UUIDs, so its edges are treated as new and pile up **beside** the superseded generations — nothing removes the old ones. (`override=True` does not close this: it purges by the *input* role's id, so a role whose UUID already churned out of the batch is never matched.) A live diagnostic once found a single agent SPM carrying 53 inbound edges across two role-id generations, retired `*-aud` scopes, an impossible self-reference, and duplicate same-name roles — all replayed into every regenerated APM/Rego.

**Reconcile** closes this. After routing (step 2) and any override purge (step 3), and **before** persist (step 4), each **touched** SPM is pruned against the step-1 catalog. It **reuses that same `get_services()` result** — no additional IdP read, so the *only-runtime-IdP-read-is-`get_services()`* invariant holds. It runs under **both** merge modes and is **order-independent** — it removes *only* edges whose entity genuinely no longer exists, never a live edge, so both onboarding orders still converge. "Touched SPMs only": at that point the SPM cache holds exactly the routed + override-purged SPMs (agent-derive SPMs aren't loaded yet).

The prune runs over **both** `inbound_allow_rules` and `inbound_deny_rules` — the keep rules below are applied per edge in each list identically (a dangling deny edge is GC'd exactly as a dangling allow edge). For each touched `SPM(X)` whose owner `X` **is present in the catalog** (a catalog **miss ⇒ skip pruning**, never wipe on a transient outage), an inbound edge is kept iff:

1. **Scope still exists** — `edge.scope.id ∈ {s.id for s in owned_scopes}` (X's current `aiac.managed` scopes, seeded from the catalog). Drops retired/churned scopes (kills the `*-aud` species and scope-model cruft).
2. **Agent role still exists** — for `role.kind == Agent`, `edge.role.id ∈` the catalog's `aiac.managed` role ids (all services). Drops retired/churned agent client roles (kills self-references and agent-role UUID churn).
3. **User-role churn collapse** — user realm roles are membership-derived, absent from the catalog, and the PCE must not read `get_subjects()`; so among surviving `User` edges grouped by `(scope.id, role.name)`, a stale edge is dropped only when **this batch** carries a *different* id for that same `(scope, name)` (the fresh id supersedes the old generation). Two *co-existing* same-name realm roles both currently held are both kept (realm hygiene, not accumulation — out of scope).

#### Decommission (service offboard)

Reconcile is passive and catalog-anchored: it prunes only **touched** SPMs and skips any whose owner is absent from `get_services()`. That leaves the **onboard→offboard** drift species uncovered — once a service `X` is decommissioned (its Keycloak client + roles/scopes deleted), `X` is gone from the catalog forever, so (1) `SPM(X)`'s own inbound edges linger; (2) `X`'s **outbound footprint** (`X_role → other_scope` edges on *other* SPMs) is never pruned; (3) `X`'s **CR stays in the PDP**. `decommission(service_id)` is the **authoritative** teardown for exactly this — it acts on an explicit offboard signal, not the catalog-miss guard.

**Keyed by the clientId, not the UUID.** An offboarded client is gone from `get_services()`, so UUID→clientId resolution is impossible; the offboard contract carries the clientId (`Service.serviceId`, the SPM key) directly. The asymmetry with onboard's `/apply/service/{uuid}` is only at the boundary: the PCE takes the clientId in both cases (see [Public API](#public-api)).

Steps:

1. **Catalog once** (`get_services()` — the same single allowed IdP read; `X` is absent, used only to seed/classify the still-live services redeployed in step 8).
2. **Load `SPM(X)`.** **Content guard:** a 404 fresh-empty SPM (never onboarded / already removed) is a **no-op** — no spurious PDP delete.
3. **Targeters** (agent side) — agents whose *outbound* loses `X`: the `actorIds` of every **Agent**-kind inbound edge on `SPM(X)`, scanning **both** `inbound_allow_rules` and `inbound_deny_rules` (they held `their_role → X_scope` on `SPM(X)`, deleted in step 5). Under target side a targeter's CR does not change: its outbound is a pass-through.
4. **Purge `X`'s outbound footprint.** For each `r ∈ SPM(X).owned_roles` that no other catalog service holds, find the SPMs referencing it via `get_service_policies_by_role(r)`; on each such SPM `B` (skip `X`), drop edges where `edge.role.id == r.id` from **both** lists; mark `B` changed. Under target side, every changed `B` is affected (its CR is rendered from `SPM(B)`). Under agent side, `B` is affected if it is an agent (its inbound `source_roles[X]` vanished). **Shared role:** an `aiac.managed` realm role can be on the service accounts of several services (a role reused by name). The edges are keyed by `role.id`, so a purge of such a role would also remove the grants of the other services. The purge skips it. `X` stays denied: its CR is deleted (step 7), and the combiner denies a pod that has no client CR (D20). Also, an offboarded client cannot authenticate.
5. **Delete `SPM(X)`** (`delete_service_policy`) — removes every user→X and agent→X inbound edge at once — and evict it from the SPM cache so re-derive can't resurrect it. `X` leaves the managed set.
6. **Persist** each changed (footprint-purged) SPM (`apply_service_policy`).
7. **Delete the CR of `X`** (`delete_service_cr(X)`, D20), for an agent and for a tool. A 404 counts as success.
8. **Redeploy the affected services** of the current side (the policy-model stage, D23), `X` excluded, filtered to live services (in the catalog and not disabled — a stored SPM of a deleted service must not bring its CR back, and a quarantined service stays with no CR); one `apply_policy` call if the model is non-empty:
   - **target side:** `TargetSidePolicyModel(services=…)` with the footprint-purged SPMs;
   - **agent side:** `AgentSidePolicyModel(agents=…)` with the re-derived APMs of `(targeters ∪ purged-agent-owners) − {X}`. Derivation is reused unchanged — it reads the freshly-persisted, `X`-deleted store, so the outbound rule lists / `target_allow_scopes` / `target_deny_scopes` / `source_roles` referencing `X` drop automatically.

**Invariants preserved:** still exactly one IdP read (`get_services()`); still a per-service partial upsert. **Not covered** (follow-ups): NATS `aiac.apply.offboard.{id}` consumer wiring; dropped-target GC where the source service survives (via `override=True` re-onboard); batch offboard.

#### Quarantine (failed onboarding)

`quarantine(service_id, deleted_roles)` is the UC1 failure-path counterpart of `decommission`. The UC1 Orchestrator calls it after the compensating rollback and before it re-raises the build error (see [`aiac-agent/uc1-service-onboarding.md` → Failure & Rollback](aiac-agent/uc1-service-onboarding.md#failure--rollback)). The Orchestrator never calls the PDP library itself. The PCE owns the PDP.

**Keyed by the clientId, not the UUID.** Like `decommission`, `quarantine` takes the clientId (the SPM key). The UC1 Orchestrator resolves it from the onboarding's UUID once, before Provision. The rollback disables the client. It does not delete it. So the failed service `X` is still in the catalog.

Steps (under the PCE lock):

1. **Catalog once** (`get_services()`). A `service_id` that is not a catalog key (for example a UUID passed by mistake) is a logged no-op.
2. **Targeters** (agent side) — the agents that targeted `X` (the `actorIds` of every Agent-kind inbound edge on `SPM(X)`, allow and deny).
3. **Remove `X`'s roles from the other SPMs** — the same purge as decommission step 4. `X`'s SPM is seeded from the catalog, so this removes the roles that `X` still has. The catalog does not list the roles that the rollback deleted, so the Orchestrator passes them in `deleted_roles` (the run's created-manifest), and this step removes their edges too. A role that another service also holds is skipped (see decommission step 4). Without this, a grant that a concurrent onboarding stored for a deleted role (for example `X_role → B_scope` on `SPM(B)`) would keep allowing `X` in `B`'s inbound policy until a later run [reconciles](#reconcile-drift-gc) `SPM(B)`.
4. **Delete `SPM(X)`** and persist each changed SPM. `X` leaves the managed set.
5. **Delete the CR of `X`** (`delete_service_cr(X)`, D20), for an agent and for a tool. In an AIAC setup the global combiner denies a pod that has no client CR, so the delete denies every request to and from `X` (see [`pdp-policy-writer-opa.md`](pdp-policy-writer-opa.md)). There is no no-rules CR. A 404 counts as success.
6. **Redeploy the affected live services** of the current side (`X` excluded) in one `apply_policy` call (the policy-model stage, D23). Under target side, these are the services whose SPMs lost `X`'s roles. Under agent side, these are the targeters and the agents whose SPMs lost `X`'s roles.

Steps 2–6 are the steps that `decommission` also runs (the shared helper `_remove_footprint`, the CR delete, and the policy-model stage). `quarantine` is idempotent: a second call finds no SPM and no edges, and deletes the CR again (a 404 counts as success). The delete takes effect at the next poll of the OPA plugin in the pod (10 s min, up to 120 s).

**The lift.** Only a successful re-onboarding lifts a quarantine. Its PRB rebuilds the rules, `compute_and_apply` (with `focus_service` = `X`) stores `SPM(X)` (also with zero rules, D21) and writes a new CR for `X` with the same SSA field manager (`aiac-pdp-policy-writer`), and then `reenable_service` re-enables the client. The UC2 rebuild route is a stub, so it does not lift a quarantine.

**Known limit (C5) — a quarantined tool cannot be lifted.** The re-onboarding of a disabled tool fails in Provision, before the build (see [`aiac-agent/uc1-service-onboarding.md` → Failure & Rollback](aiac-agent/uc1-service-onboarding.md#failure--rollback)). A failed onboarding precondition check (D30) does not quarantine and does not disable the client, so it does not cause this limit. The limit stays until handoff 14 (offboarding through Keycloak) is built.

#### Resync (Controller start)

`resync()` (D28) is the full redeploy of the current side. The Controller calls it at every start, after the start check of the combiner and before the NATS consumer starts (see [`aiac-agent.md`](aiac-agent.md)). It holds the PCE lock for its whole body, so onboardings wait on the lock.

Steps (under the PCE lock):

1. **Catalog once** (`get_services()`), and **list every stored SPM** (`list_service_policies()`, C3). The stored SPMs are the managed set.
2. **Replace every AIAC CR** with one `replace_policy(model)` call (`PUT /policy`). `model` is the full policy model of the current side, for the live services of the managed set (in the catalog and enabled):
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

#### Bootstrap CR (tool discovery)

`bootstrap(service_id, service_type)` writes the CR of the focus tool before its Provision. UC-1 discovery (`analyze_tool`) sends `tools/list` through the tool's own inbound OPA. At the first onboarding the tool has no CR, so without the bootstrap the changed combiner (D20) denies that call. The UC1 Orchestrator calls `bootstrap` for an enabled tool only: after the precondition checks, and before Provision. A disabled (quarantined) tool gets no bootstrap: its discovery fails at the token mint anyway (C5), and a bootstrap CR would then stay until the next resync (see [`aiac-agent/uc1-service-onboarding.md` → Tool discovery and the bootstrap CR](aiac-agent/uc1-service-onboarding.md#tool-discovery-and-the-bootstrap-cr)). An agent gets no bootstrap, because AIAC does not call an agent at onboarding.

Steps (under the PCE lock):

1. **Load `SPM(service_id)`** (`get_service_policy`). If the store has no SPM, use a zero-rule SPM with the given `service_type`. The type comes from the pod label (`rossoctl.io/type`), because the catalog type is not set before Provision.
2. **Write the CR** with one `apply_policy` call (`POST /policy`):
   - **target side:** `TargetSidePolicyModel(services=[that SPM])`. The tool inbound then allows only the self-discovery rule (plus any stored rules), and the outbound is a pass-through (see [`pdp-policy-writer-opa.md` → Tool inbound package](pdp-policy-writer-opa.md#tool-inbound-package-target-side-authbridgeclientinboundrequest));
   - **agent side:** `AgentSidePolicyModel(agents=[], pass_through=[service_id])`, a pass-through CR.

`bootstrap` stores no SPM, so the tool does not join the managed set. The bootstrap CR then has one of these ends:

- A successful onboarding stores the SPM of the tool (D21) and writes its CR again.
- A build failure runs the [quarantine](#quarantine-failed-onboarding), which deletes the CR.
- If the onboarding stops in a different way (for example, a retryable failure in Provision), the CR stays until the next onboarding of the tool, or until the [resync](#resync-controller-start): the tool has no SPM, so the `PUT` deletes its CR.

The CR takes effect at the next poll of the OPA plugin of the tool (10 s min, up to 120 s). So discovery waits for it: it treats a `403` from the tool as not ready and polls again, until `AIAC_MCP_DISCOVERY_READY_TIMEOUT` ends (default 180 s).

#### Read model (`policy_model_for`)

`policy_model_for(service_id)` (D18) returns the policy model of the current side with only the entry of that service. It is for tests and debugging. The Controller serves it on the read-only route `GET /policy/services/{service_id:path}` (200 with the policy model JSON, or 404).

- **target side:** `TargetSidePolicyModel(services=[SPM(service_id)])`;
- **agent side:** `AgentSidePolicyModel(agents=[APM(service_id)])` for an agent (derived from the store, as at a deploy), else `AgentSidePolicyModel(agents=[], pass_through=[service_id])` for a tool.

It returns `None` when the store has no SPM for the service (the route then gives 404). It takes no lock and writes nothing. It shows what the PCE deploys for the service from the current store. It does not read the CR in the cluster, which can be stale (D23).

#### Routing guard (disabled services)

A disabled client is a failed (quarantined) service. Under the PCE lock, after the catalog read, `compute_and_apply` drops every rule that:

- has a scope whose owner (`scope.serviceId`) is disabled, or
- has an Agent-kind role that belongs to a disabled service (`role.actorIds`).

The focus service is the exception. A re-onboarding applies while its client is still disabled, because `reenable_service` runs after the apply. So the rules of the focus service are kept. Without a `focus_service`, the guard drops every rule that touches a disabled service.

**Deleted services.** A service that is absent from the catalog is deleted (its client was removed, for example offboarded while its onboarding was still building). The guard also drops every rule whose scope owner, or the owner of whose Agent-kind role, is absent from the catalog. There is no focus exception for this case. The run also deploys only live services — in the catalog and not disabled (except the focus service). A disabled service stays with no CR (the quarantine deleted it). A service must be in the catalog because the store returns a placeholder SPM typed `Agent` on a 404, so without this check a late onboarding of a deleted tool wrote a CR for it, and a run that touched the stored SPM of a deleted service wrote its CR again. Removing a deleted service's footprint is `decommission`'s job.

The guard prevents a build that started before a quarantine or an offboard from writing its rules back into the removed footprint. The focal resolver applies the disabled-service rule on the build side (see [`aiac-agent/uc1-service-onboarding.md` → Service Policy Builder](aiac-agent/uc1-service-onboarding.md#sub-agent-service-policy-builder)).

**Known limit (C2) — a client that is disabled by hand.** The quarantine runs only after a failed onboarding. A client that an operator disables by hand keeps its SPM and its CR. The routing guard drops every new rule that touches it, so it gets no new rules. Its CR stays until the [resync](#resync-controller-start) at the next Controller start quarantines it.

### Serialization (the PCE lock)

Each public operation reads SPMs, changes them, and writes them back (a read-modify-write). The store has no versions, and its write lock protects one write, not a read-modify-write. Thus two onboardings that route rules into one shared SPM (for example, two agents granted on one tool's scope) both read the old SPM, and the second write removes the rules of the first run.

One module-level `threading.Lock` (`_pce_lock`) is held for the whole body of `compute_and_apply`, `decommission`, `quarantine`, `resync` and `bootstrap` (D22). The resync at the Controller start therefore finishes before an onboarding can apply. The read model `policy_model_for` takes no lock. The PRB (the LLM work) runs before `compute_and_apply`, outside the lock. So concurrent onboardings still do their LLM work in parallel. The part under the lock makes no LLM call.

Known limits:

- **One Controller replica only.** The lock serializes one process, like the Orchestrator's per-service lock. More replicas need store versions or a distributed lock.
- **Overlapping onboardings can leave a pair unjudged.** When two onboardings overlap, the resolver of each service reads the catalog before the Provision of the other service. So a pair between the two new services can stay unjudged. That pair gives no grant (fail closed).

### Dependencies

| Module | Purpose |
|--------|---------|
| `aiac.policy.model` | `PolicyRule`, `RuleEffect`, `ServicePolicyModel`, `AgentPolicyModel`, `EnforcementSide`, `PolicyModel`, `TargetSidePolicyModel`, `AgentSidePolicyModel`; `project_inbound` (`aiac.policy.model.projection`, the APM inbound) |
| `aiac.idp.configuration` | `Configuration.get_services` — the **only** runtime IdP read (catalog: `service_type` + own roles/scopes for the P2 seed) |
| `aiac.policy.model_store.library` | `get_service_policy` (fetch SPM; also the bootstrap), `get_service_policies_by_role` (SPMs containing a role — override purge + outbound derivation), `list_service_policies` (every SPM — the resync), `apply_service_policy` (persist SPM), `delete_service_policy` (offboard, quarantine) |
| `aiac.pdp.policy.library` | `apply_policy` — partial-upsert the policy model of the affected services (each run, and the redeploy in `quarantine` / `decommission`), and the CR of the focus tool (`bootstrap`); `replace_policy` — replace every AIAC CR (the resync); `delete_service_cr` — delete the CR of one service (`quarantine`, `decommission`). The PCE never calls `delete_policy`. |
| Env | `AIAC_ENFORCEMENT_SIDE` — `target-side` (default) or `agent-side`; read by `enforcement_side()` |

Note: the PCE no longer calls `get_services_by_role` / `get_services_by_scope` / `get_subjects_by_role` at routing or classification time — those facts arrive on the rules (input contract) and derivation reads SPMs. The single IdP read is `get_services()` for the identity seed.

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

- `aiac.idp.configuration` — mock `Configuration.get_services` (the catalog: `service_type` + each service's own roles/scopes for the P2 seed).
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
- **Affected set from the batch, not a full scan.** Under target side the affected set is the `changed` set. Under agent side the affected-agent set is computed from the batch roles/scopes. Services unrelated to the batch are never derived or upserted.
- **`apply_policy` called exactly once** after all `apply_service_policy` writes complete (partial upsert of only the affected services, with the policy model of the current side), and not called when the model is empty.
- **Reconcile (drift GC).** A touched SPM carrying dangling edges (retired scope, churned scope UUID, churned/duplicate user role, retired agent-role self-reference) is pruned against the catalog on re-onboarding; live edges survive and the pass is idempotent; a catalog miss (owner absent) leaves the SPM untouched.
- **Decommission (service offboard).** Onboard an agent A targeting tool T, then `decommission(T)`: `SPM(T)` is deleted and `delete_service_cr(T)` is called. Under agent side, A is re-derived with an empty outbound while its inbound survives. Under target side, A's CR is not redeployed (its SPM did not change). `decommission(A)`: `SPM(A)` deleted, `delete_service_cr(A)` called, A's outbound footprint (`AR→TS` on `SPM(T)`) purged while T keeps its user grant, and no entry for the deleted agent in the policy model. Under target side, the purged `SPM(T)` is redeployed. A never-onboarded / 404 service is a no-op (no `delete_service_cr` call).
- **Effect routing.** A `Deny` rule routes to `SPM(scope.serviceId).inbound_deny_rules`; an `Allow` rule to `inbound_allow_rules`. Append-dedup keys on `role.id + scope.id + effect`, so the same `(role, scope)` can be present once in each list.
- **Effect-aware derivation.** A subject DENY edge on `SPM(A)` derives into `inbound_subject_deny_rules`, and its role still appears in the effect-agnostic `subject_roles`; an agent-role → target-scope DENY edge derives into `outbound_target_deny_rules` + `target_deny_scopes[target]`.
- **Override purges both lists.** `override=True` with an input role present in a target SPM's allow **and** deny lists purges it from both before re-appending.
- **Reconcile prunes both lists.** A dangling deny edge (retired scope / churned role) is GC'd exactly as a dangling allow edge; a live deny edge survives; the pass is idempotent.
- **Decommission clears both lists.** Offboard tears down the target's own inbound (allow + deny) and its outbound footprint (allow + deny edges keyed by its roles on other SPMs).
- **PCE lock.** Two concurrent runs that route rules into one shared SPM keep the rules of both runs. `compute_and_apply`, `decommission`, `quarantine`, `resync` and `bootstrap` each hold the PCE lock.
- **Routing guard.** A rule whose scope owner is disabled, or whose agent role belongs to a disabled service, is dropped. The rules of the focus service are kept while it is disabled. Without a focus service, every rule that touches a disabled service is dropped. When all services are enabled, every rule is kept. Under override, a role whose every new rule the guard drops still loses its old grants.
- **Quarantine.** For an agent and for a tool: `SPM(X)` is deleted, its roles are removed from the other SPMs, `delete_service_cr(X)` is called (no no-rules CR is written), and the affected services of the current side are redeployed in one call (target side: the SPMs that lost X's roles; agent side: the targeters and the agents whose SPMs lost X's roles). A second call gives the same result. An unknown UUID is a no-op. `quarantine` and `decommission` keep the grants of a role that another service also holds, and never deploy a service that is absent from the catalog or disabled.
- **Resync (D28).** Under the PCE lock, `resync` calls `replace_policy` once with the full policy model of the current side: under target side, every live stored SPM; under agent side, the APMs of the live stored agent SPMs and `pass_through` = the live stored tool SPMs. A disabled service with an SPM is not in the model and is then quarantined (its SPM is deleted and `delete_service_cr` is called). A service absent from the catalog is not in the model, and its SPM stays. An empty store gives one `replace_policy` call with an empty model. A failure re-raises.
- **Bootstrap.** For a tool with no stored SPM, `bootstrap(id, Tool)` calls `apply_policy` once: under target side with a zero-rule SPM of type `Tool` (its CR then allows only the self-discovery rule); under agent side with `pass_through=[id]` and no agents. With a stored SPM, the target-side entry is the stored SPM. It calls no store write function, so the tool has no SPM after it.
- **Read model (D18).** `policy_model_for(id)` returns a target-side model with only `SPM(id)` under target side. Under agent side it returns the APM of an agent, or `pass_through=[id]` for a tool. It returns `None` when the store has no SPM for `id`. It takes no lock and calls no write function.
- **Failures propagate.** An exception from any dependency is logged and **re-raised** (it propagates to the caller, which surfaces it — e.g. the Controller returns HTTP 500, or stops at start for `resync`); on success `compute_and_apply` / `decommission` / `quarantine` / `resync` / `bootstrap` return `None`.

---

## Out of Scope

- **Fine-grained rule revocation:** removing an individual `PolicyRule` without replacing its whole role. `override=True` covers role-level replace at the SPM layer (see [Merge Semantics](#merge-semantics)); single-rule revocation is not yet designed — **TBD**. (Full-service **decommission / package deletion** *is* now designed and implemented — see [Decommission (service offboard)](#decommission-service-offboard).)
- **Full policy rebuild orchestration:** the PCE handles incremental updates; full rebuilds are driven by higher-level orchestration outside this module. The UC-2b rebuild reapplies every rule with `override=True`, and ends with `PUT /policy` (`replace_policy`, through the PCE, as the resync does) (D28a). It does not start with `DELETE /policy`, so there is no deny window under D20. **Status: not built yet** — UC2 Rebuild (`src/aiac/agent/uc/policy_update/rebuild.py`) is a stub that returns `([], True)`.
- **Direct Keycloak calls:** all IdP access goes through `aiac.idp.configuration.Configuration` (only `get_services()`). The PCE never calls Keycloak directly.
- **Persistence of `PolicyRule` inputs:** the PCE persists SPMs (source of truth); the policy model (and, under agent side, its APMs) is built and pushed, never persisted (D18). The raw input rule list is not stored.
- **Model field definitions** (handoff 01), **IdP service / library** (handoffs 02/03), **store CRUD** (handoff 04).

---

## Further Notes

- The PCE is the **only** caller of `aiac.pdp.policy.library` (`apply_policy`, `replace_policy`, `delete_service_cr`) from AIAC Agent sub-agents. Sub-agents call `compute_and_apply`, not the PDP Policy Library directly. No AIAC code calls `delete_policy` (C1).
