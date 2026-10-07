# PRD: AI-based Access Control (AIAC)

## Abstract

AI-based Access Control (AIAC) is a Rossoctl platform extension that automates RBAC/ABAC policy
enforcement for AI agents running on Kubernetes. A LangGraph-based AI agent continuously translates
a natural-language access control policy — stored in a vector knowledge base — into concrete
permission configurations in the active Policy Decision Point (PDP), eliminating manual policy
administration and preventing policy drift as services and roles evolve. The PDP backend is OPA,
which evaluates the Rego rules that AIAC renders from LLM-selected policy rules; Keycloak remains the identity provider for entity
management (subjects, roles, services).

AIAC writes one `AuthorizationPolicy` CR for each managed service, agent or tool. One global
switch selects the **enforcement side**, that is, where OPA checks the access to a callee. Under
**target side** (the default), each callee's own inbound OPA decides each call to it, from the
callee's own CR. Under **agent side** (the legacy method), each agent's outbound OPA checks the
agent's calls to tools, from the agent's CR.

---

## 1. Problem Description

Rossoctl AI agents call services across a shared platform. Every call must carry a token scoped to
exactly the permissions the caller's role entitles on the target service. Without a dedicated
policy management layer, access policy ends up scattered across per-deployment configuration,
creating three compounding problems:

1. **Policy drift** — new services and roles are onboarded without corresponding permission
   updates because there is no automated mechanism to apply them.
2. **Distributed policy intent** — no single authoritative source declares what roles may do;
   policy knowledge is fragmented across deployments.
3. **Manual administration overhead** — keeping OPA policy rules consistent with a growing fleet
   of agents and tools requires ongoing human attention with no audit trail.

---

## 2. Problem Solution

AIAC introduces a strict three-layer model that cleanly separates policy concerns: a **Policy
Management** layer (AIAC Agent) that translates natural-language policy into PDP configuration, a
**Policy Decision** layer (OPA) that evaluates caller entitlements, and a **Policy Enforcement**
layer (AuthBridge) that intercepts traffic and exchanges tokens but carries no policy knowledge of
its own.

The AIAC Agent subscribes to an event stream (NATS JetStream) and reacts to entity lifecycle
events — new services, role changes, policy updates — by retrieving the current policy from a RAG
knowledge base, reading the current policy state from the Policy Model Store, and applying the
minimal required diff via a dedicated PDP Policy Writer. **Policy intent lives entirely in the PDP,
not in per-pod configuration.**

The **enforcement side** selects which OPA decides a call. Under **target side** (the default),
each callee (agent or tool) checks the access to itself in the inbound OPA of its own AuthBridge
sidecar, from its own CR. Under **agent side**, each agent's outbound OPA checks the agent's calls
to tools, and each tool gets a pass-through CR. One global switch, `AIAC_ENFORCEMENT_SIDE`, selects
the side for every callee. The two sides never exist together.

**Status: not built yet** — the RAG knowledge base. The Agent reads the policy from the file
`AIAC_POLICY_FILE` (default `/etc/aiac/policy.md`).

---

## 3. Design Principles

### PDP/PEP separation

AIAC enforces a strict three-layer model:

| Layer | Component | Role |
|---|---|---|
| **Policy Management** | AIAC Agent | Translates natural-language policy into PDP configuration on every trigger |
| **Policy Decision (PDP)** | OPA | Evaluates the Rego rules that AIAC renders; decides what a caller may access |
| **Policy Enforcement (PEP)** | AuthBridge | Intercepts traffic; exchanges tokens; carries no policy knowledge |

The PEP (AuthBridge) is a pure enforcement layer. It performs RFC 8693 token exchanges sending only the target `audience` — no `scope` parameter. OPA evaluates the caller's role against the Rego rules and returns an allow/deny decision for the request (default deny; for each invoked MCP tool: in the tool's inbound under target side, in the calling agent's outbound under agent side); the IdP (Keycloak, via AuthBridge) issues the exchanged token for the target `audience`.

This means `token_scopes` is absent from `authproxy-routes`. Route configuration carries routing intent only (`host` → `target_audience`). Policy intent lives entirely in OPA, kept current by AIAC.

### Enforcement side

The enforcement side tells where OPA checks the access to a **callee** (a service that is called,
agent or tool). One global switch selects the side for every callee (D16). Target side is the
primary method, and agent side is the legacy method that AIAC still supports (D15). Every managed
service has a CR under both sides (D20).

| Side | Who checks a call to a tool | The CR of an agent | The CR of a tool |
|---|---|---|---|
| **target side** (default) | the tool's own inbound OPA | inbound: agent-level check (D26a); outbound: pass-through (D24) | inbound: per-tool check (D26); outbound: pass-through (D24) |
| **agent side** (legacy) | the calling agent's outbound OPA | inbound: agent-level check; outbound: per-tool checks | pass-through CR (both request packages) |

Detail: [components/pdp-policy-writer-opa.md](components/pdp-policy-writer-opa.md).

---

## 4. Major Use-Cases

Note: the code numbers the use cases differently — UC3 is Role Update (`uc/role_update/`) and UC4 is Service Offboarding (`uc/offboarding/`).

### UC-1 · Continuous Access Reconciliation (On-boarding / Off-boarding)

**Trigger:** A Role or Keycloak Client is created, updated, or removed.

The Keycloak SPI listener publishes a scoped event to the Event Broker. The AIAC Agent retrieves
relevant context from the RAG store, reads the current policy state from the Policy Model Store,
and asks the LLM to compute the minimal permission diff scoped to the affected entity. The diff is
validated by a second LLM pass and applied to OPA as updated Rego rules. Supports both
**auto-apply** (fully automated, least-privilege) and **recommendation + human review** modes.

**Status: not built yet** — the recommendation + human review mode, and the event trigger for a
removal. Offboard is HTTP-only (`POST /apply/offboard/{service_id}`). Role removal is not handled.
Role Update is a stub. The policy comes from `AIAC_POLICY_FILE`, not from the RAG store.

### UC-2 · Policy Update Reconciliation

**Trigger:** An operator ingests updated documents into the RAG store.

After ingestion the RAG Ingest Service publishes a build event. The AIAC Agent retrieves all
relevant context, computes a full policy diff against the current policy state in the Policy Model
Store, and applies the delta.
A `rebuild` variant (operator-only, direct HTTP) recomputes from scratch — used when policy
changes are too broad for incremental diff. It ends with one `PUT /policy`, which replaces every
AIAC CR (D28a). It does not clear the OPA policy first, because a pod that has no CR is denied (D20).

**Status: not built yet** — the Build and Rebuild sub-agents are stubs that return no rules.
Rebuild clears nothing. The RAG Ingest Service is not built.

### UC-3 · Entitlements Review

**Trigger:** Operator request (on-demand or scheduled).

The agent evaluates all current OPA policy rules — including manually added ones that AIAC did not
create — against the natural-language policy. It reports compliant, non-compliant, and
policy-agnostic entitlements, enabling audit and remediation workflows.

**Status: not built yet** — no code for the entitlements review.

### UC-4 · Access Request

**Trigger:** User request via chatbot.

A user requests an entitlement grant. The agent verifies the request against the policy
(permissive approach) and either auto-grants or routes to a human approver (man-in-the-loop).
Manually granted entitlements are flagged as policy-agnostic and surfaced during UC-3 reviews.

**Status: not built yet** — no code for the access request.

---

## 5. Architecture Overview

Nine components across five Kubernetes Pods plus a Python library layer, all implemented in Python (≥ 3.12; the images run 3.13). External dependencies: Keycloak Admin API, an LLM API, and an embedding API. The Keycloak SPI listener (Java) lives in `keycloak-spi/` in this repo (see `keycloak-spi/README.md`).

### Component Summary

| # | Component | Description |
|---|-----------|-------------|
| 1 | **IdP Configuration Service** | REST service that exposes IdP entity data (subjects, roles, services, scopes) for read and write operations. Read methods enrich services with assigned roles/scopes and enrich roles with child roles. Backed by Keycloak. Python library: `aiac.idp.configuration`. |
| 2 | **PDP Policy Writer** | REST service that renders Rego from a policy model and writes it to the OPA backend. Writes the two Rego request packages to one `AuthorizationPolicy` Kubernetes CR per managed service, agent or tool (D20). Reads the enforcement side from the policy-model tag. Routes (D18c): `POST /policy` (upsert), `PUT /policy` (replace), `DELETE /policy/services/{service_id:path}`, `DELETE /policy`, `GET /health`. Exposed as ClusterIP service `aiac-pdp-policy-service:7072`. Python library: `aiac.pdp.policy.library`. |
| 3 | **Policy Model Store** | REST service that owns an in-memory cache of `ServicePolicyModel` (SPM) rows, keyed by `service_id`, backed by SQLite as the authoritative structured policy store. Enables the Policy Computation Engine to read current SPM state for additive merging. `GET /policy/services` with no `role` returns every SPM (library: `list_service_policies()`), for the resync (C3). Deployed as a dedicated single-replica StatefulSet (`aiac-policy-model-store`) at `:7074`. Python library: `aiac.policy.model_store.library`. |
| 4 | **Policy Computation Engine** | Pure Python library module (`aiac.policy.computation`). No service, no Kubernetes deployment. Receives `list[PolicyRule]` from the AIAC Agent Controller. Routes each rule to the SPM of the service that owns its scope (`scope.serviceId`). The IdP reads are `get_services()` and `get_roles()`: the PCE renders the current role holders, not the `actorIds` copy in a stored edge (D32). Additively merges the rules into the `ServicePolicyModel`s in the Policy Model Store. Then the policy-model stage (D23) builds the policy model of the current side for the affected services and pushes it to the PDP Policy Writer. Under target side, this is the changed SPMs. Under agent side, this is the APMs of the affected agents (derived from the SPMs) and the pass-through IDs. The **managed set** is the services that have a stored SPM (D21). Entry points: `compute_and_apply(rules, override, focus_service)`, `decommission(service_id)`, `quarantine(service_id, deleted_roles)`, `resync()` (D28), `bootstrap(service_id, service_type)` (the CR of a tool before its Provision), `rerender_role(role_id)` (a role-mapping event: a new render with no PRB run, D32), `policy_model_for(service_id)` (read-only, D18). |
| 5 | **Policy and Domain Knowledge RAG** | ChromaDB vector store holding the access control policy and domain knowledge in persistent, queryable form, populated via a co-located RAG Ingest Service. **Status: not built yet** — no ChromaDB or RAG Ingest Service code or manifest. |
| 6 | **Policy Guardrails Agent** | Verification gate co-located with ChromaDB and the RAG Ingest Service in the RAG Pod. Every document is checked before the RAG Ingest Service writes it to ChromaDB. Reachable only on the RAG Pod's loopback network — not exposed on the RAG Pod's ClusterIP Service. One service, two API families (`policy`, `domain-knowledge`); the `policy` family runs LLM-backed hygiene + corpus-contradiction checks (defined), `domain-knowledge` specced later. **Status: not built yet** — no code or manifest. |
| 7 | **Event Broker** | NATS JetStream pod that decouples event producers (Keycloak SPI listener, RAG Ingest Service) from the AIAC Agent. Provides durable, at-least-once delivery with automatic replay on Agent pod restart. Competing consumer model ensures each event is processed exactly once. |
| 8 | **AIAC Agent** | LangGraph-based AI agent triggered by Event Broker subscriptions (`aiac.apply.>` subjects) and directly by the operator (`rebuild` and `offboard` only). Retrieves the current policy from the RAG store (not built yet: the policy comes from `AIAC_POLICY_FILE`), interprets it against the current policy state in the Policy Model Store, and applies the required policy changes immediately. A genuine grant/prohibit conflict aborts the apply and is returned as a `422` `ConflictReport`. An onboarding runs the precondition checks first; a failed check gives `409` (D30). At each start, the Controller runs the start check and the resync before it serves (D28, D30). A role-mapping event (`aiac.apply.role-members.{role-id}`, or the route `POST /apply/role-members/{role_id}`) makes the Controller call the PCE `rerender_role`: the CRs that use the role get the current holders, with no PRB run (D32). |
| 9 | **Python library** | Python API library provides typed access to IdP and policy services via `aiac.idp.configuration`, `aiac.policy.model`, `aiac.policy.model_store.library`, `aiac.pdp.policy.library`, and `aiac.policy.computation` modules backed by generic Pydantic models. |

### High-level architecture

```
        (𝗞𝗲𝘆𝗰𝗹𝗼𝗮𝗸 𝗔𝗣𝗜)       (𝗞𝘂𝗯𝗲𝗿𝗻𝗲𝘁𝗲𝘀 𝗖𝗥 𝗔𝗣𝗜)
               ▲                      ▲
               │                      |
    (𝘶𝘴𝘦𝘳𝘴, 𝘳𝘰𝘭𝘦𝘴, 𝘤𝘭𝘪𝘦𝘯𝘵𝘴)    (𝘈𝘶𝘵𝘩𝘰𝘳𝘪𝘻𝘢𝘵𝘪𝘰𝘯𝘗𝘰𝘭𝘪𝘤𝘺 𝘊𝘙)
┌──────────────┼──────────────────────┼───────────────────┐
│  Rossoctl Interface Pod             │                   │
│              │                      │                   │
│      ┌───────┴──────┐      ┌────────┴───────┐           │
│      │  IdP Config  │      │  PDP Policy    │           │
│      │  Service     │      │  Writer (OPA)  │           │
│      └──────────────┘      └────────────────┘           │
│              ▲                      ▲                   │
└──────────────┼──────────────────────┼───────────────────┘
               │                      │
             ┌─┼──────────────────────┘
             │ │
             │ │   ┌──────────────────────────────────────┐
             │ │   │  Policy Model Store Pod              │
             │ │   │                                      │
             │ │   │  ┌───────────────────────────────┐   │
             │ │   │  │  Policy Model Store Service   │   │
             │ │   │  │                               │   │
             │ │   │  │     (SQLite policy.db)        │   │
             │ │   │  └───────────────────────────────┘   │
             │ │   │                  ▲                   │
             │ │   └──────────────────┼───────────────────┘
             │ │                      │
┌────────────┼─┼──────────────────────┼───────────────────┐  ┌────────────────────────────────┐
│  Agent Pod │ └───────────────────┐  │                   │  │  Event Broker Pod              │
│            │                     │  │                   │  │                                │
│  ┌─────────┴────────────┐   ┌────────────────┐          │  │  ┌──────────────────────────┐  │
│  │ Policy Compute Engn  │◄──│   AIAC Agent   │◄─────────┼──┼──│      NATS JetStream      │  │
│  └──────────────────────┘   └────────────────┘  (𝘯𝘰𝘵𝘪𝘧𝘺) │  │  └──────────────────────────┘  │
│                                     │                   │  │         ▲              ▲       │
│                                     │                   │  │         │              │       │
└─────────────────────────────────────┼───────────────────┘  └─────────┼──────────────┼───────┘
                                      │                            (𝘱𝘶𝘣𝘭𝘪𝘴𝘩)        (𝘱𝘶𝘣𝘭𝘪𝘴𝘩)
┌─────────────────────────────────────┼───────────────────┐            │              │
│  Policy / Domain Knowledge RAG Pod  │                   │       (𝗞𝗲𝘆𝗰𝗹𝗼𝗮𝗸 𝗦𝗣𝗜)  (𝗥𝗔𝗚 𝗜𝗻𝗴𝗲𝘀𝘁)
│                                     ▼                   │
│  ┌─────────────────────┐   ┌─────────────────────────┐  │
│  │ RAG Ingest Service  │──►│ ChromaDB (vector store) │  │
│  └──────────┬──────────┘   └─────────────────────────┘  │
│             │ (verify)                   ▲ (context)    │
│             ▼                            │              │
│  ┌─────────────────────────┐             │              │
│  │ Policy Guardrails Agent │─────────────┘              │
│  └─────────────────────────┘                            │
└─────────────────────────────────────────────────────────┘
```

All inter-pod traffic is Kubernetes ClusterIP. External access is exclusively via
`kubectl port-forward` (operator/developer) or NATS publish (Keycloak SPI, RAG Ingest).

### Call Flows

**Status: not built yet** — the ChromaDB steps in the flows below. The Agent reads the policy from
`AIAC_POLICY_FILE` (default `/etc/aiac/policy.md`).

#### UC-1a · Service On-boarding (`aiac.apply.service.{id}`)

```
 Keycloak SPI
      │  CLIENT_CREATED
      │ 1. after the Keycloak commit (D33): publish aiac.apply.service.{id}
      ▼
 NATS JetStream
      │  (durable consumer, at-least-once delivery)
      │ 2. deliver event
      ▼
 AIAC Agent
      │ 3. get_service(id) ──► IdP Configuration Service ──► Keycloak Admin REST (a 404 is read again for a bounded time, D33)
      │    then the precondition checks (D30): sidecar #1, namespace pipeline #2, probes #6 ──► Kubernetes API (pod, authbridge-runtime-config)
      │    then, for a tool only: bootstrap(client_id, Tool) ──► Policy Computation Engine ──► PDP Policy Writer
      │    (it writes the tool's CR before Provision, so that discovery through the tool's inbound passes D20)
      │    then Provision: create the roles/scopes, link_subject_scope (D31), set_service_type ──► IdP Configuration Service ──► Keycloak Admin REST
      │ 4. GET /services, /roles, /scopes, /subjects, /subjects/{id}/assignments ──► IdP Configuration Service ──► Keycloak Admin REST
      │ 5. GET /services/{id}/roles, /services/{id}/scopes ──► IdP Configuration Service ──► Keycloak Admin REST
      │ 6. semantic query (policy + domain knowledge)      ──► ChromaDB
      │ 7. [LLM] compute list[PolicyRule] for new service (inbound + outbound rules)
      │ 8. [LLM] validate policy rules against retrieved policy (second pass)
      │ 9. compute_and_apply(rules, focus_service)  ──► Policy Computation Engine
      │         ├── get_services, get_roles (D32)                ──► IdP Configuration Service
      │         ├── get_service_policy / get_service_policies_by_role / apply_service_policy ──► Policy Model Store
      │         │     (the focus SPM is stored also when it has zero rules, D21)
      │         ├── build the policy model of the current side for the affected services (D23)
      │         └── apply_policy(policy model)                   ──► PDP Policy Writer ──► AuthorizationPolicy CRs (one per affected service)
      │ 10. on success: re-enable the client                     ──► IdP Configuration Service
      │     on a 404 after the wait (step 3): raise ServiceNotVisibleError (502). Nothing has changed yet.
      │     The consumer naks it with a delay (D33); the HTTP route gives 502.
      │     on a failed check (step 3): raise the error. Nothing has changed yet: no rollback, no disable, no quarantine.
      │     A failed check is permanent: the consumer sends it to the DLQ at the first delivery (the HTTP route gives 409).
      │     on a build failure (steps 7-8; step 9 does not run): delete the roles/scopes this run created, disable the
      │     client, quarantine(client_id) ──► Policy Computation Engine (it deletes the service's CR), then raise the error.
      │ 11. ACK message
      ▼
 NATS JetStream  (message removed from pending)
```

Under target side the checks run for every service. Under agent side they run for agents only,
and #2 also needs `opa` in the outbound pipeline. Detail:
[components/aiac-agent/uc1-service-onboarding.md](components/aiac-agent/uc1-service-onboarding.md).

Each role that Provision maps to the service account of an agent gives a realm role-mapping event,
so the SPI also publishes `aiac.apply.role-members.{role-id}` (D32, see the flow below). For a new
role, this event changes nothing. For a reused (shared) role, it renders again the CRs that use the
role, so the new holder gets the grants of the role at once.

#### UC-1b · Role On-boarding (`aiac.apply.role.{name}`)

**Status: not built yet** — the Role sub-agent is a stub that returns no rules.

```
 Keycloak SPI
      │  REALM_ROLE_CREATED / REALM_ROLE_UPDATED
      │ 1. publish aiac.apply.role.{name}
      ▼
 NATS JetStream
      │ 2. deliver event
      ▼
 AIAC Agent
      │ 3. GET /roles, /services, /scopes, /subjects, /subjects/{id}/assignments ──► IdP Configuration Service ──► Keycloak Admin REST
      │ 4. semantic query (policy + domain knowledge) ──► ChromaDB
      │ 5. [LLM] compute list[PolicyRule] delta for all services affected by the role change
      │ 6. [LLM] validate policy rules against retrieved policy (second pass)
      │ 7. compute_and_apply(rules)  ──► Policy Computation Engine
      │         ├── get_services, get_roles (D32)                ──► IdP Configuration Service
      │         ├── get_service_policy / get_service_policies_by_role / apply_service_policy ──► Policy Model Store
      │         ├── build the policy model of the current side for the affected services (D23)
      │         └── apply_policy(policy model)                   ──► PDP Policy Writer ──► AuthorizationPolicy CRs (one per affected service)
      │ 8. ACK message
      ▼
 NATS JetStream  (message removed from pending)
```

#### Role members · a new render (`aiac.apply.role-members.{role-id}`)

A user or an agent service account gets or loses a realm role. This changes who holds the role, not
the policy, so there is no PRB run and no SPM write (D32).

```
 Keycloak SPI
      │  REALM_ROLE_MAPPING CREATE / DELETE  (users/{user-id}/role-mappings/realm)
      │ 1. after the Keycloak commit (D33): publish aiac.apply.role-members.{role-id},
      │    one for each role in the event representation
      ▼
 NATS JetStream
      │ 2. deliver event
      ▼
 AIAC Agent (NATS consumer)
      │ 3. rerender_role(role_id)  ──► Policy Computation Engine (holds _pce_lock; no PRB run, no SPM write)
      │         ├── get_services, get_roles (D32)                ──► IdP Configuration Service
      │         ├── get_service_policies_by_role                 ──► Policy Model Store
      │         ├── build the policy model of the current side with the current holders
      │         └── apply_policy(policy model)                   ──► PDP Policy Writer ──► AuthorizationPolicy CRs (the CRs that use the role)
      │ 4. ACK message
      ▼
 NATS JetStream  (message removed from pending)
```

Under target side, the PCE writes the live SPMs that `get_service_policies_by_role` gives, and it
makes no call when there is none. Under agent side (legacy), it derives again the APM of every live
stored agent, in one `apply_policy` call, because an agent that lost the role is not in the current
holders. The operator route `POST /apply/role-members/{role_id}` calls the same `rerender_role`.
The SPI publish is at most once (D33). The resync at the next Controller start repairs a lost event
(D28). Detail:
[components/policy-computation-engine.md](components/policy-computation-engine.md) and
[components/event-broker.md](components/event-broker.md).

#### UC-2a · Incremental Policy Update (`aiac.apply.policy.build`)

**Status: not built yet** — the Build sub-agent is a stub that returns no rules. The RAG Ingest
Service and the Policy Guardrails Agent are not built.

```
 Operator
      │ 1. POST /ingest/policy/{text|file|url}
      ▼
 RAG Ingest Service
      │ 2. verify document (pre-flight, all-or-nothing) ──► Policy Guardrails Agent
      │ 3. upsert documents ──► ChromaDB
      │ 4. publish aiac.apply.policy.build
      ▼
 NATS JetStream
      │ 5. deliver event
      ▼
 AIAC Agent
      │ 6. GET /roles, /services, /scopes, /subjects, /subjects/{id}/assignments ──► IdP Configuration Service ──► Keycloak Admin REST
      │ 7. retrieve full policy context        ──► ChromaDB
      │ 8. [LLM] compute list[PolicyRule] delta against the current policy state (Policy Model Store)
      │ 9. compute_and_apply(rules)  ──► Policy Computation Engine
      │         ├── get_services, get_roles (D32)                ──► IdP Configuration Service
      │         ├── get_service_policy / get_service_policies_by_role / apply_service_policy ──► Policy Model Store
      │         ├── build the policy model of the current side for the affected services (D23)
      │         └── apply_policy(policy model)                   ──► PDP Policy Writer ──► AuthorizationPolicy CRs (one per affected service)
      │ 10. ACK message
      ▼
 NATS JetStream  (message removed from pending)
```

#### UC-2b · Full Rebuild (`POST /apply/policy/rebuild`, operator-only)

**Status: not built yet** — the Rebuild sub-agent is a stub that returns no rules. Steps 2 and 7
do not occur: no code calls them.

The rebuild does not start with `DELETE /policy`. Under D20 that delete would deny every managed
pod until the new CRs exist. The rebuild ends with `PUT /policy` instead (D28a).

Open issue (out of scope for handoff 12): a store clear before the `PUT /policy` removes the CR of every
service that the rebuild gives no rules. See [components/aiac-agent/uc2-policy-update.md](components/aiac-agent/uc2-policy-update.md).

```
 Operator
      │ 1. POST /apply/policy/rebuild  (kubectl port-forward → Agent pod)
      ▼
 AIAC Agent
      │ 2. DELETE /policy/services      (clear Policy Model Store)         ──► Policy Model Store
      │ 3. GET /roles, /services        (read fresh entity state)    ──► IdP Configuration Service ──► Keycloak Admin REST
      │ 4. retrieve full policy context                              ──► ChromaDB
      │ 5. [LLM] compute complete list[PolicyRule] from scratch
      │ 6. compute_and_apply(rules)  ──► Policy Computation Engine
      │         ├── get_services, get_roles (D32)                ──► IdP Configuration Service
      │         ├── get_service_policy / get_service_policies_by_role / apply_service_policy ──► Policy Model Store
      │         ├── build the policy model of the current side for the affected services (D23)
      │         └── apply_policy(policy model)                   ──► PDP Policy Writer ──► AuthorizationPolicy CRs (one per affected service)
      │ 7. replace_policy(full policy model of the current side), through the PCE
      │         └── PUT /policy                                  ──► PDP Policy Writer ──► AuthorizationPolicy CRs (every managed
      │                                                               service; every other AIAC CR is deleted)
      ▼
 (synchronous HTTP response to operator)
```

### Component dependencies

| Component | Called by | Calls | Returns |
|-----------|-----------|-------|---------|
| IdP Configuration Service (in Rossoctl Interface Pod) | `aiac.idp.configuration.api` | Keycloak Admin REST API | Raw Keycloak JSON (generic endpoint names) |
| PDP Policy Writer — OPA (in Rossoctl Interface Pod) | `aiac.pdp.policy.library` | Kubernetes CRs (`AuthorizationPolicy`, one per managed service) | 204 on success |
| Policy Model Store (StatefulSet `aiac-policy-model-store`) | `aiac.policy.model_store.library` | SQLite (`service_policies` table, in-memory cache) | `ServicePolicyModel` (or a list: by role, or every SPM when there is no `role`) on read; 204 on write |
| Policy Computation Engine (`aiac.policy.computation`) | AIAC Agent Controller (HTTP routes, NATS consumer, the resync at start); UC-1 Orchestrator (`bootstrap`, `quarantine`) | `aiac.idp.configuration.api`, `aiac.policy.model_store.library`, `aiac.pdp.policy.library` | `None` on success; exceptions logged and re-raised (propagate to the caller) |
| `aiac.idp.configuration.models` | `aiac.idp.configuration.api`, `aiac.policy.model`, AIAC Agent | — | Pydantic model definitions for IdP entities (Subject, Role, Service, Scope) |
| `aiac.idp.configuration.api` | AIAC Agent, Policy Computation Engine, Python scripts | IdP Configuration Service (HTTP) | Typed Pydantic instances (reads and writes IdP configuration entities) |
| `aiac.policy.model` | `aiac.pdp.policy.library`, `aiac.policy.model_store.library`, `aiac.policy.computation`, AIAC Agent | — | Pydantic model definitions for policy entities (PolicyRule, RuleEffect, ServicePolicyModel, AgentPolicyModel, EnforcementSide, PolicyModel and its subclasses TargetSidePolicyModel / AgentSidePolicyModel); the shared inbound projection `project_inbound`; `RoleHolders`, the current holders of each role (D32) |
| `aiac.pdp.policy.library` | `aiac.policy.computation` | PDP Policy Writer — OPA (HTTP) | None (writes Rego policy rules to the per-service AuthorizationPolicy CRs) |
| `aiac.policy.model_store.library` | `aiac.policy.computation`; UC-1 Service Policy Builder (read-only, `cross_service.py`) | Policy Model Store (HTTP) | `ServicePolicyModel` (a fresh empty SPM on 404) / `list[ServicePolicyModel]` on read; None on write/delete |
| ChromaDB **(not built yet)** | RAG Ingest Service (writes), Policy Guardrails Agent (reads, context), AIAC Agent (reads) | — | Policy and domain knowledge vectors |
| RAG Ingest Service **(not built yet)** | Developer (via `kubectl port-forward`) | ChromaDB, Policy Guardrails Agent, Embedding API, Event Broker | — |
| Policy Guardrails Agent (in RAG Pod) **(not built yet)** | RAG Ingest Service | ChromaDB (context reads) | Verdict per document — contract TBD |
| Event Broker (NATS JetStream) | Keycloak SPI listener, RAG Ingest Service (publishers); AIAC Agent consumer (DLQ republish) | — | Durable event delivery to AIAC Agent; DLQ on max retries |
| AIAC Agent | Event Broker (NATS consumer), operator (`/apply/policy/rebuild` and `/apply/offboard/{service_id}` HTTP direct; `/apply/role-members/{role_id}` to repair a lost role-mapping event, D32) | Service Onboarding Orchestrator, Policy Update / Role Update / Service Offboarding handlers → `aiac.idp.configuration.api`, `aiac.policy.computation`, `aiac.policy.model_store.library` (read-only), ChromaDB (not built yet; the policy comes from `AIAC_POLICY_FILE`), LLM API, Kubernetes API | Rego policy written to the per-service AuthorizationPolicy CRs; structured policy written to Policy Model Store (SQLite); provisioned service permissions/scopes (onboarding) |

### Key architectural decisions

- **Stateless PDP services are co-located in the Rossoctl Interface Pod; the stateful Policy Model Store is separate.** IdP Configuration Service and PDP Policy Writer run as two containers in the Interface Pod, sharing a Kubernetes ServiceAccount. The Policy Model Store is a dedicated single-replica StatefulSet (`aiac-policy-model-store`) with its own PVC — decoupled from the Interface Pod's restart lifecycle. Three ClusterIP Services (`aiac-pdp-config-service:7071`, `aiac-pdp-policy-service:7072`, `aiac-policy-model-store-service:7074`) provide stable addressing.
- **Policy Computation Engine is a library, not a service.** `aiac.policy.computation` runs in-process within the AIAC Agent pod. It requires no Kubernetes deployment, no container image, and no ClusterIP Service. The Controller calls `compute_and_apply(rules, override)` directly.
- **One CR per managed service + one SQLite store, distinct owners, distinct purposes.** The Policy Model Store owns a SQLite `service_policies` table (backed by a 1 Gi RWO PVC). The table holds one `ServicePolicyModel` (SPM) per service. The SPMs are the source of truth for policy state, served from an in-memory cache. Each managed service, agent or tool, has one `AuthorizationPolicy` CR, owned by the PDP Policy Writer. The CR holds the two Rego request packages that the writer renders from the service's entry in the policy model of the current side. The CR name and namespace come from the service's SPIFFE ID (`identity_ref`: the namespace and the ServiceAccount). The two services have no dependency on each other; both are driven by the PCE via their respective libraries.
- **One global switch selects the enforcement side (D16).** Under target side, each callee (agent or tool) checks the access to itself in its own inbound OPA, from its own CR. Under agent side (the legacy method), each agent's CR checks the agent's calls to tools on its outbound, and each tool's CR is a pass-through. The two sides never exist together. See [§3 Enforcement side](#enforcement-side).
- **The switch is `AIAC_ENFORCEMENT_SIDE`, and the default is `target-side` (D29).** The accepted values are `target-side` and `agent-side`. The switch is in the `aiac-agent-config` ConfigMap. The Controller reads it at start, and an unknown value stops the Controller. The writer reads the side from the policy-model tag, not from an env var. A side change is a ConfigMap patch and a Controller restart. The resync (D28) then writes every CR in the new side. `AIAC_AC_MODEL` is a different setting: it names a modeling paradigm, not the place of the check.
- **The render input is the policy model of the current side (D18).** Under target side, it is the stored SPMs. Under agent side, it is the APMs and the pass-through tool IDs. The PCE derives the APMs in memory at each deploy and never stores them. The store keeps only the SPMs. The read-only Controller route `GET /policy/services/{service_id:path}` returns the policy model of the current side with only the entry of that service, for tests and debugging. It returns `404` if the service has no SPM. See [components/aiac-agent.md](components/aiac-agent.md).
- **The policy model is a tagged hierarchy (D18a).** The base `PolicyModel` has the tag `enforcement_side: EnforcementSide` (`target-side` or `agent-side`). `TargetSidePolicyModel` has `services: list[ServicePolicyModel]`. `AgentSidePolicyModel` has `agents: list[AgentPolicyModel]` and `pass_through: list[str]` (the clientIds of the managed tools). In each subclass the tag is a `Literal` class constant, and code never sets it by hand. The writer parses each body as a discriminated union and dispatches on the subclass. So a model that mixes the sides cannot exist. A body with a wrong or missing tag gets `422`. See [components/policy-model.md](components/policy-model.md).
- **One shared inbound projection (D18b).** `project_inbound(spm)` in `aiac.policy.model` splits the inbound edges of one SPM into the user gate and the calling-agent gate (by `role.kind` and by effect). It also builds the identity maps. `_derive` (the APM inbound, agent side) and the target-side renderer both use it. So, for the same SPM, both sides give the same inbound. Under target side the writer projects one SPM and does no join.
- **The writer API (D18c).** `POST /policy` upserts one CR per entry. `PUT /policy` upserts every entry, then deletes every other CR that has the managed-by label. `DELETE /policy/services/{service_id:path}` deletes the CR of one service, and a `404` counts as success. `DELETE /policy` deletes every AIAC CR. The PDP library has `apply_policy(model)`, `replace_policy(model)`, `delete_service_cr(service_id)` and `delete_policy()`. `spec.policies` is atomic under server-side apply, so one write replaces the whole list. See [components/pdp-policy-writer-opa.md](components/pdp-policy-writer-opa.md) and [components/library-pdp-policy.md](components/library-pdp-policy.md).
- **A pod that has no client CR is denied (D20).** In an AIAC setup, the two request packages of the global combiner (the `default` CR in the bundle-service namespace) have no `client_ok if not <client package>` rule. The response packages keep the default. Other setups keep today's combiner. So every managed service gets a CR under both sides (a pass-through where AIAC has no rules), and the quarantine and the decommission delete the CR. §8 gives the chart value.
- **The pass-through packages (D24).** Under target side, the outbound request package of every service, tools included, is a pass-through, because the callee decides. Under agent side, every managed tool gets a pass-through CR (both request packages), because D20 denies a pod that has no CR, also on its outbound. An agent keeps its agent-side CR. The pass-through packages are the only ALLOW packages (D25).
- **A tool's inbound checks each MCP tool (D26).** Under target side, the tool's inbound checks each `tools/call` by `input.mcp.params.name`. A call passes only when the user gate and the calling-agent gate allow it and no deny vetoes it. `initialize`, `notifications/initialized`, `ping` and `tools/list` pass only when at least one tool of this service passes that check for the request. These four session methods also pass for the tool's own client (the self-discovery rule: `input.identity.client_id` equals the tool's clientId), so that UC-1 discovery can list the tools; `tools/call` never passes this way. Every other MCP method is denied. This is the agent-side outbound logic, moved to the callee.
- **An agent's inbound is agent-level (D26a).** Under both sides, a caller that has an allow on any scope of the agent can call the agent. The OPA input has no skill ID, and A2A requests have no standard skill field. This is a known limit.
- **No request without identity passes (D27).** A rules-based inbound package needs a subject that holds a role (the self-discovery rule of a tool needs the tool's own client ID from the token). So the callees must use `tcpSocket` or `exec` probes, and the proxy denies the A2A agent card and `/metrics` (known limits).
- **A resync at every Controller start (D28).** The resync holds the PCE lock (D22). First, the PCE calls `PUT /policy` with the full policy model of the current side: every live service that has a stored SPM (a disabled service, or one that is absent from the IdP catalog, is left out). This also deletes each AIAC CR whose service is not in the model. Then the PCE quarantines each disabled service that still has an SPM. Onboardings wait on the lock. If the resync fails, the Controller stops. See [components/policy-computation-engine.md](components/policy-computation-engine.md).
- **The rebuild ends with `PUT /policy` (D28a).** The UC-2b rebuild does not start with `DELETE /policy`, so there is no deny window under D20. **Status: not built yet** — `rebuild.py` is a stub.
- **Precondition checks (D30).** At each start, the Controller reads the `default` CR in the bundle-service namespace. If the combiner does not deny a missing client CR (#4), the Controller stops. At each onboarding, the checks run first, before Provision and the PRB: the pod has the AuthBridge sidecar (#1); the namespace inbound pipeline has `opa`, and also `mcp-parser` for a tool (#2); no app container has an `httpGet` probe (#6). Under target side the checks cover every service. Under agent side they cover agents only, and #2 also needs `opa` in the outbound pipeline. A tool's pass-through CR needs no check. A failed check raises `EnforcementPreconditionError`. This error is permanent (the consumer sends it to the DLQ at the first delivery). It is not a rollback error: the checks run first, so nothing has changed yet, and there is no rollback, no client disable and no quarantine. A first onboarding then has no CR, so D20 denies the service; an onboarded service keeps its policy. It gives HTTP `409` with a body that names each failed check. After a fix, the operator starts the onboarding again. #3 (no direct path to the app port) is documented only. See [components/aiac-agent/uc1-service-onboarding.md](components/aiac-agent/uc1-service-onboarding.md).
- **The subject is the username on every leg (D31).** Every user token that reaches an AIAC-managed agent or tool has `sub` = the username, because the CRs key users by username. The rule has two sources with the same mapping (`username` → claim `sub`). The login client's own `username-to-sub` mapper sets `sub` in the login token (on `rossoctl`: a manual prerequisite, unchanged, §8). The client scope `aiac-username-sub` sets `sub` in the exchanged token. The Keycloak standard token exchange (V2) applies only the scopes of the requester (the agent client), so the mapper of the login client never reaches an exchanged token. At each onboarding, Provision links `aiac-username-sub` as a default scope to the client of the service, agent or tool, before `set_service_type`, so before `compute_and_apply` writes the CR from the rules (the bootstrap CR of a tool comes earlier, but it grants no user). The IdP Configuration Service creates the scope and its mapper if they are not there, and changes a wrong `username-to-sub` mapper back (`POST /services/{id}/subject-scope`, idempotent), so a deleted scope comes back at the next onboarding. AIAC never links the scope to `rossoctl` and never makes it a realm default scope. The rule covers both enforcement sides: under target side, the tool inbound; under agent side, the inbound and the outbound `delegation.origin` of a second agent in a chain. The scope has no `aiac.managed` marker. It is linked to many clients, so a marker would make the scope an own scope of each linked service (in the policy model and in the PRB candidates). The scope is not in the created-manifest, so the rollback, the quarantine and the offboarding never delete it. Precondition: usernames are unique, cannot change and are never used again (§8). Option C (AuthBridge takes the subject from another claim, `subject_claim`) is a later step. It gives the same username, so AIAC can then remove the scope with no policy change. See [analysis/user-subject-across-token-exchange.md](../analysis/user-subject-across-token-exchange.md) and [components/idp-configuration-service.md](components/idp-configuration-service.md).
- **A realm is a tenant, and one policy covers the whole realm (D32).** To isolate tenants, use separate Keycloak realms. AIAC gives no isolation between namespaces in one realm. The role-to-scope match comes from one policy, common to all AIAC-managed services in the realm, across namespaces. So it is correct that two services share a role or a scope with a close or similar meaning. For example, `team1/github-tool` and `team2/github-tool` share the scope `github-tool.source-read`, and `team1/github-agent` and `team2/github-agent` share the role `github-agent.source_operations`. In one namespace, Provision does not share a role by itself (two workloads cannot have the same name), but an admin can assign the role to the service account of a second agent in Keycloak. The decision has seven parts. (a) The names and the reuse do not change. Provision names each role and scope `<workload>.<tool|skill>`, and `create_service_scope` / `create_service_role` reuse an object of the same name. When the description of the reused object is not the same as the new description, the library logs a warning and does not update Keycloak, so a policy decision does not change silently. Agent roles stay realm roles, because a client role cannot be shared (issue 1.7 stays separate). (b) A shared object is deleted only when its last owner goes. `DELETE /services/{id}/scopes/{scope_id}` deletes the scope only when the owner index shows no other client, and `DELETE /services/{id}/roles/{role_id}` deletes the role only when it has no other member. In the PCE, `_remove_footprint` (quarantine and decommission) keeps a role that another service in the catalog still holds (`held_elsewhere`), and renders again the CRs that have an edge of that role, with the current holders and with no store write, so the removed holder leaves them at once (a client delete gives no role-mapping event). (c) Assumption 2 ("an `aiac.managed` scope has exactly one owner") and its check are removed. A shared scope is valid. `GET /services/{id}/scopes` gives each owner its own copy of the scope, with `Scope.serviceId` = that owner, and the PCE routes each copy to the SPM of its owner. The check never fired on a live system (the Keycloak default-scope list has only `id` and `name`), and if it fired, its `409` would stop every catalog read in the realm. The PRB prompt lists a shared scope once, and the rule assembly gives one rule for each copy. (d) The role holders come from the current IdP data at render time, not from the `actorIds` copy in the stored edge. The stored `actorIds` are only a snapshot: before D32, a shared role kept only the holder of the copy that came first, and a user who lost a role kept access. One pure module, `RoleHolders` (`aiac.policy.model.holders`), gives the holders. The PCE builds it one time for each operation, under the PCE lock (D22), and applies it to each SPM that it reads from the store and to each input rule, before the routing guard. When a run touches an SPM whose stored holders are not the current ones, the run writes that SPM and deploys its CR, so a duplicate rule (for example the rule of the second holder of a shared role) still updates the CR of the callee. The holders of an `Agent`-kind role are the live services (in the catalog and enabled; the focus service counts as live) whose roles contain the role. The holders of a `User`-kind role are the direct members that `GET /roles` gives now. A role that `GET /roles` does not list has no holder (fail closed). The store schema does not change. (e) So the read rule of the PCE is relaxed: the PCE reads `get_services()` and also `get_roles()` (the current members of the user roles). The reason: a membership change changes who holds a role, not the policy (role → scope). It needs no PRB run, only a new render of the CRs that use the role, and the render must know the current members. The PCE still never reads `get_subjects()`. (f) The routing guard keeps a rule when the scope owner is live and, for an `Agent`-kind role, at least one current holder is live. Before, every `actorIds` owner had to be live, but a shared role is also the grant of its other holders. (g) The trigger is a role-mapping event. The Keycloak SPI maps the admin event `REALM_ROLE_MAPPING` (`CREATE` or `DELETE`, on `users/{user-id}/role-mappings/realm`, for users and for agent service accounts) and publishes `aiac.apply.role-members.{role-id}` for each role in the event representation, after the commit (D33). The Controller calls the PCE `rerender_role(role_id)`: it renders again the CRs that use the role, with the current holders, with no PRB run and no SPM write. The operator route `POST /apply/role-members/{role_id}` calls the same function. Provision's own role mapping, and the unmap of a rollback, also give the event, so a new holder of a shared role gets the grants at once. A new role has no SPM edge, so its event changes nothing. The resync and the other render paths (`compute_and_apply`, `quarantine`, `decommission`, `bootstrap`, `policy_model_for`) also use the current holders, so the next Controller start repairs a missed event. Rejected: namespace-qualified names (option A), a loud failure on reuse (option B), A and B together (option C), and client roles with client-owned scopes (option D). Each of them prevents the sharing that the realm-wide policy needs. See [components/policy-computation-engine.md](components/policy-computation-engine.md#role-holders-at-render-time-d32), [components/policy-model.md](components/policy-model.md), [components/idp-configuration-service.md](components/idp-configuration-service.md#shared-roles-and-scopes-d32), [components/library-idp.md](components/library-idp.md), [components/aiac-agent/uc1-service-onboarding.md](components/aiac-agent/uc1-service-onboarding.md), [components/event-broker.md](components/event-broker.md) and [keycloak-spi/README.md](../../keycloak-spi/README.md).
- **The onboarding event comes after the Keycloak commit (D33).** The problem: Keycloak calls the SPI listener inside `AdminEventBuilder.send()`, before it commits the change. So the `aiac.apply.service.{id}` message could come before the commit of the new client, and the first read of the Controller got `404`. The IdP Configuration Service changed that `404` to `502`, the IdP library did not retry it, and the consumer left the message unacked. The onboarding then started only at the NATS redelivery after `AckWait` (600 s). During that time the new agent or tool had no CR, so D20 denied it. The decision has five layers. (a) The SPI publishes after the commit. `onEvent` only queues the subject. One after-completion transaction for each listener-provider instance (Keycloak creates one provider for each `AdminEventBuilder`, in practice one for each admin request) publishes the queued subjects after Keycloak commits. A rollback or a failed commit publishes nothing, so a rolled-back create gives no phantom event. Keycloak commits the main transactions one by one, so if one fails after another one has committed the change, the change can be saved with no event. With no active transaction, the SPI publishes at once. (b) The IdP Configuration Service keeps a Keycloak `404` as `404` on the reads of one service (`GET /services/{id}` and its `/roles`, `/scopes` and `/discovery-token`) and on `GET /roles/{name}/composites` (a sub-read of `get_service`). Other Keycloak errors stay `502`. (c) The IdP library keeps the status. A non-2xx response raises `IdPHTTPError`, a `RuntimeError` subclass with `.status` and `.response`. The library retries a `5xx` or a transport error, up to `UPSTREAM_MAX_RETRIES` attempts (default 3), and does not retry a `4xx`. Before, it retried no HTTP status. (d) Defense in depth: on a `404` at the first read, `onboard_service` reads the service again for a bounded time (`ONBOARD_CLIENT_WAIT_ATTEMPTS` 15 reads, `ONBOARD_CLIENT_WAIT_BACKOFF` 2 s between them, ≈30 s). Then it raises `ServiceNotVisibleError` (`502`). The consumer handles one message at a time, so the budget is short. A `404` cannot tell a new client from a client that does not exist, so an unknown UUID also waits for the full budget. (e) Below `MAX_DELIVER` (5), the consumer naks a `ServiceNotVisibleError` with the delay `AIAC_NOT_VISIBLE_NAK_DELAY_SECONDS` (default 30 s). Each nak uses one delivery. The other retryable errors still wait for `AckWait`. `AckWait` stays 600 s, because it is sized for long LLM onboardings. The SPI publish stays core NATS, at most once. The event is lost when Keycloak stops between the commit and the publish, when the listener has no usable NATS connection at that time (it never connected, or the client closed it after its reconnect budget), or in the partial commit above. The operator then starts the onboarding by hand (`POST /apply/service/{uuid}` on the Controller). Rejected: a lower `AckWait` (NATS would redeliver an LLM onboarding that is still running); an outbox in the SPI (a durable store and a relay in Keycloak, for a small loss window that a manual start recovers). See [keycloak-spi/README.md](../../keycloak-spi/README.md#publish-after-the-commit), [components/idp-configuration-service.md](components/idp-configuration-service.md), [components/library-idp.md](components/library-idp.md), [components/aiac-agent/uc1-service-onboarding.md](components/aiac-agent/uc1-service-onboarding.md#the-first-read-waits-for-a-new-client-d33) and [components/aiac-agent.md](components/aiac-agent.md#ack-contract).
- **`aiac.pdp.policy.library` has one caller: `aiac.policy.computation`.** AIAC Agent sub-agents do not call the PDP Policy Library directly. The Controller calls `compute_and_apply()`, `decommission()` or `rerender_role()` (D32), and the UC-1 Orchestrator calls `bootstrap()` and `quarantine()`. At each start, the Controller calls `resync()`. This centralises all Policy Model Store ↔ PDP Policy Writer coordination.
- **Clean `idp` / `pdp` / `policy` Python namespace split.** IdP-related code (Keycloak entity management) lives under `aiac.idp.*`; PDP policy code (OPA Rego writing) lives under `aiac.pdp.*`; shared policy model and computation code lives under `aiac.policy.*`.
- **`aiac.policy.model` is dependency-free (only `pydantic` + `aiac.idp.configuration.models`).** `PolicyRule`, `RuleEffect`, `ServicePolicyModel`, `AgentPolicyModel`, `EnforcementSide`, the policy-model classes (`PolicyModel`, `TargetSidePolicyModel`, `AgentSidePolicyModel`) and the shared projection `project_inbound` live in a neutral namespace importable by any consumer — Policy Model Store library, PDP Policy Library, PCE — without forcing a dependency on any service namespace.
- **`PolicyRule.role` and `PolicyRule.scope` are typed objects.** They hold `Role` and `Scope` instances from `aiac.idp.configuration.models`, enabling the PCE to route each rule by `scope.serviceId` and classify it by `role.kind`, with no IdP lookup per rule. The `role.actorIds` of a rule or a stored edge is a snapshot: the PCE replaces it with the current holders before it uses it (D32).
- **`AgentPolicyModel` relationship maps are keyed by a plain string.** `source_roles` (the source clientId), `subject_roles` (the subject username), and the split target maps (`target_allow_scopes` / `target_deny_scopes`, the target clientId) use a plain string as the dict key, so `Service`, `Role`, `Scope`, and `Subject` need no custom hash/eq and keep pydantic's default field-based equality. This also lets the maps serialize to JSON without a custom key serializer.
- **PCE merge semantics are additive, with drift-GC and an authoritative offboard.** The default merge (`override=False`) is additive — new rules are appended to a service's SPM inbound rules, routed by effect into `inbound_allow_rules` / `inbound_deny_rules` (dedup by `role.id + scope.id + effect`); existing edges are preserved. Three mechanisms remove edges: (1) **reconcile drift-GC** prunes each *touched* SPM against the `get_services()` catalog on every write, dropping edges whose scope or agent-role no longer exists and collapsing churned/duplicate user-role generations (order-independent; skipped on a catalog miss so a transient outage never wipes an SPM); (2) **`decommission(service_id)`** — the authoritative service **offboard** — deletes a decommissioned service's SPM, purges its outbound footprint from other SPMs, deletes its CR (agent or tool, `delete_service_cr`), and redeploys the affected services of the current side (keyed by clientId, since an offboarded client is gone from `get_services()`); and (3) **`quarantine(service_id, deleted_roles)`** — the UC-1 failure path. The Orchestrator first deletes the roles/scopes that the failed run created and disables the client. Then `quarantine` deletes the service's SPM, removes its roles from the other SPMs, deletes the service's CR (agent or tool, `delete_service_cr`; under D20 the pod is then denied), and redeploys the affected services of the current side. Fine-grained **single-rule** revocation is still TBD; `override=True` gives role-level replace. A routing guard in `compute_and_apply` drops every rule that touches a disabled or deleted service (the `focus_service` of a re-onboarding is exempt). For a shared `Agent`-kind role, one live holder is sufficient (D32). After the store writes, the policy-model stage deploys only the affected services (D23). Under target side, these are the services whose SPM changed in the run; a zero-rule focus SPM counts (D21). Under agent side, these are the affected agents, plus the pass-through CR of the focus service when it is a tool. A stale or missing CR stays until the service is affected again, or until the resync. One in-process lock, `_pce_lock`, serializes `compute_and_apply`, `decommission`, `quarantine`, `rerender_role` and the resync (D22). Every rules-based Rego package defaults to DENY (`default allow := false`); there is no default-effect field. The pass-through packages are the only ALLOW packages (D25).
- **PDP services bind to `0.0.0.0`.** Exposed as Kubernetes ClusterIP Services so that the Agent Pod can reach them over the cluster network.
- **RBAC via OPA Rego rules.** AIAC manages role → service permission mappings. The PDP Policy Writer renders each entry of the policy model into two Rego request packages and writes them to that service's own `AuthorizationPolicy` CR (one per managed service). `bundle-service` composes the CRs into per-pod OPA bundles, which the OPA plugin of each agent and tool pod polls.
- **Status: not built yet** — the RAG Pod (ChromaDB, RAG Ingest Service, Policy Guardrails Agent). There is no code or manifest for it. The next five bullets describe the planned design.
- **RAG Pod is a StatefulSet with persistent ChromaDB storage.** ChromaDB data is stored on a 1 Gi `ReadWriteOnce` PersistentVolumeClaim mounted at `/chroma/chroma` (ChromaDB default). On pod recreation, the StatefulSet rebinds the same PVC and ChromaDB resumes from persisted state without re-ingestion. The pod runs a single replica.
- **RAG Pod runs ChromaDB, RAG Ingest Service, and the Policy Guardrails Agent together.** Exposed as `aiac-rag-service` on ports 8000 (ChromaDB default) and 7073 (RAG Ingest Service).
- **The Policy Guardrails Agent is not exposed on the RAG Pod's ClusterIP Service.** It is reachable only on the pod's loopback network (`localhost:7075`), making the RAG Ingest Service structurally the only caller.
- **Guardrails verification is a synchronous, per-document, pre-flight, fail-closed gate.** The RAG Ingest Service calls the Policy Guardrails Agent once per document before making any ChromaDB mutation; any rejection fails the whole request with nothing written, and an unreachable or erroring agent is treated the same as a rejection unless verification is explicitly disabled via `AIAC_GUARDRAILS_ENABLED`.
- **The Policy Guardrails Agent has no Event Broker involvement.** It neither publishes nor consumes NATS subjects; the RAG Ingest Service's existing `aiac.apply.policy.build` publish is unchanged.
- **AIAC Agent is stateless.** Changes are applied immediately on trigger — no pending session or human confirmation step.
- **Grant/prohibit conflicts surface on `/apply` as a `422` `ConflictReport`.** `/apply` is the sole policy entry point. A genuine conflict — a cross-pass structural conflict or the LLM auditor's contradiction — aborts the apply (no `compute_and_apply` call) and returns a `ConflictReport` (all conflicts at once, with verbatim quotes) as the `422` body. On UC-1 onboarding, the Orchestrator first rolls back what Provision created, disables the client, and runs the PCE `quarantine`. The earlier standalone read-only `POST /policy/check` diagnostic is **retired** — the diagnostic is folded into `/apply` ([PRB design decision: identify conflicts, never reconcile](components/aiac-agent/policy-rules-builder.md#design-decision-identify-conflicts-never-reconcile) / #2503).
- **Event Broker decouples all automated triggers from the Agent.** The Keycloak SPI listener and RAG Ingest Service publish to NATS subjects; the Agent subscribes as a durable competing consumer. This removes all direct dependencies between trigger sources and the Agent.
- **`rebuild` and `offboard` bypass the Event Broker.** They are operator-only commands issued directly via HTTP (`kubectl port-forward`). They are never published to NATS and have no NATS listener.
- **NATS consumer is a thin adapter.** It receives events from the Event Broker and calls the same internal handler functions used by the debug HTTP endpoints. No business logic lives in the consumer.
- **Agent HTTP endpoints are retained for debugging.** They are not the primary trigger path; the NATS consumer is. `kubectl port-forward` to the Agent is used only for `rebuild`, `offboard`, and debugging.
- **Event Broker uses WorkQueuePolicy.** Messages are removed from the stream after acknowledgement. Unacknowledged messages survive Agent pod restarts and are redelivered automatically. After 5 failed deliveries, messages are routed to `aiac.apply.dlq`. A permanent failure (conflict, contradiction, PRB error, unparseable LLM response, failed precondition check) goes to the DLQ on the first delivery. A `ServiceNotVisibleError` (the IdP does not show the new service yet, D33) gets a nak with a delay, so NATS redelivers it after `AIAC_NOT_VISIBLE_NAK_DELAY_SECONDS`, not after `AckWait`.
- **AIAC init container gates Agent startup.** Before the Agent container starts, the `aiac-init` init container (same image, `python -m aiac.agent.init.wait_and_provision`) waits for NATS, IdP Configuration Service, and PDP Policy Writer to be healthy (RAG Ingest Service only when `AIAC_RAG_INGEST_URL` is set). Then it creates the `aiac-events` JetStream stream idempotently.
- **All `__init__.py` files under `aiac.*` are empty.** Callers use explicit submodule paths: `from aiac.idp.configuration.models import Subject`, `from aiac.policy.model.models import PolicyModel`.
- **ChromaDB hosts two collections: `aiac-policies` and `aiac-domain-knowledge`.** Collection slug to ChromaDB name mapping: `policy` → `aiac-policies`, `domain-knowledge` → `aiac-domain-knowledge`. **Status: not built yet** — there is no ChromaDB in the deployment.
- **`user/{id}` trigger not implemented.** OPA rules are role-scoped; individual user creation/update does not require agent intervention. A change of the realm roles of a user or of an agent service account is different: it changes the holders of a role, which the CRs contain. So the SPI publishes `aiac.apply.role-members.{role-id}`, and the PCE renders the CRs that use the role again (D32).

---

## 6. Rossoctl / Keycloak / OPA Interfaces

**AIAC ↔ Rossoctl platform**
The AIAC Agent reads `AgentCard` custom resources, pod labels (`rossoctl.io/type`), and Services from the Kubernetes API to
extract service metadata during UC-1 service onboarding. For the precondition checks (D30), it also reads the pod's containers and
probes and the namespace ConfigMap `authbridge-runtime-config` at each onboarding, and the `default` `AuthorizationPolicy` in the
bundle-service namespace at each start. The `aiac.idp.configuration` and `aiac.pdp.policy.library` Python packages are the integration surface for other Rossoctl components needing typed access to the IdP and PDP respectively.

**AIAC ↔ Keycloak**
The IdP Configuration Service proxies Keycloak Admin REST endpoints under generic entity names (subjects, roles, services, scopes, assignments). Read endpoints include per-service role and scope enrichment. At each onboarding, AIAC also makes sure that the client scope `aiac-username-sub` and its `username-to-sub` mapper exist, and links the scope as a default scope to the client of the onboarded service (`POST /services/{id}/subject-scope`, D31). AIAC never changes the login client `rossoctl`. The Keycloak SPI listener publishes entity lifecycle events to NATS after the Keycloak commit (D33); it lives in `keycloak-spi/` in this repo. It also publishes a realm role-mapping change (`aiac.apply.role-members.{role-id}`, D32), because the CRs contain the holders of each role. A realm is a tenant: AIAC applies one policy to all AIAC-managed services of the realm, and gives no isolation between namespaces in one realm (D32).

**AIAC ↔ OPA**
The PDP Policy Writer (`aiac-pdp-policy-opa`) writes one `AuthorizationPolicy` Kubernetes CR for each managed service, agent or tool. Each CR has the two Rego request packages `authbridge.client.inbound.request` and `authbridge.client.outbound.request`, rendered from the service's entry in the policy model of the current side. Each agent and tool pod embeds two OPA plugin instances inside AuthBridge (one for the inbound pipeline, one for the outbound pipeline); `bundle-service` composes the CRs into per-pod OPA bundles, which each plugin polls. A pod's bundle has the global CRs, the `scope: namespace` CRs of its namespace, and its client CR: the CR whose namespace and name are the namespace and the ServiceAccount of the pod's SPIFFE ID. A tool pod gets the AuthBridge sidecar only when the operator's `injectTools` is on. AuthBridge requires no changes when policy rules are updated. Full spec: [components/pdp-policy-writer-opa.md](components/pdp-policy-writer-opa.md).

Under target side, the tool's own inbound OPA checks each MCP tool call (D26), and an agent's inbound checks its callers at agent level (D26a). The outbound of every service is a pass-through (D24). Under agent side, an agent's CR has the agent-level inbound and the per-tool checks on its outbound; each managed tool has a pass-through CR. In an AIAC setup, the global combiner denies a pod that has no client CR (D20).

**Known limits (enforcement)**
- The agent inbound is agent-level under both sides (D26a). The OPA input has no skill ID.
- A request without identity does not pass a rules-based inbound (D27). So callees must use `tcpSocket` or `exec` probes, and the proxy denies the A2A agent card and `/metrics`.
- In reverse-proxy mode (the default), other pods can reach the moved app port directly, with no JWT and no OPA (D30 #3). Use transparent mode or a NetworkPolicy for the app port.
- The AgentCard sync: when no `<agent>-card-signed` ConfigMap exists, the operator fetches the agent card over HTTP with no token from the first Service port (only the optional `agentcard-signer` init container writes that ConfigMap). The demo reaches the moved app port directly (the D30 #3 hole). If that path is closed, D20 and D27 deny the fetch, and the agent onboarding fails (the card does not sync, so Provision gets no skills). Then use the signed-card ConfigMap.
- Under target side, the outbound pass-through has no egress check.
- Under agent side, the agent outbound denies A2A `message/send` and LLM calls (`b435aa1`).
- A quarantined tool cannot be lifted until handoff 14 (offboarding through Keycloak) is built (C5). A failed D30 check does not quarantine and does not disable the client, so it does not cause this limit.
- `DELETE /policy` has no AIAC caller. Under D20 it denies every managed pod (C1).
- A client that is disabled by hand keeps its SPM and CR, and gets no new rules, until the next resync quarantines it (C2).
- A CR change takes effect at the next poll of the OPA plugin (10 s minimum, up to 120 s). Before the first bundle loads, every request gets `503`.
- Pods that share a ServiceAccount share one CR and one bundle.

**Known limits (the subject, D31)**
- The `sub` override with a username is not a use that Keycloak documents. It goes against OIDC Core §5.7 and RFC 9068 §2.2, which make `sub` the stable identifier of the user. The username precondition (§8) gives the same stability.
- A backchannel logout token keeps `sub` = the user ID. AIAC-managed services are resource servers behind AuthBridge, so they are not expected to get logout tokens (**to verify**).
- A token of the service account of a client (client credentials, for example the UC-1 discovery token) gets `sub` = `service-account-<clientId>`. This causes no problem: the self-discovery rule of a tool keys on `client_id`, not on the subject (D26).
- The legacy token exchange (V1) is on in the realm. Keycloak sends a request to V1 only when the standard exchange (V2) declines it: the requester client has no `standard.token.exchange.enabled`, or the request has `requested_subject`, `requested_issuer` or `subject_issuer`. The AuthBridge requests do not meet these conditions (the operator sets the switch on each workload client, and AuthBridge sends none of these parameters), so V2 handles them. If V1 handles a request, it builds the token from the scopes of the target client, not of the requester. AIAC links `aiac-username-sub` to each managed agent and tool, so an exchange to an onboarded service still gets `sub` = the username. A target that AIAC has not onboarded gives the user ID, but it has no CR, so the global combiner denies it (D20). A wrong subject can only cause a deny: the CRs key users by username, a user ID matches no key, and each rules-based package denies by default (D25). AIAC does not depend on a V1 setting (§8).
- A service that was onboarded before D31 gets the link at its next onboarding. The Controller start does not add the link (no backfill), and a pod restart does not start an onboarding (the SPI publishes only on a client create). If an admin deletes the scope, Keycloak removes its link from every client, and the next onboarding links it again only to the client that it onboards. To link the scope again, start the onboarding of each managed service again (`POST /apply/service/{uuid}` on the Controller), or call `POST /services/{uuid}/subject-scope` on the IdP Configuration Service for each client that has `client.type`. After a late link, AuthBridge's `token-exchange` plugin can still use a token that it exchanged before the link (`sub` = the user ID): it caches each exchanged token by the subject token and the audience, until 30 s before that token expires. So the fix takes effect for a user at the latest when the access token lifetime ends, or at once after a restart of the agent pod.
- The mapping follows the **requester**, not the target. The scope is a default scope of the managed agent's client, so **every** token that the agent exchanges gets `sub` = the username, for every route and audience of its `authproxy-routes`, also for a target that AIAC does not manage. With the `client-credentials` no-token policy, the agent's own token gets `sub` = `service-account-<clientId>` for every audience. A target outside AIAC that keys users by the Keycloak user ID sees usernames. The alternative placement (the mapper on each target's optional audience scope) applies only when the route names that scope in `token_scopes`, and AuthBridge sends no `scope` for a route without `token_scopes` or for a per-host derived audience, so it is not used.

**Known limits (shared roles and scopes, D32)**
- AIAC gives no isolation between namespaces in one realm. A role or a scope with the same name is shared across namespaces. To isolate tenants, use separate realms.
- Under agent side, the outbound subject map of an agent CR is role → bare tool name, with no target key (`subject_role_allow_scopes` / `subject_role_deny_scopes`). So a deny of `source-read` for one tool also blocks the same user's `source-read` on another tool that has the same bare tool name. For a shared scope, this agrees with the realm-wide policy. For two different scopes with the same bare tool name, it is a limit.
- A role that a user or an agent holds only through a group or through a composite parent role is not a holder. The PCE reads only the direct members of a role (`GET /roles`) and the direct roles of each service. A user role that has no `aiac.managed` marker has no holders (`GET /roles` gives it no `actorIds`).
- The role-mapping event is at most once (core NATS, D33). If it is lost, the CRs keep the old holders until the next Controller start (the resync, D28) or a manual `POST /apply/role-members/{role_id}` on the Controller. Until then, a user who lost the role keeps access, and a user who got the role is denied.
- The SPI drops the group membership events (`GROUP_MEMBERSHIP`), the role mappings of a group (`groups/...`) and the client-role mappings (`CLIENT_ROLE_MAPPING`). The PCE does not count a holder that comes through these paths (see the limit above), so the resync does not add it either.
- A shared role or scope keeps the description of its first owner. A later owner with a different description gets a warning in the log, and Keycloak does not change. The PRB reads only the first description.

**AIAC ↔ Event Broker (NATS JetStream)**
The Agent subscribes to the event stream as a durable consumer with at-least-once delivery.
Unacknowledged messages survive pod restarts; failed messages are routed to a dead-letter subject.
See Section 7.6 (Event Broker) and Section 8 (Deployment) for subject names and handler mapping.

---

## 7. AIAC System Components

### 7.1 IdP Configuration Service

FastAPI service (`0.0.0.0:7071`) co-located with the PDP Policy Writer in the **Rossoctl Interface Pod**. Manages IdP (Keycloak) entity data (subjects, roles, services, scopes) via Keycloak Admin REST API. Exposes read and write endpoints for configuration entities. Stateless. All endpoints except `/health` require a `?realm=<realm>` query parameter; returns `422` if absent. `/health` requires no realm parameter — it uses `KEYCLOAK_ADMIN_REALM` directly. `KeycloakAdmin` instances are created lazily per realm and cached in a thread-safe map; the admin always authenticates via the realm in `KEYCLOAK_ADMIN_REALM`.

**Full spec:** [components/idp-configuration-service.md](components/idp-configuration-service.md)

---

### 7.2 PDP Policy Writer

FastAPI service (`0.0.0.0:7072`, `aiac-pdp-policy-opa`) co-located with the IdP Configuration Service in the **Rossoctl Interface Pod**. Renders the two Rego request packages from the policy model of the current side and writes them to one `AuthorizationPolicy` Kubernetes CR per managed service, agent or tool (D20). It reads the side from the policy-model tag. Under target side, it renders each callee's CR from the callee's stored SPM and does no join. Under agent side, it renders each agent's CR from its APM and a pass-through CR for each managed tool. `POST /policy` upserts, `PUT /policy` replaces (it also deletes every other CR that has the managed-by label), and `DELETE /policy/services/{service_id:path}` deletes the CR of one service (D18c). `bundle-service` composes the CRs into per-pod OPA bundles, which each AuthBridge OPA plugin instance polls.

**Full spec:** [components/pdp-policy-writer-opa.md](components/pdp-policy-writer-opa.md)

---

### 7.3 Policy Model Store

FastAPI service (`0.0.0.0:7074`, `aiac-policy-model-store-service`) deployed as a dedicated single-replica StatefulSet (`aiac-policy-model-store`) with a `volumeClaimTemplate` PVC (1 Gi, `ReadWriteOnce`) mounted at `/data`. Owns an in-memory `ServicePolicyModel` cache (one SPM per `service_id`) backed by a SQLite database (`/data/policy_model.db`, table `service_policies`) as the authoritative structured policy store. All GET requests are served from the in-memory cache; mutations write through to SQLite synchronously; on pod restart the cache is repopulated from SQLite. The Policy Computation Engine reads current SPM state for additive merging and writes updated state after each computation. `GET /policy/services` with no `role` returns every SPM; the library call is `list_service_policies()`, and the PCE resync uses it (C3). The PDP Policy Writer has no dependency on the Policy Model Store; the SQLite store and the `AuthorizationPolicy` CRs are written by distinct services and serve distinct purposes.

**Full spec:** [components/policy-model-store.md](components/policy-model-store.md)

---

### 7.4 Policy Computation Engine

Pure Python library module (`aiac.policy.computation`). No FastAPI, no Kubernetes deployment, no container image. Runs in-process within the AIAC Agent pod. The AIAC Agent Controller calls `compute_and_apply(rules, override=False, focus_service=None) -> None`. It folds partial policy rule lists into the per-service `ServicePolicyModel`s. Then it builds the policy model of the current side for the affected services (D23) and pushes it to OPA. More entry points: `decommission(service_id)` (offboard), `quarantine(service_id, deleted_roles)` (UC-1 failure path), `resync()` (at each Controller start, D28), `bootstrap(service_id, service_type)` (the CR of a tool before its Provision, so that UC-1 discovery passes D20), `rerender_role(role_id)` (a role-mapping event, D32) and `policy_model_for(service_id)` (read-only, D18). `enforcement_side()` reads `AIAC_ENFORCEMENT_SIDE`; an unknown value raises `ValueError`.

The PCE is the **single point of coordination** between the Policy Model Store and PDP Policy Writer: it reads the current SPMs, additively merges new rules, and writes the changed SPMs back to the Policy Model Store. Then it builds the policy model of the current side and pushes it to `aiac.pdp.policy.library.apply_policy()`. Under target side, the model holds the changed SPMs. Under agent side, it holds the APMs of the affected agents, which the PCE derives from the SPMs, and the pass-through IDs. `decommission` and `quarantine` call `delete_service_cr` for agents and for tools (D20). `resync` calls `replace_policy` with the full policy model of the current side, then quarantines each disabled service that still has an SPM (D28). `bootstrap` calls `apply_policy` with the entry of one tool and stores no SPM.

**The role holders come from the IdP at render time (D32).** The `role.actorIds` in a stored edge is a snapshot, not the authority. At each operation, under the PCE lock, the PCE reads `get_services()` and `get_roles()` one time and builds `RoleHolders` (`aiac.policy.model.holders`). It applies the holders to each SPM that it reads from the store and to each input rule, before the routing guard. So the routing guard, the affected set, `_derive` and the writer's `project_inbound` see the current holders. The holders of an `Agent`-kind role are the live services whose roles contain the role. The holders of a `User`-kind role are the direct members that `GET /roles` gives now. This relaxes the old read rule (only `get_services()`): a membership change changes who holds a role, not the policy, so it needs only a new render, and the render needs the current members. The PCE never reads `get_subjects()`. `rerender_role(role_id)` is the entry point for a role-mapping event: it holds the lock, makes no PRB call and writes no SPM. Under target side, it calls `apply_policy` with the live SPMs that `get_service_policies_by_role` gives (no call when there is none). Under agent side, it derives again the APM of every live stored agent, in one `apply_policy` call. The resync, `compute_and_apply`, `quarantine`, `decommission`, `bootstrap` and the read model `policy_model_for` also render with the current holders. So `policy_model_for` now reads the IdP too, because the read model must show what the PCE deploys (D18).

All exceptions from any dependency (IdP, Policy Model Store, PDP) are logged and **re-raised** so the caller (the Controller / HTTP layer) surfaces the failure — e.g. as a 500 — instead of returning success while silently applying nothing.

**Full spec:** [components/policy-computation-engine.md](components/policy-computation-engine.md)

---

### 7.5 Library

Python package at `src/`. Clean `idp` / `pdp` / `policy` namespace split:

**IdP library** (Keycloak entity management):
- **`aiac.idp.configuration.models`** — dependency-free Pydantic models for IdP entities (`Subject`, `Role`, `Service`, `Scope`). Plain pydantic models with default field-based equality; not hashable and not used as dict keys.
- **`aiac.idp.configuration.api`** — HTTP client class `Configuration` wrapping the IdP Configuration Service; read and write access to configuration entities; returns typed Pydantic instances. It is built per realm with `Configuration.for_realm(realm)` or `Configuration.for_default_realm()` (reads `KEYCLOAK_REALM`); the methods take no `realm` argument. The PCE uses only `get_services()` and `get_roles()` (the current role holders, D32). `create_service_role` / `create_service_scope` reuse an object of the same name, and log a warning when its description is not the same (D32).

**Policy model** (shared, dependency-light):
- **`aiac.policy.model`** — canonical Pydantic models for policy entities (`PolicyRule`, `RuleEffect`, `ServicePolicyModel`, `AgentPolicyModel`, `EnforcementSide`, and the policy models `PolicyModel`, `TargetSidePolicyModel`, `AgentSidePolicyModel`) with typed `Role`/`Scope`/`Service` fields, the shared inbound projection `project_inbound` (D18b), and `RoleHolders` (`aiac.policy.model.holders`, the current holders of each role, D32). Importable by any consumer without pulling in HTTP or service dependencies.

**Policy libraries** (OPA + Policy Model Store access):
- **`aiac.pdp.policy.library`** — HTTP client wrapping the PDP Policy Writer (OPA). Four module-level functions (D18c): `apply_policy(model)` (`POST /policy`), `replace_policy(model)` (`PUT /policy`), `delete_service_cr(service_id)` (`DELETE /policy/services/{service_id}`), `delete_policy()` (`DELETE /policy`). Called exclusively by `aiac.policy.computation`.
- **`aiac.policy.model_store.library`** — HTTP client wrapping the Policy Model Store. Seven module-level functions: `get_service_policy`, `get_service_policy_by_scope`, `get_service_policies_by_role`, `list_service_policies` (every SPM; C3), `apply_service_policy`, `delete_service_policy`, `clear_service_policies`. Returns `ServicePolicyModel` directly (a fresh empty SPM on 404). Called by `aiac.policy.computation`, and read-only (`get_service_policy`) by the UC-1 Service Policy Builder's cross-service conflict check.

**Computation library** (policy rule processing):
- **`aiac.policy.computation`** — library module implementing `compute_and_apply(rules, override=False, focus_service=None) -> None`, `decommission(service_id)`, `quarantine(service_id, deleted_roles)`, `resync()`, `bootstrap(service_id, service_type)`, `rerender_role(role_id)` and `policy_model_for(service_id)`. Orchestrates IdP resolution, Policy Model Store merge, and PDP Policy Writer push.

**Full specs:** [components/library-idp.md](components/library-idp.md) · [components/library-pdp-policy.md](components/library-pdp-policy.md) · [components/library-policy-model-store.md](components/library-policy-model-store.md) · [components/policy-model.md](components/policy-model.md) · [components/policy-computation-engine.md](components/policy-computation-engine.md)

---

### 7.6 Event Broker

NATS JetStream pod (`aiac-event-broker-service:4222`). Decouples event producers (Keycloak SPI listener, RAG Ingest Service) from the AIAC Agent. Provides at-least-once delivery, replay on pod restart via `WorkQueuePolicy`, and a dead-letter subject (`aiac.apply.dlq`) after 5 failed deliveries (a permanent failure goes there on the first delivery). No authentication — ClusterIP network isolation is the access control mechanism. Stream: `aiac-events`, subjects `aiac.apply.>`, consumer group `aiac-agent-consumer`.

The at-least-once delivery starts at the stream. The Keycloak SPI listener publishes with core NATS, at most once, and only after the Keycloak commit (D33, §7.11). When the IdP does not show a new service yet (`ServiceNotVisibleError`, D33), the Agent consumer naks the message with a delay (`AIAC_NOT_VISIBLE_NAK_DELAY_SECONDS`, default 30 s). NATS then redelivers it after the delay, not after `AckWait` (600 s). Each nak uses one of the 5 deliveries. See [components/event-broker.md → Delivery Guarantees](components/event-broker.md#delivery-guarantees).

The subject `aiac.apply.role-members.{role-id}` (D32) carries a realm role-mapping change, with the payload `{"id": "<role-id>"}`. The role id is a UUID, so it needs no encoding, and the event of a deleted role can still cause a new render. The consumer calls the PCE `rerender_role(role_id)`, with no PRB run. `CONSUMER_FILTER_SUBJECTS` has `aiac.apply.role-members.*`. A nats-py `subscribe()` binds to an existing durable consumer and keeps its old config, so the consumer start creates or updates the durable consumer config (`add_consumer`) before it subscribes. Thus a new filter subject also gets to a running cluster.

**Full spec:** [components/event-broker.md](components/event-broker.md)

---

### 7.7 AIAC Agent

FastAPI + LangGraph service (`0.0.0.0:7070`). Receives automated triggers via the **Event Broker** (NATS JetStream durable consumer, `aiac-agent-consumer` queue group) and the operator-only `rebuild` and `offboard` commands directly via HTTP. Structured as a thin **Controller** (`controller/routes.py`) that dispatches `/apply/*` to the **Service Onboarding Orchestrator** (which owns compiled `StateGraph` sub-agents) or directly to the Policy Update, Role Update, and Service Offboarding handlers. A **NATS consumer** (asyncio background task in the FastAPI `lifespan` handler) is a thin adapter that receives NATS events and calls the same internal handler functions used by the HTTP endpoints:

| Use case | Trigger(s) | Sub-agents |
|---|---|---|
| Service Onboarding (Orchestrator) | `aiac.apply.service.{id}` | Service Provision → Service Policy Builder (sequential) |
| Policy Update | `aiac.apply.policy.build`, `/apply/policy/rebuild` (HTTP) | Build sub-agent or Rebuild sub-agent (alternative) |
| Role Update | `aiac.apply.role.{name}` | Role sub-agent |
| Service Offboarding | `POST /apply/offboard/{service_id}` (HTTP only) | Offboard handler → PCE `decommission` (no rules) |
| Role members (a new render, D32) | `aiac.apply.role-members.{role-id}`, `POST /apply/role-members/{role_id}` (HTTP) | None: the Controller calls the PCE `rerender_role` (no rules, no PRB run) |

All sub-agent `StateGraph` instances are logically separated modules running within a single pod and process. Sub-UC agents produce `list[PolicyRule]` and return it to the Controller, which calls `compute_and_apply(rules, override)` once. They do not call `aiac.pdp.policy.library` directly. The Service Policy Builder reads `aiac.policy.model_store.library.get_service_policy` (read-only) for the cross-service conflict check. The **Policy Update** sub-agents compute a minimal rule delta between the current ChromaDB policy and the current policy state in the Policy Model Store. The **Rebuild** variant additionally clears the Policy Model Store before recomputing, and ends with `PUT /policy` through the PCE; it does not clear the OPA policy first (D28a). The **Role Update** sub-agent computes rules for all services affected by the role change. The **Service Onboarding** orchestrator classifies the new service via the pod's `rossoctl.io/type` label (for agents reads the `AgentCard` CR; for tools calls `tools/list` on the MCP endpoint discovered via K8s Service label lookup), then computes rules; the Controller calls `compute_and_apply`. Before Provision and the PRB, the Orchestrator runs the precondition checks (D30). Then, for a tool only, it calls the PCE `bootstrap`, which writes the tool's CR, so that discovery passes D20. On a build failure the Orchestrator rolls back, disables the client, and calls the PCE `quarantine`. A failed check changes nothing (no rollback, no quarantine). Stateless; changes are applied immediately. Integrated retry with differentiated error codes per upstream.

**Status: not built yet** — the Policy Update (Build, Rebuild) and Role Update sub-agents are stubs that return no rules. Rebuild clears nothing. The Agent reads the policy from `AIAC_POLICY_FILE`, not from ChromaDB.

A genuine grant/prohibit conflict on `/apply` returns a `422` `ConflictReport` — see §5 Key architectural decisions.

A failed precondition check returns `409` with the body `{"detail": "…", "failed_checks": [...]}`. The NATS consumer treats it as permanent and sends it to the DLQ at the first delivery (D30). It is not a rollback error, so there is no rollback and no quarantine.

**Start sequence** (FastAPI `lifespan`): (1) read `AIAC_ENFORCEMENT_SIDE`; (2) run start check #4 on the global combiner; (3) run the PCE resync (D28); (4) start the NATS consumer. A failure in steps 1 to 3 stops the Controller. The pod then restarts, and the sequence runs again. `GET /health` answers only after the start sequence ends, so the Deployment has a `startupProbe` (`httpGet /health`) whose budget covers the start sequence.

**Read-only route** `GET /policy/services/{service_id:path}` (D18): it returns `200` with the policy model of the current side that holds only the entry of that service, or `404` if the service has no SPM. It is for tests and debugging.

**Full spec:** [components/aiac-agent.md](components/aiac-agent.md)

---

### 7.8 RAG Knowledge Base

ChromaDB vector store (`aiac-rag-service:8000`) hosting two collections: `aiac-policies` (access control policy rules) and `aiac-domain-knowledge` (org/business context such as team rosters, application ownership, and department mappings). Both collections are managed by the RAG Ingest Service and read by the AIAC Agent. Co-located with the RAG Ingest Service in the RAG Pod. ChromaDB data is persisted on a 1 Gi PVC mounted at `/chroma/chroma`; the RAG Pod is a StatefulSet.

**Status: not built yet** — no ChromaDB code or manifest; the Agent reads the policy from `AIAC_POLICY_FILE`.

**Full spec:** [components/rag-knowledge-base.md](components/rag-knowledge-base.md)

---

### 7.9 RAG Ingest Service

FastAPI service (`0.0.0.0:7073`) co-located with ChromaDB. Thirteen collection-parameterized endpoints across three semantics: complete collection replacement (`POST /ingest/{collection}/{text|file|url}`), document-level upsert (`POST /ingest/{collection}/update/{text|file|url}`), and explicit removal (`DELETE /ingest/{collection}/{doc_id}`). The `{collection}` slug is validated against `AIAC_RAG_COLLECTIONS` (default: `policy,domain-knowledge`). After every successful ingest the service publishes to `aiac.apply.policy.build` on the Event Broker (`NATS_URL`). Developer access via `kubectl port-forward`.

**Status: not built yet** — no RAG Ingest Service code or manifest.

**Full spec:** [components/rag-ingest-service.md](components/rag-ingest-service.md)

---

### 7.10 Policy Guardrails Agent

FastAPI service (`0.0.0.0:7075`) co-located with ChromaDB and the RAG Ingest Service in the **RAG Pod**. Verifies each document before the RAG Ingest Service writes it to ChromaDB — one verification call per document, pre-flight (before any ChromaDB mutation), all-or-nothing (any rejection fails the whole ingest request, nothing is written), fail-closed (an unreachable or erroring agent is treated as a rejection unless verification is disabled via `AIAC_GUARDRAILS_ENABLED`). Reachable only on the RAG Pod's loopback network — not exposed on `aiac-rag-service`, so the RAG Ingest Service is structurally the only caller. May read ChromaDB for evaluation context. Neither publishes nor consumes Event Broker subjects. One service exposing two independently-developed API families (`policy`, `domain-knowledge`) selected by collection slug. The `policy` family is defined — LangGraph agent running **policy hygiene** (on-topic/well-formed, actionable/translatable, internally consistent) and **contradiction against the persistent corpus** (`update` only; `replace` gets hygiene only), returning a two-level-severity verdict; the `domain-knowledge` family is specced independently later.

**Status: not built yet** — no Policy Guardrails Agent code or manifest.

**Full spec:** [components/policy-guardrails-agent.md](components/policy-guardrails-agent.md)

---

### 7.11 Keycloak SPI Listener

A custom Keycloak Event Listener SPI (Java) that listens to Keycloak's internal event bus and translates entity-scoped events into NATS publish calls to the Event Broker. The AIAC Agent subject schema is authoritative; the SPI README references it.

| Keycloak Event | Event Broker subject |
|---|---|
| All user events (for example `REGISTER`, `UPDATE_PROFILE`) and all other admin events, also the group membership (`GROUP_MEMBERSHIP`), the role mappings of a group (`groups/...`) and the client-role mappings (`CLIENT_ROLE_MAPPING`) | — (dropped; a user create or update does not change who holds a role, and AIAC does not count a role that comes through a group or a client-role mapping, D32) |
| `CLIENT_CREATED` (admin event `CLIENT` + `CREATE`) | `aiac.apply.service.{id}` (the internal client UUID) |
| Role created/updated (admin event `REALM_ROLE` or `CLIENT_ROLE` + `CREATE` or `UPDATE`) | `aiac.apply.role.{name}` (percent-encoded) |
| A realm role assigned or unassigned (admin event `REALM_ROLE_MAPPING` + `CREATE` or `DELETE`, resource path `users/{user-id}/role-mappings/realm`; users and agent service accounts) | `aiac.apply.role-members.{role-id}`, one for each role in the event representation (D32) |

**Publish after the commit (D33).** Keycloak calls the listener inside the admin request, before it commits the change. So `onEvent` does not publish: it maps the event and queues the subject. One after-completion transaction for each listener-provider instance (Keycloak creates one for each `AdminEventBuilder`, in practice one for each admin request) publishes the queued subjects after the commit. A rolled-back admin change (a rollback, or a failed commit) publishes nothing. With no active transaction, the listener publishes at once. The publish is core NATS, at most once, with no outbox. A failed publish is logged and dropped; it does not fail the admin request. See [keycloak-spi/README.md → Publish after the commit](../../keycloak-spi/README.md#publish-after-the-commit).

**The role-mapping event (D32).** The listener reads the role ids from the event representation, a JSON array of `RoleRepresentation` (each with `id` and `name`). Keycloak sets the representation on each role-mapping event, also when the realm has `adminEventsDetailsEnabled = false` (verified in the Keycloak 26.5.2 bytecode). The payload is `{"id": "<role-id>"}`. A missing or bad representation is logged and dropped; the resync repairs it. The event uses the same publish after the commit as the other events.

**Full spec:** [keycloak-spi/README.md](../../keycloak-spi/README.md).

---

## 8. Deployment

### Kubernetes manifests

Five manifest files (`rag-statefulset.yaml` is not built yet):

| File | Contents |
|------|----------|
| `k8s/pdp-interface-deployment.yaml` | `aiac-pdp-config` ConfigMap + Rossoctl Interface Pod Deployment (IdP Configuration Service container + PDP Policy Writer container) + two ClusterIP Services (`aiac-pdp-config-service:7071`, `aiac-pdp-policy-service:7072`) + `aiac-pdp-policy-writer` ServiceAccount, ClusterRole and ClusterRoleBinding (`get`, `list`, `create`, `update`, `patch`, `delete` on `AuthorizationPolicy` CRs; `PUT /policy` and `DELETE /policy` need `list`) |
| `k8s/policy-model-store-statefulset.yaml` | `aiac-policy-model-store` StatefulSet (Policy Model Store container) + `volumeClaimTemplate` (1 Gi, `ReadWriteOnce`, mounted at `/data`) + headless Service + `aiac-policy-model-store-service:7074` ClusterIP Service |
| `k8s/agent-deployment.yaml` | `aiac-agent-config` ConfigMap (with `AIAC_ENFORCEMENT_SIDE`) + `aiac-agent` ServiceAccount, ClusterRole (pods `get`/`list`, services `get`, agentcards `list`; `get` on `configmaps` for check #2 in the service namespaces; `get` on `authorizationpolicies` for check #4 on the `default` CR in the bundle-service namespace) and ClusterRoleBinding + Agent Pod Deployment (`aiac-init` init container + AIAC Agent container) + `aiac-agent-service:7070` ClusterIP Service |
| `k8s/event-broker-deployment.yaml` | Event Broker Pod Deployment (NATS JetStream) + ClusterIP Service |
| `k8s/rag-statefulset.yaml` *(pending)* | **Status: not built yet** — no manifest. RAG StatefulSet (ChromaDB + RAG Ingest Service + Policy Guardrails Agent containers) + 1 Gi PVC template + ClusterIP Service (ChromaDB + RAG Ingest Service ports only — the Policy Guardrails Agent is pod-local, not on the ClusterIP Service) |

Both Interface Pod containers mount `aiac-pdp-config` (KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_ADMIN_REALM) as env vars; only the IdP Configuration Service container also mounts `keycloak-admin-secret` (KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_ADMIN_PASSWORD) and uses `KEYCLOAK_ADMIN_REALM` (ignoring `KEYCLOAK_REALM`). The PDP Policy Writer (`aiac-pdp-policy-opa`) needs no Keycloak credentials — it server-side-applies one `AuthorizationPolicy` CR per managed service, with the `aiac-pdp-policy-writer` ServiceAccount and RBAC. It writes a `.rego` dump to `REGO_OUTPUT_DIR` (default `/rego`) only when `POLICY_WRITER_DUMP_REGO` is truthy. The Policy Model Store container mounts `aiac-policy-model-store-config` for `SERVICEPOLICY_DB_PATH` (default `/data/policy_model.db`) — no Kubernetes API access or RBAC required.

### Docker images

Built by the `.github/workflows/build.yaml` CI matrix (pushed to ghcr.io), or locally:

```bash
# Build IdP Configuration Service (Rossoctl Interface Pod container 1)
docker build -f src/aiac/idp/service/configuration/keycloak/Dockerfile -t aiac-pdp-config:latest src/aiac/idp/service/configuration/keycloak/

# Build PDP Policy Writer — OPA (Rossoctl Interface Pod container 2; writes per-service AuthorizationPolicy CRs)
docker build -f src/aiac/pdp/service/policy/opa/Dockerfile -t aiac-pdp-policy-opa:latest src/

# Build Policy Model Store (deployed as StatefulSet aiac-policy-model-store)
docker build -f src/aiac/policy/model_store/service/Dockerfile -t aiac-policy-model-store:latest src/

# Build Agent (the same image also runs the aiac-init init container)
docker build -f src/aiac/agent/controller/Dockerfile -t aiac-agent:latest src/

# Status: not built yet — the two source directories below do not exist.
# Build RAG Ingest Service
docker build -t aiac-rag-ingest:latest aiac/rag-ingest/

# Build Policy Guardrails Agent
docker build -t aiac-policy-guardrails:latest aiac/policy-guardrails/
```

The Event Broker uses the official `nats` Docker image with JetStream enabled (`-js` flag). No custom build required.

### `aiac-pdp-config` ConfigMap template

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aiac-pdp-config
  namespace: aiac-system
data:
  KEYCLOAK_URL: "http://keycloak-service.keycloak.svc:8080"
  KEYCLOAK_REALM: "rossoctl"
  KEYCLOAK_ADMIN_REALM: "master"
  AIAC_PDP_CONFIG_URL: "http://aiac-pdp-config-service:7071"
  AIAC_PDP_POLICY_URL: "http://aiac-pdp-policy-service:7072"
  AIAC_POLICY_MODEL_STORE_URL: "http://aiac-policy-model-store-service:7074"
  PLATFORM_SOURCE_CLIENTS: "rossoctl"
  # Added in Phase 2 by issue 4.19 (Event Broker):
  NATS_URL: "nats://aiac-event-broker-service:4222"
  # Added in Phase 3 by issue 4.20 (RAG Pod). Status: not built yet — the live ConfigMap does not have these two keys:
  AIAC_RAG_INGEST_URL: "http://aiac-rag-service:7073"
  AIAC_CHROMADB_URL: "http://aiac-rag-service:8000"
```

`SERVICEPOLICY_DB_PATH` is absent — it belongs to `aiac-policy-model-store-config` (defined in `policy-model-store-statefulset.yaml`), not to the shared ConfigMap. Likewise, `AIAC_GUARDRAILS_URL` and `AIAC_GUARDRAILS_ENABLED` (RAG Ingest Service → Policy Guardrails Agent, both pod-local) belong to the RAG Pod's own ConfigMap, not the shared `aiac-pdp-config` — no component outside the RAG Pod calls the Policy Guardrails Agent.

### `aiac-policy-model-store-config` ConfigMap template

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aiac-policy-model-store-config
data:
  SERVICEPOLICY_DB_PATH: "/data/policy_model.db"
```

Update `KEYCLOAK_URL` and `KEYCLOAK_REALM` for the target environment before applying.

### `aiac-agent-config`: the enforcement side

`AIAC_ENFORCEMENT_SIDE` is in the `aiac-agent-config` ConfigMap (`k8s/agent-deployment.yaml`), next to `AIAC_AC_MODEL`. AIAC has no Helm chart.

```yaml
data:
  AIAC_AC_MODEL: "RBAC"                  # names a modeling paradigm (RBAC/ABAC/REBAC); no code reads it
  AIAC_ENFORCEMENT_SIDE: "target-side"   # where the check runs: target-side (default) or agent-side
```

The Controller reads `AIAC_ENFORCEMENT_SIDE` at start, and an unknown value stops it (D29). To change the side, patch the ConfigMap and restart the Controller. The resync (D28) then writes every CR in the new side, so no mixed state stays. Start check #4 reads the `default` CR in the namespace `AIAC_BUNDLE_SERVICE_NAMESPACE` (default `rossoctl-system`).

### Platform prerequisites (operator)

- **The combiner (D20).** In an AIAC setup, the global combiner (the `default` `AuthorizationPolicy` in the bundle-service namespace) must deny a pod that has no client CR. Its two request packages must not have `client_ok if not data.authbridge.client.inbound.request` and `client_ok if not data.authbridge.client.outbound.request`. The response packages keep the default. The combiner is rendered only with `bundleService.enabled=true`.
- **The upstream chart value.** An opt-in operator chart value, `bundleService.defaultPolicy.requireClientPolicy` (default `false`), omits those two lines when it is `true`. Until that value exists, `k8s/opa-kind-enable.sh` applies a changed `default` CR after the install. A `helm upgrade` of the operator reverts it, and start check #4 then stops the Controller.
- **The sidecar on tools.** The operator injects the AuthBridge sidecar into a tool pod only when `injectTools` is on (default off). The Kind overlay sets `injectTools=true`.
- **The namespace pipelines.** The `authbridge-runtime-config` ConfigMap of each service namespace must have `opa` in the inbound pipeline, and also `mcp-parser` for a tool. Under agent side, the agents' namespaces also need `opa` in the outbound pipeline. Onboarding check #2 finds a missing plugin.
- **Pod restarts.** The webhook injects the sidecar only on pod CREATE. After a change to the pipeline or to `injectTools`, restart the agent pods and the tool pods (`rossoctl.io/type=agent` and `rossoctl.io/type=tool`).
- **The username precondition (D31).** The CRs key users by username, and `sub` is the username. So usernames must be unique, must not change and must never be used again. Keep `editUsernameAllowed: false` and `registrationAllowed: false` in the realm (the operator's realm template sets `registrationAllowed: false`; it does not set `editUsernameAllowed`, so that value is `false` only by the Keycloak default). An admin must never create a deleted username again: the new user would get the grants of the old user until AIAC writes the CRs again.
- **The subject mapper on each login client (D31).** Each login client that calls AIAC agents directly must have a `username → sub` mapper, so that the login token has `sub` = the username. `rossoctl` has it (`username-to-sub`), from a one-time manual step in the runbook. This prerequisite does not change. AIAC never changes a login client; `aiac-username-sub` covers only the exchanged tokens.
- **The legacy token exchange (optional hardening).** AIAC does not need the Keycloak feature `token-exchange` (V1) to be off: the AuthBridge requests go to the standard exchange (V2), and a request that V1 handles still gets `sub` = the username for an onboarded target (§6). Keycloak recommends to turn V1 off, because then a request that V2 declines fails with `400` ("Standard token exchange is not enabled for the requested client") and does not silently go to a different engine. `KC_FEATURES` is in the Keycloak deployment of the rossoctl platform, not in this repo. If V1 stays on, AIAC needs no change.

Detail: [`k8s/opa-kind-runbook.md`](../../k8s/opa-kind-runbook.md).

---

## 9. Testing

Tests live in `test/` (Testing) and `eval/` (Evaluation); selection is marker-only.

### Unit tests

| Target | What to mock | What to assert |
|--------|-------------|----------------|
| IdP Configuration Service endpoints | `KeycloakAdmin` methods (return fixture dicts) | Correct JSON response, 502 on Keycloak error; the reads of one service (`GET /services/{id}` and its `/roles`, `/scopes`, `/discovery-token`) and `GET /roles/{name}/composites` give `404` on a Keycloak `404` (D33); `POST /services/{id}/subject-scope` (D31) creates `aiac-username-sub` with no `aiac.managed` marker and adds the `username-to-sub` mapper with the exact config, changes an existing wrong `username-to-sub` mapper back (a `PUT` for a wrong config; a delete and an add for a wrong type; a mapper with another name is not changed), is idempotent (an existing scope, mapper or link; a `409` of a concurrent create or mapper add), moves an optional link to a default link, and gives `409` on a scope that has the marker; `GET /services/{id}/scopes` gives `200` for a client that links the unmarked scope; with the live default-scope shape (`id` and `name` only), an `aiac.managed` scope that two clients link is listed for each of them, with that client as `serviceId`, and gives no `409` (D32); the delete guards keep a shared scope or role while another owner or member is left |
| PDP Policy Writer (OPA) endpoints | Kubernetes CR write (`AuthorizationPolicy`) | 204 on success, 502 on CR write error; 422 on a body with a wrong or missing tag; 400 on a bad service id; a tool CR (name and namespace from `identity_ref`, the managed-by label, both request packages); `POST` upserts one CR per entry; `PUT` also deletes the stale labelled CRs and keeps the CRs without the label; `DELETE /policy/services/{id}` counts a 404 as success |
| Target-side Rego (`opa eval`; skips without `opa`) | No mock needed | Tool inbound: a granted `tools/call` passes, an ungranted one is denied, a deny vetoes an allow, the session messages pass only for a granted caller or for the tool's own client (the self-discovery rule, which never allows `tools/call`), other MCP methods are denied, a request with no identity is denied. Agent inbound: agent-level; a request with no identity is denied. The outbound pass-through allows. The changed combiner (both sides): no client package → deny; a client package that allows → allow; the namespace tier works as before |
| Agent-side Rego (`opa eval`; skips without `opa`) | No mock needed | An agent CR has the agent-level inbound, the per-tool outbound checks and the MCP session rule; a tool's pass-through CR allows in both request packages |
| Policy Model Store endpoints | SQLite `:memory:` database | Correct read/write/delete; 404 on missing service; 502 on SQLite write error; 503 on SQLite open/query failure at `/health`; `GET /policy/services` with no `role` returns every SPM |
| `aiac.policy.model_store.library` functions | Policy Model Store HTTP endpoints | Correct method + path per function; returns typed model on read; `RuntimeError` on non-2xx; default URL fallback |
| `aiac.policy.model` | No mock needed | `extra='ignore'` drops unknown fields; relationship maps keyed by string `id` round-trip through `model_dump(mode="json")` / `model_validate` with typed `Role` / `Scope` values preserved; a target-side body parses to `TargetSidePolicyModel` and an agent-side body to `AgentSidePolicyModel`; a body with a wrong or missing tag is rejected; for the same SPM, `project_inbound` gives the same inbound gates as `_derive`; `RoleHolders` gives an `Agent`-kind role the live services that hold it (a quarantined or deleted service is not a holder) and a `User`-kind role the current members from `get_roles()` (a role that is not listed has no holder), and merges the copies of a shared role (D32) |
| `aiac.idp.configuration.api` functions | IdP Configuration Service HTTP endpoints | Returns correct Pydantic model instances; `IdPHTTPError` (a `RuntimeError` that keeps `.status` and `.response`) on non-2xx; a `5xx` is tried up to `UPSTREAM_MAX_RETRIES` attempts in total and a `4xx` is not retried (D33); default URL fallback; `get_subjects_by_role` sends `role_id`; `get_services_by_role` / `get_services_by_scope` filter `get_services()` client-side; `link_subject_scope` sends `POST /services/{id}/subject-scope` and returns a `Scope` with `aiac_managed` = `False` (D31); `create_service_scope` / `create_service_role` reuse an object of the same name and log a `WARNING` when its description is not the same, with no Keycloak update (D32) |
| `aiac.pdp.policy.library` functions | PDP Policy Writer HTTP endpoints | Correct serialisation; correct method + path for `apply_policy` (`POST`), `replace_policy` (`PUT`), `delete_service_cr` (`DELETE /policy/services/{id}`) and `delete_policy` (`DELETE`); `RuntimeError` on non-2xx; default URL fallback |
| `aiac.policy.computation` | `aiac.idp.configuration.api`, `aiac.policy.model_store.library`, `aiac.pdp.policy.library` (import-boundary mocks) | Correct `apply_service_policy` calls per changed SPM; additive merge preserves existing rules; no duplicate rule insertion; `apply_policy` called once after all writes (not at all when the model is empty), with the policy model of the current side for the affected services only; the managed set; the zero-rule focus SPM is stored; the affected set for each side; `quarantine` and `decommission` call `delete_service_cr` for agents and tools; the resync writes every CR with `replace_policy`, leaves out the services that are not live (disabled, or absent from the IdP catalog), and quarantines the disabled ones; `bootstrap` writes the CR of a tool and stores no SPM; an unmarked scope (the D31 subject scope) is never an owned scope; the CRs get the role holders from the current `get_services()` and `get_roles()`, not from the stored `actorIds` (a later holder is added and a removed holder goes, with no new rules; a user who loses a role loses access); the routing guard keeps a shared `Agent`-kind role that has at least one live holder; `rerender_role` writes the live SPMs that use the role (under agent side, every live agent) with no SPM write and no PRB call, and the resync gives the same result when the event is missed (D32); an unknown `AIAC_ENFORCEMENT_SIDE` raises `ValueError`; exceptions logged and re-raised (propagate to the caller) |
| Keycloak SPI listener (Java, `keycloak-spi/`, `mvn test`) | `KeycloakSession`, `KeycloakTransactionManager` and the jnats `Connection` (Mockito); Keycloak's own `DefaultKeycloakTransactionManager` (test scope) | `SubjectMapper` gives the subject of each event; the publish comes only at the commit of the after-completion transaction, after the main commits; a rollback, a failed main commit, or a main commit that fails after another one, publishes nothing; with no active transaction the event is published at once; a publish failure does not throw; an event after the provider's transaction finished is dropped with a warning (D33); a `REALM_ROLE_MAPPING` `CREATE` or `DELETE` event on `users/{id}/role-mappings/realm` gives one `aiac.apply.role-members.{role-id}` for each role in the representation, and a missing or bad representation, a group path, a client-role mapping and a group membership event give no subject (D32) |
| Event Broker NATS consumer | NATS message delivery (mock `nats-py` subscription) | Correct handler dispatched per subject; ack issued on success; no ack on handler exception; a `ServiceNotVisibleError` below `MAX_DELIVER` gets a nak with a delay, and a failed nak leaves the message unacked (D33); `aiac.apply.role-members.{role-id}` calls the PCE `rerender_role` and no PRB; the consumer start creates or updates the durable consumer config (with `aiac.apply.role-members.*` in the filter subjects) before it subscribes (D32) |
| Event Broker DLQ | NATS max redelivery exceeded | Message routed to `aiac.apply.dlq` after 5 failures (a permanent failure: on the first delivery) |
| Init container health-check | HTTP 4xx then 200 sequence; NATS TCP refused then connected | Exits 0 only after NATS, IdP and PDP are healthy (RAG Ingest only when `AIAC_RAG_INGEST_URL` is set); `add_stream` called with correct config |
| Policy Guardrails Agent endpoints | ChromaDB (context reads) | TBD — pending the verification endpoint and verdict contract. **Status: not built yet** — no code. |
| AIAC Agent | IdP library (`Configuration`), Policy Store library, PCE, Kubernetes API, the LLM seam (`_structured_call`) | Route dispatch and status codes; consumer ack/DLQ; the first IdP read of an onboarding reads a `404` again for a bounded time, then gives `502` (`ServiceNotVisibleError`, D33); Provision; Provision links the subject scope (`link_subject_scope`, D31) for agents and tools, before `set_service_type`, keeps it out of the created-manifest, and gives `502` (no type set) on a failed link; the unmarked subject scope is neither an own scope nor an other scope of the PRB; Service Policy Builder rule sets; the resolver merges the holders of a shared role, and the PRB prompt lists a shared scope once while the assembly gives one rule for each owner's copy (D32); `POST /apply/role-members/{role_id}` calls `rerender_role` (D32); rollback + `quarantine` on a build failure (the rollback never deletes the subject scope); conflict `422`; the start sequence (an unknown side or a failed check #4 stops the Controller); the onboarding checks #1, #2 and #6 run before the bootstrap, Provision and the PRB, give `409`, are permanent in the consumer (DLQ at the first delivery) and run no rollback and no quarantine; a tool gets the bootstrap before Provision; the read-only route gives `200` or `404` (`test/unit/agent/`) |

### Integration tests

Offline: several AIAC units in one process, with no cluster, no Keycloak and no LLM endpoint. The tests live under `test/integration/` (a mirror of `src/aiac/`) and have `pytestmark = pytest.mark.integration`. Run them with `pytest -m integration`.

| Target | What to mock | What to assert |
|--------|-------------|----------------|
| Shared roles and scopes (D32): `test/integration/policy/computation/test_shared_roles.py` | Fakes behind the library seams (`fakes.py`): Keycloak behind `Configuration`, the Policy Model Store, the Kubernetes API of the writer; the PRB LLM seam (`_structured_call`) is stubbed. A call that gets past a fake fails the test | The real focal resolver, Service Policy Builder (with the real PRB graphs), PCE (`compute_and_apply`, `rerender_role`, `resync`) and PDP Policy Writer render work together. Across namespaces (two agents and two tools with the same workload names in `team1` and `team2`) and in one namespace (two agents with different workload names in `team1` that hold one role; the second assignment is made directly, as an admin does in Keycloak): every holder is in `source_roles` of every tool CR that grants or denies the role, for each onboarding order; each owner's SPM gets the rule for its own copy; the PRB prompt lists a shared scope once. A user who gets a role gets access and a user who loses it loses access, and a later holder appears and a removed holder goes, through the role-mapping event and through the resync. Each case fails on the code before D32 |

### System tests

Require a live rossoctl/Kind cluster with the AuthBridge OPA pipeline wired in (see `k8s/opa-kind-runbook.md`), a live Keycloak instance, and an LLM endpoint. Controlled by env vars (the repo-root `.env`):

| Variable | Description |
|----------|-------------|
| `KEYCLOAK_URL` | Keycloak base URL |
| `KEYCLOAK_ADMIN_USERNAME` | Admin username |
| `KEYCLOAK_ADMIN_PASSWORD` | Admin password |
| `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` | LLM endpoint for onboarding |
| `AIAC_TEST_REALM` | Optional: realm of the live stack (default from the scenario) |

System tests onboard through the in-cluster Controller and assert the deployed OPA plugin's allow/deny on real HTTP requests through AuthBridge. They skip cleanly when the cluster or the env is missing. Under target side, github-tool's own inbound OPA decides the tool calls, and the agent's outbound is a pass-through. A service that has no CR is denied, and a quarantine deletes the CR. The demo passes under each enforcement side, and a Controller restart with the other side moves every CR. After each workload converges, `require_subject_scope` checks that its client links `aiac-username-sub` as a default scope (D31); a missing link is a failure, not a skip. Rung 2 also checks the scope and the login client (`test_subject_scope_linked`) and the `sub` of an exchanged token (`test_exchanged_token_subject_is_username`: the harness exchanges as the agent client with its client secret, the identity that `k8s/opa-kind-enable.sh` gives AuthBridge; it skips only if the agent client uses another client authenticator). Together with `verify_subject_mapper` (the login token through `rossoctl`), these checks cover both sources of the rule. Rung 5 checks that the rollback keeps the scope (`test_rollback_keeps_the_subject_scope`).

Selection is marker-only — no path argument. `integration` (several units in-process, no cluster), `system`, `llm` (real LLM, no cluster) and `eval` are opt-in markers:

```bash
pytest                # unit only (the default)
pytest -m integration # integration only (offline, several units)
pytest -m system      # system only
pytest -m llm         # live-LLM tests only
pytest -m eval        # evaluation suite only
```

### Test & evaluation specifications

Beyond the marker-gated pytest tests above, individual tests are specified **one spec per test** under `docs/testing/` (and, for the evaluation suite, `docs/evaluation/`) — top-level siblings of `specs/`, following the same "one spec per unit" convention the component PRDs use. This section is the dedicated index of those specs (mirroring the Component Summary in §5) and grows as tests are added; each entry is a distinct test with its own spec.

| Integration test | Description | Spec |
|---|---|---|
| PDP Policy Writer — `generate_rego.py` | Standalone launcher (no Docker) that boots the OPA stub locally, applies a policy model through `aiac.pdp.policy.library`, and writes the generated Rego to a known directory for manual inspection. Write-only; not a `@pytest.mark`-tagged test. | [testing/pdp-policy-writer.md](../testing/pdp-policy-writer.md) |
| `policy-pipeline` — `test_policy_pipeline.py` | End-to-end system test of the full identity→policy→enforcement pipeline — onboards `github-agent` + `github-tool` through the in-cluster UC-1 Controller (upserting the `AuthorizationPolicy` CRs) and asserts the deployed OPA plugin's allow/deny on real requests through AuthBridge. No `.rego` dump. `@pytest.mark.system`. | [testing/policy-pipeline.md](../testing/policy-pipeline.md) |
| `uc1-onboarding-pipeline` — a **ladder** of UC-1 onboarding tests | Discovery-driven sibling of `policy-pipeline` validating the **phase-1** deliverable against **one** in-cluster AIAC stack (CR-backed writer, single abstract `policy.md`): `github-agent` + a simplified `github-tool` are deployed one at a time (each deploy registers a Keycloak client and fires the trigger); three gradual rungs drive **real event-driven UC-1 onboarding** (deploy → Keycloak SPI → NATS) — agent-only, agent→tool, tool→agent — and assert the deployed OPA plugin's allow/deny on real requests through AuthBridge (verdicts from `scenario_uc1.py`). Rungs 2/3 assert onboarding-**order-independence**. A fifth rung covers a failed onboarding (rollback + quarantine). A fourth two-policy rung is **deferred** (two-stack topology discarded). Same scenario facts/tables as `policy-pipeline`; Rego semantically similar (not byte-identical). `@pytest.mark.system`. | [testing/uc1-onboarding-pipeline.md](../testing/uc1-onboarding-pipeline.md) |
| `policy-eval-scenarios` — `test_policy_pipeline_eval.py` + guardrail tests | Generalized evaluation suite extending `policy-pipeline`'s single-agent/single-tool proof to ten scenarios: baseline-scale (many entities, names decoupled from roles, one agent→agent delegation grant), missing-details (emergent unreachability/zero-access under deny-by-default, a broad-sounding clause narrowed by an explicit qualifier, wildcard-grant expansion), adversarial-authoring (misleading names/descriptions, an identity/boundary-confusion probe, empty descriptions), and ambiguous-and-contradictory / adversarial-injection-and-edge-cases (whole-document `xfail` checks against the PRB directly, no Keycloak or `opa`). The eight heavy scenarios (scenario modules under `eval/scenarios/` except `agent_delegation`) assert full per-cell `opa eval` truth tables; the two light scenarios assert PRB-level rejection. The eight heavy scenarios carry `@pytest.mark.eval` (the five former `eval_*` markers collapsed into one flat `eval`); the two light guardrail tests live under `test/unit/agent/policy_rules_builder/` and carry `@pytest.mark.llm`. | [evaluation/policy-eval-scenarios.md](../evaluation/policy-eval-scenarios.md) |
| `policy-eval-robustness-consistency` — `test_policy_pipeline_consistency.py` + `test_policy_pipeline_robustness.py` | Companion to `policy-eval-scenarios`, reusing its 8-scenario corpus to check the PRB's raw grant decisions (no OPA/PCE/k8s) for **consistency** (`@pytest.mark.eval`: N repeated runs on the same input, exact grant-set equality) and **robustness** (`@pytest.mark.eval`: two never-blended families, each its own metric — **invariance** under mechanical text/order perturbation and a hand-reworded semantic-sibling corpus under `eval/scenarios_perturbed/`, and **sensitivity** under a deterministic, meaning-changing mechanical edit per scenario (`SENSITIVITY_EDITS`) — all checked against the truth-table oracle). Mechanical-tier invariance/sensitivity feed the committed trend log; semantic-tier sensitivity is future work (#2467). No Keycloak/`opa` needed — only `LLM_BASE_URL`/`LLM_MODEL`/`LLM_API_KEY`. | [evaluation/policy-eval-robustness-consistency.md](../evaluation/policy-eval-robustness-consistency.md) |
| `policy-eval-correctness-prb` — `test_policy_pipeline_correctness_prb.py` | Companion to `policy-eval-scenarios`/`policy-eval-robustness-consistency`, reusing the same 8-scenario corpus to score the PRB's raw grant/deny output (no OPA/PCE/k8s) against each scenario's truth table via a reusable, effect-aware scorer (`eval/correctness_scorer.py`): precision and recall tracked separately per gate and aggregated, plus a non-gating denial-precision figure for explicit `Deny` rules. `@pytest.mark.eval`, zero-tolerance over-grant gate; under-grants/incorrect denials reported only. No Keycloak/`opa` needed — only `LLM_BASE_URL`/`LLM_MODEL`/`LLM_API_KEY`. | [evaluation/policy-eval-correctness-prb.md](../evaluation/policy-eval-correctness-prb.md) |
| `policy-eval-correctness-e2e` — `test_policy_pipeline_correctness_e2e.py` | Companion to `policy-eval-correctness-prb`, scoring the same 8-scenario corpus and the same reusable scorer one layer further downstream: real Keycloak provisioning → real Policy Rules Builder → real Policy Computation Engine → real `opa eval` against the rendered Rego, sourced from the rendered data maps (`subject_role_allow/deny_scopes`, `agent_role_scopes`) rather than per-pair decision probing. `@pytest.mark.eval`, same zero-tolerance over-grant gate. The shared `pipeline` fixture (`eval/test_policy_pipeline_eval.py`, also used by the other eval suites) now provisions all 8 scenarios concurrently via `ProcessPoolExecutor`. Needs `KEYCLOAK_URL` + admin creds + `LLM_BASE_URL`/`LLM_MODEL`/`LLM_API_KEY`, plus `opa` on `PATH`. | [evaluation/policy-eval-correctness-e2e.md](../evaluation/policy-eval-correctness-e2e.md) |
| `policy-eval-scale` — `test_policy_pipeline_scale.py` | Companion to the other four `policy-eval-*` suites, but over a **procedurally generated** (not hand-authored) fixed-100-service corpus with ground truth known by construction (`eval/scale_generator.py`) — hand-authored truth tables don't scale past low double digits of entities. Two independent dimensions, never blended (**total-corpus**: many roles/scopes/services, each PRB decision still modest; **per-decision**: one role/scope facing a very large candidate list in one call), each checked by two check types (**structural**: completeness/no-duplication/no-orphans gated, latency/cost reported-only; **correctness**: the same `correctness_scorer.score_scenario`) at both PRB and end-to-end levels — eight test functions, four trend-log rows. Every independent PRB call is fanned out concurrently (`eval/scale_prb.py`) rather than run sequentially. `@pytest.mark.eval`. PRB-level cases need only `LLM_BASE_URL`/`LLM_MODEL`/`LLM_API_KEY`; end-to-end cases additionally need `KEYCLOAK_URL` + admin creds and `opa` on `PATH`. | [evaluation/policy-eval-scale.md](../evaluation/policy-eval-scale.md) |

Tracking issues: the live-Keycloak pytest integration tests in `testing/5.1-integration-tests.md`; the PDP Policy Writer integration test in `testing/5.2-pdp-writer-integration-test.md`; the policy-pipeline integration test in `testing/5.3-policy-pipeline-integration-test.md`; the UC-1 onboarding pipeline integration-test ladder in `testing/5.4-uc1-onboarding-integration-test.md` (epic) with rungs `testing/5.4.1`/`5.4.2`/`5.4.3` and the deferred two-policy `testing/5.4.4`.

---

## 10. Conventions and constraints

- Python version: ≥ 3.12 (the images run 3.13)
- Base Docker image: `python:3.13-slim` (pinned by digest)
- Linting: ruff (line length 120, target py312 per root `pyproject.toml`)
- Commits: DCO sign-off required (`git commit -s`); use `Assisted-By` not `Co-Authored-By`
- No auth on IdP Configuration Service, PDP Policy Writer, RAG Ingest Service, Policy Guardrails Agent, or Event Broker — network isolation (ClusterIP + `kubectl port-forward`; the Policy Guardrails Agent additionally has no ClusterIP exposure at all) is the access control mechanism
- The IdP Configuration Service, PDP Policy Writer, Policy Model Store, Agent, and Keycloak SPI images are built by the `.github/workflows/build.yaml` CI matrix. The Event Broker uses the stock `nats` image. The RAG Ingest Service and Policy Guardrails Agent are not built yet
- `aiac/__init__.py` exists and is empty — `aiac` is a regular package, not a namespace package
- NATS consumer must **await** handler completion before issuing ack — fire-and-forget (`asyncio.create_task`) is prohibited; premature ack breaks at-least-once delivery guarantees
- AIAC provisioning marker: every role and client scope AIAC provisions carries the Keycloak attribute `aiac.managed` = `true`, distinguishing AIAC-provisioned entities from Keycloak's built-ins (default client scopes, `default-roles-<realm>`). Realm-role attribute values are lists (`["true"]`), client-scope values are plain strings (`"true"`). The IdP Configuration Service stamps it on create and returns full role representations so it survives reads; the Policy Computation Engine filters on it (`Role.aiac_managed` / `Scope.aiac_managed`) when embedding each agent's own roles/scopes (P2). One exception: the subject scope `aiac-username-sub` (D31) has no marker, because every managed client shares it. So it never becomes an own scope of a service
- Names of the AIAC-provisioned roles and scopes: `<workload>.<tool|skill>` (Provision; an agent with no synced skills gets `<workload>.access`). The name has no namespace. Provision reuses a role or a scope of the same name, also across namespaces. This is by design (D32): a realm is a tenant, and one policy covers all AIAC-managed services in the realm, so the two `github-tool`s of `team1` and `team2` share their scopes. A reused object keeps its first description; a different new description gives a warning in the log and no Keycloak update
