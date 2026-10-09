# Component PRD: Event Broker

## Description

A NATS JetStream pod that decouples event producers from the AIAC Agent. Producers (Keycloak SPI listener, RAG Ingest Service) publish lightweight trigger events to named NATS subjects. The AIAC Agent subscribes as a durable competing consumer, guaranteeing at-least-once delivery and automatic replay of unprocessed events after pod restarts. The guarantee starts at the stream: the Keycloak SPI publish itself is at most once (see [Delivery Guarantees](#delivery-guarantees)).

The Event Broker is a single-node NATS JetStream instance. It owns no business logic — it is a pure transport layer. All policy decisions, orchestration, and state remain in the AIAC Agent.

---

## Stream Configuration

| Property | Value |
|---|---|
| Stream name | `aiac-events` |
| Subjects | `aiac.apply.>` |
| Retention policy | `WorkQueuePolicy` — message deleted from stream after acknowledgement |
| Consumer name | `aiac-agent-consumer` |
| Consumer type | Durable push consumer with queue group (competing consumers) |
| Consumer filter subjects | `aiac.apply.service.*`, `aiac.apply.role.*`, `aiac.apply.role-members.*`, `aiac.apply.policy.build` (`CONSUMER_FILTER_SUBJECTS`, `stream.py`). Not the DLQ subject, so the consumer never gets a dead-lettered message again. At each start, the Agent updates an existing durable consumer to this config (see [Consumer config at start](#consumer-config-at-start)) |
| Authentication | None — ClusterIP network isolation is the access control mechanism |
| Dead-letter subject | `aiac.apply.dlq` |
| Max delivery attempts | 5 — after the 5th failed delivery, the Agent consumer republishes the message to `aiac.apply.dlq` and calls `term()`. A permanent error (`PolicyConflictError`, `PolicyContradictionError`, `PolicyRulesBuilderError`, `UnparseableLLMResponseError`, `EnforcementPreconditionError`) goes to the DLQ on the first delivery. A nak with a delay (see [Delivery Guarantees](#delivery-guarantees)) also uses one of the 5 deliveries |
| Ack wait | `600` s (`ACK_WAIT_SECONDS`, sized for long LLM onboardings) |

---

## Subjects

| Subject | Publisher | Consumer | Trigger |
|---|---|---|---|
| `aiac.apply.service.{id}` | Keycloak SPI listener | AIAC Agent | Keycloak `CLIENT_CREATED` event (published after the Keycloak commit, see [Delivery Guarantees](#delivery-guarantees)) |
| `aiac.apply.role.{role-name}` (percent-encoded, so the name stays one NATS token) | Keycloak SPI listener | AIAC Agent | Keycloak role created/updated (published after the Keycloak commit) |
| `aiac.apply.role-members.{role-id}` (the Keycloak role id, a UUID: one NATS token, no encoding) | Keycloak SPI listener | AIAC Agent (the PCE `rerender_role`, no PRB run) | A user or an agent service account gets or loses a realm role: admin event `REALM_ROLE_MAPPING`, `CREATE` or `DELETE`, on `users/{user-id}/role-mappings/realm`. One subject for each role in the event representation. Published after the Keycloak commit ([D32](../PRD.md#key-architectural-decisions), see [Role-membership events](#role-membership-events)) |
| `aiac.apply.policy.build` | RAG Ingest Service | AIAC Agent | Post-ingest completion (any collection) |
| `aiac.apply.dlq` | AIAC Agent consumer (republish + `term()`) | Operator (manual inspection) | Max delivery attempts reached, or a permanent handler error |

**Status: not built yet** — the role and build handlers (`update_role`, `build_policy`) are stubs, and the RAG Ingest Service (the `aiac.apply.policy.build` publisher) does not exist. The `aiac.apply.role-members.{role-id}` path is built in the Agent (consumer, route and PCE) and deployed: the listener that publishes it is in the SPI jar of this repo, and the platform Keycloak runs it since 2026-10-08. A lost event gets to the CRs only through the resync at each Controller start, the operator route `POST /apply/role-members/{role_id}`, or a later PCE run that touches an SPM that uses the role (for example a `compute_and_apply`, a quarantine or a decommission; each one renders with the current holders). A run deploys every SPM that it touches. Under agent side, a holder that lost a role is re-derived only when the stored snapshot of a touched SPM names it. See [PRD → Role members · a new render](../PRD.md#role-members--a-new-render-aiacapplyrole-membersrole-id).

**`rebuild` and `offboard` are not routed through the Event Broker.** They are operator-only commands, issued directly via `POST /apply/policy/rebuild` and `POST /apply/offboard/{service_id}` on the AIAC Agent using `kubectl port-forward`.

---

## Message Payload

All messages carry a minimal JSON payload containing only the entity ID:

```json
{ "id": "<entity-id>" }
```

For `aiac.apply.policy.build`, the payload is empty (`{}`). For `aiac.apply.role-members.{role-id}`, the `id` is the role id. The AIAC Agent pulls all required state from the IdP Configuration Service at processing time — the event payload is a trigger, not a data carrier. The consumer reads the id from the subject, not from the payload.

---

## Delivery Guarantees

- **The Keycloak SPI publishes after the commit, at most once** ([D33](../PRD.md#key-architectural-decisions)). Keycloak calls the listener before it commits the change. Thus the listener only queues the subject, and publishes it from an after-completion transaction: one transaction for each listener-provider instance (Keycloak creates one provider for each `AdminEventBuilder`, in practice one for each admin request). See [`keycloak-spi/README.md` → Publish after the commit](../../../keycloak-spi/README.md#publish-after-the-commit).
  - A rollback, or a failed commit, publishes nothing. Thus a rolled-back create gives no phantom event. Keycloak commits the main transactions one by one: if one fails after another one has committed the change, the change can be saved with no event.
  - With no active transaction, the listener publishes at once.
  - The publish goes to core NATS, with no acknowledgement and no outbox. If the listener has no usable NATS connection at commit time (it never connected, or the client closed it after its reconnect budget), it logs a warning and drops the event. During a short reconnect, the NATS client keeps the publish in its reconnect buffer and sends it after the reconnect. If Keycloak stops between the commit and the publish, the event is lost with no log. Recovery for each lost event: start the onboarding by hand (`POST /apply/service/{uuid}` on the AIAC Agent). For a lost role-membership event: the resync at the next Controller start, or `POST /apply/role-members/{role_id}` on the AIAC Agent (see [Role-membership events](#role-membership-events)).
  - The guarantees below apply only from the stream onward.
- **At-least-once delivery** — NATS redelivers any message not acknowledged within the `AckWait` window (600 s), or after the delay of a nak (see below).
- **Delayed nak for a service that is not visible yet** — when the IdP still answers `404` for a new service after the UC1 Orchestrator's bounded wait on the first read, the handler raises `ServiceNotVisibleError`. Below `MAX_DELIVER`, the Agent consumer naks only this error with a delay: `AIAC_NOT_VISIBLE_NAK_DELAY_SECONDS` (default `30` s; an Agent env knob, not set in `k8s/`). NATS then redelivers the message after the delay, not after `AckWait`. Each nak uses one of the 5 deliveries. When the 5th delivery fails, the consumer moves the message to the DLQ with no nak, as for every other retryable error. If the nak itself fails, the message stays unacked, and NATS redelivers it after `AckWait`. See [`aiac-agent.md` → Ack contract](aiac-agent.md#ack-contract).
- **One consumer at a time** — the Agent subscribes via a queue group (`aiac-agent-consumer`). Only one Agent pod receives each delivery of a message; other pods in the group are not notified. A redelivery (after `AckWait`, or after the delay of a nak) can run a handler again for the same event, so the handlers are replay-safe.
- **Replay on restart** — `WorkQueuePolicy` retains all unacknowledged messages. A restarted Agent pod automatically receives pending messages on reconnection.
- **DLQ on repeated failure** — after the 5th failed delivery (or on the first delivery for a permanent error), the Agent consumer republishes the message to `aiac.apply.dlq` for operator inspection and terminates it. The consumer does not call `term()` until the DLQ publish is confirmed. No message is silently dropped.

### Role-membership events

`aiac.apply.role-members.{role-id}` ([D32](../PRD.md#key-architectural-decisions)) tells the Agent that the holders of a role changed: a user or an agent service account got or lost the realm role. A membership change does not change the policy (role → scope). It changes only who holds the role, and the CRs contain the holders. So the Agent consumer calls the PCE `rerender_role(role_id)` in the thread pool. That function renders again the CRs that use the role, with the current holders from the IdP. It makes no PRB run and writes no SPM. The consumer calls no use-case handler and no `compute_and_apply`, and it re-enables no client. See [`policy-computation-engine.md`](policy-computation-engine.md) for `rerender_role`.

- **Ack.** On success, the consumer acks the message. A failure of `rerender_role` (an IdP, Policy Store or PDP error) is retryable: the message stays unacked, NATS redelivers it after `AckWait`, and after the 5th failed delivery it goes to `aiac.apply.dlq`. There is no nak with a delay for this subject. See [`aiac-agent.md` → Ack contract](aiac-agent.md#ack-contract).
- **Idempotent, order-free.** Each run reads the current holders. So a redelivery or a duplicate gives the same CRs, and the order of two events for one role does not change the result: the last run shows the current members. The Agent runs one replica, and the PCE lock (D22) serializes the run with the other PCE operations.
- **Provision makes the event too.** UC1 Provision maps each role to the service account of the service (`assign_role_to_service`), also a role that it reuses by name. A UC1 rollback unmaps only the roles that this run created (the created-manifest), and deletes each of these roles that then has no member. Each mapping and each unmap is a `REALM_ROLE_MAPPING` event, so each gives `aiac.apply.role-members.{role-id}`. This is correct: when a new agent gets a shared role, the CRs that use the role get the new holder at once. A repeat mapping of a role that the service account already has (the re-map of a reused role) also gives the event: Keycloak sends it for each request that is not empty. A new role has no SPM edge, so its event changes no decision. Under target side it changes no CR. Under agent side, `rerender_role` writes the CR of every live stored agent again, because an agent that lost a role is not in the current holders (a known limit, G-18). A reused (shared) role stays mapped to the disabled client, so the rollback gives no event for it. The quarantine renders the CRs that use that role again without the client, because a disabled service is not a holder (D32). A role that is deleted before the consumer handles its event still renders again: its edges get no holder (fail closed).
- **Not covered (known limit).** The SPI drops a role held through a group (`groups/...` paths, `GROUP_MEMBERSHIP`) and a client-role mapping (`CLIENT_ROLE_MAPPING`). A missing or bad event representation is logged and dropped. A role delete gives no event: the SPI drops `REALM_ROLE` (or `CLIENT_ROLE`) `DELETE`, and Keycloak removes the mappings of the role with no `REALM_ROLE_MAPPING` event. A user delete (also of the service account of a deleted client) gives no `REALM_ROLE_MAPPING` event. In these cases the CRs keep the old holders until the resync at the next Controller start, or until `POST /apply/role-members/{role_id}` (see *A lost event* below). See [`keycloak-spi/README.md` → Known limits](../../../keycloak-spi/README.md#known-limits).
- **A lost event.** The publish is at most once (see above). The resync at each Controller start (D28) renders every CR with the current holders, so it repairs a lost event. To repair it at once, call `POST /apply/role-members/{role_id}` on the AIAC Agent. Until then, a user who lost the role keeps access, and a user who got the role is denied.

### Consumer config at start

nats-py `subscribe()` uses its `config` argument only to create a missing durable consumer. For an existing durable consumer, it reads `consumer_info` and binds with the config that the server has, with no compare. So without a change, a new filter subject (for example `aiac.apply.role-members.*`) does not get to a running cluster where `aiac-agent-consumer` exists. Thus the Agent consumer start runs `ensure_consumer` (`stream.py`) after `ensure_stream` and before `subscribe()`:

- **No consumer:** no call. `subscribe()` creates it from `consumer_config()`, with a new deliver inbox and the deliver group `aiac-agent-consumer`.
- **The consumer matches:** its filter subjects (in any order), ack policy, `max_deliver` and `ack_wait` are the ones of the code. No call.
- **Else:** `add_consumer` with the config that the server has, and only these four fields changed. On an existing durable name, JetStream takes this as an update. Every other field stays as the server has it, also the deliver subject and the deliver group, so the push/queue binding does not change. JetStream updates the filter subjects, `max_deliver` and `ack_wait` in place. It refuses a change of the ack policy, the deliver policy, the replay policy, the heartbeat, flow control, and the deliver subject of a bound push consumer. If JetStream refuses the update, the consumer start logs the error and tries again with backoff, and the Agent consumes no event. Then delete the durable consumer (for example `nats consumer rm aiac-events aiac-agent-consumer` from a `nats-box` pod) and restart the Agent: `subscribe()` then creates it again. The stream keeps the unacked messages (`WorkQueuePolicy`), and the new consumer (deliver policy `all`) gets them.

The start sequence runs the resync before the consumer starts. So an event that the old filter did not get is repaired at the same start.

---

## Configuration

| Variable | Default | Source |
|---|---|---|
| `NATS_URL` | `nats://aiac-event-broker-service:4222` | ConfigMap (`aiac-pdp-config`) |

No authentication credentials are required. The NATS server runs with no-auth configuration.

---

## Runtime

- Image: `nats:2.14-alpine` with JetStream enabled (`-js` flag)
- Bind: `0.0.0.0:4222` (NATS client port)
- Kubernetes ClusterIP service: `aiac-event-broker-service:4222`
- Base image: official `nats` Docker image

---

## Kubernetes Manifest

`k8s/event-broker-deployment.yaml` — NATS JetStream Pod Deployment + ClusterIP Service.

---

## AIAC Init Container

A dedicated `aiac-init` init container runs in the **Agent Pod** before the Agent container starts. It orchestrates the AIAC startup sequence.

1. **Wait for NATS** — poll `aiac-event-broker-service:4222` until TCP connection succeeds.
2. **Wait for IdP Configuration Service** — poll `AIAC_PDP_CONFIG_URL/health` until HTTP 200.
3. **Wait for PDP Policy Writer** — poll `AIAC_PDP_POLICY_URL/health` until HTTP 200.
4. **Wait for RAG Ingest Service** — poll `AIAC_RAG_INGEST_URL/health` until HTTP 200 (confirms ChromaDB in the same RAG pod is also up). Optional: the init container skips this step when `AIAC_RAG_INGEST_URL` is not set (the RAG Pod is not built yet).
5. **Create NATS JetStream stream** — call `js.add_stream()` idempotently with the `aiac-events` stream configuration. Safe to call on every restart.

The init container reuses the AIAC Agent image (`python:3.13-slim`) with a command override (`python -m aiac.agent.init.wait_and_provision`). Code: `src/aiac/agent/init/wait_and_provision.py`. It is version-controlled alongside the Agent. All dependency URLs are read from the `aiac-pdp-config` ConfigMap.

### Init Container Configuration

| Variable | Source | Resolves to |
|---|---|---|
| `NATS_URL` | ConfigMap (`aiac-pdp-config`) | `nats://aiac-event-broker-service:4222` |
| `AIAC_PDP_CONFIG_URL` | ConfigMap (`aiac-pdp-config`) | `http://aiac-pdp-config-service:7071` |
| `AIAC_PDP_POLICY_URL` | ConfigMap (`aiac-pdp-config`) | `http://aiac-pdp-policy-service:7072` |
| `AIAC_RAG_INGEST_URL` | ConfigMap (`aiac-pdp-config`) | `http://aiac-rag-service:7073` |

**Status: not built yet** — `AIAC_RAG_INGEST_URL` is not in the `aiac-pdp-config` ConfigMap yet. It is optional.

### Init Container Dependencies

The dependencies come from the Agent image's `src/aiac/agent/controller/requirements.txt` (`nats-py`, `httpx`, `tenacity`, …).

---

## Testing

| Target | What to mock | What to assert |
|---|---|---|
| Init container health-check loop | HTTP 4xx then 200 sequence | Exits 0 only after NATS, IdP Configuration Service and PDP Policy Writer respond healthy (RAG Ingest only when `AIAC_RAG_INGEST_URL` is set) |
| Init container stream creation | NATS JetStream `add_stream` call | Called with correct stream name, subjects, and retention policy; idempotent on second call |
| Agent NATS consumer dispatch | NATS message delivery | Correct `/apply/*` handler invoked for each subject pattern; message acked on success; message left unacked on a retryable exception; a `ServiceNotVisibleError` below `MAX_DELIVER` is nak'd with the delay, and a failed nak leaves it unacked (no DLQ); a permanent exception goes to the DLQ and `term()` on the first delivery; `aiac.apply.role-members.{role-id}` calls the PCE `rerender_role` in the thread pool (no use-case handler, no `compute_and_apply`), and `aiac.apply.role.role-members` stays a role subject |
| Agent consumer config at start | `consumer_info` / `add_consumer` (a server-shaped `ConsumerInfo`) | No consumer: no `add_consumer` (the subscribe creates it); a consumer with old filter subjects, `max_deliver` or `ack_wait`: one `add_consumer` with the new fields and the same deliver subject and deliver group; a matching consumer: no call; a refused update raises; the start calls `ensure_consumer` after `ensure_stream` and before `subscribe` |
| DLQ routing | NATS max redelivery exceeded | Message appears on `aiac.apply.dlq` after 5 failures |
