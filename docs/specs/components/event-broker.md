# Component PRD: Event Broker

## Description

A NATS JetStream pod that decouples event producers from the AIAC Agent. Producers (Keycloak SPI listener, RAG Ingest Service) publish lightweight trigger events to named NATS subjects. The AIAC Agent subscribes as a durable competing consumer, guaranteeing at-least-once delivery and automatic replay of unprocessed events after pod restarts.

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
| Authentication | None — ClusterIP network isolation is the access control mechanism |
| Dead-letter subject | `aiac.apply.dlq` |
| Max delivery attempts | 5 — after the 5th failed delivery, the Agent consumer republishes the message to `aiac.apply.dlq` and calls `term()`. A permanent error (`PolicyConflictError`, `PolicyContradictionError`, `PolicyRulesBuilderError`, `UnparseableLLMResponseError`) goes to the DLQ on the first delivery |

---

## Subjects

| Subject | Publisher | Consumer | Trigger |
|---|---|---|---|
| `aiac.apply.service.{id}` | Keycloak SPI listener | AIAC Agent | Keycloak `CLIENT_CREATED` event |
| `aiac.apply.role.{role-name}` (percent-encoded, so the name stays one NATS token) | Keycloak SPI listener | AIAC Agent | Keycloak role created/updated |
| `aiac.apply.policy.build` | RAG Ingest Service | AIAC Agent | Post-ingest completion (any collection) |
| `aiac.apply.dlq` | AIAC Agent consumer (republish + `term()`) | Operator (manual inspection) | Max delivery attempts reached, or a permanent handler error |

**Status: not built yet** — the role and build handlers (`update_role`, `build_policy`) are stubs, and the RAG Ingest Service (the `aiac.apply.policy.build` publisher) does not exist.

**`rebuild` and `offboard` are not routed through the Event Broker.** They are operator-only commands, issued directly via `POST /apply/policy/rebuild` and `POST /apply/offboard/{service_id}` on the AIAC Agent using `kubectl port-forward`.

---

## Message Payload

All messages carry a minimal JSON payload containing only the entity ID:

```json
{ "id": "<entity-id>" }
```

For `aiac.apply.policy.build`, the payload is empty (`{}`). The AIAC Agent pulls all required state from the IdP Configuration Service at processing time — the event payload is a trigger, not a data carrier.

---

## Delivery Guarantees

- **At-least-once delivery** — NATS redelivers any message not acknowledged within the `AckWait` window.
- **Exactly-one processing** — the Agent subscribes via a queue group (`aiac-agent-consumer`). Only one Agent pod receives each message; other pods in the group are not notified.
- **Replay on restart** — `WorkQueuePolicy` retains all unacknowledged messages. A restarted Agent pod automatically receives pending messages on reconnection.
- **DLQ on repeated failure** — after the 5th failed delivery (or on the first delivery for a permanent error), the Agent consumer republishes the message to `aiac.apply.dlq` for operator inspection and terminates it. The consumer does not call `term()` until the DLQ publish is confirmed. No message is silently dropped.

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
| Agent NATS consumer dispatch | NATS message delivery | Correct `/apply/*` handler invoked for each subject pattern; message acked on success; message left unacked on a retryable exception; a permanent exception goes to the DLQ and `term()` on the first delivery |
| DLQ routing | NATS max redelivery exceeded | Message appears on `aiac.apply.dlq` after 5 failures |
