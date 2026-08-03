# Component PRD: Policy Guardrails Agent

## Description

A FastAPI verification service co-located with ChromaDB and the RAG Ingest Service in the RAG Pod. It sits between the RAG Ingest Service and ChromaDB: before any document from an ingest request is written, the RAG Ingest Service calls the Policy Guardrails Agent to obtain a verdict on that document. It is reachable only on the RAG Pod's loopback network (`localhost:7075`) — it is not exposed on the `aiac-rag-service` ClusterIP Service, so the RAG Ingest Service is structurally the only caller.

The agent evaluates one document per call. It may query the co-located ChromaDB instance for evaluation context, including the current (pre-update) version of the same `doc_id` when one exists.

The concrete checks the agent performs are **not yet defined** — see [Open decisions (TBD)](#open-decisions-tbd). This spec fixes the agent's place in the architecture and its contract with the RAG Ingest Service so that scope can be filled in without changing wiring.

## Endpoints

**TBD.** The verification route's path, request schema, and verdict/findings response model are unresolved — see [Open decisions (TBD)](#open-decisions-tbd). A `/health` endpoint is expected, following the convention used by every other AIAC service.

## Verification contract

These behaviors are fixed regardless of what the endpoint surface ends up looking like:

- Invoked by the RAG Ingest Service on all 12 write endpoints (`replace` and `update`, each across `text`/`file`/`url`) for every collection slug in `AIAC_RAG_COLLECTIONS`. `DELETE /ingest/{collection}/{doc_id}` is exempt — removal introduces no new text to verify.
- Called once per document. A multi-document request (a multi-doc `replace` body, or a multipart `/file` upload with several files) results in one call per document.
- **Pre-flight**: every document in a request is verified before the RAG Ingest Service makes any ChromaDB mutation for that request.
- **All-or-nothing**: if any document in a request is rejected, the whole ingest request fails and nothing is written — the collection is left exactly as it was. This preserves the RAG Ingest Service's existing collection-level atomicity guarantee for `replace`.
- **Fail-closed**: if the agent is unreachable, times out, or errors, the RAG Ingest Service treats this as a failure and writes nothing. `AIAC_GUARDRAILS_ENABLED` (on the RAG Ingest Service) is the explicit operator off-switch — with it set to `false` the RAG Ingest Service skips verification entirely. This keeps "guardrails disabled" distinguishable from "guardrails enabled but broken."
- No Event Broker interaction. The agent neither publishes nor consumes NATS subjects. The RAG Ingest Service's existing `aiac.apply.policy.build` publish behavior is unchanged: a fail-closed rejection means the ingest request never succeeds, so the build event is simply never published for that request.

## Configuration

| Variable | Default | Source |
|----------|---------|--------|
| `CHROMA_URL` | `http://localhost:8000` | ConfigMap |

Corresponding variables on the **RAG Ingest Service** side (documented in [rag-ingest-service.md](rag-ingest-service.md)): `AIAC_GUARDRAILS_URL`, `AIAC_GUARDRAILS_ENABLED`, `AIAC_GUARDRAILS_TIMEOUT_SECONDS`.

LLM API and Secret wiring (base URL, model, API key) are deferred until the check set is defined — see [Open decisions (TBD)](#open-decisions-tbd).

## Runtime

- Framework: FastAPI with uvicorn
- Bind: `0.0.0.0:7075`
- Base image: `python:3.12-slim`

## Dependencies (`requirements.txt`)

```
fastapi
uvicorn[standard]
httpx
chromadb
```

(LLM / agent framework client TBD — depends on the chosen check implementation)

## Open decisions (TBD)

1. **Responsibilities and check set** — what the agent actually verifies (e.g. prompt-injection / adversarial content, policy hygiene, contradiction against the existing corpus). Not yet defined.
2. **Endpoint surface and verdict model** — the verification route's path, request body shape, and how a verdict (and any findings) is represented in the response.
3. **LLM wiring** — whether checks are LLM-backed, and if so which `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY`-equivalent configuration and Secret references are required.
4. **Findings persistence** — whether rejection findings are only returned synchronously in the response, or also persisted somewhere for audit.
5. **Operator override** — whether an operator can force-accept a rejected document, and if so through what path.
