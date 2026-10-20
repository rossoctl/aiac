# Component PRD: PDP Policy Library (`aiac.pdp.policy.library`)

HTTP client module wrapping the PDP Policy Writer (OPA) REST API. These modules have no dependency on Keycloak — all IdP operations use `aiac.idp.configuration`.

## Location
`src/aiac/pdp/policy/library/`

## Package structure

```
src/aiac/pdp/policy/
└── library/
    ├── __init__.py     # empty
    └── api.py          # apply_policy, replace_policy, delete_service_cr, delete_policy
```

All `__init__.py` files are empty. Callers use explicit submodule paths:

```python
from aiac.pdp.policy.library.api import apply_policy, replace_policy, delete_service_cr, delete_policy
from aiac.policy.model.models import PolicyModel
```

---

## Submodule: `aiac.pdp.policy.library.api`

### Description
HTTP client module wrapping the PDP Policy Writer REST API. Exposes four module-level functions. Service URL is read from the `AIAC_PDP_POLICY_URL` environment variable (default: `http://127.0.0.1:7072`). All functions raise `RuntimeError` on non-2xx response. Every request has a timeout (`AIAC_PDP_HTTP_TIMEOUT`, default 60 s), so a hung writer (for example a stuck Kubernetes API) cannot block the caller, which holds the PCE lock, for an unlimited time. A request that times out raises the `requests` timeout error.

No `realm` parameter — the PDP Policy Writer operates on a Kubernetes CR, not a Keycloak realm.

**Primary consumer:** `aiac.policy.computation` — the Policy Computation Engine is the only caller. AIAC Agent sub-UC agents do not call this library directly; they call `compute_and_apply` instead.

### Dependencies
```
requests
pydantic
python-dotenv
```

### Functions

```python
def apply_policy(model: PolicyModel) -> None
    # POST /policy — upsert one CR per entry of the (partial) policy model.
    # No rollback on a partial failure.

def replace_policy(model: PolicyModel) -> None
    # PUT /policy — replace: upsert one CR per entry of the full policy model,
    # then delete every other CR that has the managed-by label.

def delete_service_cr(service_id: str) -> None
    # DELETE /policy/services/{service_id} — delete the CR of one service
    # (agent or tool). A Kubernetes 404 counts as success.

def delete_policy() -> None
    # DELETE /policy — delete every CR that has the managed-by label.
```

The `model` of `apply_policy` and `replace_policy` is the policy model `PolicyModel(services=[...])` (D18a): the stored SPMs, one per callee. The writer parses the body as `PolicyModel`. The writer rejects with **422** a body without `services` (see [`pdp-policy-writer-opa.md` → The policy model](pdp-policy-writer-opa.md#the-policy-model-policymodel-d18a)). An **entry** is one CR: each `services[]` SPM. See [`policy-model.md`](policy-model.md) and [`pdp-policy-writer-opa.md`](pdp-policy-writer-opa.md).

`service_id` is the clientId (it can contain `/`). The library URL-encodes it into one safe path segment before it builds the URL. The writer takes the CR name and namespace from `identity_ref(service_id)`. The writer returns `204` on success, `422` for a bad body, and `502` for a Kubernetes API failure. A bad id (one that gives no CR identity) is not an error: each write route logs it and skips it (`POST` and `PUT` skip its entry, and `DELETE /policy/services/{service_id:path}` has nothing to delete). The library raises `RuntimeError` on every non-2xx response.

### Routes and callers (D18c)

| Function | Route | AIAC caller | When |
|----------|-------|-------------|------|
| `apply_policy` | `POST /policy` | the PCE | At the end of each `compute_and_apply` run, with the affected services (D23). In `quarantine` and `decommission`, to redeploy the affected services. In `rerender_role` (D32; the role-members event and `POST /apply/role-members/{role_id}`), to render the CRs that use the role again with its current holders, with no PRB call and no SPM write: the live stored SPMs that have an edge of the role. No call when the set is empty (see [policy-computation-engine.md → Role re-render](policy-computation-engine.md#role-re-render-rerender_role)). In `bootstrap`, to write the focus tool's first CR before UC-1 Provision. |
| `replace_policy` | `PUT /policy` | the PCE | In `resync()` at every Controller start (D28), with the full policy model. The UC-2b rebuild also ends with it, through the PCE (D28a). |
| `delete_service_cr` | `DELETE /policy/services/{service_id}` | the PCE | In `quarantine` and `decommission` (D20), for an agent and for a tool. In `drop_bootstrap`, for a tool that has no stored SPM: it deletes the bootstrap CR after a failed onboarding that ran no quarantine. |
| `delete_policy` | `DELETE /policy` | none (C1) | An operator tool only. |

There is no no-rules CR: the quarantine deletes the CR.

**`delete_policy` has no AIAC caller (C1).** The UC-2b rebuild ends with `replace_policy`. It does not start with `delete_policy`, so there is no deny window (D28a). Under D20 the global combiner denies a pod that has no client CR, so `delete_policy` **denies every managed pod** until the next resync writes the CRs again.

**Status: not built yet** — the UC-2b rebuild (`src/aiac/agent/uc/policy_update/rebuild.py`) is a stub that returns `([], True)`, so the rebuild does not call `replace_policy` yet.

Known limits:

- **The poll delay.** A `204` means that the CR is written, not that OPA enforces it. A CR change takes effect at the next poll of the OPA plugin in the pod (10 s min, up to 120 s). This applies to each upsert and each delete.
- **One CR per ServiceAccount.** The CR name and namespace come from the ServiceAccount in the SPIFFE ID. Pods that share a ServiceAccount share one CR and one bundle.

### Configuration

Read from the environment (or `.env` file co-located with `api.py`). Falls back to the default if absent. `AIAC_PDP_HTTP_TIMEOUT` is read at each call. An unset, non-numeric, non-finite, zero or negative value falls back to `60`, so a bad value does not stop the Controller at import.

| Variable | Default |
|----------|---------|
| `AIAC_PDP_POLICY_URL` | `http://127.0.0.1:7072` |
| `AIAC_PDP_HTTP_TIMEOUT` | `60` (seconds, per request; longer than the store's `AIAC_HTTP_TIMEOUT`, because one `PUT /policy` writes every CR) |

### Usage

```python
from aiac.pdp.policy.library.api import apply_policy, replace_policy, delete_service_cr, delete_policy
from aiac.policy.model.models import PolicyModel

# A run: upsert the CRs of the affected services (called by the PCE)
apply_policy(PolicyModel(services=[tool_spm, agent_spm]))

# The resync at the Controller start: replace every AIAC CR (called by the PCE)
replace_policy(PolicyModel(services=every_stored_spm))

# The quarantine or the decommission: delete the CR of one service (called by the PCE)
delete_service_cr("team1/github-tool")

# Operator tool only, no AIAC caller: delete every AIAC CR (under D20 this denies every managed pod)
delete_policy()
```

---

## Testing Decisions

**Seam:** HTTP boundary — mock responses from `AIAC_PDP_POLICY_URL`.

Key behaviors to assert:
- `apply_policy(model)` issues `POST /policy` with the serialized policy model (its `services` list).
- `replace_policy(model)` issues `PUT /policy` with the serialized policy model.
- `delete_service_cr(id)` issues `DELETE /policy/services/{id}`, with a slash-bearing `id` encoded as one path segment.
- `delete_policy()` issues `DELETE /policy`.
- Any non-2xx response raises `RuntimeError`.
- Every call sends the timeout (`AIAC_PDP_HTTP_TIMEOUT`).
- `AIAC_PDP_POLICY_URL` is read from env; falls back to `http://127.0.0.1:7072`.

---

## Out of Scope

- **Keycloak interaction:** this library never calls Keycloak directly. All IdP operations go through `aiac.idp.configuration`.
- **Policy computation:** translating `list[PolicyRule]` into the policy model is the responsibility of `aiac.policy.computation`, not this library.
- **Policy persistence:** the Policy Model Store (`aiac.policy.model_store`) owns structured `ServicePolicyModel` durability. This library targets the OPA runtime only.

---

## Further Notes

- The `aiac.pdp.library.policy` module (old path) has been removed. All consumers import from `aiac.pdp.policy.library.api`.
- The model `PolicyModel` is imported from `aiac.policy.model.models`, not from the removed `aiac.pdp.library.models`.
- The name `delete_service_cr` is different from the store library's `delete_service_policy` on purpose. The PCE calls both in the quarantine and the decommission: one deletes the CR, the other deletes the SPM. `drop_bootstrap` calls only `delete_service_cr`: the tool has no SPM.
