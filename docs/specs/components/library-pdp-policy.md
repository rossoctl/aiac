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
from aiac.policy.model.models import PolicyModel, TargetSidePolicyModel, AgentSidePolicyModel
```

---

## Submodule: `aiac.pdp.policy.library.api`

### Description
HTTP client module wrapping the PDP Policy Writer REST API. Exposes four module-level functions. Service URL is read from the `AIAC_PDP_POLICY_URL` environment variable (default: `http://127.0.0.1:7072`). All functions raise `RuntimeError` on non-2xx response.

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

The `model` of `apply_policy` and `replace_policy` is a subclass of the policy model (D18a): a `TargetSidePolicyModel` or an `AgentSidePolicyModel`. The library sends it with its `enforcement_side` tag. The writer parses the body as `AnyPolicyModel` (a discriminated union on the tag) and dispatches the render on the subclass. A body with a wrong or missing tag gets **422**. An **entry** is one CR: under target side, each `services[]` SPM; under agent side, each `agents[]` APM (the agent CR) and each `pass_through[]` clientId (a pass-through CR). See [`policy-model.md`](policy-model.md) and [`pdp-policy-writer-opa.md`](pdp-policy-writer-opa.md).

`service_id` is the clientId (it can contain `/`). The library URL-encodes it into one safe path segment before it builds the URL. The writer takes the CR name and namespace from `identity_ref(service_id)`. The writer returns `204` on success, `400` for a bad id, `422` for a bad body, and `502` for a Kubernetes API failure. The library raises `RuntimeError` on every non-2xx response.

### Routes and callers (D18c)

| Function | Route | AIAC caller | When |
|----------|-------|-------------|------|
| `apply_policy` | `POST /policy` | the PCE | At the end of each `compute_and_apply` run, with the affected services (D23). In `quarantine` and `decommission`, to redeploy the affected services. In `bootstrap`, to write the focus tool's first CR before UC-1 Provision. |
| `replace_policy` | `PUT /policy` | the PCE | In `resync()` at every Controller start (D28), with the full policy model of the current side. The UC-2b rebuild also ends with it, through the PCE (D28a). |
| `delete_service_cr` | `DELETE /policy/services/{service_id}` | the PCE | In `quarantine` and `decommission` (D20), for an agent and for a tool. |
| `delete_policy` | `DELETE /policy` | none (C1) | An operator tool only. |

The retired routes `POST /policy/agents/{agent_id}` and `DELETE /policy/agents/{agent_id}` and their functions `apply_agent_policy` and `delete_agent_policy` are removed. There is no no-rules CR: the quarantine deletes the CR.

**`delete_policy` has no AIAC caller (C1).** The UC-2b rebuild ends with `replace_policy`. It does not start with `delete_policy`, so there is no deny window (D28a). Under D20 the global combiner denies a pod that has no client CR, so `delete_policy` **denies every managed pod** until the next resync writes the CRs again.

**Status: not built yet** — the UC-2b rebuild (`src/aiac/agent/uc/policy_update/rebuild.py`) is a stub that returns `([], True)`, so the rebuild does not call `replace_policy` yet.

Known limits:

- **The poll delay.** A `204` means that the CR is written, not that OPA enforces it. A CR change takes effect at the next poll of the OPA plugin in the pod (10 s min, up to 120 s). This applies to each upsert and each delete.
- **One CR per ServiceAccount.** The CR name and namespace come from the ServiceAccount in the SPIFFE ID. Pods that share a ServiceAccount share one CR and one bundle.

### Configuration

Read from `AIAC_PDP_POLICY_URL` environment variable (or `.env` file co-located with `api.py`). Falls back to the default if absent.

| Variable | Default |
|----------|---------|
| `AIAC_PDP_POLICY_URL` | `http://127.0.0.1:7072` |

### Usage

```python
from aiac.pdp.policy.library.api import apply_policy, replace_policy, delete_service_cr, delete_policy
from aiac.policy.model.models import TargetSidePolicyModel

# A run: upsert the CRs of the affected services (called by the PCE)
apply_policy(TargetSidePolicyModel(services=[tool_spm, agent_spm]))

# The resync at the Controller start: replace every AIAC CR (called by the PCE)
replace_policy(TargetSidePolicyModel(services=every_stored_spm))

# The quarantine or the decommission: delete the CR of one service (called by the PCE)
delete_service_cr("team1/github-tool")

# Operator tool only, no AIAC caller: delete every AIAC CR (under D20 this denies every managed pod)
delete_policy()
```

---

## Testing Decisions

**Seam:** HTTP boundary — mock responses from `AIAC_PDP_POLICY_URL`.

Key behaviors to assert:
- `apply_policy(model)` issues `POST /policy` with the serialized policy model, which carries its `enforcement_side` tag (for a `TargetSidePolicyModel` and for an `AgentSidePolicyModel`).
- `replace_policy(model)` issues `PUT /policy` with the serialized policy model and its tag.
- `delete_service_cr(id)` issues `DELETE /policy/services/{id}`, with a slash-bearing `id` encoded as one path segment.
- `delete_policy()` issues `DELETE /policy`.
- The module has no `apply_agent_policy` and no `delete_agent_policy`.
- Any non-2xx response raises `RuntimeError`.
- `AIAC_PDP_POLICY_URL` is read from env; falls back to `http://127.0.0.1:7072`.

---

## Out of Scope

- **Keycloak interaction:** this library never calls Keycloak directly. All IdP operations go through `aiac.idp.configuration`.
- **Policy computation:** translating `list[PolicyRule]` into the policy model (and, under agent side, into `AgentPolicyModel` objects) is the responsibility of `aiac.policy.computation`, not this library.
- **The side:** the library does not read `AIAC_ENFORCEMENT_SIDE`. The side is the subclass of the model that the caller passes.
- **Policy persistence:** the Policy Model Store (`aiac.policy.model_store`) owns structured `ServicePolicyModel` durability (the `AgentPolicyModel` is a derived projection, never persisted). This library targets the OPA runtime only.

---

## Further Notes

- The `aiac.pdp.library.policy` module (old path) has been removed. All consumers import from `aiac.pdp.policy.library.api`.
- Models (`PolicyModel`, `TargetSidePolicyModel`, `AgentSidePolicyModel`) are imported from `aiac.policy.model.models`, not from the removed `aiac.pdp.library.models`.
- The name `delete_service_cr` is different from the store library's `delete_service_policy` on purpose. The PCE calls both in the quarantine and the decommission: one deletes the CR, the other deletes the SPM.
