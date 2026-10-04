"""PDP Policy Writer (OPA) — always-on Custom Resource writer (D18c).

The body of ``POST`` / ``PUT /policy`` is a policy model tagged with its enforcement side
(``AnyPolicyModel``). The writer reads the side from the tag, never from an env var (D29). For each
entry of the model it renders the two request packages via ``rego.py`` and server-side-applies them
into one ``AuthorizationPolicy`` Custom Resource (``agent.rossoctl.dev/v1alpha1``, ``scope:
client``) — one CR per managed service, agent or tool. Under target side an entry is one
``services[]`` SPM. The writer does no join: the PCE builds the policy model. ``bundle-service``
(operator repo) composes those CRs into per-pod OPA bundles that AuthBridge polls.

Routes:

- ``POST /policy`` — upsert one CR per entry (no rollback on a partial failure).
- ``PUT /policy`` — replace: upsert every entry, then delete every other CR that has the
  managed-by label. The delete step runs only after every upsert succeeded.
- ``DELETE /policy/services/{service_id:path}`` — delete the CR of one service (the quarantine and
  the decommission); a k8s 404 is success.
- ``DELETE /policy`` — delete every CR that has the managed-by label.
- ``GET /health`` — a bounded CR list.

With the changed combiner (D20) a pod that has no CR is denied, so a delete closes the service.

The CR write is **always active** — it is never gated by an env var. Setting
``POLICY_WRITER_DUMP_REGO`` truthy *additionally* dumps the same rego to
``REGO_OUTPUT_DIR`` for local inspection; the toggle defaults off and never
disables, replaces, or gates the CR write.
"""

import os
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated

from fastapi import Body, FastAPI
from kubernetes import client, config
from kubernetes.client import ApiException
from starlette.responses import JSONResponse, Response

from aiac.pdp.service.policy.opa.rego import ClientPolicies, identity_ref, render_target_side
from aiac.policy.model.models import AnyPolicyModel, PolicyModel, TargetSidePolicyModel

# --------------------------------------------------------------------------- #
# CR coordinates & write identity — code constants, never env vars (Q6, Q8a). #
# --------------------------------------------------------------------------- #
_GROUP = "agent.rossoctl.dev"
_VERSION = "v1alpha1"
_PLURAL = "authorizationpolicies"
_MANAGED_BY_LABEL = {"app.kubernetes.io/managed-by": "aiac-pdp-policy-writer"}
_FIELD_MANAGER = "aiac-pdp-policy-writer"
# Selects only CRs this writer owns (the delete step of PUT /policy, and DELETE /policy).
_MANAGED_BY_SELECTOR = "app.kubernetes.io/managed-by=aiac-pdp-policy-writer"

# Truthy spellings for the additive rego-dump toggle.
_TRUTHY = {"1", "true", "yes", "on"}


# --------------------------------------------------------------------------- #
# Kubernetes client — constructed at startup (incluster -> kubeconfig fallback)#
# --------------------------------------------------------------------------- #
def _load_kube_config() -> None:
    """Load in-cluster config, falling back to a local kubeconfig.

    Both failing (e.g. a unit-test / CI host with neither) is non-fatal: the
    client is still constructed and API calls surface as 502/503 until real
    config exists. This keeps the module importable everywhere.
    """
    try:
        config.load_incluster_config()
    except config.ConfigException:
        try:
            config.load_kube_config()
        except config.ConfigException:
            pass


_load_kube_config()
_api = client.CustomObjectsApi()


# --------------------------------------------------------------------------- #
# Env-derived config — read at call time so tests can toggle it per request.   #
# --------------------------------------------------------------------------- #
def get_output_dir() -> Path:
    """Local rego-dump destination (only consulted when the dump toggle is on)."""
    return Path(os.environ.get("REGO_OUTPUT_DIR", "/rego"))


def _dump_enabled() -> bool:
    """True when ``POLICY_WRITER_DUMP_REGO`` is truthy.

    Off by default. This gates the *additive* local-debug dump only — never the
    CR write.
    """
    return os.environ.get("POLICY_WRITER_DUMP_REGO", "").strip().lower() in _TRUTHY


def _platform_clients() -> tuple[str, ...]:
    """Platform source clients for the inbound generator's bypass rules (Q5).

    ``PLATFORM_SOURCE_CLIENTS`` comma-split, blanks dropped; unset or all-blank
    falls back to ``("rossoctl",)`` (dropping the bypass would deny end-user
    traffic, which carries the platform client).
    """
    raw = os.environ.get("PLATFORM_SOURCE_CLIENTS")
    if raw is None:
        return ("rossoctl",)
    clients = tuple(c.strip() for c in raw.split(",") if c.strip())
    return clients or ("rossoctl",)


# --------------------------------------------------------------------------- #
# CR body + write ops                                                          #
# --------------------------------------------------------------------------- #
def _entries(model: PolicyModel) -> Iterator[tuple[str, ClientPolicies]]:
    """The CRs that ``model`` asks for: one ``(service_id, packages)`` per entry (D18c).

    Dispatches on the policy-model subclass, so the side comes from the tag, never from an env var
    (D29). Target side: one entry per ``services[]`` SPM. (The agent side adds its own branch: one
    agent CR per APM and one pass-through CR per ``pass_through`` id.) Lazy, so a batch writes its
    entries in order and stops at the first failure.
    """
    if isinstance(model, TargetSidePolicyModel):
        platform_clients = _platform_clients()
        for spm in model.services:
            yield spm.service_id, render_target_side(spm, platform_clients=platform_clients)
        return
    raise TypeError(f"no renderer for the policy model {type(model).__name__}")


def _build_cr(service_id: str, policies: ClientPolicies) -> dict:
    """Build the ``AuthorizationPolicy`` CR body of one entry (Q6a).

    ``metadata.name`` / ``.namespace`` come from ``identity_ref(service_id)``;
    ``spec.clientID`` is the DNS-label-safe ``name`` — display / print-column
    only, since bundle-service matches on name+namespace, never ``clientID``.
    ``spec.policies`` is exactly the two request packages; the list is atomic under
    server-side apply, so one write replaces both. Raises ``ValueError`` (via
    ``identity_ref``) on a malformed ``service_id``.
    """
    namespace, name = identity_ref(service_id)
    return {
        "apiVersion": f"{_GROUP}/{_VERSION}",
        "kind": "AuthorizationPolicy",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": dict(_MANAGED_BY_LABEL),
        },
        "spec": {
            "scope": "client",
            "clientID": name,
            "policies": [
                {"path": "inbound/request.rego", "content": policies.inbound},
                {"path": "outbound/request.rego", "content": policies.outbound},
            ],
        },
    }


def _dump_cr(namespace: str, name: str, body: dict) -> None:
    """Additive local dump: write each policy under ``<out>/<ns>/<name>/<path>``.

    Mirrors the CR ``policies[].path`` so on-disk output equals CR content. Any
    ``OSError`` propagates (mapped to 502 upstream) — a broken debug mount should
    surface, not silently drop files.
    """
    base = get_output_dir() / namespace / name
    for policy in body["spec"]["policies"]:
        dest = base / policy["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(policy["content"])


def _upsert(service_id: str, policies: ClientPolicies) -> tuple[str, str]:
    """Server-side-apply the CR of one entry (idempotent), then dump if enabled (Q6b).

    Returns the CR's ``(namespace, name)``."""
    body = _build_cr(service_id, policies)
    namespace, name = body["metadata"]["namespace"], body["metadata"]["name"]
    _api.patch_namespaced_custom_object(
        group=_GROUP,
        version=_VERSION,
        namespace=namespace,
        plural=_PLURAL,
        name=name,
        body=body,
        field_manager=_FIELD_MANAGER,
        force=True,
        _content_type="application/apply-patch+yaml",
    )
    if _dump_enabled():
        _dump_cr(namespace, name, body)
    return namespace, name


def _apply(model: PolicyModel) -> set[tuple[str, str]]:
    """Upsert one CR per entry of ``model``; return the ``(namespace, name)`` of each.

    No rollback: a failure stops the batch, and the entries already written stay written (SSA is
    idempotent, so a retry re-applies the whole set)."""
    return {_upsert(service_id, policies) for service_id, policies in _entries(model)}


def _delete_cr(namespace: str, name: str) -> None:
    """Delete one CR (idempotent: a k8s 404 is success), then dump-clear its tree (Q6c)."""
    try:
        _api.delete_namespaced_custom_object(
            group=_GROUP,
            version=_VERSION,
            namespace=namespace,
            plural=_PLURAL,
            name=name,
        )
    except ApiException as e:
        if e.status != 404:
            raise
    if _dump_enabled():
        shutil.rmtree(get_output_dir() / namespace / name, ignore_errors=True)


def _managed_crs() -> list[tuple[str, str]]:
    """``(namespace, name)`` of every CR that carries the managed-by label, cluster-wide.

    A CR without the label is never listed, so it is never touched."""
    listing = _api.list_cluster_custom_object(_GROUP, _VERSION, _PLURAL, label_selector=_MANAGED_BY_SELECTOR)
    return [(item["metadata"]["namespace"], item["metadata"]["name"]) for item in listing.get("items", [])]


def _replace(model: PolicyModel) -> None:
    """``PUT /policy``: upsert every entry, then delete every other managed CR.

    The delete step runs only after every upsert succeeded: an upsert failure propagates before
    the list, so nothing is deleted. A per-item 404 (a concurrent delete) is success."""
    keep = _apply(model)
    for namespace, name in _managed_crs():
        if (namespace, name) not in keep:
            _delete_cr(namespace, name)


def _delete_all() -> None:
    """Delete every CR carrying the managed-by label, cluster-wide (Q6c).

    A per-item 404 (a concurrent delete race) is tolerated; other API failures
    propagate (mapped to 502). If the dump is on, clear the dumped tree too.
    """
    for namespace, name in _managed_crs():
        _delete_cr(namespace, name)
    if _dump_enabled():
        # Clear the dumped tree's contents without removing the mount point itself.
        for child in get_output_dir().glob("*"):
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)


def _run_write(op) -> Response:
    """Run a write op, mapping failures to HTTP responses.

    - ``ValueError`` — a malformed / namespace-less service id from
      ``identity_ref`` — maps to **400** (its message names the bad id).
    - ``ApiException`` — a Kubernetes API failure — maps to **502**.
    - ``OSError`` — the additive rego dump's filesystem write — maps to **502**.

    400 is reserved for a malformed id; 502 strictly for Kubernetes API failures
    and the additive dump. The two are never conflated. A body that does not parse
    (a wrong or missing tag) never gets here: FastAPI returns **422**.
    """
    try:
        op()
        return Response(status_code=204)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})
    except ApiException as e:
        return JSONResponse(status_code=502, content={"error": str(e)})
    except OSError as e:
        return JSONResponse(status_code=502, content={"error": str(e)})


# --------------------------------------------------------------------------- #
# Routes                                                                       #
# --------------------------------------------------------------------------- #
app = FastAPI()


# The body of POST / PUT /policy. The discriminator makes the tag mandatory: a body with a wrong
# or missing ``enforcement_side`` is a 422 (pydantic), also while ``AnyPolicyModel`` has one class.
_PolicyBody = Annotated[AnyPolicyModel, Body(discriminator="enforcement_side")]


@app.post("/policy", status_code=204)
def upsert_policy(policy: _PolicyBody):
    return _run_write(lambda: _apply(policy))


@app.put("/policy", status_code=204)
def replace_policy(policy: _PolicyBody):
    return _run_write(lambda: _replace(policy))


# The id is a SPIFFE URI or ``<ns>/<name>``: the server decodes the library's ``%2F`` back to ``/``
# before routing, so the route takes ``{service_id:path}`` (a single-segment ``{service_id}`` never
# matches it — HTTP 404).
@app.delete("/policy/services/{service_id:path}", status_code=204)
def delete_service(service_id: str):
    return _run_write(lambda: _delete_cr(*identity_ref(service_id)))


@app.delete("/policy", status_code=204)
def delete_all():
    return _run_write(_delete_all)


@app.get("/health")
def health():
    # A bounded cluster-wide list proves the API is reachable and the CRD is
    # served. An empty list is success; any failure (unreachable API, RBAC
    # forbidden) is 503. The dump dir is not part of this signal.
    try:
        _api.list_cluster_custom_object(_GROUP, _VERSION, _PLURAL, limit=1)
        return {"status": "ok"}
    except Exception as e:
        # Any failure — unreachable API, RBAC-forbidden, CRD not served — means
        # the writer cannot serve, so it is reported as unavailable.
        return JSONResponse(
            status_code=503,
            content={"status": "unavailable", "error": str(e)},
        )
