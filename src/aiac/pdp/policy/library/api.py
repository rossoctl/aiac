"""HTTP client for the PDP Policy Writer (OPA) REST API.

Module-level functions wrapping ``{AIAC_PDP_POLICY_URL}/policy...`` endpoints (D18c). The body
of ``apply_policy`` / ``replace_policy`` is a tagged policy model; the writer upserts one CR per
entry and reads the enforcement side from the tag. The PDP Policy Writer operates on Kubernetes
CRs, not a Keycloak realm, so none of these functions take or send a ``realm`` parameter.
"""

import os
import re
from pathlib import Path
from urllib.parse import quote

import requests
from dotenv import load_dotenv

from aiac.policy.model.models import PolicyModel

load_dotenv(Path(__file__).resolve().parent / ".env")

# ``quote(..., safe="")`` emits only unreserved characters (``A-Za-z0-9-._~``) and ``%XX`` escapes.
# Asserting the encoded value against this set before it is spliced into a request URL proves it is
# a single, inert path segment — no scheme, host, ``/`` or ``..`` can be injected (closes the
# partial-SSRF vector). The fullmatch barrier is what CodeQL recognises; ``quote`` alone does not.
_URL_SEGMENT_RE = re.compile(r"[A-Za-z0-9._~%-]+")


def _base_url() -> str:
    return os.getenv("AIAC_PDP_POLICY_URL", "http://127.0.0.1:7072")


def _service_id_segment(service_id: str) -> str:
    """URL-encode ``service_id`` as a single, validated path segment.

    ``service_id`` is the Keycloak clientId (``{ns}/{name}`` or a SPIFFE URI), so it can carry
    slashes and other reserved characters; ``safe=""`` escapes them all. The fullmatch check
    then guarantees the result cannot alter the request target.
    """
    segment = quote(service_id, safe="")
    if not _URL_SEGMENT_RE.fullmatch(segment):
        raise ValueError(f"service_id {service_id!r} does not yield a safe URL path segment")
    return segment


def _check(resp: requests.Response) -> None:
    if not resp.ok:
        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")


def apply_policy(model: PolicyModel) -> None:
    """``POST /policy`` — upsert one CR per entry of ``model``."""
    _check(requests.post(f"{_base_url()}/policy", json=model.model_dump(mode="json")))


def replace_policy(model: PolicyModel) -> None:
    """``PUT /policy`` — upsert every entry of ``model``, then delete every other AIAC CR."""
    _check(requests.put(f"{_base_url()}/policy", json=model.model_dump(mode="json")))


def delete_service_cr(service_id: str) -> None:
    """``DELETE /policy/services/{service_id}`` — delete the CR of one service (a missing CR is
    success). Under D20 the service is then denied."""
    _check(requests.delete(f"{_base_url()}/policy/services/{_service_id_segment(service_id)}"))


def delete_policy() -> None:
    """``DELETE /policy`` — delete every AIAC CR. No AIAC code calls it (C1)."""
    _check(requests.delete(f"{_base_url()}/policy"))
