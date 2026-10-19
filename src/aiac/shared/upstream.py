"""Shared upstream-call helper (project-level).

`run_upstream` wraps a zero-arg callable in a bounded retry loop for transient upstream
failures (IdP Configuration Service, Kubernetes API, MCP endpoints). ``upstream_retrying`` builds
the same loop with another budget and backoff (the LLM seam, ``aiac.agent.llm``, uses it). It is
deliberately transport-agnostic: it retries then **re-raises the original exception**, leaving each
caller to map the failure to the right HTTP status at the service boundary (e.g.
``HTTPException(502)`` for IdP/Kubernetes — see the Error Handling table in
``aiac-agent.md``). The retry budget is read from ``UPSTREAM_MAX_RETRIES`` (default 3) at
call time, so tests can tune it via the environment.

Lives at the project root (``aiac.shared``) so any layer can reuse it without importing from
the ``agent`` package. Retry now lives at the transport boundary: the idp-library
``Configuration`` methods, the ``_mcp_tools_list`` helper, and the provision k8s seam
(``provision/kube.py``) each call it internally so the agent nodes no longer orchestrate
retries.
"""

import os
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Callable, TypeVar

from tenacity import RetryCallState, Retrying, retry_if_exception, stop_after_attempt, wait_exponential

T = TypeVar("T")

_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_MIN = 1.0
_DEFAULT_BACKOFF_MAX = 30.0

# The 4xx statuses that can clear on the next attempt: 408 (request timeout) and 429 (rate limit, or
# Kubernetes API Priority and Fairness). They are retried like a 5xx.
_TRANSIENT_4XX_STATUSES = frozenset({408, 429})

# The error codes of a 429 that cannot clear by a wait: the account has no quota or no billing left
# (OpenAI ``insufficient_quota``, and the same idea on other OpenAI-compatible endpoints). Such a 429
# is permanent, so it is not retried. Compared in lower case.
_QUOTA_ERROR_CODES = frozenset(
    {"insufficient_quota", "quota_exceeded", "billing_hard_limit_reached", "billing_not_active"}
)


def max_retries() -> int:
    """Retry budget from ``UPSTREAM_MAX_RETRIES`` (default 3), tolerant of an unset or
    non-numeric value — a bad value must not crash the request, it falls back to the default."""
    try:
        value = int(os.getenv("UPSTREAM_MAX_RETRIES", str(_DEFAULT_MAX_RETRIES)))
    except (TypeError, ValueError):
        return _DEFAULT_MAX_RETRIES
    return value if value > 0 else _DEFAULT_MAX_RETRIES


def http_status(exc: BaseException) -> int | None:
    """Best-effort HTTP status of an exception: ``requests`` HTTPError carries it on
    ``.response.status_code``; a Kubernetes ``ApiException`` and the IdP library's ``IdPHTTPError``
    carry it on ``.status``. Only an ``int`` or a numeric ``str`` is a status: any other value (also
    an object that ``int()`` can convert) is skipped, so it does not hide the error's own
    ``.status``. A ``bool`` is not a status."""
    resp = getattr(exc, "response", None)
    for candidate in (getattr(resp, "status_code", None), getattr(exc, "status", None)):
        if isinstance(candidate, bool) or not isinstance(candidate, (int, str)):
            continue
        try:
            return int(candidate)
        except ValueError:
            continue
    return None


def _error_codes(exc: BaseException) -> set[str]:
    """The error codes that ``exc`` carries, in lower case: the ``code`` and ``type`` attributes (the
    openai errors set them from the response body) and the ``code`` / ``type`` of a dict ``body``, also
    one level down in ``body["error"]``. Only strings count."""
    found = [getattr(exc, "code", None), getattr(exc, "type", None)]
    body = getattr(exc, "body", None)
    for part in (body, body.get("error") if isinstance(body, dict) else None):
        if isinstance(part, dict):
            found += [part.get("code"), part.get("type")]
    return {value.lower() for value in found if isinstance(value, str)}


def _quota_exhausted(exc: BaseException) -> bool:
    """True when ``exc`` names a quota or billing limit that a wait cannot clear (``_QUOTA_ERROR_CODES``)."""
    return not _error_codes(exc).isdisjoint(_QUOTA_ERROR_CODES)


def retry_after(exc: BaseException | None) -> float | None:
    """The wait in seconds that the ``Retry-After`` header of the error's response asks for, or
    ``None``. The header is read from ``.response.headers`` (``requests``, ``httpx`` / openai) or from
    ``.headers`` (a Kubernetes ``ApiException``). Its value is seconds or an HTTP date; a date in the
    past gives ``0``. Any other value (also a stand-in object in a unit test) gives ``None``."""
    if exc is None:
        return None
    for headers in (getattr(getattr(exc, "response", None), "headers", None), getattr(exc, "headers", None)):
        try:
            value = headers.get("Retry-After") or headers.get("retry-after")
        except Exception:  # noqa: BLE001 — no headers, or headers of an unknown shape
            continue
        if not isinstance(value, str) or not value.strip():
            continue
        value = value.strip()
        try:
            return max(float(value), 0.0)
        except ValueError:
            pass
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max((when - datetime.now(timezone.utc)).total_seconds(), 0.0)
    return None


def is_transient(exc: BaseException) -> bool:
    """Only transient upstream failures are worth retrying: connection resets, timeouts, a 5xx
    server response, or HTTP 408 / 429 (``_TRANSIENT_4XX_STATUSES``). A 429 that names an exhausted
    quota or billing limit (``_QUOTA_ERROR_CODES``, for example OpenAI ``insufficient_quota``) cannot
    clear, so it is permanent. Other permanent failures (other 4xx, value/validation errors) fail
    identically on every attempt, so they are surfaced immediately rather than retried. Duck-typed so
    it covers ``requests``, openai and Kubernetes client errors without importing any of them here."""
    if isinstance(exc, (ConnectionError, TimeoutError)):  # builtins (also OSError subclasses)
        return True
    # requests.exceptions.ConnectionError / Timeout are NOT subclasses of the builtins above;
    # match them structurally by class name so this module stays transport-agnostic.
    transient_names = {
        "ConnectionError",
        "Timeout",
        "ConnectTimeout",
        "ReadTimeout",
        "ConnectionResetError",
        # openai / langchain_openai raise these on request timeout / dropped connection;
        # matched by name so this module keeps no openai import (transport-agnostic).
        "APITimeoutError",
        "APIConnectionError",
    }
    # Match against the WHOLE class hierarchy, not just the leaf name: a wrapper subclasses a
    # transient base under a NEW name (e.g. langchain-openai's ``OpenAIConnectionError`` <-
    # ``openai.APIConnectionError``), so the retryable base is present in the MRO even when the
    # leaf name is not in the set. A leaf-only check misclassified such a connection error as
    # permanent, dead-lettering an onboard on a transient LLM blip.
    if any(base.__name__ in transient_names for base in type(exc).__mro__):
        return True
    status = http_status(exc)
    if status in _TRANSIENT_4XX_STATUSES:
        return not (status == 429 and _quota_exhausted(exc))
    return status is not None and status >= 500


def upstream_retrying(*, attempts: int, backoff_min: float, backoff_max: float) -> Retrying:
    """A tenacity ``Retrying`` that makes at most ``attempts`` attempts and retries **only transient
    failures** (``is_transient``). Between attempts it waits the error's ``Retry-After``
    (``retry_after``) when there is one, else the exponential backoff from ``backoff_min``; each wait
    is at most ``backoff_max``. ``reraise=True``: after the last attempt the ORIGINAL error is raised
    (never a tenacity ``RetryError``)."""
    backoff = wait_exponential(multiplier=1, min=backoff_min, max=backoff_max)

    def _wait(state: RetryCallState) -> float:
        asked = retry_after(state.outcome.exception() if state.outcome else None)
        return backoff(state) if asked is None else min(asked, backoff_max)

    return Retrying(
        retry=retry_if_exception(is_transient),
        stop=stop_after_attempt(attempts),
        wait=_wait,
        reraise=True,
    )


def run_upstream(fn: Callable[[], T]) -> T:
    """Run ``fn`` with bounded retries (``UPSTREAM_MAX_RETRIES``, default 3) and exponential
    backoff (1 s, 2 s, 4 s, … at most 30 s between attempts; a ``Retry-After`` replaces the backoff,
    up to the same 30 s), retrying **only transient failures** (``is_transient``) and reraising the
    last error so the caller can convert it to a 502. Returns whatever ``fn`` returns (the return
    type is preserved for callers)."""
    retryer = upstream_retrying(
        attempts=max_retries(), backoff_min=_DEFAULT_BACKOFF_MIN, backoff_max=_DEFAULT_BACKOFF_MAX
    )
    return retryer(fn)
