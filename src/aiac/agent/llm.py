"""Shared LLM seam for the agent layer.

The ChatOpenAI client, its dedicated retry cadence, the schema-agnostic
``call_with_retry`` wrapper, and the sanitized LLM error vocabulary — extracted from
the Policy Rules Builder so every agent-layer LLM consumer (the PRB and the Policy
Digester) shares ONE seam and ONE patch point.

The client is built lazily (never at import). ``call_with_retry`` is error-agnostic:
it transport-retries transient failures and re-raises the ORIGINAL exception (never a
tenacity ``RetryError``) so each caller can classify it. ``raise_sanitized`` turns a
raw transport/parse error into a typed, endpoint-free error (the raw error chained on
``__cause__`` for internal logs only); callers pass their own error subclasses so a
consumer can specialise the vocabulary (the PRB folds these into its
``PolicyRulesBuilderBaseError`` hierarchy).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, NoReturn, TypeVar

from langchain_core.messages import BaseMessage
from langchain_openai import ChatOpenAI
from pydantic import SecretStr
from tenacity import Retrying, retry_if_exception, stop_after_attempt, wait_exponential

from aiac.shared.upstream import is_transient

_DEFAULT_LLM_REQUEST_TIMEOUT = 120.0
_DEFAULT_LLM_MAX_RETRIES = 3
_DEFAULT_LLM_RETRY_BACKOFF_MIN = 1.0
_DEFAULT_LLM_RETRY_BACKOFF_MAX = 30.0

_N = TypeVar("_N", int, float)


class LLMError(Exception):
    """Base for the sanitized LLM error vocabulary. Its message never carries the endpoint / host /
    API key; the raw transport error is chained on ``__cause__`` for internal logging only."""


class LLMAccessError(LLMError):
    """The LLM endpoint stayed unreachable after the transport retry budget was exhausted (a
    transient failure that never cleared)."""


class UnparseableLLMResponseError(LLMError):
    """The LLM was REACHABLE but its response could not be parsed / failed validation (a
    non-transient failure, so it is not retried). Distinct from ``LLMAccessError`` so a consumer can
    tell the two apart."""


@dataclass(frozen=True)
class LLMSettings:
    """A single LLM consumer's fully-resolved parameter set — client params (endpoint, model, key,
    per-request timeout) and the dedicated retry cadence (attempt count + backoff bounds). The PRB
    and the Policy Digester each resolve their OWN ``LLMSettings`` so they can differ on every knob."""

    base_url: str | None
    model: str
    api_key: str
    request_timeout: float
    max_retries: int
    backoff_min: float
    backoff_max: float


def _raw(namespace: str, suffix: str) -> str | None:
    """Resolve env var ``{namespace}_LLM_{suffix}`` if ``namespace`` is set and the var is present;
    otherwise fall back to the shared ``LLM_{suffix}``. With an empty ``namespace`` (the PRB profile)
    this reads the bare ``LLM_{suffix}`` directly."""
    if namespace:
        value = os.getenv(f"{namespace}_LLM_{suffix}")
        if value is not None:
            return value
    return os.getenv(f"LLM_{suffix}")


def _num(raw: str | None, default: _N, cast: type[_N]) -> _N:
    """Parse ``raw`` with ``cast`` (int/float), tolerant of a missing or non-numeric value — a bad
    value must not crash the request, it falls back to ``default``. A non-positive value also falls
    back, so a knob can never disable retries or set a zero/negative backoff/timeout."""
    if raw is None:
        return default
    try:
        value = cast(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def load_llm_settings(namespace: str = "") -> LLMSettings:
    """Resolve an ``LLMSettings`` for one consumer from the environment. ``namespace=""`` reads the
    bare ``LLM_*`` vars (the PRB profile); a namespace like ``"DIGEST"`` reads ``DIGEST_LLM_*`` and
    falls back per-key to the shared ``LLM_*`` (then the built-in default). So an operator can set
    only ``LLM_*`` to drive both consumers, and override just the keys that must differ.

    The retry cadence is DELIBERATELY SEPARATE from the shared ``UPSTREAM_MAX_RETRIES``
    (``aiac.shared.upstream``, which governs the IdP/MCP/K8s transport seams): the LLM call is slower
    and fails differently, so it gets its own ``*_LLM_MAX_RETRIES`` / ``*_LLM_RETRY_BACKOFF_MIN`` /
    ``*_LLM_RETRY_BACKOFF_MAX`` knobs, each tolerant of unset / non-numeric values."""
    return LLMSettings(
        base_url=_raw(namespace, "BASE_URL"),
        model=_raw(namespace, "MODEL") or "",
        api_key=_raw(namespace, "API_KEY") or "",
        request_timeout=_num(_raw(namespace, "REQUEST_TIMEOUT"), _DEFAULT_LLM_REQUEST_TIMEOUT, float),
        max_retries=_num(_raw(namespace, "MAX_RETRIES"), _DEFAULT_LLM_MAX_RETRIES, int),
        backoff_min=_num(_raw(namespace, "RETRY_BACKOFF_MIN"), _DEFAULT_LLM_RETRY_BACKOFF_MIN, float),
        backoff_max=_num(_raw(namespace, "RETRY_BACKOFF_MAX"), _DEFAULT_LLM_RETRY_BACKOFF_MAX, float),
    )


def build_llm(settings: LLMSettings) -> ChatOpenAI:  # lazy -- NEVER called at import
    return ChatOpenAI(
        base_url=settings.base_url,
        model=settings.model,
        api_key=SecretStr(settings.api_key),
        temperature=0,
        # Fail fast on a stalled socket; retries are owned by call_with_retry's tenacity Retrying,
        # so disable the client's own so attempts don't multiply.
        timeout=settings.request_timeout,
        max_retries=0,
    )


def call_with_retry(runnable: Any, messages: list[BaseMessage], *, settings: LLMSettings) -> Any:
    """Invoke ``runnable`` on ``messages``, transport-retrying each ``.invoke()`` via a call-time
    tenacity ``Retrying`` on ``settings``' dedicated cadence. Schema-agnostic: the caller decides
    what the runnable is (a structured-output binding, or a bare chat model) and what its result
    means.

    Only transient failures (connection errors / timeouts / 5xx) are retried; a permanent failure
    (bad request, validation error) fails identically on every attempt, so it surfaces immediately.
    ``reraise=True`` hands back the ORIGINAL last exception (never a tenacity ``RetryError``) so the
    caller can classify it exactly as the retry loop did — see ``raise_sanitized``."""
    retryer = Retrying(
        retry=retry_if_exception(is_transient),
        stop=stop_after_attempt(settings.max_retries),
        wait=wait_exponential(multiplier=1, min=settings.backoff_min, max=settings.backoff_max),
        reraise=True,
    )
    return retryer(runnable.invoke, messages)


def raise_sanitized(
    err: BaseException,
    *,
    access_error: type[LLMError] = LLMAccessError,
    unparseable_error: type[LLMError] = UnparseableLLMResponseError,
) -> NoReturn:
    """Re-raise ``err`` as a typed, sanitized LLM error. A still-transient error means the retry
    budget was exhausted against an unreachable LLM -> ``access_error``; anything else means the LLM
    was reachable but its response was unusable -> ``unparseable_error``. The messages are STATIC
    (never ``str(err)``) so an endpoint / host / API key embedded in the raw error cannot leak; the
    raw error stays reachable via ``__cause__``. Callers pass their own subclasses to specialise the
    error vocabulary (the PRB folds these into ``PolicyRulesBuilderBaseError``)."""
    if is_transient(err):
        raise access_error("LLM endpoint unreachable after exhausting transport retries") from err
    raise unparseable_error("LLM returned an unparseable or schema-invalid response") from err
