"""Unit tests for the shared LLM seam (``aiac.agent.llm``).

The client/retry/error machinery extracted from the Policy Rules Builder so both the PRB
and the Policy Digester share ONE mechanism — but each with its OWN parameter set. A
consumer resolves an ``LLMSettings`` profile from the environment via ``load_llm_settings``:
the PRB uses the bare ``LLM_*`` vars; the digester uses ``DIGEST_LLM_*`` with fallback to
the shared ``LLM_*`` (then the built-in default). ``build_llm`` and ``call_with_retry`` are
driven by that resolved settings object, so the two consumers can differ on everything from
model to retry budget.
"""

from __future__ import annotations

from dataclasses import replace
from unittest.mock import MagicMock, patch

import httpx
import openai
import pytest

from aiac.agent.llm import (
    LLMAccessError,
    LLMCredentialsError,
    LLMSettings,
    UnparseableLLMResponseError,
    build_llm,
    call_with_retry,
    load_llm_settings,
    raise_sanitized,
)

_POISON = "https://secret-endpoint.example/v1?api_key=SUPERSECRET"

# A concrete settings object for the client/retry tests, independent of the environment.
_SETTINGS = LLMSettings(
    base_url="http://llm.example/v1",
    model="test-model",
    api_key="k",
    request_timeout=45.0,
    max_retries=3,
    backoff_min=1.0,
    backoff_max=30.0,
)


# --------------------------------------------------------------------------- #
# load_llm_settings — per-consumer profiles with LLM_* fallback               #
# --------------------------------------------------------------------------- #
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for base in (
        "BASE_URL",
        "MODEL",
        "API_KEY",
        "REQUEST_TIMEOUT",
        "MAX_RETRIES",
        "RETRY_BACKOFF_MIN",
        "RETRY_BACKOFF_MAX",
    ):
        for ns in ("LLM_", "DIGEST_LLM_"):
            monkeypatch.delenv(f"{ns}{base}", raising=False)


def test_settings_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    s = load_llm_settings()  # PRB profile (bare LLM_*)
    assert s.base_url is None
    assert s.model == ""
    assert (s.request_timeout, s.max_retries, s.backoff_min, s.backoff_max) == (120.0, 3, 1.0, 30.0)


def test_prb_profile_reads_bare_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("LLM_MODEL", "prb-model")
    monkeypatch.setenv("LLM_MAX_RETRIES", "7")
    s = load_llm_settings()
    assert s.model == "prb-model"
    assert s.max_retries == 7


def test_digest_profile_reads_its_own_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("DIGEST_LLM_MODEL", "digest-model")
    monkeypatch.setenv("DIGEST_LLM_MAX_RETRIES", "9")
    s = load_llm_settings("DIGEST")
    assert s.model == "digest-model"
    assert s.max_retries == 9


def test_digest_profile_falls_back_to_shared_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("LLM_MODEL", "shared-model")  # only the shared var is set
    s = load_llm_settings("DIGEST")
    assert s.model == "shared-model"  # DIGEST_LLM_MODEL unset -> shared LLM_MODEL


def test_digest_prefix_overrides_shared(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("LLM_MODEL", "shared-model")
    monkeypatch.setenv("DIGEST_LLM_MODEL", "digest-model")
    assert load_llm_settings("DIGEST").model == "digest-model"  # prefixed wins
    assert load_llm_settings().model == "shared-model"  # PRB profile untouched by DIGEST_*


def test_profiles_are_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("LLM_MODEL", "prb-model")
    monkeypatch.setenv("LLM_MAX_RETRIES", "2")
    monkeypatch.setenv("DIGEST_LLM_MODEL", "digest-model")
    monkeypatch.setenv("DIGEST_LLM_MAX_RETRIES", "8")
    prb, digest = load_llm_settings(), load_llm_settings("DIGEST")
    assert (prb.model, prb.max_retries) == ("prb-model", 2)
    assert (digest.model, digest.max_retries) == ("digest-model", 8)


def test_settings_tolerate_non_numeric(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("LLM_MAX_RETRIES", "not-a-number")
    monkeypatch.setenv("LLM_REQUEST_TIMEOUT", "")
    s = load_llm_settings()
    assert s.max_retries == 3  # bad value falls back to default, never crashes the request
    assert s.request_timeout == 120.0


# --------------------------------------------------------------------------- #
# build_llm — driven by a settings object                                     #
# --------------------------------------------------------------------------- #
def test_build_llm_uses_settings() -> None:
    with patch("aiac.agent.llm.ChatOpenAI") as mk:
        build_llm(_SETTINGS)
    kwargs = mk.call_args.kwargs
    assert kwargs["model"] == "test-model"
    assert kwargs["base_url"] == "http://llm.example/v1"
    assert kwargs["timeout"] == 45.0
    assert kwargs["max_retries"] == 0  # tenacity owns retry; client's own is off


# --------------------------------------------------------------------------- #
# call_with_retry — schema-agnostic, driven by settings                       #
# --------------------------------------------------------------------------- #
def test_call_with_retry_returns_result_without_retrying() -> None:
    runnable = MagicMock()
    runnable.invoke.return_value = "ok"
    assert call_with_retry(runnable, ["msg"], settings=_SETTINGS) == "ok"
    runnable.invoke.assert_called_once_with(["msg"])


def test_call_with_retry_retries_transient_then_reraises_original(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda _s: None)  # no real backoff in a unit test
    boom = TimeoutError("stalled")  # is_transient -> True
    runnable = MagicMock()
    runnable.invoke.side_effect = boom
    with pytest.raises(TimeoutError) as ei:  # reraise=True hands back the ORIGINAL, never RetryError
        call_with_retry(runnable, ["msg"], settings=replace(_SETTINGS, max_retries=3))
    assert ei.value is boom
    assert runnable.invoke.call_count == 3  # settings.max_retries


def test_call_with_retry_does_not_retry_permanent() -> None:
    runnable = MagicMock()
    runnable.invoke.side_effect = ValueError("bad request")  # is_transient -> False
    with pytest.raises(ValueError):
        call_with_retry(runnable, ["msg"], settings=_SETTINGS)
    runnable.invoke.assert_called_once()


# --------------------------------------------------------------------------- #
# raise_sanitized — endpoint/secret-free typed errors, cause chained          #
# --------------------------------------------------------------------------- #
def test_raise_sanitized_transient_gives_access_error() -> None:
    cause = ConnectionError(_POISON)
    with pytest.raises(LLMAccessError) as ei:
        raise_sanitized(cause)
    assert _POISON not in str(ei.value)
    assert ei.value.__cause__ is cause


def test_raise_sanitized_permanent_gives_unparseable_error() -> None:
    cause = ValueError(_POISON)
    with pytest.raises(UnparseableLLMResponseError) as ei:
        raise_sanitized(cause)
    assert _POISON not in str(ei.value)
    assert ei.value.__cause__ is cause


def test_raise_sanitized_uses_caller_supplied_error_types() -> None:
    class MyAccess(LLMAccessError): ...

    with pytest.raises(MyAccess):
        raise_sanitized(TimeoutError("x"), access_error=MyAccess)


def _openai_status_error(cls: type[openai.APIStatusError], status: int) -> openai.APIStatusError:
    response = httpx.Response(status, request=httpx.Request("POST", "http://llm.example/v1/chat/completions"))
    return cls(_POISON, response=response, body=None)


@pytest.mark.parametrize(
    ("cls", "status"),
    [(openai.AuthenticationError, 401), (openai.PermissionDeniedError, 403)],
    ids=["401", "403"],
)
def test_raise_sanitized_rejected_credentials_give_credentials_error(cls, status) -> None:
    # The LLM proxy refuses the API key (401) or its permissions (403): not an unparseable response.
    cause = _openai_status_error(cls, status)
    with pytest.raises(LLMCredentialsError) as ei:
        raise_sanitized(cause)
    assert not isinstance(ei.value, UnparseableLLMResponseError)
    assert _POISON not in str(ei.value)
    assert ei.value.__cause__ is cause


def _status_error(status: int) -> openai.APIStatusError:
    """The openai error for ``status``: ``RateLimitError`` for 429, the generic ``APIStatusError`` else."""
    return _openai_status_error(openai.RateLimitError if status == 429 else openai.APIStatusError, status)


@pytest.mark.parametrize("status", [408, 429], ids=["408", "429"])
def test_call_with_retry_retries_request_timeout_and_rate_limit(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    # A rate limit (429) or a request timeout (408) can clear on the next attempt: it is retried.
    monkeypatch.setattr("time.sleep", lambda _s: None)  # no real backoff in a unit test
    runnable = MagicMock()
    runnable.invoke.side_effect = [_status_error(status), "ok"]
    assert call_with_retry(runnable, ["msg"], settings=_SETTINGS) == "ok"
    assert runnable.invoke.call_count == 2


@pytest.mark.parametrize("status", [408, 429], ids=["408", "429"])
def test_exhausted_request_timeout_and_rate_limit_give_access_error(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    # When the retries are exhausted, the error is an access error (as for a 5xx), not an unparseable one.
    monkeypatch.setattr("time.sleep", lambda _s: None)
    cause = _status_error(status)
    runnable = MagicMock()
    runnable.invoke.side_effect = cause
    with pytest.raises(openai.APIStatusError) as raw:
        call_with_retry(runnable, ["msg"], settings=replace(_SETTINGS, max_retries=3))
    assert raw.value is cause
    assert runnable.invoke.call_count == 3
    with pytest.raises(LLMAccessError) as ei:
        raise_sanitized(raw.value)
    assert not isinstance(ei.value, UnparseableLLMResponseError)
    assert _POISON not in str(ei.value)
    assert ei.value.__cause__ is cause


def test_raise_sanitized_other_4xx_stays_unparseable_error() -> None:
    # A 404 (e.g. a wrong base URL path) keeps its old classification.
    with pytest.raises(UnparseableLLMResponseError):
        raise_sanitized(_openai_status_error(openai.NotFoundError, 404))


def test_raise_sanitized_uses_caller_supplied_credentials_error_type() -> None:
    class MyCredentials(LLMCredentialsError): ...

    with pytest.raises(MyCredentials):
        raise_sanitized(_openai_status_error(openai.AuthenticationError, 401), credentials_error=MyCredentials)


def _rate_limit(*, retry_after: str | None = None, code: str | None = None) -> openai.RateLimitError:
    """The ``openai.RateLimitError`` that the client raises for a 429: the response (with an optional
    ``Retry-After``) and the body ``error`` object (openai passes ``body["error"]``)."""
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    response = httpx.Response(
        429, headers=headers, request=httpx.Request("POST", "http://llm.example/v1/chat/completions")
    )
    body = {"message": _POISON, "type": code, "code": code} if code else None
    return openai.RateLimitError(_POISON, response=response, body=body)


def test_call_with_retry_waits_the_retry_after_of_a_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    waits: list[float] = []
    monkeypatch.setattr("time.sleep", waits.append)
    runnable = MagicMock()
    runnable.invoke.side_effect = [_rate_limit(retry_after="12"), _rate_limit(retry_after="600"), "ok"]
    assert call_with_retry(runnable, ["msg"], settings=_SETTINGS) == "ok"
    assert waits == [12.0, 30.0]  # the Retry-After, capped at settings.backoff_max


def test_call_with_retry_uses_the_backoff_without_a_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    waits: list[float] = []
    monkeypatch.setattr("time.sleep", waits.append)
    runnable = MagicMock()
    runnable.invoke.side_effect = [_rate_limit(), _rate_limit(), "ok"]
    assert call_with_retry(runnable, ["msg"], settings=replace(_SETTINGS, backoff_min=2.0)) == "ok"
    assert waits == [2.0, 2.0]  # wait_exponential from backoff_min


def test_a_rate_limit_for_an_exhausted_quota_is_not_retried_and_is_permanent(monkeypatch: pytest.MonkeyPatch) -> None:
    # OpenAI answers 429 ``insufficient_quota`` when the account has no quota: a wait cannot clear it,
    # so it is permanent (not the retryable access error), as before the 429 rule.
    monkeypatch.setattr("time.sleep", lambda _s: pytest.fail("a quota 429 must not be retried"))
    cause = _rate_limit(retry_after="1", code="insufficient_quota")
    runnable = MagicMock()
    runnable.invoke.side_effect = cause
    with pytest.raises(openai.RateLimitError):
        call_with_retry(runnable, ["msg"], settings=_SETTINGS)
    runnable.invoke.assert_called_once()
    with pytest.raises(UnparseableLLMResponseError) as ei:
        raise_sanitized(cause)
    assert not isinstance(ei.value, LLMAccessError)
    assert _POISON not in str(ei.value)
    assert ei.value.__cause__ is cause


@pytest.mark.parametrize(
    ("cause", "error", "message"),
    [
        (_openai_status_error(openai.NotFoundError, 404), UnparseableLLMResponseError, "response (HTTP 404)"),
        (_openai_status_error(openai.InternalServerError, 503), LLMAccessError, "retries (HTTP 503)"),
        (ValueError(_POISON), UnparseableLLMResponseError, "schema-invalid response"),
        (TimeoutError(_POISON), LLMAccessError, "transport retries"),
    ],
    ids=["404", "503", "no-status", "timeout"],
)
def test_the_sanitized_message_names_the_status_and_nothing_else(cause, error, message) -> None:
    # The status number is the one part of the raw error in the message: the ERROR log line names the
    # cause (the rung-5 system test reads it), and the endpoint / key still cannot leak.
    with pytest.raises(error) as ei:
        raise_sanitized(cause)
    assert str(ei.value).endswith(message)
    assert _POISON not in str(ei.value)
