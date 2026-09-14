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

import pytest

from aiac.agent.llm import (
    LLMAccessError,
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
