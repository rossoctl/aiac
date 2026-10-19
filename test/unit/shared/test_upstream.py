"""Unit tests for aiac.shared.upstream — the status that ``is_transient`` reads from an error, the
transient 408 / 429 rule, and the ``Retry-After`` wait of the shared retry loop."""

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import MagicMock

import pytest
import requests
from kubernetes.client.exceptions import ApiException

from aiac.idp.configuration.api import IdPHTTPError
from aiac.shared.upstream import is_transient, retry_after, run_upstream, upstream_retrying


def _response(status: int) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    return resp


class _StatusError(Exception):
    """An error that carries its own ``status`` next to a stand-in ``response``."""

    def __init__(self, status, response=None) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status
        self.response = response


# ---------------------------------------------------------------------------
# The seams that call run_upstream keep their behaviour
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("status", "transient"), [(500, True), (503, True), (404, False), (409, False)])
def test_requests_http_error_status_comes_from_the_response(status, transient):
    # MCP discovery: resp.raise_for_status() raises an HTTPError with the real response.
    assert is_transient(requests.HTTPError(response=_response(status))) is transient


@pytest.mark.parametrize(("status", "transient"), [(503, True), (404, False)])
def test_requests_http_error_with_a_mock_response_that_has_a_status_code(status, transient):
    assert is_transient(requests.HTTPError(response=MagicMock(status_code=status))) is transient


def test_requests_http_error_with_no_response_is_not_transient():
    assert is_transient(requests.HTTPError()) is False


@pytest.mark.parametrize(("status", "transient"), [(500, True), (503, True), (404, False), (403, False)])
def test_kubernetes_api_exception_status(status, transient):
    # The provision k8s seam: ApiException carries the status on .status and has no .response.
    assert is_transient(ApiException(status=status)) is transient


# ---------------------------------------------------------------------------
# IdPHTTPError: its own status wins over a stand-in response with no status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("status", "transient"), [(502, True), (503, True), (404, False), (409, False)])
def test_idp_http_error_with_a_real_response(status, transient):
    assert is_transient(IdPHTTPError(status, "text", _response(status))) is transient


@pytest.mark.parametrize(("status", "transient"), [(502, True), (404, False)])
def test_idp_http_error_with_no_response(status, transient):
    assert is_transient(IdPHTTPError(status, "text")) is transient


@pytest.mark.parametrize(("status", "transient"), [(502, True), (503, True), (404, False)])
def test_a_mock_response_with_no_status_code_does_not_hide_the_status(status, transient):
    # A MagicMock attribute that is not set is a MagicMock, and int(MagicMock()) is 1; it must not
    # hide the error's own .status.
    assert is_transient(IdPHTTPError(status, "text", MagicMock())) is transient
    assert is_transient(_StatusError(status, MagicMock())) is transient


def test_a_bool_or_non_numeric_status_is_not_a_status():
    assert is_transient(_StatusError(True)) is False
    assert is_transient(_StatusError("unavailable")) is False
    assert is_transient(_StatusError("503")) is True  # a numeric string still counts, as before


# ---------------------------------------------------------------------------
# HTTP 408 / 429 are transient for every upstream; a 429 for an exhausted quota is not
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [408, 429])
def test_request_timeout_and_rate_limit_are_transient_for_every_seam(status):
    # The Kubernetes API (API Priority and Fairness answers 429), the IdP library and MCP discovery.
    assert is_transient(ApiException(status=status)) is True
    assert is_transient(IdPHTTPError(status, "text", _response(status))) is True
    assert is_transient(requests.HTTPError(response=_response(status))) is True


class _QuotaError(Exception):
    """An error shaped like ``openai.RateLimitError``: ``status``, ``code`` and a dict ``body``."""

    def __init__(self, status=429, *, code=None, body=None) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status
        self.code = code
        self.body = body


@pytest.mark.parametrize(
    "error",
    [
        _QuotaError(code="insufficient_quota"),
        _QuotaError(body={"code": "insufficient_quota"}),
        _QuotaError(body={"error": {"type": "insufficient_quota", "code": None}}),
        _QuotaError(code="QUOTA_EXCEEDED"),
        _QuotaError(body={"code": "billing_hard_limit_reached"}),
    ],
    ids=["code", "body-code", "nested-type", "upper-case", "billing"],
)
def test_a_rate_limit_for_an_exhausted_quota_is_permanent(error):
    # A wait cannot clear a quota or billing limit: it is not retried (as before the 429 rule).
    assert is_transient(error) is False


def test_a_plain_rate_limit_is_transient():
    assert is_transient(_QuotaError(code="rate_limit_exceeded", body={"code": "rate_limit_exceeded"})) is True
    assert is_transient(_QuotaError(body="not json")) is True


def test_a_quota_code_on_another_status_does_not_change_it():
    assert is_transient(_QuotaError(503, code="insufficient_quota")) is True  # a 5xx stays transient
    assert is_transient(_QuotaError(400, code="insufficient_quota")) is False


# ---------------------------------------------------------------------------
# retry_after — the Retry-After header of the error, in seconds
# ---------------------------------------------------------------------------


def _with_retry_after(value: str, status: int = 429) -> requests.HTTPError:
    resp = _response(status)
    resp.headers["Retry-After"] = value
    return requests.HTTPError(response=resp)


def test_retry_after_in_seconds():
    assert retry_after(_with_retry_after("7")) == 7.0
    assert retry_after(_with_retry_after(" 1.5 ")) == 1.5
    assert retry_after(_with_retry_after("-3")) == 0.0


def test_retry_after_as_an_http_date():
    when = datetime.now(timezone.utc) + timedelta(seconds=20)
    wait = retry_after(_with_retry_after(format_datetime(when, usegmt=True)))
    assert wait is not None and 15 <= wait <= 20
    assert retry_after(_with_retry_after("Wed, 21 Oct 2015 07:28:00 GMT")) == 0.0  # in the past


def test_retry_after_of_a_kubernetes_api_exception():
    exc = ApiException(status=429)
    exc.headers = {"Retry-After": "2"}
    assert retry_after(exc) == 2.0


@pytest.mark.parametrize(
    "exc",
    [
        _with_retry_after("soon"),
        requests.HTTPError(response=_response(429)),
        requests.HTTPError(),
        IdPHTTPError(429, "text", MagicMock()),  # a stand-in response: its headers are not a header map
        ValueError("no response"),
        None,
    ],
    ids=["not-a-number-or-date", "no-header", "no-response", "mock-response", "plain-error", "none"],
)
def test_no_usable_retry_after_is_none(exc):
    assert retry_after(exc) is None


# ---------------------------------------------------------------------------
# upstream_retrying / run_upstream — Retry-After replaces the backoff, with a cap
# ---------------------------------------------------------------------------


@pytest.fixture
def waits(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    recorded: list[float] = []
    monkeypatch.setattr("time.sleep", recorded.append)  # tenacity sleeps via time.sleep at run time
    monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "3")
    return recorded


def test_run_upstream_waits_the_retry_after_of_a_rate_limit(waits):
    fn = MagicMock(side_effect=[_with_retry_after("5"), _with_retry_after("0"), "ok"])
    assert run_upstream(fn) == "ok"
    assert waits == [5.0, 0.0]


def test_run_upstream_caps_the_retry_after(waits):
    fn = MagicMock(side_effect=[_with_retry_after("3600"), "ok"])
    assert run_upstream(fn) == "ok"
    assert waits == [30.0]  # the backoff maximum of run_upstream


def test_run_upstream_uses_the_backoff_without_a_retry_after(waits):
    fn = MagicMock(side_effect=ApiException(status=429))
    with pytest.raises(ApiException):
        run_upstream(fn)
    assert fn.call_count == 3
    assert waits == [1, 2]


def test_run_upstream_does_not_retry_a_quota_rate_limit(waits):
    fn = MagicMock(side_effect=_QuotaError(code="insufficient_quota"))
    with pytest.raises(_QuotaError):
        run_upstream(fn)
    fn.assert_called_once()
    assert waits == []


def test_upstream_retrying_uses_its_own_budget_and_cap(waits):
    fn = MagicMock(side_effect=[_with_retry_after("60"), TimeoutError(), "ok"])
    retryer = upstream_retrying(attempts=5, backoff_min=2.0, backoff_max=10.0)
    assert retryer(fn) == "ok"
    assert waits == [10.0, 2.0]  # Retry-After capped at backoff_max, then the backoff from backoff_min
