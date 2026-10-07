"""Unit tests for aiac.shared.upstream — the status that ``is_transient`` reads from an error."""

from unittest.mock import MagicMock

import pytest
import requests
from kubernetes.client.exceptions import ApiException

from aiac.idp.configuration.api import IdPHTTPError
from aiac.shared.upstream import is_transient


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
