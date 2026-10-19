"""Unit tests for the login-client audience warning (D30, ``warn_platform_tool_audiences``).

The helper reads the enforcement side from ``AIAC_ENFORCEMENT_SIDE`` (unset here, so target side,
unless a test sets it) and the IdP through a ``Configuration`` (a ``MagicMock`` here, or the
patched ``platform_audience.Configuration`` for the default realm). It only logs: it never raises.
"""

import logging
from typing import Literal
from unittest.mock import MagicMock, patch

import pytest

from aiac.agent.uc.onboarding import platform_audience
from aiac.agent.uc.onboarding.platform_audience import warn_platform_tool_audiences
from aiac.idp.configuration.api import IdPHTTPError
from aiac.idp.configuration.models import ClientId, PlatformToolAudience

TOOL = ClientId("spiffe://localtest.me/ns/team1/sa/github-tool")
SCOPE = "agent-team1-github-tool-aud"


@pytest.fixture(autouse=True)
def _target_side(monkeypatch):
    monkeypatch.delenv("AIAC_ENFORCEMENT_SIDE", raising=False)


@pytest.fixture
def agent_side(monkeypatch):
    monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", "agent-side")


def _link(
    link: Literal["default", "optional", "client"] = "default",
    scope: str | None = SCOPE,
    mapper: str = SCOPE,
    login_client: str = "rossoctl",
):
    return PlatformToolAudience(login_client=login_client, link=link, scope=scope, mapper=mapper, tool_client_id=TOOL)


def _config(*links):
    config = MagicMock()
    config.get_platform_tool_audiences.return_value = list(links)
    return config


def _warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


def test_under_target_side_there_is_no_idp_read_and_no_log(caplog):
    config = _config(_link())
    with caplog.at_level(logging.WARNING):
        warn_platform_tool_audiences(config, TOOL)
    config.get_platform_tool_audiences.assert_not_called()
    assert _warnings(caplog) == []


def test_under_agent_side_each_link_gives_one_warning(agent_side, caplog):
    config = _config(
        _link("default"),
        _link("optional", scope="opt-aud", mapper="opt-mapper"),
        _link("client", scope=None, mapper="direct-aud"),
    )
    with caplog.at_level(logging.WARNING):
        warn_platform_tool_audiences(config, TOOL)
    default, optional, client = _warnings(caplog)
    for message in (default, optional, client):
        assert "'rossoctl'" in message and repr(TOOL) in message and "agent side" in message
    assert repr(SCOPE) in default and "as a default scope" in default
    assert "'opt-aud'" in optional and "as a optional scope" not in optional and "as an optional scope" in optional
    assert "'opt-mapper'" in optional
    assert "on its own client" in client and "'direct-aud'" in client


def test_the_tool_client_id_is_the_filter(agent_side):
    config = _config()
    warn_platform_tool_audiences(config, TOOL)
    config.get_platform_tool_audiences.assert_called_once_with(TOOL)
    config = _config()
    warn_platform_tool_audiences(config)
    config.get_platform_tool_audiences.assert_called_once_with(None)


def test_no_link_gives_no_warning(agent_side, caplog):
    with caplog.at_level(logging.WARNING):
        warn_platform_tool_audiences(_config(), TOOL)
    assert _warnings(caplog) == []


@pytest.mark.parametrize("error", [IdPHTTPError(502, "boom"), RuntimeError("down"), ConnectionError()], ids=repr)
def test_an_idp_failure_is_logged_and_not_raised(agent_side, caplog, error):
    config = MagicMock()
    config.get_platform_tool_audiences.side_effect = error
    with caplog.at_level(logging.WARNING):
        assert warn_platform_tool_audiences(config, TOOL) is None
    (message,) = _warnings(caplog)
    assert "cannot read" in message and repr(TOOL) in message


def test_with_no_config_it_uses_the_default_realm(agent_side):
    with patch.object(platform_audience, "Configuration") as configuration:
        configuration.for_default_realm.return_value.get_platform_tool_audiences.return_value = []
        warn_platform_tool_audiences()
    configuration.for_default_realm.assert_called_once_with()
    configuration.for_default_realm.return_value.get_platform_tool_audiences.assert_called_once_with(None)


def test_an_unset_realm_is_logged_and_not_raised(agent_side, monkeypatch, caplog):
    monkeypatch.delenv("KEYCLOAK_REALM", raising=False)
    with caplog.at_level(logging.WARNING):
        warn_platform_tool_audiences()
    (message,) = _warnings(caplog)
    assert "cannot read" in message and "the managed tools" in message and "KEYCLOAK_REALM" in message


def test_an_unknown_side_is_logged_and_not_raised(monkeypatch, caplog):
    monkeypatch.setenv("AIAC_ENFORCEMENT_SIDE", "both-sides")
    config = _config(_link())
    with caplog.at_level(logging.WARNING):
        warn_platform_tool_audiences(config, TOOL)
    config.get_platform_tool_audiences.assert_not_called()
    (message,) = _warnings(caplog)
    assert "cannot read" in message


def test_log_values_have_no_line_breaks(agent_side, caplog):
    config = _config(_link(scope="evil\nINFO:forged line", mapper="m\r\nx", login_client="ross\noctl"))
    with caplog.at_level(logging.WARNING):
        warn_platform_tool_audiences(config, ClientId("tool\nid"))
    (message,) = _warnings(caplog)
    assert "\n" not in message and "\r" not in message


def test_the_read_failure_warning_has_no_line_breaks(agent_side, caplog):
    # An IdP error body or a Keycloak message can hold a line break: it must not forge a log line.
    config = MagicMock()
    config.get_platform_tool_audiences.side_effect = RuntimeError("down\nINFO:forged line\r")
    with caplog.at_level(logging.WARNING):
        warn_platform_tool_audiences(config, ClientId("tool\nid"))
    (message,) = _warnings(caplog)
    assert "cannot read" in message
    assert "\n" not in message and "\r" not in message
