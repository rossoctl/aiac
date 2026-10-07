"""The event-before-commit race hint of the UC-1 system-test harness (handoff 20, D33) — pure unit tests.

Keycloak calls the ``aiac-event-listener`` SPI inside the admin request. Before the fix the SPI
published ``CLIENT_CREATED`` before Keycloak committed the new client, so the Controller's first IdP
read got Keycloak's ``404 "Could not find client"`` and the onboarding started only with a NATS
redelivery, after ``ACK_WAIT`` (600 s) — longer than the harness gates. Now the SPI publishes after the
commit and the Controller reads again for a bounded time (``ONBOARD_CLIENT_WAIT_*``), so the default
gates hold. When a gate still times out, its message tells whether the Controller log shows that 404
(``uc1_onboard.commit_race_hint`` over the log text; ``controller_commit_race_hint`` reads the log).

These tests pin the offline parts with ``kubectl`` stubbed (no cluster): the pure hint (which lines
count, the client filter, the bounded quote, the advice), the bounded read-only log call (a time window
and a tail), and the best-effort contract (a failure gives no hint, never an exception, so it cannot
replace the gate failure).

They import the system harness like ``test_uc1_cr_capture.py`` does
(``from test.system import uc1_onboard``): that harness does **no** cluster I/O at import time.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import pytest

HERE = Path(__file__).resolve().parent  # test/unit/agent/uc/onboarding/
REPO_ROOT = HERE.parents[4]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from test.system import uc1_onboard as uc1  # noqa: E402

UUID = "3e0af988-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
OTHER_UUID = "77aa0c11-2b3c-4d5e-9f00-112233445566"
POD = "aiac-agent-6d9f7c5b8-x2x7q"
DEPLOYED_AT = datetime(2026, 10, 6, 21, 55, 14, 795000, tzinfo=timezone.utc)

# Keycloak's 404 body, as the IdP service passes it on in ``{"error": str(KeycloakError)}``.
_KEYCLOAK_404 = (
    '{"error":"404: b\'{\\"error\\":\\"Could not find client\\",'
    '\\"error_description\\":\\"For more on this error consult the server log.\\"}\'"}'
)


def _before_fix(uuid: str = UUID) -> str:
    """The Controller line before handoff 20: the IdP service answered 502, the library tried once."""
    return f"HTTPException: 502: IdP config unavailable resolving service {uuid!r}: HTTP 502: {_KEYCLOAK_404}"


def _after_wait(uuid: str = UUID) -> str:
    """The Controller line after handoff 20, when the client is still not visible after the bounded wait."""
    return (
        f"ServiceNotVisibleError: 502: IdP config unavailable resolving service {uuid!r}: the client is not "
        f"visible after 15 reads (ONBOARD_CLIENT_WAIT_*): HTTP 404: {_KEYCLOAK_404}"
    )


NOISE = "\n".join(
    [
        "INFO:     Started server process [1]",
        "INFO:     Application startup complete.",
        "UC1 rollback: deleted scope 'github-agent.source_operations' (service x)",
    ]
)


# ======================================================================================
# The pure hint — log text in, hint string out
# ======================================================================================


def test_no_hint_for_a_clean_log() -> None:
    assert uc1.commit_race_hint(NOISE) == ""
    assert uc1.commit_race_hint("") == ""


@pytest.mark.parametrize("line", [_before_fix(), _after_wait()], ids=["before-fix-502", "after-wait-404"])
def test_hint_for_could_not_find_client(line: str) -> None:
    """A Controller line with Keycloak's ``Could not find client`` gives the hint: what the log shows,
    the probable cause (the event came before the Keycloak commit, handoff 20 / D33), and what to check
    (the SPI image publishes after the commit; the Controller's bounded wait ``ONBOARD_CLIENT_WAIT_*``)."""
    hint = uc1.commit_race_hint(f"{NOISE}\n{line}\n{NOISE}")
    assert "Could not find client" in hint
    assert "before" in hint and "commit" in hint
    assert "handoff 20" in hint and "D33" in hint
    assert "aiac-event-listener" in hint and "after the commit" in hint
    assert "ONBOARD_CLIENT_WAIT_ATTEMPTS" in hint and "ONBOARD_CLIENT_WAIT_BACKOFF" in hint


def test_hint_quotes_the_first_line_and_counts_the_lines() -> None:
    """The hint quotes the first matching line (it names the client UUID) and gives the number of
    matching lines (more than one: redeliveries)."""
    hint = uc1.commit_race_hint("\n".join([NOISE, _before_fix(), NOISE, _after_wait()]))
    assert "2 line(s)" in hint
    assert UUID in hint
    assert "HTTPException: 502" in hint  # the first line, not the second


def test_service_not_visible_error_counts_without_the_keycloak_text() -> None:
    """The Controller's own ``ServiceNotVisibleError`` is the same race, also if the IdP 404 body does not
    carry Keycloak's text."""
    line = f"ServiceNotVisibleError: 502: IdP config unavailable resolving service {UUID!r}: HTTP 404: {{}}"
    assert "ServiceNotVisibleError" in uc1.commit_race_hint(line)


@pytest.mark.parametrize(
    "line",
    [
        'KeycloakGetError: 404: b\'{"error":"Could not find client scope"}\'',
        "Could not find clients for the realm",
        "Could not find clientScope abc",
    ],
    ids=["client-scope", "clients", "clientScope"],
)
def test_other_not_found_errors_give_no_hint(line: str) -> None:
    """Keycloak's ``Could not find client scope`` (or any longer word) is another error, not the race."""
    assert uc1.commit_race_hint(line) == ""


def test_service_uuid_keeps_only_the_lines_of_that_client() -> None:
    """With the client's UUID, a line for another client (for example a redelivery for a client that an
    earlier run deleted) gives no hint; a line for this client does."""
    other = _before_fix(OTHER_UUID)
    assert uc1.commit_race_hint(other, service_uuid=UUID) == ""
    assert uc1.commit_race_hint(other) != ""  # with no UUID, every line counts
    hint = uc1.commit_race_hint(f"{other}\n{_after_wait()}", service_uuid=UUID)
    assert "1 line(s)" in hint and UUID in hint and OTHER_UUID not in hint


def test_quoted_line_is_bounded() -> None:
    """A very long log line does not make the gate message very long."""
    line = _before_fix() + " " + "x" * 5000
    hint = uc1.commit_race_hint(line)
    assert "Could not find client" in hint
    assert len(hint) < 1500


def test_append_hint() -> None:
    assert uc1.append_hint("gate failed.", "") == "gate failed."
    assert uc1.append_hint("gate failed.", "Hint.") == "gate failed. Hint."


# ======================================================================================
# The live reader — bounded and read-only, best-effort
# ======================================================================================


def _stub_logs(
    monkeypatch: pytest.MonkeyPatch, answer: str | Exception, *, client: dict | None | Exception = None
) -> list[tuple[str, ...]]:
    """Replace the harness ``kubectl`` (the log read), the Controller pod lookup and the client lookup.
    ``answer`` is the log text (an exception value is raised); ``client`` is the Keycloak client that
    ``workload_client`` gives. Returns the argv of each ``kubectl`` call."""
    calls: list[tuple[str, ...]] = []

    def fake_kubectl(*args: str, input_text: str | None = None, timeout: float = 60.0) -> str:
        calls.append(args)
        if isinstance(answer, Exception):
            raise answer
        return answer

    def fake_client(admin, workload: str) -> dict | None:
        if isinstance(client, Exception):
            raise client
        return client

    monkeypatch.setattr(uc1, "kubectl", fake_kubectl)
    monkeypatch.setattr(uc1, "resolve_controller_pod", lambda: POD)
    monkeypatch.setattr(uc1, "workload_client", fake_client)
    return calls


def test_controller_logs_reads_a_bounded_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """``controller_logs(since=, tail=)`` reads only the app container's lines since the time (RFC 3339,
    UTC) and at most ``tail`` lines; with no argument it reads the full log, as before."""
    calls = _stub_logs(monkeypatch, "log")
    local = DEPLOYED_AT.astimezone(timezone(timedelta(hours=3)))
    assert uc1.controller_logs(since=local, tail=500) == "log"
    assert uc1.controller_logs() == "log"
    bounded, full = calls
    assert bounded[:2] == ("logs", "-n") and POD in bounded and uc1.CONTROLLER_DEPLOYMENT in bounded
    assert "--since-time=2026-10-06T21:55:14Z" in bounded and "--tail=500" in bounded
    assert not any(a.startswith(("--since-time", "--tail")) for a in full)


def test_live_hint_reads_since_the_deploy_with_slack(monkeypatch: pytest.MonkeyPatch) -> None:
    """The live hint reads the log from a short slack before the deploy, at most
    ``CONTROLLER_LOG_TAIL`` lines, with ``kubectl logs`` only (read-only)."""
    calls = _stub_logs(monkeypatch, _after_wait(), client={"id": UUID})
    hint = uc1.controller_commit_race_hint(DEPLOYED_AT, admin=object(), workload="github-agent")
    assert "Could not find client" in hint and UUID in hint
    (args,) = calls
    assert args[0] == "logs"
    start = DEPLOYED_AT - timedelta(seconds=uc1.CONTROLLER_LOG_SLACK_SECONDS)
    assert f"--since-time={start.strftime('%Y-%m-%dT%H:%M:%SZ')}" in args
    assert f"--tail={uc1.CONTROLLER_LOG_TAIL}" in args


def test_live_hint_filters_on_the_workload_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """The live hint looks up the workload's client UUID, so a line for another client gives no hint."""
    _stub_logs(monkeypatch, _before_fix(OTHER_UUID), client={"id": UUID})
    assert uc1.controller_commit_race_hint(DEPLOYED_AT, admin=object(), workload="github-agent") == ""


def test_live_hint_without_the_client_counts_every_line(monkeypatch: pytest.MonkeyPatch) -> None:
    """A client that is gone, or a failed client lookup, does not stop the hint: every line counts."""
    for client in (None, RuntimeError("Keycloak down")):
        _stub_logs(monkeypatch, _before_fix(OTHER_UUID), client=client)
        assert "Could not find client" in uc1.controller_commit_race_hint(
            DEPLOYED_AT, admin=object(), workload="github-agent"
        )
    _stub_logs(monkeypatch, _before_fix(OTHER_UUID))
    assert "Could not find client" in uc1.controller_commit_race_hint(DEPLOYED_AT)  # no admin, no window


ERRORS: list[Callable[[], Exception]] = [
    lambda: subprocess.CalledProcessError(1, ["kubectl"], stderr="Unauthorized"),
    lambda: subprocess.TimeoutExpired(["kubectl"], 60),
    lambda: FileNotFoundError("kubectl"),
    lambda: RuntimeError("no (non-terminating) pod matches selector"),
]


@pytest.mark.parametrize("make_error", ERRORS, ids=["called-process", "timeout", "no-kubectl", "no-pod"])
def test_live_hint_never_raises(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, make_error: Callable[[], Exception]
) -> None:
    """A log that cannot be read gives no hint and a WARNING, never an exception: the hint is built in a
    gate's failure path, so it must not replace the gate's own error."""
    _stub_logs(monkeypatch, make_error(), client={"id": UUID})
    with caplog.at_level(logging.WARNING, logger=uc1.log.name):
        assert uc1.controller_commit_race_hint(DEPLOYED_AT, admin=object(), workload="github-agent") == ""
    assert any(rec.levelno == logging.WARNING for rec in caplog.records)
