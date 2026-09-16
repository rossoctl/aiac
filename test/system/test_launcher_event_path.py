"""Unit coverage for ``launcher.event_path_reason`` — the **pure** event-path skip gate.

The event-driven onboarding path (deploy -> operator registers a Keycloak client -> Keycloak emits
``CLIENT_CREATED`` -> the AIAC SPI ``aiac-event-listener`` publishes on NATS -> the agent consumer
runs ``onboard_service``) is wired only when three facts hold: the NATS broker pod is Running, the
realm lists ``aiac-event-listener`` in ``eventsListeners``, and ``adminEventsEnabled`` is true
(``CLIENT_CREATED`` is an *admin* event). ``event_path_reason`` decides that from the two
already-gathered facts, side-effect-free, so a cluster wired for OPA but not for events skips cleanly
rather than hanging on a trigger that never fires.

These tests need **no** cluster — ``event_path_reason`` is pure, so they exercise the decision, not the
I/O that gathers its inputs (``event_path_unwired_reason``, which reads the live realm + broker). They
are therefore left **untagged** — a bare ``pytest`` runs them in the default (offline) lane, so the pure
skip-gate logic keeps fast-lane regression cover. The file lives under ``test/system/`` only to sit
beside the ``launcher.py`` it covers (test infra, with no ``src/aiac/`` module to mirror)."""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]  # -> aiac/
if str(REPO_ROOT) not in sys.path:  # so ``import test.system.*`` resolves
    sys.path.insert(0, str(REPO_ROOT))

from test.system.launcher import event_path_reason  # noqa: E402


def _wired_realm() -> dict:
    return {
        "eventsListeners": ["jboss-logging", "aiac-event-listener"],
        "adminEventsEnabled": True,
    }


def test_wired_returns_none():
    reason = event_path_reason(
        broker_phase="Running",
        realm_config={
            "eventsListeners": ["jboss-logging", "aiac-event-listener"],
            "adminEventsEnabled": True,
        },
    )
    assert reason is None


@pytest.mark.parametrize("broker_phase", ["Pending", "", "CrashLoopBackOff", "Succeeded"])
def test_broker_not_running_returns_reason(broker_phase):
    reason = event_path_reason(broker_phase=broker_phase, realm_config=_wired_realm())
    assert reason is not None
    assert "broker" in reason.lower()


def test_spi_listener_missing_returns_reason():
    reason = event_path_reason(
        broker_phase="Running",
        realm_config={"eventsListeners": ["jboss-logging"], "adminEventsEnabled": True},
    )
    assert reason is not None
    assert "aiac-event-listener" in reason


def test_events_listeners_absent_returns_reason():
    # A realm representation that omits ``eventsListeners`` entirely is treated as unwired, not a crash.
    reason = event_path_reason(broker_phase="Running", realm_config={"adminEventsEnabled": True})
    assert reason is not None
    assert "aiac-event-listener" in reason


def test_admin_events_disabled_returns_reason():
    reason = event_path_reason(
        broker_phase="Running",
        realm_config={
            "eventsListeners": ["jboss-logging", "aiac-event-listener"],
            "adminEventsEnabled": False,
        },
    )
    assert reason is not None
    assert "adminEventsEnabled" in reason
