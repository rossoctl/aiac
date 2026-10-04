"""Unit tests for ``aiac.shared.logging_config``.

The regression these guard is the one that made ``kubectl logs deployment/aiac-agent`` show
nothing but uvicorn access lines: no entrypoint configured the root logger, so it had no
handler and defaulted to WARNING, and every ``logger.info(...)`` in the package was dropped.
``test_package_logger_emits_info_after_configure`` is the direct expression of that bug — it
fails against an unconfigured root logger and passes once ``configure_logging()`` has run.

Each test restores the root logger's handlers and level afterwards, so configuring logging
here cannot leak into the rest of the suite (pytest's own ``caplog`` relies on that state).
"""

import logging
import sys

import pytest

from aiac.shared.logging_config import configure_logging, log_level


@pytest.fixture(autouse=True)
def _restore_root_logger():
    """Snapshot/restore the root logger — ``configure_logging`` mutates global state."""
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


# ── log_level() ───────────────────────────────────────────────────────────────
def test_defaults_to_info_when_unset(monkeypatch):
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    assert log_level() == logging.INFO


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("DEBUG", logging.DEBUG),
        ("debug", logging.DEBUG),  # case-insensitive
        ("  WARNING  ", logging.WARNING),  # surrounding whitespace tolerated
        ("ERROR", logging.ERROR),
        ("CRITICAL", logging.CRITICAL),
        ("10", logging.DEBUG),  # numeric form
    ],
)
def test_parses_names_and_numbers(monkeypatch, raw, expected):
    monkeypatch.setenv("LOG_LEVEL", raw)
    assert log_level() == expected


@pytest.mark.parametrize("raw", ["", "VERBOSE", "not-a-level"])
def test_unrecognized_value_falls_back_to_info(monkeypatch, raw):
    """A misspelled level must not stop a service booting — it falls back to INFO."""
    monkeypatch.setenv("LOG_LEVEL", raw)
    assert log_level() == logging.INFO


# ── configure_logging() ───────────────────────────────────────────────────────
def test_installs_stdout_handler_and_sets_level(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    root = logging.getLogger()
    root.handlers[:] = []

    configure_logging()

    assert root.level == logging.DEBUG
    streams = [getattr(h, "stream", None) for h in root.handlers]
    assert sys.stdout in streams, "root logger should log to stdout, not stderr"


def test_package_logger_emits_info_after_configure(monkeypatch):
    """The actual bug: a package logger's INFO records were being discarded.

    Before ``configure_logging()`` the root logger is at its WARNING default and an
    ``aiac.*`` INFO record goes nowhere; after it, the record is emitted.
    """
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    root = logging.getLogger()
    root.handlers[:] = []
    root.setLevel(logging.WARNING)  # the unconfigured default that caused the silence

    consumer_logger = logging.getLogger("aiac.agent.eventbus.consumer")
    assert not consumer_logger.isEnabledFor(logging.INFO), "precondition: INFO is dropped"

    configure_logging()

    assert consumer_logger.isEnabledFor(logging.INFO)

    records = []
    root.addHandler(logging.Handler())
    root.handlers[-1].emit = records.append  # type: ignore[method-assign]
    consumer_logger.info("aiac-agent-consumer subscribed to %s", ["aiac.apply.service.*"])
    assert [r.getMessage() for r in records] == [
        "aiac-agent-consumer subscribed to ['aiac.apply.service.*']"
    ]


def test_level_is_authoritative_when_root_already_has_a_handler(monkeypatch):
    """``basicConfig`` is a no-op once the root logger has a handler — and in that case it
    does not apply its ``level`` either, so ``configure_logging`` sets it explicitly."""
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    root = logging.getLogger()
    root.handlers[:] = [logging.NullHandler()]  # another harness configured it first
    root.setLevel(logging.WARNING)

    configure_logging()

    assert root.level == logging.DEBUG


def test_is_idempotent(monkeypatch):
    """Several entrypoints may call it (or one may call it twice) without stacking handlers."""
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    root = logging.getLogger()
    root.handlers[:] = []

    configure_logging()
    count_after_first = len(root.handlers)
    configure_logging()

    assert len(root.handlers) == count_after_first
