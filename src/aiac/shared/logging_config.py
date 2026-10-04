"""Shared logging configuration (project-level).

``configure_logging()`` installs a root-logger handler on **stdout** and sets its level
from ``LOG_LEVEL`` (default ``INFO``). Every service entrypoint must call it before the
app object is built, because **nothing else configures the root logger**: uvicorn's own
``LOGGING_CONFIG`` defines handlers for ``uvicorn``/``uvicorn.error``/``uvicorn.access``
only, so without this call the root logger has no handler and defaults to ``WARNING`` —
every ``logger.info(...)`` in the package is discarded and a pod's log shows nothing but
uvicorn's access lines. That is exactly what happened to aiac-agent: the *same*
``aiac.agent.eventbus.stream`` line that is visible in the init container's log (it calls
``basicConfig`` itself) was invisible in the Controller's.

``uvicorn --log-level`` is **not** a substitute: it retargets uvicorn's own loggers and
leaves the root logger untouched, so application logs stay silent.

Ordering is safe in both directions. uvicorn applies its ``LOGGING_CONFIG`` before it
imports the app, and that config sets ``disable_existing_loggers: False`` and configures
no root logger — so a module-import-time call here is neither wiped by uvicorn nor does it
duplicate uvicorn's lines (uvicorn's loggers carry ``propagate: False``).

Lives at the project root (``aiac.shared``) alongside ``upstream.py`` so any layer can
reuse it without importing from the ``agent`` package.
"""

import logging
import os
import sys

_DEFAULT_LEVEL = "INFO"

# ``levelname:name:message`` — the stdlib ``basicConfig`` default shape, which is what the
# init container already emits. Kept identical so both of the Agent pod's containers read the
# same way, and because kubectl supplies per-line wall-clock timestamps anyway (the demo
# driver scopes collection with ``--since-time``, not by parsing a timestamp out of the text).
_FORMAT = "%(levelname)s:%(name)s:%(message)s"


def log_level() -> int:
    """Level from ``LOG_LEVEL`` (default ``INFO``), tolerant of an unset, misspelled, or
    numeric value — a bad value must not stop a service from booting, it falls back to the
    default. Accepts a name (``DEBUG``, case-insensitive) or a number (``10``)."""
    raw = os.getenv("LOG_LEVEL", _DEFAULT_LEVEL).strip()
    if raw.isdigit():
        return int(raw)
    # ``getLevelName`` maps a known name to its int and returns the string "Level X"
    # for an unknown one — so anything non-int is an unrecognized name.
    level = logging.getLevelName(raw.upper())
    return level if isinstance(level, int) else logging.getLevelName(_DEFAULT_LEVEL)


def configure_logging() -> None:
    """Point the root logger at stdout and set its level from ``LOG_LEVEL``. Idempotent:
    safe to call from several entrypoints or twice in one process."""
    level = log_level()
    logging.basicConfig(level=level, format=_FORMAT, stream=sys.stdout)
    # ``basicConfig`` is a no-op when the root logger already has a handler (a second call,
    # or another harness that configured it first) — and in that case it does not apply
    # ``level`` either. Set it explicitly so ``LOG_LEVEL`` is authoritative regardless.
    logging.getLogger().setLevel(level)
