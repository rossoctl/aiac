"""Session hooks of the system tree."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

log = logging.getLogger(__name__)

# The harness that holds Direct Access Grants on the login client (``hold_direct_access_grants``).
HARNESS_FILE = Path(__file__).resolve().with_name("uc1_onboard.py")


def _harness_modules() -> list:
    """Each loaded copy of the harness, whatever name it was imported under (``test.system.uc1_onboard``,
    ``uc1_onboard`` from another ``sys.path`` entry, or a module of ``--import-mode=importlib``). A copy
    is a module whose file is ``HARNESS_FILE``. Each copy has its own holds, so each one is released."""
    found = []
    for module in list(sys.modules.values()):
        path = getattr(module, "__file__", None)
        try:
            same = bool(path) and Path(path).resolve() == HARNESS_FILE
        except (OSError, TypeError, ValueError):
            continue
        if same:
            found.append(module)
    return found


def release_harness_grants() -> None:
    """Run ``release_direct_access_grants`` of each loaded copy of the harness (``_harness_modules``).
    No copy loaded = no stack ran = nothing to release. A copy with no release function, or a release
    that raises, is logged as a warning (the grant can then stay on until a later run takes it over);
    it never fails the session teardown."""
    for module in _harness_modules():
        release = getattr(module, "release_direct_access_grants", None)
        if not callable(release):
            log.warning(
                "the harness module %r has no release_direct_access_grants: Direct Access Grants on the "
                "login client is not released by this session",
                module.__name__,
            )
            continue
        try:
            release()
        except Exception:  # noqa: BLE001 — a teardown hook: log, never fail the session end
            log.warning(
                "the release of Direct Access Grants by the harness module %r failed: the grant can stay on "
                "until its holder entry expires and a later run takes it over",
                module.__name__,
                exc_info=True,
            )


@pytest.fixture(scope="session", autouse=True)
def _release_direct_access_grants():
    """At the end of the session, release Direct Access Grants on each login client that the harness
    holds (``uc1_onboard.hold_direct_access_grants``; ``release_harness_grants``). Session scope: the
    grant is held once, by the first stack of the session, and released once. A no-op when no stack ran."""
    yield
    release_harness_grants()
