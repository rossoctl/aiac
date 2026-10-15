"""Session hooks of the system tree."""

from __future__ import annotations

import sys

import pytest


@pytest.fixture(scope="session", autouse=True)
def _release_direct_access_grants():
    """At the end of the session, turn Direct Access Grants off again on each login client that the
    harness turned it on for (``uc1_onboard.hold_direct_access_grants``). Session scope: the grant is
    turned on once, by the first stack of the session, and off once. A no-op when no stack ran."""
    yield
    uc1 = sys.modules.get("test.system.uc1_onboard")  # not imported = no stack ran = nothing to release
    if uc1 is not None:
        uc1.release_direct_access_grants()
