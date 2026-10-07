"""Tolerant numeric environment knobs, shared by the onboarding waits and the NATS consumer."""

import math
import os


def env_num(name: str, default, cast, minimum):
    """Read ``name`` from the environment, tolerant of an unset / non-numeric / non-finite /
    below-``minimum`` value — a bad value must not crash the caller, it falls back to the default.
    ``inf`` is refused because ``time.sleep(inf)`` raises ``OverflowError`` outside the probe."""
    try:
        value = cast(os.environ[name])
    except (KeyError, TypeError, ValueError):
        return default
    return value if math.isfinite(value) and value >= minimum else default
