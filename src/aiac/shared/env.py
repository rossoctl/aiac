"""Tolerant numeric environment knobs, shared by the onboarding waits, the NATS consumer and the PDP library."""

import math
import os
from collections.abc import Callable
from typing import TypeVar

N = TypeVar("N", int, float)


def env_num(name: str, default: N, cast: Callable[[str], N], minimum: N, *, exclusive: bool = False) -> N:
    """Read ``name`` from the environment, tolerant of an unset / non-numeric / non-finite /
    below-``minimum`` value — a bad value must not crash the caller, it falls back to the default.
    With ``exclusive``, a value equal to ``minimum`` is bad too (for example ``minimum=0.0`` gives a
    strictly positive value). ``inf`` is refused because a caller that sleeps or waits for the value
    would raise ``OverflowError`` (``time.sleep(inf)``) or never end."""
    try:
        value = cast(os.environ[name])
    except (KeyError, TypeError, ValueError):
        return default
    in_range = value > minimum if exclusive else value >= minimum
    return value if math.isfinite(value) and in_range else default
