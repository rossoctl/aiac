"""Shared pytest-nodeid parsing (spec: ``docs/evaluation/eval-framework.md`` §9.1, issue #2472) --
split out so ``eval.conftest`` and ``eval.dashboard.dashboard`` agree on exactly ONE
implementation. They used to carry independent copies (``conftest``'s own ``rindex("[")``-based
``_scenario_name_from_nodeid`` vs. ``dashboard``'s regex-based ``_scenario_for_nodeid``) that could
give different answers for an unusual parametrize id -- confirmed as a real finding in PR review:
the recommendations section and the dashboard drill-down could then disagree on which scenario a
nodeid belongs to.
"""

from __future__ import annotations

import re

_SCENARIO_RE = re.compile(r"\[([^\[\]]+)\]$")


def scenario_for_nodeid(nodeid: str) -> str | None:
    """The trailing ``[...]`` parametrize id of ``nodeid`` (e.g.
    ``eval/test_policy_pipeline_eval.py::test_prb_correctness[baseline]`` -> ``"baseline"``), or
    ``None`` for a nodeid with no trailing ``[...]`` at all (e.g. the Scale suite's structural/
    correctness tests, which run once per dimension/level, not per scenario -- a bare,
    non-parametrized nodeid). A nodeid that DOES end in brackets but belongs to an unrelated suite
    (e.g. ``eval_extended``'s ``test_inbound[scenario-agent-subject]``) still returns that bracket
    content as a string -- it is this function's CALLER that decides whether a given suite even
    has a meaningful "scenario" (``eval.dashboard.dashboard.parse_report`` only calls this when
    ``suite is not None``). The pattern disallows a nested ``[``/``]`` inside the captured group,
    so it only ever matches a genuine trailing parametrize id, never an unrelated literal bracket
    earlier in the nodeid."""
    m = _SCENARIO_RE.search(nodeid)
    return m.group(1) if m else None
