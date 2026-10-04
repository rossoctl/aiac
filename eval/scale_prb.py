"""Concurrent PRB fan-out for the Scale suite (spec: ``docs/evaluation/policy-eval-scale.md``).

The total-corpus dimension's whole point is stressing *many* PRB decisions (one per generated
agent inbound scope, tool/target scope, and agent role -- ~100-150 calls at the fixed-100 size).
``eval.test_policy_pipeline_eval.orchestrate_prb`` makes exactly that set of calls, but
sequentially (production code, not modified here). Running them one after another would pay
~100-150x one call's LLM round-trip latency for no benefit: each call is independent -- its own
fresh state dict, its own freshly-built ``ChatOpenAI`` client (``_build_llm()`` is called fresh
per ``_structured_call``) -- so nothing about them shares mutable state across calls.
``run_concurrently``/``orchestrate_prb_concurrent`` fan the same call set out across a
``ThreadPoolExecutor`` instead, capped by ``SCALE_CONCURRENCY`` (mirrors
``EVAL_PIPELINE_PARALLELISM``'s existing override convention) to stay under a typical LLM
endpoint's rate limits. ``run_concurrently`` is the shared primitive, reused as-is by the e2e
level's Keycloak provisioning loops (independent per-entity admin-API calls) in
``eval/test_policy_pipeline_scale.py``.

**Usage-metadata tracking under threads**: LangChain's ``get_usage_metadata_callback()`` is a
context-var-scoped callback handler. Confirmed empirically (not merely assumed) that its context
var does **not** propagate into ``ThreadPoolExecutor`` worker threads -- wrapping it around the
whole pool submission block sees zero usage recorded. Scoping one *inside* each worker task (this
module's ``_invoke_with_usage``) instead correctly captures that task's own usage, which the caller
then aggregates on the main thread -- see ``eval.scale_structural`` for the aggregation.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, Callable, Iterator, TypeVar

from langchain_core.callbacks.usage import get_usage_metadata_callback

from aiac.agent.policy_rules_builder.graph import ROLE_GRAPH, SCOPE_GRAPH, PolicyRulesBuilderBaseError
from aiac.idp.configuration.models import Role, Scope
from aiac.policy.model.models import PolicyRule
from eval.test_policy_pipeline_eval import _invoke_graph

DEFAULT_CONCURRENCY = 20
T = TypeVar("T")

# The exact logger name and message prefix aiac.agent.policy_rules_builder.graph's own _precheck
# step logs a diagnostic warning under when it drops a hallucinated (non-candidate) name --
# ``logger = logging.getLogger(__name__)`` there, so this is that module's dotted path, not an
# arbitrary string. Capturing this (see ``capture_precheck_drops`` below) observes a message
# production code already emits on purpose for exactly this kind of diagnosis -- no production
# code is read, called, or modified to recover it.
_PRECHECK_LOGGER_NAME = "aiac.agent.policy_rules_builder.graph"
_PRECHECK_DROP_MESSAGE = "PRB precheck dropped hallucinated names: granted=%s denied=%s"


def concurrency() -> int:
    """``SCALE_CONCURRENCY`` env override (default ``DEFAULT_CONCURRENCY``), floored at 1 -- same
    floor rationale as ``test_policy_pipeline_eval.py``'s ``EVAL_PIPELINE_PARALLELISM`` read."""
    return max(1, int(os.environ.get("SCALE_CONCURRENCY", str(DEFAULT_CONCURRENCY))))


def run_concurrently(fns: list[Callable[[], T]], *, max_workers: int | None = None) -> list[T]:
    """Run each zero-arg callable in ``fns`` on a thread pool, returning results in the same order
    as ``fns`` (``ThreadPoolExecutor.map`` preserves input order while still executing
    concurrently). The shared fan-out primitive both ``orchestrate_prb_concurrent`` below and the
    e2e provisioning loops (``eval/test_policy_pipeline_scale.py``) build on."""
    if not fns:
        return []
    with ThreadPoolExecutor(max_workers=max_workers or concurrency()) as executor:
        return list(executor.map(lambda fn: fn(), fns))


def _invoke_with_usage(
    graph: Any, *, best_effort: bool, **entity: object
) -> tuple[list[PolicyRule], str, str | None, dict[str, Any]]:
    """``_invoke_graph``, with its own dedicated ``get_usage_metadata_callback()`` scope -- see the
    module docstring for why this must be scoped per-call, not around the whole pool."""
    with get_usage_metadata_callback() as cb:
        rules, reasoning, note = _invoke_graph(graph, best_effort=best_effort, **entity)
    return rules, reasoning, note, dict(cb.usage_metadata)


class PrecheckDrops(logging.Handler):
    """Collects the names ``_precheck``'s own diagnostic warning reports as dropped (a candidate
    the LLM selected or denied that was never offered to it -- see ``capture_precheck_drops``
    below). Not meant to be instantiated directly outside that context manager."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.granted: list[str] = []
        self.denied: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        if record.msg == _PRECHECK_DROP_MESSAGE and record.args:
            granted, denied = record.args
            self.granted.extend(granted)
            self.denied.extend(denied)


@contextmanager
def capture_precheck_drops() -> Iterator[PrecheckDrops]:
    """Attach a :class:`PrecheckDrops` handler to ``_precheck``'s own logger for the duration of
    the ``with`` block, so a hallucinated (non-candidate) name it drops can actually be observed
    from eval code -- without reading, calling, or modifying any production code, only listening
    to a diagnostic warning ``_precheck`` already logs on purpose. ``eval.scale_structural.
    invalid_selected_names`` cannot see this itself: by the time a PRB call returns, the final
    state's ``selected_names``/``denied_names`` are already the post-``_precheck`` *filtered*
    lists, so an invented name is already gone from everything a caller can read off the result.

    **Not thread-safe** -- a ``logging.Logger``'s handler list is one shared, global object; two
    concurrent ``with`` blocks on different threads would both receive every record logged by
    *either* call, misattributing drops across jobs, and concurrently mutating the same handler
    list is itself a race. Only use this around a single, non-concurrent call (the per-decision
    fixtures' two sequential ``_invoke_with_usage`` calls) -- never from
    ``orchestrate_prb_concurrent``'s ``ThreadPoolExecutor`` jobs.
    """
    handler = PrecheckDrops()
    logger = logging.getLogger(_PRECHECK_LOGGER_NAME)
    logger.addHandler(handler)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)


def orchestrate_prb_concurrent(
    roles: dict[str, Role],
    scopes: dict[str, Scope],
    scenario: SimpleNamespace,
    *,
    best_effort: bool = True,
    max_workers: int | None = None,
) -> tuple[list[PolicyRule], dict[str, str], dict[str, str], dict[str, str], dict[str, dict], dict[str, str]]:
    """Concurrent counterpart of ``eval.test_policy_pipeline_eval.orchestrate_prb`` -- same call
    set (one ``SCOPE_GRAPH`` call per agent inbound scope and per tool/agent-target scope, one
    ``ROLE_GRAPH`` call per agent role), fanned out via ``run_concurrently`` instead of run one
    after another. Returns the same four values ``orchestrate_prb`` does, plus ``usage_by_name``
    (``{scope_or_role_name: usage_metadata}``, for the cost structural check
    (``eval.scale_structural``) to sum) and ``failed_decisions`` (``{scope_or_role_name: reason}``,
    see below).

    ``best_effort`` defaults to ``True`` here (unlike ``orchestrate_prb``'s ``False`` default) --
    at ~100-150 decisions per total-corpus run, one auditor rejection must not discard every other
    decision's real result; every sibling correctness/robustness/consistency suite already makes
    this same choice at its own call sites.

    ``best_effort=True`` only buys that guarantee against an ``_invoke_graph``-caught rejection
    (``PolicyContradictionError``/``PolicyRulesBuilderError``) -- it does **not** catch a sibling
    ``LLMAccessError``/``UnparseableLLMResponseError`` from the same ``PolicyRulesBuilderBaseError``
    family, which at ~100-150 *concurrent* calls against a real, possibly rate-limited endpoint is
    the more likely failure mode. Left uncaught, ``run_concurrently``'s ``executor.map`` would raise
    that one job's exception and discard every other job's already-finished result -- exactly what
    this function exists to avoid. Each job below therefore catches
    ``PolicyRulesBuilderBaseError`` itself and reports a failed decision (no rules, no reasoning
    entry) rather than raising, so ``missing_decisions`` sees it as a decision that never completed
    instead of losing the whole run.

    A failed decision's reason is kept in its own ``failed_decisions`` dict, **not** folded into
    ``best_effort_notes`` -- that dict is rendered as "best-effort proposals the auditor never
    approved", which is a different, misleading story for a call that never produced a proposal at
    all. Its usage is left out of ``usage_by_name`` entirely rather than recorded as ``{}``, for the
    same reason: ``_invoke_with_usage``'s ``get_usage_metadata_callback()`` scope never reaches its
    own return when the wrapped call raises, so there is no usage to report, and recording an empty
    dict would read as "the endpoint didn't report usage" (lowering ``token_coverage``) instead of
    "this call never finished".
    """
    user_roles = [roles[name] for name in scenario.USER_ROLES]

    inbound_scope_names = [n for agent in scenario.AGENTS.values() for n in agent["inbound_scopes"]]
    target_scope_names = [n for tool in scenario.TOOLS.values() for n in tool["scopes"]]
    target_scope_names += [n for agent in scenario.AGENTS.values() for n in agent.get("delegation_scopes", {})]
    agent_role_names = [n for agent in scenario.AGENTS.values() for n in agent["roles"]]

    inbound_scopes = [scopes[n] for n in inbound_scope_names]
    target_scopes = [scopes[n] for n in target_scope_names]
    agent_roles = [roles[n] for n in agent_role_names]

    def _scope_job(scope: Scope) -> Callable[[], tuple[str, str, list[PolicyRule], str | None, str | None, dict]]:
        def _run() -> tuple[str, str, list[PolicyRule], str | None, str | None, dict]:
            try:
                job_rules, reasoning, note, usage = _invoke_with_usage(
                    SCOPE_GRAPH, roles=user_roles, scope=scope, best_effort=best_effort
                )
            except PolicyRulesBuilderBaseError as exc:
                return "scope", scope.name, [], None, f"decision call raised {type(exc).__name__}: {exc}", {}
            return "scope", scope.name, job_rules, reasoning, note, usage

        return _run

    def _role_job(role: Role) -> Callable[[], tuple[str, str, list[PolicyRule], str | None, str | None, dict]]:
        def _run() -> tuple[str, str, list[PolicyRule], str | None, str | None, dict]:
            try:
                job_rules, reasoning, note, usage = _invoke_with_usage(
                    ROLE_GRAPH, role=role, scopes=target_scopes, best_effort=best_effort
                )
            except PolicyRulesBuilderBaseError as exc:
                return "role", role.name, [], None, f"decision call raised {type(exc).__name__}: {exc}", {}
            return "role", role.name, job_rules, reasoning, note, usage

        return _run

    jobs = [_scope_job(s) for s in inbound_scopes + target_scopes] + [_role_job(r) for r in agent_roles]
    results = run_concurrently(jobs, max_workers=max_workers)

    rules: list[PolicyRule] = []
    reasoning_by_scope: dict[str, str] = {}
    reasoning_by_agent_role: dict[str, str] = {}
    best_effort_notes: dict[str, str] = {}
    usage_by_name: dict[str, dict] = {}
    failed_decisions: dict[str, str] = {}
    for kind, name, job_rules, reasoning, note, usage in results:
        rules += job_rules
        # ``reasoning`` is ``None`` only for a job that raised above -- leaving its name out of
        # reasoning_by_scope/reasoning_by_agent_role (rather than recording an empty string) is
        # what lets missing_decisions report it as a decision that never ran, instead of a
        # decision that ran and produced nothing. Its ``note`` (the failure reason) goes to
        # failed_decisions, not best_effort_notes, and no usage is recorded for it at all -- see
        # this function's own docstring for why both would otherwise misreport the cause.
        if reasoning is None:
            if note is not None:
                failed_decisions[name] = note
            continue
        if kind == "scope":
            reasoning_by_scope[name] = reasoning
        else:
            reasoning_by_agent_role[name] = reasoning
        if note is not None:
            best_effort_notes[name] = note
        usage_by_name[name] = usage

    return rules, reasoning_by_scope, reasoning_by_agent_role, best_effort_notes, usage_by_name, failed_decisions
