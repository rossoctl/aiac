"""The Controller start sequence — runs in the FastAPI lifespan, before the NATS consumer starts.

1. **The enforcement side (D29):** the PCE ``enforcement_side()`` reads ``AIAC_ENFORCEMENT_SIDE``
   (``target-side``, the default, or ``agent-side``). An unknown value raises ``ValueError`` (it
   names the variable and the value). The side in use is logged at INFO. Every later PCE operation
   reads the same env, so the Controller serves one side. The side is set at deploy time: a live
   switch is not supported, and a side change is a clean redeploy of AIAC.
2. **Start check #4 (D30):** the global combiner denies a pod that has no client CR. The check reads
   the ``AuthorizationPolicy`` named ``default`` in the bundle-service namespace
   (``AIAC_BUNDLE_SERVICE_NAMESPACE``, default ``rossoctl-system``). Its ``inbound/request.rego``
   and ``outbound/request.rego`` entries must exist, and each rule of ``client_ok`` in them must be
   one of the safe rules of the AIAC combiner: ``client_ok if
   data.authbridge.client.<direction>.request.allow`` or ``default client_ok := false`` (comments
   do not count; there must be at least one rule). The check is an allowlist, not a search for the
   stock line ``client_ok if not data.authbridge.client.<direction>.request``: an equivalent
   fail-open rule in another form (a multi-line body, ``.allow`` after ``not``) must fail too. A
   missing CR, a missing entry, a CR that cannot be read, or any other ``client_ok`` rule fails
   the check.
   Reason: the quarantine and the decommission delete the CR of the service (D20); the stock
   combiner allows a pod that has no client CR, so a delete would open the service. A ``helm
   upgrade`` of the operator can put the stock combiner back; this check finds that at the next start.
   The check runs under both sides.
3. **The resync (D28):** the PCE ``resync()`` writes every CR of the current side and quarantines
   each disabled service that still has an SPM.
4. **The login-client audience warning (C2):** under agent side only, a WARNING for each client
   scope of a platform login client that puts a managed tool's clientId into ``aud`` (see
   ``aiac.agent.uc.onboarding.platform_audience``). It catches a link that came after the tool's
   onboarding. A failure is logged and does not stop the Controller.

A failure in step 1, 2 or 3 stops the Controller: the error is logged (naming the failed step) and raised
from the lifespan, so uvicorn never serves, exits, and Kubernetes restarts the pod. Each restart
runs the steps again. The NATS consumer starts after this sequence (see ``eventbus.consumer.lifespan``).
"""

import logging
import os
import re

from aiac.agent.uc.onboarding.platform_audience import warn_platform_tool_audiences
from aiac.agent.uc.onboarding.provision.kube import is_not_found, read_authorization_policy
from aiac.policy.computation import enforcement_side, resync

logger = logging.getLogger(__name__)

BUNDLE_NAMESPACE_ENV = "AIAC_BUNDLE_SERVICE_NAMESPACE"
DEFAULT_BUNDLE_NAMESPACE = "rossoctl-system"
COMBINER_NAME = "default"

# The two request packages of the combiner, and the only rules of ``client_ok`` that each may have:
# the rules of the AIAC combiner, which deny a pod with no client CR. The response packages keep the
# default.
_SAFE_CLIENT_OK_RULES = {
    path: {f"client_ok if data.authbridge.client.{direction}.request.allow", "default client_ok := false"}
    for path, direction in (("inbound/request.rego", "inbound"), ("outbound/request.rego", "outbound"))
}

# The name ``client_ok`` as a whole word.
_CLIENT_OK = re.compile(r"\bclient_ok\b")

# The brackets that open and close a nested part of a Rego statement (a rule body, a collection, a call).
_OPEN, _CLOSE = "{[(", "}])"


class StartCheckError(RuntimeError):
    """A Controller start check failed; the Controller must not serve."""


def _code(content: str) -> str:
    """``content`` with each comment removed and the text of each string replaced by nothing.

    Rego ignores a comment (``#`` to the end of the line, outside a string), and a bracket or a
    ``client_ok`` in a string is not code. A ``"..."`` string ends at the line end at the latest; a
    raw string (in back-ticks) can span lines, so its line breaks are kept.
    """
    out: list[str] = []
    i, n = 0, len(content)
    while i < n:
        c = content[i]
        if c == "#":
            end = content.find("\n", i)
            i = n if end < 0 else end
        elif c == '"':
            i += 1
            while i < n and content[i] not in '"\n':
                i += 2 if content[i] == "\\" else 1
            out.append('""')
            i += 1 if i < n and content[i] == '"' else 0
        elif c == "`":
            end = content.find("`", i + 1)
            end = n if end < 0 else end
            out.append("``" + "\n" * content.count("\n", i, end))
            i = end + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _client_ok_rules(content: str) -> list[str]:
    """Each line of ``content`` that can start a rule of ``client_ok``, with runs of white space as
    one space: each line that names ``client_ok`` and starts outside every bracket.

    A rule head is never inside a bracket, and the head of a rule can span lines (``client_ok`` on
    one line and ``if ...`` on the next one is a valid rule), so a line that is only ``client_ok`` is
    a rule start too when it is outside every bracket. A ``client_ok`` inside a bracket (the body
    ``{ ns_ok; client_ok }`` of ``allow``) is a reference, not a rule. This fails closed: a
    reference in a body with no brackets (``allow if`` and then ``client_ok``) is also returned, and
    it is not a safe rule. Comments and strings are ignored (``_code``). Unbalanced brackets also
    fail closed: the whole ``content`` is then returned as one rule, which is not a safe rule.
    """
    depth = 0
    rules = []
    for raw in _code(content).splitlines():
        line = " ".join(raw.split())
        if depth == 0 and _CLIENT_OK.search(line):
            rules.append(line)
        for c in line:
            depth += (c in _OPEN) - (c in _CLOSE)
            if depth < 0:
                break
        if depth < 0:
            break
    if depth != 0:
        return [" ".join(content.split())]
    return rules


def combiner_problems(cr: dict) -> list[str]:
    """Each reason why the combiner ``cr`` (the ``default`` ``AuthorizationPolicy``, already read) can
    allow a pod that has no client CR; an empty list when it cannot. Pure: start check #4 and the
    skip gate of the system tests (``test/system/launcher.py``) use the same rules."""
    # Every entry of a path: a CR that lists a path two times must not hide a fail-open entry.
    contents: dict[str, list[str]] = {}
    for policy in (cr.get("spec") or {}).get("policies") or []:
        contents.setdefault(policy.get("path"), []).append(policy.get("content") or "")
    problems = []
    for path, safe in _SAFE_CLIENT_OK_RULES.items():
        if path not in contents:
            problems.append(f"{path} is missing")
            continue
        for content in contents[path]:
            rules = _client_ok_rules(content)
            if not rules:
                problems.append(f"{path} has no client_ok rule")
            problems.extend(f"{path} has the rule {rule!r}" for rule in rules if rule not in safe)
    return problems


def check_combiner() -> None:
    """Start check #4 (D30). Raise :class:`StartCheckError` if the global combiner can allow a pod
    that has no client CR, or if the check cannot read it."""
    namespace = os.getenv(BUNDLE_NAMESPACE_ENV) or DEFAULT_BUNDLE_NAMESPACE
    where = f"the AuthorizationPolicy {COMBINER_NAME!r} in namespace {namespace!r}"
    try:
        cr = read_authorization_policy(COMBINER_NAME, namespace)
    except Exception as e:
        if is_not_found(e):
            raise StartCheckError(
                f"start check #4 failed: {where} is missing, so the global combiner cannot deny a pod "
                "that has no client CR"
            ) from e
        raise StartCheckError(f"start check #4 failed: cannot read {where}: {e}") from e

    problems = combiner_problems(cr)
    if problems:
        raise StartCheckError(
            f"start check #4 failed: the global combiner ({where}) allows a pod that has no client CR: "
            + "; ".join(problems)
            + ". Apply the AIAC combiner (see k8s/opa-kind-enable.sh)."
        )


def run_start_sequence() -> None:
    """Run the start sequence (the side, check #4, the resync, then the audience warning). Raise on the
    first failure of the side, check #4 or the resync; the audience warning never raises."""
    try:
        side = enforcement_side()
    except ValueError as e:
        logger.error("Controller start stopped: unknown enforcement side (D29): %s", e)
        raise
    logger.info("enforcement side (D29): %s", side.value)
    try:
        check_combiner()
    except StartCheckError as e:
        logger.error("Controller start stopped: %s", e)
        raise
    logger.info("start check #4 passed: the global combiner denies a pod that has no client CR")
    try:
        resync()
    except Exception:
        logger.exception("Controller start stopped: the resync (D28) failed")
        raise
    logger.info("resync (D28) done")
    # C2 (agent side only, best effort): it logs a warning for each tool whose audience a platform login
    # client holds, and never stops the start.
    warn_platform_tool_audiences()
