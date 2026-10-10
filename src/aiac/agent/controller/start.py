"""The Controller start sequence — runs in the FastAPI lifespan, before the NATS consumer starts.

1. **The enforcement side (D29):** the PCE ``enforcement_side()`` reads ``AIAC_ENFORCEMENT_SIDE``
   (``target-side``, the default, or ``agent-side``). An unknown value raises ``ValueError`` (it
   names the variable and the value). The side in use is logged at INFO. Every later PCE operation
   reads the same env, so the Controller serves one side until it restarts; a side change is a
   ConfigMap patch and a Controller restart, and the resync (step 3) then moves every CR to the new
   side.
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

A failure in a step stops the Controller: the error is logged (naming the failed step) and raised
from the lifespan, so uvicorn never serves, exits, and Kubernetes restarts the pod. Each restart
runs the steps again. The NATS consumer starts after this sequence (see ``eventbus.consumer.lifespan``).
"""

import logging
import os
import re

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

# The start of a rule of ``client_ok``: its head, also a ``default`` one. A line that is only
# ``client_ok`` is a reference in the body of another rule.
_CLIENT_OK_HEAD = re.compile(r"(default )?client_ok\b.")


class StartCheckError(RuntimeError):
    """A Controller start check failed; the Controller must not serve."""


def _client_ok_rules(content: str) -> list[str]:
    """Each line of ``content`` that starts a rule of ``client_ok``: comments (``#`` to the end of
    the line) are ignored and runs of white space count as one space."""
    lines = (" ".join(raw.split("#", 1)[0].split()) for raw in content.splitlines())
    return [line for line in lines if _CLIENT_OK_HEAD.match(line)]


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

    policies = {p.get("path"): p.get("content") or "" for p in ((cr.get("spec") or {}).get("policies") or [])}
    problems = []
    for path, safe in _SAFE_CLIENT_OK_RULES.items():
        if path not in policies:
            problems.append(f"{path} is missing")
            continue
        rules = _client_ok_rules(policies[path])
        if not rules:
            problems.append(f"{path} has no client_ok rule")
        problems.extend(f"{path} has the rule {rule!r}" for rule in rules if rule not in safe)
    if problems:
        raise StartCheckError(
            f"start check #4 failed: the global combiner ({where}) allows a pod that has no client CR: "
            + "; ".join(problems)
            + ". Apply the AIAC combiner (see k8s/opa-kind-enable.sh)."
        )


def run_start_sequence() -> None:
    """Run the start sequence (the side, check #4, then the resync). Raise on the first failure."""
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
