"""Service Onboarding Orchestrator (UC1).

The only use case with an Orchestrator, because it is a **two-stage** pipeline. Invoked by
the Controller for the ``aiac.apply.service.{id}`` / ``POST /apply/service/{service_id}``
trigger, it sequences the two sub-agents and returns ``(list[PolicyRule], override=False, client_id)``
(``client_id`` is the service's clientId, which the Controller passes to the PCE as ``focus_service``):

    1. Service Provision  — classifies the service and writes its roles/scopes into the IdP,
       producing the discovered ``service_type`` and the **created-manifest** (exactly the
       roles/scopes it created on this run — see ``provision_service``).
    2. Service Policy Builder — reads the excluded-self IdP universe and builds the rules.

There is **no Apply stage** here: the Controller makes the single
``compute_and_apply(rules, override=False)`` (PCE) call. UC1 is incremental, so ``override``
is always ``False`` (append; existing roles keep their other access).

**Replay safety (at-least-once delivery):** Provision IdP writes are idempotent and the PCE
reconcile is idempotent, so a crash between stages simply re-runs the full pipeline to
convergence on NATS redelivery. A build **failure**, however, triggers a **compensating
rollback** (UC1-only) and then the PCE ``quarantine`` before the error propagates — see
:func:`_rollback` and :func:`onboard_service`. The PCE owns the PDP: this module never imports
``aiac.pdp.policy.library``.
"""

import contextlib
import logging
import threading

from aiac.agent.policy_rules_builder.conflict_detection import PolicyConflictError
from aiac.agent.policy_rules_builder.graph import (
    LLMAccessError,
    PolicyRulesBuilderError,
    UnparseableLLMResponseError,
)
from aiac.agent.uc.onboarding.policy_builder.builder import ServicePolicyBuilder
from aiac.agent.uc.onboarding.provision.graph import build_provision_graph
from aiac.agent.uc.onboarding.provision.state import OnboardingProvisionState, Trigger
from aiac.idp.configuration.api import Configuration
from aiac.idp.configuration.models import ClientId, Service, ServiceUuid
from aiac.policy.computation import quarantine
from aiac.policy.model.models import PolicyRule

logger = logging.getLogger(__name__)

# The build failures that trigger the UC1 compensating rollback. A conflict finding
# (``PolicyConflictError``) and the three hard PRB faults (``PolicyRulesBuilderError``,
# ``LLMAccessError``, ``UnparseableLLMResponseError``) all leave a provisioned-but-unusable
# service, so each rolls back what Provision created. Any other exception (e.g. an
# ``HTTPException`` from IdP focus resolution) propagates untouched — no teardown.
_ROLLBACK_ERRORS = (
    PolicyConflictError,
    PolicyRulesBuilderError,
    LLMAccessError,
    UnparseableLLMResponseError,
)


# --------------------------------------------------------------------------- #
# Per-service_id serialization                                                 #
# --------------------------------------------------------------------------- #
# ``onboard_service`` runs the full provision → build → rollback lifecycle. Two
# concurrent runs for the SAME ``service_id`` (an overlapping ``POST /apply/service/{id}``
# and an ``aiac.apply.service.{id}`` NATS delivery, say) each snapshot the existing
# role/scope names before creating, so both can record the same resolved entity in their
# created-manifest — and a rollback would then delete an entity the other run still uses.
# A per-service lock serializes the whole lifecycle so same-service runs proceed one at a
# time, while DIFFERENT service_ids stay concurrent (each has its own lock). Guarding only
# ``provision_service`` is insufficient because the rollback runs here in the orchestrator.
#
# Multi-replica caveat: this in-process lock serializes within ONE agent replica only.
# Cross-replica serialization (multiple agent pods sharing a Keycloak realm) needs external
# coordination (e.g. a distributed lock) and is out of scope here.
#
# Eviction (issue 202): the registry must not grow one idle ``Lock`` per distinct
# ``service_id`` ever seen. Each entry is **reference-counted** — a plain delete on the last
# run's exit is unsafe, because another thread may still be *blocked* on that same ``Lock``
# instance: deleting the entry would let a later arrival mint a fresh lock and run
# concurrently with the waiter, silently breaking serialization. So a run registers as a
# holder/waiter (``refcount += 1``) under the guard *before* it blocks on the lock, and the
# entry is removed only when the last holder/waiter leaves (``refcount == 0``) — again under
# the guard. While ``refcount > 0`` every arrival for that ``service_id`` shares the one
# ``Lock`` in the map, so serialization holds across the eviction boundary.
class _LockEntry:
    """A per-``service_id`` lock paired with a count of runs holding or waiting on it."""

    __slots__ = ("lock", "refcount")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.refcount = 0


_service_locks: dict[str, _LockEntry] = {}
_service_locks_guard = threading.Lock()


@contextlib.contextmanager
def _service_lock(service_id: str):
    """Serialize the ``service_id``'s onboarding lifecycle, evicting the registry entry once
    the last holder/waiter leaves.

    Under the guard, register as a holder/waiter (creating the entry lazily so threads racing
    on a first-seen ``service_id`` share one ``Lock``), then block on that lock *outside* the
    guard. On exit, release the lock and drop the reference under the guard; when no run still
    holds or waits (``refcount == 0``) the entry is removed. Because the increment happens
    under the guard before the block, a still-queued waiter keeps ``refcount > 0`` and so
    keeps the shared lock in the map — a later arrival cannot mint a fresh one and overtake."""
    with _service_locks_guard:
        entry = _service_locks.get(service_id)
        if entry is None:
            entry = _LockEntry()
            _service_locks[service_id] = entry
        entry.refcount += 1
        lock = entry.lock
    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _service_locks_guard:
            entry.refcount -= 1
            if entry.refcount == 0:
                del _service_locks[service_id]


# --------------------------------------------------------------------------- #
# Seam (patched in unit tests)                                                 #
# --------------------------------------------------------------------------- #
def _config() -> Configuration:
    return Configuration.for_default_realm()


def _loggable(value: object) -> str:
    """Neutralize a value for single-line logging: coerce to ``str`` and drop CR/LF so a
    user-controlled ``service_id`` or entity name cannot forge or inject extra log lines
    (mitigates CodeQL ``py/log-injection``)."""
    return str(value).replace("\r", "").replace("\n", "")


def _rollback(config: Configuration, service: Service, created_roles, created_scopes) -> None:
    """Compensating rollback (UC1-only): tear down exactly what Provision created on this run, then
    disable the client as a failed-service marker.

    ``created_roles`` / ``created_scopes`` are the **created-manifest** — only the entities this
    run added (reused-by-name entities are absent, so a role/scope another service shares is never
    removed). Each ``delete_service_*`` unmaps-then-deletes and is idempotent, so a retry that
    finds an object already gone does not crash. The disable lands **last**, after the teardown,
    so an interrupted rollback never leaves a disabled-but-still-provisioned client. Actions are
    logged at INFO.

    The client **type is kept**: the rollback removes only what this run created, and the type
    was not created by it. The
    policy side of the teardown is the PCE's :func:`~aiac.policy.computation.quarantine`, which
    the caller runs next."""
    safe_id = _loggable(service.id)
    for role in created_roles:
        config.delete_service_role(service, role)
        logger.info("UC1 rollback: deleted role %r (service %s)", _loggable(getattr(role, "name", role)), safe_id)
    for scope in created_scopes:
        config.delete_service_scope(service, scope)
        logger.info("UC1 rollback: deleted scope %r (service %s)", _loggable(getattr(scope, "name", scope)), safe_id)
    config.set_service_enabled(service, False)
    logger.info("UC1 rollback: disabled client — failed-service marker (service %s)", safe_id)


def reenable_service(service_id: ServiceUuid) -> None:
    """Re-enable the Keycloak client (UC1-only, idempotent), clearing any prior failed-disable marker.

    The **caller** (Controller route or NATS consumer) invokes this AFTER a successful
    ``compute_and_apply`` (PCE) call — deliberately post-apply. Re-enabling only after the policy
    is applied means a PCE failure leaves the client **disabled** (the failed-service marker set by
    a prior :func:`_rollback` stays in place), so a client is never enabled with no applied policy.

    ``set_service_enabled(service, True)`` is idempotent, so a redelivery that re-enables an
    already-enabled client is a no-op."""
    config = _config()
    config.set_service_enabled(config.get_service(service_id), True)


def onboard_service(service_id: ServiceUuid) -> tuple[list[PolicyRule], bool, ClientId]:
    """Sequence Provision → Policy Builder and return ``(rules, override=False, client_id)``.

    ``service_id`` is the Keycloak internal client UUID that the trigger carries. The Orchestrator
    reads the ``Service`` from the IdP **once**, before Provision, and resolves its clientId
    (``Service.serviceId``) — the only service id the PCE takes. The caller passes the returned
    ``client_id`` to ``compute_and_apply`` as ``focus_service``, so it makes no second IdP read. If
    the read fails, nothing exists yet that needs compensation: the error propagates before
    Provision.

    On any of the four typed build failures (see ``_ROLLBACK_ERRORS``, for agents and tools, on the
    first failure — also the retryable ``LLMAccessError``) the Orchestrator runs the compensating
    :func:`_rollback` (delete this run's created roles/scopes; disable the client last), then the
    PCE's ``quarantine(client_id, created_roles)`` (delete the SPM, remove the service's roles —
    including the created roles the rollback deleted — from the other SPMs,
    replace an agent's CR with a no-rules CR, re-derive the affected agents), and **re-raises** the
    original error unchanged. The disable comes before the quarantine, so no run after the teardown
    sees the service as enabled. The quarantine runs even when the rollback raises, so a failed
    rollback never leaves a first onboarding fail-open. A rollback or quarantine failure
    propagates in place of the build error (the build error stays on its ``__context__``): the
    compensation failure is not in the consumer's permanent set, so NATS redelivers and the next
    run tries the compensation again. If the build error won, a permanent build error would
    ``term()`` the message and leave the half-compensated service fail-open. The
    quarantine is lifted only by a successful re-onboarding. On
    success it does **not** re-enable the client here: the client is re-enabled by the caller via
    :func:`reenable_service`, but only AFTER the caller's ``compute_and_apply`` (PCE) call succeeds,
    so a PCE failure leaves the client disabled rather than enabled-with-no-policy.

    The full provision → build → rollback lifecycle is serialized per ``service_id`` (see
    :func:`_service_lock`): a concurrent same-service run cannot corrupt the created-manifest
    or roll back a shared entity, while different service_ids run concurrently. The registry
    entry is reference-counted and evicted once the last run using it exits (issue 202), on
    both the success and failure paths, without breaking serialization. This is an in-process
    lock (one agent replica only); cross-replica serialization is out of scope."""
    with _service_lock(service_id):
        config = _config()
        service = config.get_service(service_id)
        client_id = ClientId(service.serviceId)

        provision = build_provision_graph().invoke(OnboardingProvisionState(trigger=Trigger(entity_id=service_id)))
        service_type = provision["service_type"]
        created_roles = provision["created_roles"]
        created_scopes = provision["created_scopes"]

        try:
            rules = ServicePolicyBuilder.build(service_id, service_type)
        except _ROLLBACK_ERRORS:
            try:
                _rollback(config, service, created_roles, created_scopes)
            finally:
                # A failed rollback must not leave a first onboarding fail-open.
                # Pass the created roles: the rollback deleted them from the IdP, so the quarantine
                # cannot find them in the catalog, but their grants can be on other SPMs.
                quarantine(client_id, created_roles)
            raise

        return rules, False, client_id
