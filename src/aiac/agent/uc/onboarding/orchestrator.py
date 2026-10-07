"""Service Onboarding Orchestrator (UC1).

The only use case with an Orchestrator, because it is a **two-stage** pipeline. Invoked by
the Controller for the ``aiac.apply.service.{id}`` / ``POST /apply/service/{service_id}``
trigger, it sequences the two sub-agents and returns ``(list[PolicyRule], override=False, client_id)``
(``client_id`` is the service's clientId, which the Controller passes to the PCE as ``focus_service``):

    0. The precondition checks (D30, see ``preconditions``) — run FIRST, after the one IdP read
       that resolves the clientId (a ``404`` on that read is the event-before-commit race: it is read
       again for a bounded time, see ``CLIENT_WAIT``): the pod has the AuthBridge sidecar (#1),
       the namespace pipeline has ``opa`` (and ``mcp-parser`` for a tool) inbound, and under agent
       side also ``opa`` outbound (#2), no app container has an ``httpGet`` probe (#6). The scope
       depends on the enforcement side: every service under target side, agents only under agent side (a tool
       then gets a pass-through CR, which needs no check; its pod type is still read). A failed
       check raises ``EnforcementPreconditionError``.
       Then, for an enabled TOOL only, the PCE ``bootstrap`` writes the tool's first CR (under
       target side its rules-based CR, under agent side a pass-through CR), so that discovery
       (``tools/list`` through the tool's own inbound) passes D20 (checkpoint B1).
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
:func:`_rollback` and :func:`onboard_service`. A failed precondition check is **not** a build
failure: nothing changed yet, so it runs no rollback, no client disable and no quarantine
(checkpoint O2). The PCE owns the PDP: this module never imports ``aiac.pdp.policy.library``.
"""

import contextlib
import logging
import threading

from fastapi import HTTPException

from aiac.agent.policy_rules_builder.conflict_detection import PolicyConflictError
from aiac.agent.policy_rules_builder.graph import (
    LLMAccessError,
    PolicyRulesBuilderError,
    UnparseableLLMResponseError,
)
from aiac.agent.uc.onboarding.policy_builder.builder import ServicePolicyBuilder
from aiac.agent.uc.onboarding.preconditions import check_preconditions
from aiac.agent.uc.onboarding.provision.graph import build_provision_graph
from aiac.agent.uc.onboarding.provision.nodes import WaitConfig, poll_until_ready
from aiac.agent.uc.onboarding.provision.state import OnboardingProvisionState, Trigger
from aiac.idp.configuration.api import Configuration, IdPHTTPError
from aiac.idp.configuration.models import ClientId, Service, ServiceType, ServiceUuid
from aiac.policy.computation import bootstrap, quarantine
from aiac.policy.model.models import PolicyRule

logger = logging.getLogger(__name__)

# The build failures that trigger the UC1 compensating rollback. A conflict finding
# (``PolicyConflictError``) and the three hard PRB faults (``PolicyRulesBuilderError``,
# ``LLMAccessError``, ``UnparseableLLMResponseError``) all leave a provisioned-but-unusable
# service, so each rolls back what Provision created. Any other exception (e.g. an
# ``HTTPException`` from IdP focus resolution) propagates untouched — no teardown.
# ``EnforcementPreconditionError`` is deliberately NOT here (checkpoint O2): the checks run before
# Provision, so nothing exists that needs compensation. A first onboarding then has no CR, so D20
# denies the service (fail closed); an onboarded service keeps its policy.
_ROLLBACK_ERRORS = (
    PolicyConflictError,
    PolicyRulesBuilderError,
    LLMAccessError,
    UnparseableLLMResponseError,
)


class ServiceNotVisibleError(HTTPException):
    """The IdP still answers ``404`` for the service after the bounded wait on the first read (see
    :func:`_read_service`). It is an ``HTTPException(502)``, so the HTTP route answers ``502`` as
    before, and the consumer can tell it from the other retryable failures."""

    def __init__(self, detail: str) -> None:
        super().__init__(502, detail)


# Event-before-commit race tolerance for the first IdP read (handoff 20). The Keycloak SPI listener runs
# inside the admin request, so the ``CLIENT_CREATED`` event (and the ``aiac.apply.service.{id}``
# message) can come BEFORE Keycloak commits the new client: the first ``get_service`` then gets
# ``404``. A ``404`` on that read is therefore a transient not-visible state, read again before we
# give up with a 502; without the wait, the next try is the NATS redelivery after ACK_WAIT (600 s).
# The SPI fix (publish after the commit) removes the race; this wait is defense in depth. The wait
# runs inside ``_service_lock``, and the NATS consumer handles one message at a time, so it blocks
# the other onboardings: keep the default short (≈30 s, as the label wait). Tests set it fast.
# A 404 cannot tell a not-yet-committed client from one that does not exist, so an unknown or
# deleted UUID (a manual POST, a phantom event, a redelivery after a teardown) also waits the
# whole budget before its 502; before this wait it was a 502 at once.
CLIENT_WAIT = WaitConfig("ONBOARD_CLIENT_WAIT_ATTEMPTS", "ONBOARD_CLIENT_WAIT_BACKOFF", 15, 2.0)


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


def _read_service(config: Configuration, service_id: ServiceUuid) -> Service:
    """The first IdP read of ``onboard_service``: ``get_service(service_id)``, tolerant of the
    event-before-commit race (see ``CLIENT_WAIT``).

    A ``404`` (``IdPHTTPError`` with ``status == 404``) means that the new client is not visible
    yet (or that it does not exist: the two look the same, so an unknown UUID also waits the whole
    budget): the read is polled again, up to ``ONBOARD_CLIENT_WAIT_ATTEMPTS`` reads with
    ``ONBOARD_CLIENT_WAIT_BACKOFF`` seconds between them. A client that is still not visible after
    the budget raises :class:`ServiceNotVisibleError` (a ``502``). Any other error (a ``5xx`` after
    the library retries, another ``4xx``, a ``RuntimeError``) is a real failure, never the race: it
    raises ``HTTPException(502)`` at once."""
    last_not_found: IdPHTTPError | None = None
    reads = 0

    def _probe():
        nonlocal last_not_found, reads
        reads += 1
        try:
            return config.get_service(service_id)
        except Exception as e:
            if isinstance(e, IdPHTTPError) and e.status == 404:
                last_not_found = e
                return None
            # The same boundary as Provision's classify_service: an IdP outage or a bad request is
            # a 502, not a raw error that the Controller turns into a 500.
            raise HTTPException(502, f"IdP config unavailable resolving service {service_id!r}: {e}") from e

    service = poll_until_ready(_probe, CLIENT_WAIT)
    if service is None:
        raise ServiceNotVisibleError(
            f"IdP config unavailable resolving service {service_id!r}: the client is not visible after "
            f"{reads} reads (ONBOARD_CLIENT_WAIT_*): {last_not_found}"
        ) from last_not_found
    return service


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
    """Sequence the precondition checks → (tool) bootstrap → Provision → Policy Builder and return
    ``(rules, override=False, client_id)``.

    ``service_id`` is the Keycloak internal client UUID that the trigger carries. The Orchestrator
    reads the ``Service`` from the IdP **once**, before Provision, and resolves its clientId
    (``Service.serviceId``) — the only service id the PCE takes. The caller passes the returned
    ``client_id`` to ``compute_and_apply`` as ``focus_service``, so it makes no second IdP read. The
    SPI event can come before Keycloak commits the new client, so a ``404`` on this read is polled
    again for a bounded time (``ONBOARD_CLIENT_WAIT_*``, default ≈30 s, see :func:`_read_service`).
    If the read fails, nothing exists yet that needs compensation: it raises ``HTTPException(502)``
    (as Provision's ``classify_service`` does) before Provision — ``ServiceNotVisibleError`` when
    the client is still not visible after the wait, at once for any other error.

    Then the precondition checks (D30, :func:`~aiac.agent.uc.onboarding.preconditions.check_preconditions`)
    run, before Provision and the PRB. They read the enforcement side: under target side they check
    every service, under agent side agents only (a tool's pass-through CR needs no check, but the
    checks still return its pod type). A failed check raises ``EnforcementPreconditionError``,
    which names each failed check; nothing changed yet, so there is no rollback, no client disable
    and no quarantine (checkpoint O2). If the service is a tool (the type of its pod label) and its
    client is enabled, the PCE ``bootstrap(client_id, ServiceType.TOOL)`` writes the tool's first CR
    before Provision (of the current side: rules-based under target side, a pass-through under
    agent side), so that discovery passes (checkpoint B1). A disabled tool gets no bootstrap:
    it fails at the discovery-token mint anyway (C5). A bootstrap failure propagates (no rollback:
    Provision has not run).

    On any of the four typed build failures (see ``_ROLLBACK_ERRORS``, for agents and tools, on the
    first failure — also the retryable ``LLMAccessError``) the Orchestrator runs the compensating
    :func:`_rollback` (delete this run's created roles/scopes; disable the client last), then the
    PCE's ``quarantine(client_id, created_roles)`` (delete the SPM, remove the service's roles —
    including the created roles the rollback deleted — from the other SPMs, delete the service's
    CR, deploy the affected services), and **re-raises** the original error unchanged. The disable
    comes before the quarantine, so no run after the teardown sees the service as enabled. The
    quarantine runs even when the rollback raises, so a failed rollback never leaves a first
    onboarding fail-open. A rollback or quarantine failure
    propagates in place of the build error (the build error stays on its ``__context__``): the
    compensation failure is not in the consumer's permanent set, so NATS redelivers and the next
    run tries the compensation again. If the build error won, a permanent build error would
    ``term()`` the message and leave the half-compensated service fail-open. The
    quarantine is lifted only by a successful re-onboarding. On
    success it does **not** re-enable the client here: the client is re-enabled by the caller via
    :func:`reenable_service`, but only AFTER the caller's ``compute_and_apply`` (PCE) call succeeds,
    so a PCE failure leaves the client disabled rather than enabled-with-no-policy.

    The full checks → provision → build → rollback lifecycle is serialized per ``service_id`` (see
    :func:`_service_lock`): a concurrent same-service run cannot corrupt the created-manifest
    or roll back a shared entity, while different service_ids run concurrently. The registry
    entry is reference-counted and evicted once the last run using it exits (issue 202), on
    both the success and failure paths, without breaking serialization. This is an in-process
    lock (one agent replica only); cross-replica serialization is out of scope."""
    with _service_lock(service_id):
        config = _config()
        # A 404 is the event-before-commit race: read again for a bounded time (ServiceNotVisibleError
        # after the budget). Any other error is a 502 at once.
        service = _read_service(config, service_id)
        client_id = ClientId(service.serviceId)

        # D30: the precondition checks run FIRST, before anything changes. A failed check raises
        # EnforcementPreconditionError, which is NOT a rollback error (checkpoint O2): nothing was
        # provisioned, so there is no rollback, no client disable and no quarantine. Under agent
        # side a tool gets no check, but its pod type is still returned (for the bootstrap below).
        pod_type = check_preconditions(service)  # the type from the pod label (no catalog type yet)
        # Checkpoint B1: the first CR of a tool, before Provision, so that discovery (tools/list
        # through the tool's own inbound) passes D20. Only for an enabled client: a disabled
        # (quarantined) tool fails at the discovery-token mint anyway (C5), and its bootstrap CR
        # would stay stale until the next resync. Agents get no bootstrap.
        if pod_type is ServiceType.TOOL and service.enabled:
            bootstrap(client_id, ServiceType.TOOL)

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
