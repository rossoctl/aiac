"""NATS JetStream consumer — thin adapter, mirrors the ``/apply/*`` HTTP routes.

Subscribes to the ``aiac-agent-consumer`` durable queue group and, on each
message, calls the same use-case handler + ``compute_and_apply`` sequence the
HTTP routes use, awaiting completion before acking. On a **permanent** failure (see
``_PERMANENT_ERRORS``: a policy conflict or contradiction, a PRB fault, an unparseable LLM
response, or a failed UC1 precondition check) the message is republished to the DLQ subject and
terminated at the FIRST delivery. On any other failure the message is left unacked (NATS
redelivers after ``ACK_WAIT_SECONDS``) until ``num_delivered`` reaches ``MAX_DELIVER``, at which
point it is republished to the DLQ subject and terminated (stops redelivery on this consumer). One
retryable failure is nak'd instead of left unacked: ``ServiceNotVisibleError`` (the IdP does not show
a new service yet, the event-before-commit race), so NATS redelivers it after a short delay
(``AIAC_NOT_VISIBLE_NAK_DELAY_SECONDS``), not after ``ACK_WAIT_SECONDS``.

Also owns the FastAPI ``lifespan``: it runs the Controller start sequence (the enforcement side,
start check #4, then the PCE resync; see ``controller.start``) and starts the consumer only after
it. A failed step (also an unknown ``AIAC_ENFORCEMENT_SIDE``) raises from the lifespan, so the
Controller stops before it serves.
"""

import asyncio
import functools
import logging
import math
import os
from contextlib import asynccontextmanager
from urllib.parse import unquote

import nats
from fastapi import FastAPI
from nats.aio.msg import Msg
from nats.js.api import AckPolicy, ConsumerConfig

from aiac.agent.controller.start import run_start_sequence
from aiac.agent.eventbus.stream import (
    ACK_WAIT_SECONDS,
    CONSUMER_FILTER_SUBJECTS,
    CONSUMER_NAME,
    DEFAULT_NATS_URL,
    DLQ_SUBJECT,
    MAX_DELIVER,
    STREAM_NAME,
    ensure_stream,
)
from aiac.agent.policy_rules_builder.conflict_detection import PolicyConflictError
from aiac.agent.policy_rules_builder.graph import (
    PolicyContradictionError,
    PolicyRulesBuilderError,
    UnparseableLLMResponseError,
)
from aiac.agent.shared.error_logging import log_by_type
from aiac.agent.uc.onboarding.orchestrator import ServiceNotVisibleError, onboard_service, reenable_service
from aiac.agent.uc.onboarding.preconditions import EnforcementPreconditionError
from aiac.agent.uc.policy_update.build import build_policy
from aiac.agent.uc.role_update.role import update_role
from aiac.idp.configuration.models import ClientId, ServiceUuid
from aiac.policy.computation import compute_and_apply
from aiac.policy.model.models import PolicyRule

logger = logging.getLogger(__name__)

NATS_URL = os.environ.get("NATS_URL", DEFAULT_NATS_URL)

_START_RETRY_INITIAL_BACKOFF = 1.0
_START_RETRY_MAX_BACKOFF = 30.0

_SERVICE_PREFIX = "aiac.apply.service."
_ROLE_PREFIX = "aiac.apply.role."
_POLICY_BUILD_SUBJECT = "aiac.apply.policy.build"

# PERMANENT failures: redelivery can never make them succeed (a real policy conflict /
# contradiction, an unparseable LLM response, a builder fault, or a failed UC1 precondition
# check — that one needs a fix in the cluster first), so they are DLQ'd + term()ed on the
# FIRST delivery. Everything else — LLMAccessError (a transient LLM
# outage that may clear) and genuinely unknown/transient errors — is RETRYABLE: left
# unacked to redeliver until MAX_DELIVER, then DLQ'd (ServiceNotVisibleError is nak'd with a
# short delay instead; see _NOT_VISIBLE_NAK_DELAY_ENV below). LLMAccessError is a sibling of the
# permanent PRB errors under PolicyRulesBuilderBaseError, so isinstance() below correctly
# excludes it from the permanent set.
_PERMANENT_ERRORS: tuple[type[Exception], ...] = (
    PolicyConflictError,
    PolicyContradictionError,
    PolicyRulesBuilderError,
    UnparseableLLMResponseError,
    EnforcementPreconditionError,
)

# The event-before-commit race (handoff 20): the IdP can still answer 404 for a new service after the
# orchestrator's bounded wait (``ServiceNotVisibleError``). The client can become visible in some
# seconds, so the consumer naks that message with this delay instead of leaving it unacked: the
# redelivery then comes after the delay, not after ACK_WAIT (600 s). Each nak uses one of the
# MAX_DELIVER deliveries. Only this error class is nak'd; ACK_WAIT stays sized for long LLM
# onboardings (see stream.py). Read from the env at call time; keep it well below ACK_WAIT.
_NOT_VISIBLE_NAK_DELAY_ENV = "AIAC_NOT_VISIBLE_NAK_DELAY_SECONDS"
_NOT_VISIBLE_NAK_DELAY_DEFAULT = 30.0


def _not_visible_nak_delay() -> float:
    """The nak delay in seconds for a not-visible service; an unset, non-numeric, non-finite, zero
    or negative value falls back to the default (nats-py sends a plain nak, with no delay, for 0)."""
    try:
        value = float(os.getenv(_NOT_VISIBLE_NAK_DELAY_ENV, str(_NOT_VISIBLE_NAK_DELAY_DEFAULT)))
    except (TypeError, ValueError):
        return _NOT_VISIBLE_NAK_DELAY_DEFAULT
    return value if math.isfinite(value) and value > 0 else _NOT_VISIBLE_NAK_DELAY_DEFAULT


async def _nak_not_visible(msg: Msg) -> None:
    """Nak ``msg`` with the not-visible delay (nats-py takes the delay in seconds). A failed nak (for
    example a dropped connection) must not crash the callback: it is logged, and the message stays
    unacked, so NATS redelivers it after ACK_WAIT."""
    delay = _not_visible_nak_delay()
    try:
        await msg.nak(delay=delay)
    except Exception:
        logger.exception("nak of %s failed; NATS redelivers it after ACK_WAIT", msg.subject)
        return
    logger.info(
        "nak'd %s (service not visible yet, delivery %d); redelivery in %.0fs",
        msg.subject,
        msg.metadata.num_delivered,
        delay,
    )


def _handle(subject: str) -> tuple[list[PolicyRule], bool, ClientId | None]:
    """Dispatch ``subject`` to its use-case handler — the consumer's only subject switch. Returns
    ``(rules, override, focus_service)``: ``focus_service`` is the onboarded service's clientId (from
    ``onboard_service``), and ``None`` for every other subject."""
    if subject.startswith(_SERVICE_PREFIX):
        return onboard_service(ServiceUuid(subject[len(_SERVICE_PREFIX) :]))
    if subject.startswith(_ROLE_PREFIX):
        # Mirror image of the Keycloak SPI's SubjectMapper.encodeSubjectToken: role names may
        # contain '.', which NATS treats as a token separator, so the SPI percent-encodes them
        # into a single token before publishing. unquote() is the general-purpose inverse; safe
        # here because every literal '%' in the original name was itself escaped to "%25".
        return *update_role(unquote(subject[len(_ROLE_PREFIX) :])), None
    if subject == _POLICY_BUILD_SUBJECT:
        return *build_policy(), None
    raise ValueError(f"no handler for subject {subject!r}")


class AiacEventConsumer:
    def __init__(self, nats_url: str = NATS_URL) -> None:
        self._nats_url = nats_url
        self._nc: nats.aio.client.Client | None = None
        self._sub = None

    async def start(self) -> None:
        # max_reconnect_attempts=-1: once connected, never give up on a dropped connection
        # (nats-py's own default is a bounded 60 attempts at a fixed reconnect_time_wait, not
        # indefinite). This only covers post-connect drops — the exponential backoff is
        # start_with_retry's, for retrying this initial connect/subscribe sequence itself.
        self._nc = await nats.connect(self._nats_url, max_reconnect_attempts=-1)
        js = self._nc.jetstream()
        await ensure_stream(js)
        self._sub = await js.subscribe(
            subject="aiac.apply.>",
            queue=CONSUMER_NAME,
            durable=CONSUMER_NAME,
            stream=STREAM_NAME,
            manual_ack=True,
            cb=self._dispatch,
            config=ConsumerConfig(
                filter_subjects=CONSUMER_FILTER_SUBJECTS,
                ack_policy=AckPolicy.EXPLICIT,
                max_deliver=MAX_DELIVER,
                ack_wait=ACK_WAIT_SECONDS,
            ),
        )
        logger.info("aiac-agent-consumer subscribed to %s", CONSUMER_FILTER_SUBJECTS)

    async def start_with_retry(self) -> None:
        """Retry ``start()`` with exponential backoff until it succeeds.

        Without this, a failure anywhere in ``start()`` (connect, stream provisioning,
        subscribe) leaves the background task dead with nothing to restart it — the
        Controller keeps serving ``/health`` as if event consumption were live.
        """
        backoff = _START_RETRY_INITIAL_BACKOFF
        while True:
            try:
                await self.start()
                return
            except Exception:
                logger.exception("consumer failed to start; retrying in %.0fs", backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _START_RETRY_MAX_BACKOFF)

    async def stop(self) -> None:
        if self._sub is not None:
            await self._sub.unsubscribe()
        if self._nc is not None:
            await self._nc.close()

    async def _dispatch(self, msg: Msg) -> None:
        try:
            # ``_handle`` (the LLM-backed policy-rules builder) and ``compute_and_apply`` are
            # SYNCHRONOUS and slow (tens of seconds). nats-py runs this callback ON the event loop,
            # so calling them inline froze the loop for the whole onboard — starving the FastAPI
            # ``/health`` endpoint until the liveness probe killed the pod mid-onboard (then NATS
            # redelivered the unacked message and the race repeated). Offload both to the default
            # threadpool so the loop stays free to answer ``/health`` while onboarding runs.
            loop = asyncio.get_running_loop()
            # UC1 only: ``focus`` is the onboarded service's clientId, so the PCE routing guard keeps
            # its rules while its client is still disabled (a re-onboarding of a quarantined service).
            rules, override, focus = await loop.run_in_executor(None, _handle, msg.subject)
            await loop.run_in_executor(None, functools.partial(compute_and_apply, rules, override, focus_service=focus))
            # UC1 only (only an onboarding has a focus service): re-enable the client AFTER a
            # successful compute_and_apply, mirroring the HTTP route. If compute_and_apply raised
            # above, this is skipped and the client stays disabled (the failed-service marker), never
            # enabled-with-no-policy. The re-enable is an IdP call, so it takes the subject's UUID.
            if focus is not None:
                reenable_service(ServiceUuid(msg.subject.removeprefix(_SERVICE_PREFIX)))
        except Exception as exc:
            # Log exactly once, routed by exception TYPE to its per-persona named logger.
            # FastAPI's exception handlers never fire on this path (there is no request), so
            # this is the single place the failure is surfaced.
            log_by_type(exc)
            permanent = isinstance(exc, _PERMANENT_ERRORS)
            if permanent or msg.metadata.num_delivered >= MAX_DELIVER:
                # jetstream().publish() waits for the broker's PubAck and raises on failure —
                # unlike the raw client's fire-and-forget publish() — so the message is only
                # terminated once the DLQ write is confirmed persisted.
                await self._nc.jetstream().publish(DLQ_SUBJECT, msg.data)
                await msg.term()
                logger.error(
                    "moved %s to %s (%s failure after %d deliveries)",
                    msg.subject,
                    DLQ_SUBJECT,
                    "permanent" if permanent else "retryable",
                    msg.metadata.num_delivered,
                )
            elif isinstance(exc, ServiceNotVisibleError):
                # Retryable + still under MAX_DELIVER, and the IdP does not show the new service yet:
                # nak with a short delay, so the redelivery comes after the delay, not after ACK_WAIT.
                await _nak_not_visible(msg)
            # Any other retryable failure still under MAX_DELIVER: leave unacked so NATS redelivers.
            return
        await msg.ack()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # The Controller start sequence (the enforcement side, start check #4, then the resync) runs
    # FIRST, before the NATS consumer starts and before uvicorn serves: a failure raises here, so
    # uvicorn exits and the pod restarts. It is synchronous (k8s and PDP calls), so it runs in a thread.
    await asyncio.to_thread(run_start_sequence)
    consumer = AiacEventConsumer()
    # Backgrounded so a slow NATS handshake never blocks /apply/* from becoming
    # available. Each individual message is still awaited to completion by
    # nats-py before this consumer's own ack/term call — see _dispatch.
    task = asyncio.create_task(consumer.start_with_retry())
    try:
        yield
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await consumer.stop()
