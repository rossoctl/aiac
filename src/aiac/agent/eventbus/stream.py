"""Shared NATS JetStream stream/consumer configuration.

Used both by the ``aiac-init`` init container (creates the stream) and the
Agent's own consumer startup (binds to it, and defensively re-runs the
idempotent ``add_stream`` call in case the init container hasn't run yet).
The consumer startup also updates an existing durable consumer to the config
below (``ensure_consumer``) before it subscribes.
"""

import logging

from nats.js import JetStreamContext
from nats.js.api import AckPolicy, ConsumerConfig, RetentionPolicy, StreamConfig
from nats.js.errors import BadRequestError, NotFoundError

logger = logging.getLogger(__name__)

DEFAULT_NATS_URL = "nats://aiac-event-broker-service:4222"

STREAM_NAME = "aiac-events"
STREAM_SUBJECTS = ["aiac.apply.>"]

CONSUMER_NAME = "aiac-agent-consumer"
# Deliberately narrower than the stream's own subjects: the stream captures
# every aiac.apply.> publish (including aiac.apply.dlq, so dead-lettered
# messages stay inspectable), but the consumer must not resubscribe to its
# own DLQ subject or it would reprocess dead-lettered messages forever.
# A new subject here reaches a running cluster only through ensure_consumer.
CONSUMER_FILTER_SUBJECTS = [
    "aiac.apply.service.*",
    "aiac.apply.role.*",
    "aiac.apply.role-members.*",
    "aiac.apply.policy.build",
]

DLQ_SUBJECT = "aiac.apply.dlq"
MAX_DELIVER = 5

# Onboarding's LLM calls run synchronously inside the dispatch callback, each bounded by
# LLM_REQUEST_TIMEOUT (default 120s) and retried up to UPSTREAM_MAX_RETRIES times (default 3),
# across multiple structured calls (propose/audit). JetStream's own 30s default ack_wait would
# redeliver a message that's still being processed, so this is sized well above the worst case.
ACK_WAIT_SECONDS = 600.0

# JetStream's "stream name already in use with a different configuration" error code.
_STREAM_CONFIG_MISMATCH_ERR_CODE = 10058


async def ensure_stream(js: JetStreamContext) -> None:
    """Idempotently create the ``aiac-events`` stream.

    ``add_stream`` is itself idempotent (no-op success when the stream already
    exists with an identical config); this only needs to swallow the specific
    "already exists with a different config" error, since that's not our
    scenario here — the config below is the single source of truth for both
    callers.
    """
    try:
        await js.add_stream(
            config=StreamConfig(
                name=STREAM_NAME,
                subjects=STREAM_SUBJECTS,
                retention=RetentionPolicy.WORK_QUEUE,
            )
        )
        logger.info("aiac-events stream ready (name=%s, subjects=%s)", STREAM_NAME, STREAM_SUBJECTS)
    except BadRequestError as e:
        if e.err_code != _STREAM_CONFIG_MISMATCH_ERR_CODE:
            raise
        logger.info("aiac-events stream already exists with a different configuration: %s", e)


def consumer_config() -> ConsumerConfig:
    """The fields of the ``aiac-agent-consumer`` config that the code sets. A new object at each call:
    nats-py's ``subscribe()`` writes into the config that it gets (durable name, deliver subject, ...)."""
    return ConsumerConfig(
        filter_subjects=list(CONSUMER_FILTER_SUBJECTS),
        ack_policy=AckPolicy.EXPLICIT,
        max_deliver=MAX_DELIVER,
        ack_wait=ACK_WAIT_SECONDS,
    )


def _filters(config: ConsumerConfig) -> set[str]:
    """The filter subjects of ``config``, as a set: ``filter_subjects``, else the single legacy
    ``filter_subject``, else none."""
    return set(config.filter_subjects or ([config.filter_subject] if config.filter_subject else []))


async def ensure_consumer(js: JetStreamContext) -> None:
    """Update an existing ``aiac-agent-consumer`` to the fields of ``consumer_config()``.

    nats-py's ``subscribe()`` creates a missing durable consumer from the config that it gets, but it
    binds to an existing one with the config that the server has (it reads ``consumer_info`` and does
    not compare). So without this, a filter subject that a new release adds never reaches a running
    cluster. Call it before ``subscribe()``:

    - no consumer (``NotFoundError``): no call; ``subscribe()`` creates it, with its own deliver inbox;
    - a consumer whose filter subjects (in any order), ack policy, ``max_deliver`` and ``ack_wait``
      match: no call;
    - else ``add_consumer`` with the server's config and only those fields changed. On an existing
      durable name the server takes it as an update. The update keeps every other field as the server
      has it, because JetStream refuses a change of most of them (the deliver and replay policy, the
      heartbeat, flow control, a push consumer's deliver subject while it is bound). So the push/queue
      binding keeps its deliver subject and deliver group. JetStream updates the filter subjects,
      ``max_deliver`` and ``ack_wait`` in place; it refuses a change of the ack policy. A refused update
      raises, and the consumer start retries (the operator must then delete the durable consumer).
    """
    try:
        info = await js.consumer_info(STREAM_NAME, CONSUMER_NAME)
    except NotFoundError:
        return
    want, have = consumer_config(), info.config
    if (
        _filters(have) == _filters(want)
        and have.ack_policy == want.ack_policy
        and have.max_deliver == want.max_deliver
        and have.ack_wait == want.ack_wait
    ):
        return
    await js.add_consumer(
        STREAM_NAME,
        config=have.evolve(
            filter_subject=None,
            filter_subjects=want.filter_subjects,
            ack_policy=want.ack_policy,
            max_deliver=want.max_deliver,
            ack_wait=want.ack_wait,
        ),
    )
    logger.info(
        "%s updated (filter_subjects=%s, max_deliver=%s, ack_wait=%ss; was %s, %s, %ss)",
        CONSUMER_NAME,
        want.filter_subjects,
        want.max_deliver,
        want.ack_wait,
        sorted(_filters(have)),
        have.max_deliver,
        have.ack_wait,
    )
