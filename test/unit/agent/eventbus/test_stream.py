"""Unit tests for aiac.agent.eventbus.stream (ensure_stream, ensure_consumer).

``add_stream`` (mocked here as an AsyncMock JetStreamContext) is itself
idempotent — it only raises a ``BadRequestError`` when the stream name is
already in use. err_code 10058 means "already exists with a different
configuration" (JetStream's benign already-exists signal here, since both
callers share the same config constants); anything else is a genuine failure
and must propagate. These tests assert we swallow the former and re-raise
the latter.

``ensure_consumer`` updates an existing durable consumer to the config of the
code; the server replies are mocked in the shape that nats-py parses.
"""

import asyncio
from unittest.mock import AsyncMock

import pytest
from nats.js.api import AckPolicy, ConsumerConfig, ConsumerInfo, DeliverPolicy, ReplayPolicy, RetentionPolicy
from nats.js.errors import BadRequestError, NotFoundError, ServiceUnavailableError

from aiac.agent.eventbus.stream import (
    ACK_WAIT_SECONDS,
    CONSUMER_FILTER_SUBJECTS,
    CONSUMER_NAME,
    DLQ_SUBJECT,
    MAX_DELIVER,
    STREAM_NAME,
    STREAM_SUBJECTS,
    consumer_config,
    ensure_consumer,
    ensure_stream,
)


def test_ensure_stream_creates_stream_with_expected_config():
    js = AsyncMock()

    asyncio.run(ensure_stream(js))

    _, kwargs = js.add_stream.call_args
    config = kwargs["config"]
    assert config.name == STREAM_NAME
    assert config.subjects == STREAM_SUBJECTS
    assert config.retention == RetentionPolicy.WORK_QUEUE


def test_ensure_stream_swallows_config_mismatch():
    js = AsyncMock()
    js.add_stream.side_effect = BadRequestError(err_code=10058)

    asyncio.run(ensure_stream(js))  # must not raise


def test_ensure_stream_reraises_other_bad_request_errors():
    js = AsyncMock()
    js.add_stream.side_effect = BadRequestError(err_code=99999)

    try:
        asyncio.run(ensure_stream(js))
    except BadRequestError:
        pass
    else:
        raise AssertionError("expected BadRequestError to propagate for a non-10058 error code")


# --------------------------------------------------------------------------- #
# ensure_consumer: nats-py ``subscribe()`` binds to an existing durable         #
# consumer with the config that the server has, so the start updates it first. #
# --------------------------------------------------------------------------- #
# The filter subjects of the release before ``aiac.apply.role-members.*``.
_OLD_FILTER_SUBJECTS = ["aiac.apply.service.*", "aiac.apply.role.*", "aiac.apply.policy.build"]
_DELIVER_SUBJECT = "_INBOX.9f3c1d2e7a"


def _server_consumer_info(**config) -> ConsumerInfo:
    """The durable consumer as nats-py parses the server's CONSUMER.INFO reply: the enum values are strings
    and ``ack_wait`` comes in nanoseconds. ``config`` overrides fields of the consumer config."""
    return ConsumerInfo.from_response(
        {
            "type": "io.nats.jetstream.api.v1.consumer_info_response",
            "stream_name": STREAM_NAME,
            "name": CONSUMER_NAME,
            "created": "2026-10-01T12:00:00.123456789Z",
            "config": {
                "name": CONSUMER_NAME,
                "durable_name": CONSUMER_NAME,
                "deliver_policy": "all",
                "ack_policy": "explicit",
                "ack_wait": int(ACK_WAIT_SECONDS * 1_000_000_000),
                "max_deliver": MAX_DELIVER,
                "filter_subjects": list(_OLD_FILTER_SUBJECTS),
                "replay_policy": "instant",
                "max_ack_pending": 1000,
                "deliver_subject": _DELIVER_SUBJECT,
                "deliver_group": CONSUMER_NAME,
                "num_replicas": 0,
                **config,
            },
            "delivered": {"consumer_seq": 4, "stream_seq": 9},
            "ack_floor": {"consumer_seq": 4, "stream_seq": 9},
            "num_ack_pending": 0,
            "num_redelivered": 0,
            "num_waiting": 0,
            "num_pending": 0,
            "push_bound": True,
        }
    )


def _js_with(info: ConsumerInfo | Exception) -> AsyncMock:
    js = AsyncMock()
    if isinstance(info, Exception):
        js.consumer_info.side_effect = info
    else:
        js.consumer_info.return_value = info
    return js


def _sent_config(js: AsyncMock) -> ConsumerConfig:
    """The config of the one ``add_consumer`` call (the create-or-update request) on the stream."""
    js.add_consumer.assert_called_once()
    args, kwargs = js.add_consumer.call_args
    assert args == (STREAM_NAME,)
    return kwargs["config"]


def test_consumer_filter_subjects_cover_role_members_and_not_the_dlq():
    # D32: the role-membership subject of the Keycloak SPI. The DLQ subject stays out.
    assert "aiac.apply.role-members.*" in CONSUMER_FILTER_SUBJECTS
    assert "aiac.apply.role.*" in CONSUMER_FILTER_SUBJECTS
    assert DLQ_SUBJECT not in CONSUMER_FILTER_SUBJECTS
    assert not any(s.endswith(">") for s in CONSUMER_FILTER_SUBJECTS)


def test_consumer_config_has_the_fields_of_the_code():
    config = consumer_config()

    assert config.filter_subjects == CONSUMER_FILTER_SUBJECTS
    assert config.ack_policy == AckPolicy.EXPLICIT
    assert config.max_deliver == MAX_DELIVER
    assert config.ack_wait == ACK_WAIT_SECONDS
    # nats-py's subscribe() writes into the config that it gets: each call gives a new object.
    assert consumer_config() is not config
    assert consumer_config().filter_subjects is not config.filter_subjects


def test_ensure_consumer_leaves_a_new_consumer_to_the_subscribe():
    # No durable consumer yet: subscribe() creates it from consumer_config(), with its own deliver inbox.
    js = _js_with(NotFoundError(code=404, err_code=10014, description="consumer not found"))

    asyncio.run(ensure_consumer(js))

    js.consumer_info.assert_called_once_with(STREAM_NAME, CONSUMER_NAME)
    js.add_consumer.assert_not_called()


def test_ensure_consumer_updates_an_existing_consumer_with_the_old_filter_subjects():
    js = _js_with(_server_consumer_info())

    asyncio.run(ensure_consumer(js))

    sent = _sent_config(js)
    assert sent.filter_subjects == CONSUMER_FILTER_SUBJECTS
    assert sent.filter_subject is None  # JetStream refuses filter_subject and filter_subjects together
    # The push/queue binding stays: the same durable name, deliver subject and deliver group.
    assert sent.durable_name == CONSUMER_NAME
    assert sent.name == CONSUMER_NAME
    assert sent.deliver_subject == _DELIVER_SUBJECT
    assert sent.deliver_group == CONSUMER_NAME
    # Every other field is the one that the server has: JetStream refuses a change of most of them.
    assert sent.deliver_policy == DeliverPolicy.ALL
    assert sent.replay_policy == ReplayPolicy.INSTANT
    assert sent.max_ack_pending == 1000
    assert sent.ack_policy == AckPolicy.EXPLICIT
    assert sent.max_deliver == MAX_DELIVER
    assert sent.ack_wait == ACK_WAIT_SECONDS
    assert sent.as_dict()["ack_wait"] == int(ACK_WAIT_SECONDS * 1_000_000_000)


def test_ensure_consumer_updates_an_existing_consumer_with_a_single_old_filter_subject():
    js = _js_with(_server_consumer_info(filter_subjects=None, filter_subject="aiac.apply.>"))

    asyncio.run(ensure_consumer(js))

    sent = _sent_config(js)
    assert sent.filter_subjects == CONSUMER_FILTER_SUBJECTS
    assert sent.filter_subject is None
    assert "filter_subject" not in sent.as_dict()


@pytest.mark.parametrize(
    "drift",
    [{"max_deliver": 3}, {"ack_wait": 30 * 1_000_000_000}],
    ids=["max_deliver", "ack_wait"],
)
def test_ensure_consumer_updates_an_existing_consumer_with_other_delivery_limits(drift):
    js = _js_with(_server_consumer_info(filter_subjects=list(CONSUMER_FILTER_SUBJECTS), **drift))

    asyncio.run(ensure_consumer(js))

    sent = _sent_config(js)
    assert sent.max_deliver == MAX_DELIVER
    assert sent.ack_wait == ACK_WAIT_SECONDS
    assert sent.deliver_subject == _DELIVER_SUBJECT


def test_ensure_consumer_does_not_update_a_consumer_that_matches():
    js = _js_with(_server_consumer_info(filter_subjects=list(CONSUMER_FILTER_SUBJECTS)))

    asyncio.run(ensure_consumer(js))

    js.add_consumer.assert_not_called()


def test_ensure_consumer_does_not_update_for_a_different_order_of_the_same_filter_subjects():
    js = _js_with(_server_consumer_info(filter_subjects=list(reversed(CONSUMER_FILTER_SUBJECTS))))

    asyncio.run(ensure_consumer(js))

    js.add_consumer.assert_not_called()


def test_ensure_consumer_propagates_a_refused_update():
    # JetStream cannot change the ack policy of a consumer: the server refuses the update, and the error goes
    # to the caller (the consumer start logs it and retries).
    js = _js_with(_server_consumer_info(ack_policy="none"))
    js.add_consumer.side_effect = BadRequestError(code=400, err_code=10012, description="ack policy can not be updated")

    with pytest.raises(BadRequestError):
        asyncio.run(ensure_consumer(js))

    assert _sent_config(js).ack_policy == AckPolicy.EXPLICIT


def test_ensure_consumer_propagates_another_consumer_info_error():
    js = _js_with(ServiceUnavailableError(code=503))

    with pytest.raises(ServiceUnavailableError):
        asyncio.run(ensure_consumer(js))

    js.add_consumer.assert_not_called()
