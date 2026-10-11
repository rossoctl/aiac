"""Unit tests for aiac.agent.eventbus.consumer.

Covers subject-based dispatch and the ack/DLQ contract: ack on success,
no ack (implicit redelivery) on failure below MAX_DELIVER, a delayed nak for a
service that the IdP does not show yet (``ServiceNotVisibleError``), and DLQ
publish + term() once MAX_DELIVER is reached. A role-membership subject
(``aiac.apply.role-members.{role-id}``) goes to the PCE ``rerender_role``, with no
use-case handler and no ``compute_and_apply``.
"""

import asyncio
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from nats.js.api import AckPolicy

from aiac.agent.eventbus.consumer import (
    _NOT_VISIBLE_NAK_DELAY_DEFAULT,
    _NOT_VISIBLE_NAK_DELAY_ENV,
    AiacEventConsumer,
    _handle,
    _not_visible_nak_delay,
    lifespan,
)
from aiac.agent.eventbus.stream import (
    ACK_WAIT_SECONDS,
    CONSUMER_FILTER_SUBJECTS,
    CONSUMER_NAME,
    DLQ_SUBJECT,
    MAX_DELIVER,
    STREAM_NAME,
)
from aiac.agent.policy_rules_builder.conflict_detection import PolicyConflictError
from aiac.agent.policy_rules_builder.diagnostic_models import ConflictReport, ConflictStatus
from aiac.agent.policy_rules_builder.graph import (
    LLMAccessError,
    PolicyContradictionError,
    PolicyRulesBuilderError,
    UnparseableLLMResponseError,
)
from aiac.agent.uc.onboarding.orchestrator import ServiceNotVisibleError
from aiac.agent.uc.onboarding.preconditions import EnforcementPreconditionError


def _fake_msg(subject: str, num_delivered: int = 1, seq: int = 1) -> MagicMock:
    msg = MagicMock()
    msg.subject = subject
    msg.data = b'{"id":"x"}'
    msg.metadata.num_delivered = num_delivered
    msg.metadata.sequence.stream = seq
    msg.ack = AsyncMock()
    msg.nak = AsyncMock()
    msg.term = AsyncMock()
    return msg


def _fake_nc() -> MagicMock:
    # .jetstream() is sync in the real client and returns a context whose .publish() is
    # async — a plain AsyncMock would make jetstream() itself async, unlike the real client.
    nc = MagicMock()
    nc.jetstream.return_value = AsyncMock()
    return nc


def test_handle_has_no_handler_for_a_service_subject():
    # _process sends a service subject to onboard_and_apply before _handle, so _handle has no handler for it.
    with (
        patch("aiac.agent.eventbus.consumer.onboard_and_apply") as onboard,
        pytest.raises(ValueError, match="no handler"),
    ):
        _handle("aiac.apply.service.svc-1")

    onboard.assert_not_called()


def test_handle_routes_role_subject_to_update_role():
    with patch("aiac.agent.eventbus.consumer.update_role", return_value=([], True)) as role:
        result = _handle("aiac.apply.role.role-1")

    role.assert_called_once_with("role-1")
    assert result == ([], True)


def test_handle_decodes_percent_encoded_dotted_role_name():
    # Mirrors SubjectMapper.encodeSubjectToken on the Keycloak SPI side: a role name
    # containing '.' (e.g. "team.admin") is percent-encoded into one NATS subject token.
    with patch("aiac.agent.eventbus.consumer.update_role", return_value=([], True)) as role:
        result = _handle("aiac.apply.role.team%2Eadmin")

    role.assert_called_once_with("team.admin")
    assert result == ([], True)


def test_handle_routes_policy_build_subject():
    with patch("aiac.agent.eventbus.consumer.build_policy", return_value=([], False)) as build:
        result = _handle("aiac.apply.policy.build")

    build.assert_called_once_with()
    assert result == ([], False)


def test_handle_raises_for_unknown_subject():
    with pytest.raises(ValueError):
        _handle("aiac.apply.offboard.svc-1")


def test_dispatch_acks_on_success():
    consumer = AiacEventConsumer()
    consumer._nc = AsyncMock()
    msg = _fake_msg("aiac.apply.service.svc-1")

    with (
        patch("aiac.agent.eventbus.consumer.onboard_and_apply") as onboard,
        patch("aiac.agent.eventbus.consumer.compute_and_apply") as pce,
    ):
        asyncio.run(consumer._dispatch(msg))

    # UC1 service-onboarding subject: onboard_and_apply gets the subject's UUID. It makes the
    # compute_and_apply call and the re-enable itself, so the consumer does not call the PCE.
    onboard.assert_called_once()
    assert onboard.call_args.args == ("svc-1",)
    pce.assert_not_called()
    msg.ack.assert_called_once()
    msg.term.assert_not_called()


def test_dispatch_onboards_a_first_delivery_with_the_client_wait():
    # The first delivery can come before Keycloak commits the new client (the event-before-commit
    # race), so the orchestrator waits for the client on its first IdP read.
    consumer = AiacEventConsumer()
    consumer._nc = AsyncMock()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=1)

    with patch("aiac.agent.eventbus.consumer.onboard_and_apply") as onboard:
        asyncio.run(consumer._dispatch(msg))

    onboard.assert_called_once_with("svc-1", wait_for_client=True)
    msg.ack.assert_called_once()


def test_dispatch_onboards_the_redelivery_after_a_not_visible_nak_with_no_client_wait():
    # The redelivery after a not-visible nak comes after the nak delay, which already gave the client
    # time to become visible: the orchestrator reads the client one time, with no wait.
    consumer = AiacEventConsumer()
    consumer._nc = _fake_nc()
    first = _fake_msg("aiac.apply.service.svc-1", num_delivered=1, seq=7)
    again = _fake_msg("aiac.apply.service.svc-1", num_delivered=2, seq=7)

    with patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=[_not_visible(), None]) as onboard:
        asyncio.run(consumer._dispatch(first))
        asyncio.run(consumer._dispatch(again))

    assert [c.kwargs["wait_for_client"] for c in onboard.call_args_list] == [True, False]
    first.nak.assert_called_once()
    again.ack.assert_called_once()
    assert consumer._not_visible_seqs == set()


@pytest.mark.parametrize("num_delivered", [2, MAX_DELIVER])
def test_dispatch_onboards_a_redelivery_after_another_failure_with_the_client_wait(num_delivered):
    # A redelivery after another failure (an LLM timeout and the ACK_WAIT redelivery, say) did not get
    # the nak delay for the client: it waits again, so one IdP read does not use up a delivery.
    consumer = AiacEventConsumer()
    consumer._nc = AsyncMock()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=num_delivered)

    with patch("aiac.agent.eventbus.consumer.onboard_and_apply") as onboard:
        asyncio.run(consumer._dispatch(msg))

    onboard.assert_called_once_with("svc-1", wait_for_client=True)
    msg.ack.assert_called_once()


def test_a_not_visible_nak_of_one_message_does_not_change_another_message():
    consumer = AiacEventConsumer()
    consumer._nc = _fake_nc()
    naked = _fake_msg("aiac.apply.service.svc-1", seq=7)
    other = _fake_msg("aiac.apply.service.svc-2", num_delivered=2, seq=8)

    with patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=[_not_visible(), None]) as onboard:
        asyncio.run(consumer._dispatch(naked))
        asyncio.run(consumer._dispatch(other))

    assert onboard.call_args_list[1].kwargs["wait_for_client"] is True


def test_dispatch_applies_a_role_subject_with_no_focus_service_and_no_onboarding():
    # Only an onboarding has a focus service: a role subject goes through _handle and the consumer's
    # own compute_and_apply call, with no focus_service, and never reaches onboard_and_apply.
    consumer = AiacEventConsumer()
    consumer._nc = AsyncMock()
    msg = _fake_msg("aiac.apply.role.role-1")

    with (
        patch("aiac.agent.eventbus.consumer.update_role", return_value=([], True)),
        patch("aiac.agent.eventbus.consumer.compute_and_apply") as pce,
        patch("aiac.agent.eventbus.consumer.onboard_and_apply") as onboard,
    ):
        asyncio.run(consumer._dispatch(msg))

    pce.assert_called_once_with([], True)
    onboard.assert_not_called()
    msg.ack.assert_called_once()


# A role-membership change (D32): the Keycloak SPI publishes ``aiac.apply.role-members.{role-id}`` when a
# user or a service account gets or loses a realm role. The role id is a UUID.
ROLE_ID = "5f0c2a8e-1b7d-4c3e-9a61-2d8f4e7b9c10"


def test_dispatch_routes_role_members_subject_to_rerender_role_with_no_prb_run():
    # A membership change does not change the policy, only who holds the role: the consumer re-renders
    # the CRs that use the role. No use-case handler (so no PRB run), no compute_and_apply, no onboarding.
    consumer = AiacEventConsumer()
    consumer._nc = AsyncMock()
    msg = _fake_msg(f"aiac.apply.role-members.{ROLE_ID}")

    with (
        patch("aiac.agent.eventbus.consumer.rerender_role") as rerender,
        patch("aiac.agent.eventbus.consumer.update_role") as role,
        patch("aiac.agent.eventbus.consumer.onboard_and_apply") as onboard,
        patch("aiac.agent.eventbus.consumer.compute_and_apply") as pce,
    ):
        asyncio.run(consumer._dispatch(msg))

    rerender.assert_called_once_with(ROLE_ID)
    role.assert_not_called()
    onboard.assert_not_called()
    pce.assert_not_called()
    msg.ack.assert_called_once()
    msg.term.assert_not_called()


def test_dispatch_runs_rerender_role_in_the_thread_pool():
    # rerender_role is synchronous (IdP, store and PDP calls): it must not run on the event loop, which
    # also serves /health.
    consumer = AiacEventConsumer()
    consumer._nc = AsyncMock()
    msg = _fake_msg(f"aiac.apply.role-members.{ROLE_ID}")
    threads = []

    with patch(
        "aiac.agent.eventbus.consumer.rerender_role",
        side_effect=lambda _role_id: threads.append(threading.current_thread()),
    ):
        asyncio.run(consumer._dispatch(msg))

    assert len(threads) == 1
    assert threads[0] is not threading.main_thread()
    msg.ack.assert_called_once()


def test_dispatch_routes_a_role_named_role_members_to_update_role():
    # The two prefixes are different: "aiac.apply.role.role-members" is the role subject of a role NAMED
    # "role-members", not a role-membership change.
    consumer = AiacEventConsumer()
    consumer._nc = AsyncMock()
    msg = _fake_msg("aiac.apply.role.role-members")

    with (
        patch("aiac.agent.eventbus.consumer.update_role", return_value=([], True)) as role,
        patch("aiac.agent.eventbus.consumer.compute_and_apply") as pce,
        patch("aiac.agent.eventbus.consumer.rerender_role") as rerender,
    ):
        asyncio.run(consumer._dispatch(msg))

    role.assert_called_once_with("role-members")
    pce.assert_called_once_with([], True)
    rerender.assert_not_called()
    msg.ack.assert_called_once()


def test_dispatch_does_not_rerender_for_a_role_subject():
    consumer = AiacEventConsumer()
    consumer._nc = AsyncMock()
    msg = _fake_msg("aiac.apply.role.role-1")

    with (
        patch("aiac.agent.eventbus.consumer.update_role", return_value=([], True)),
        patch("aiac.agent.eventbus.consumer.compute_and_apply"),
        patch("aiac.agent.eventbus.consumer.rerender_role") as rerender,
    ):
        asyncio.run(consumer._dispatch(msg))

    rerender.assert_not_called()


def test_dispatch_leaves_a_failed_rerender_unacked_before_max_deliver():
    # A dependency error of rerender_role (IdP, store or PDP) is retryable: left unacked, so NATS
    # redelivers it after ACK_WAIT. Logged once.
    consumer = AiacEventConsumer()
    consumer._nc = nc = _fake_nc()
    msg = _fake_msg(f"aiac.apply.role-members.{ROLE_ID}", num_delivered=MAX_DELIVER - 1)
    exc = HTTPException(502, "IdP config unavailable")

    with (
        patch("aiac.agent.eventbus.consumer.rerender_role", side_effect=exc),
        patch("aiac.agent.eventbus.consumer.log_by_type") as log,
    ):
        asyncio.run(consumer._dispatch(msg))

    msg.ack.assert_not_called()
    msg.nak.assert_not_called()
    msg.term.assert_not_called()
    nc.jetstream.assert_not_called()
    log.assert_called_once_with(exc)


def test_dispatch_routes_a_failed_rerender_to_dlq_at_max_deliver():
    consumer = AiacEventConsumer()
    consumer._nc = nc = _fake_nc()
    msg = _fake_msg(f"aiac.apply.role-members.{ROLE_ID}", num_delivered=MAX_DELIVER)

    with patch("aiac.agent.eventbus.consumer.rerender_role", side_effect=RuntimeError("pdp boom")):
        asyncio.run(consumer._dispatch(msg))

    msg.ack.assert_not_called()
    msg.term.assert_called_once()
    nc.jetstream.return_value.publish.assert_called_once_with(DLQ_SUBJECT, msg.data)


def test_dispatch_leaves_message_unacked_before_max_deliver():
    consumer = AiacEventConsumer()
    consumer._nc = _fake_nc()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=MAX_DELIVER - 1)

    with patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=RuntimeError("boom")):
        asyncio.run(consumer._dispatch(msg))

    msg.ack.assert_not_called()
    msg.nak.assert_not_called()  # only a not-visible service is nak'd; NATS redelivers after ACK_WAIT
    msg.term.assert_not_called()
    consumer._nc.jetstream.assert_not_called()


def test_dispatch_routes_to_dlq_after_max_deliver():
    consumer = AiacEventConsumer()
    consumer._nc = _fake_nc()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=MAX_DELIVER)

    with patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=RuntimeError("boom")):
        asyncio.run(consumer._dispatch(msg))

    msg.ack.assert_not_called()
    msg.term.assert_called_once()
    consumer._nc.jetstream.return_value.publish.assert_called_once_with(DLQ_SUBJECT, msg.data)


_PERMANENT_EXCEPTIONS = [
    PolicyConflictError(ConflictReport(status=ConflictStatus.CONFLICTS_FOUND)),
    PolicyContradictionError("scope:read", []),
    PolicyRulesBuilderError("builder blew up"),
    UnparseableLLMResponseError("cannot parse"),
    # A failed onboarding precondition check (D30) needs a fix in the cluster first: no retry helps.
    EnforcementPreconditionError(["#1 sidecar: no authbridge-proxy container"]),
]


@pytest.mark.parametrize("exc", _PERMANENT_EXCEPTIONS, ids=[type(e).__name__ for e in _PERMANENT_EXCEPTIONS])
def test_dispatch_terminates_permanent_failure_immediately_below_max_deliver(exc):
    # Every permanent failure is DLQ'd + term()ed on FIRST delivery, never left to
    # redeliver — even though num_delivered is well below MAX_DELIVER — and logged once.
    consumer = AiacEventConsumer()
    consumer._nc = _fake_nc()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=1)

    with (
        patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=exc),
        patch("aiac.agent.eventbus.consumer.log_by_type") as log,
    ):
        asyncio.run(consumer._dispatch(msg))

    msg.ack.assert_not_called()
    msg.term.assert_called_once()
    consumer._nc.jetstream.return_value.publish.assert_called_once_with(DLQ_SUBJECT, msg.data)
    log.assert_called_once_with(exc)


def test_dispatch_leaves_retryable_llm_access_error_unacked_below_max_deliver():
    # A retryable failure (LLMAccessError — a transient LLM outage that may clear) is left
    # UNACKED below MAX_DELIVER so NATS redelivers it; not term()ed, not acked. Logged once.
    consumer = AiacEventConsumer()
    consumer._nc = _fake_nc()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=MAX_DELIVER - 1)
    exc = LLMAccessError("endpoint unreachable")

    with (
        patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=exc),
        patch("aiac.agent.eventbus.consumer.log_by_type") as log,
    ):
        asyncio.run(consumer._dispatch(msg))

    msg.ack.assert_not_called()
    msg.nak.assert_not_called()
    msg.term.assert_not_called()
    consumer._nc.jetstream.assert_not_called()
    log.assert_called_once_with(exc)


def test_dispatch_routes_retryable_llm_access_error_to_dlq_at_max_deliver():
    # A retryable failure that never clears is DLQ'd + term()ed once MAX_DELIVER is reached.
    consumer = AiacEventConsumer()
    consumer._nc = _fake_nc()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=MAX_DELIVER)
    exc = LLMAccessError("endpoint unreachable")

    with (
        patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=exc),
        patch("aiac.agent.eventbus.consumer.log_by_type") as log,
    ):
        asyncio.run(consumer._dispatch(msg))

    msg.ack.assert_not_called()
    msg.term.assert_called_once()
    consumer._nc.jetstream.return_value.publish.assert_called_once_with(DLQ_SUBJECT, msg.data)
    log.assert_called_once_with(exc)


# The IdP still answers 404 for the service after the orchestrator's bounded wait (the
# event-before-commit race, D33): the client can become visible in some seconds, so the consumer
# naks with a short delay instead of waiting ACK_WAIT (600 s) for the redelivery.
def _not_visible() -> ServiceNotVisibleError:
    return ServiceNotVisibleError("IdP has no service svc-1 yet")


@pytest.mark.parametrize("num_delivered", [1, MAX_DELIVER - 1])
def test_dispatch_naks_not_visible_service_with_delay_below_max_deliver(monkeypatch, num_delivered):
    monkeypatch.delenv(_NOT_VISIBLE_NAK_DELAY_ENV, raising=False)
    consumer = AiacEventConsumer()
    consumer._nc = nc = _fake_nc()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=num_delivered)
    exc = _not_visible()

    with (
        patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=exc),
        patch("aiac.agent.eventbus.consumer.log_by_type") as log,
    ):
        asyncio.run(consumer._dispatch(msg))

    msg.nak.assert_called_once_with(delay=_NOT_VISIBLE_NAK_DELAY_DEFAULT)
    msg.ack.assert_not_called()
    msg.term.assert_not_called()
    nc.jetstream.assert_not_called()
    log.assert_called_once_with(exc)


def test_dispatch_naks_not_visible_service_with_the_configured_delay(monkeypatch):
    monkeypatch.setenv(_NOT_VISIBLE_NAK_DELAY_ENV, "5")
    consumer = AiacEventConsumer()
    consumer._nc = _fake_nc()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=1)

    with patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=_not_visible()):
        asyncio.run(consumer._dispatch(msg))

    msg.nak.assert_called_once_with(delay=5.0)


def test_dispatch_routes_not_visible_service_to_dlq_at_max_deliver():
    # At MAX_DELIVER the not-visible service goes to the DLQ like every other retryable failure: no
    # nak (a nak would ask for a delivery that the consumer's max_deliver does not allow).
    consumer = AiacEventConsumer()
    consumer._nc = nc = _fake_nc()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=MAX_DELIVER)

    with patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=_not_visible()):
        asyncio.run(consumer._dispatch(msg))

    msg.nak.assert_not_called()
    msg.ack.assert_not_called()
    msg.term.assert_called_once()
    nc.jetstream.return_value.publish.assert_called_once_with(DLQ_SUBJECT, msg.data)


def test_dispatch_does_not_nak_another_http_502():
    # Only the not-visible class is nak'd. Another 502 from onboard_and_apply (for example an IdP
    # outage) keeps the old behaviour: no ack and no nak, so NATS redelivers after ACK_WAIT.
    consumer = AiacEventConsumer()
    consumer._nc = nc = _fake_nc()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=1)
    exc = HTTPException(502, "IdP config unavailable resolving service svc-1")

    with patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=exc):
        asyncio.run(consumer._dispatch(msg))

    msg.nak.assert_not_called()
    msg.ack.assert_not_called()
    msg.term.assert_not_called()
    nc.jetstream.assert_not_called()


def test_dispatch_survives_a_failed_nak(caplog):
    # A failed nak (for example a dropped connection) must not crash the callback: the consumer logs
    # it, and NATS redelivers the unacked message after ACK_WAIT.
    consumer = AiacEventConsumer()
    consumer._nc = nc = _fake_nc()
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=1)
    msg.nak.side_effect = RuntimeError("connection closed")

    with (
        patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=_not_visible()),
        caplog.at_level("ERROR", logger="aiac.agent.eventbus.consumer"),
    ):
        asyncio.run(consumer._dispatch(msg))

    msg.nak.assert_called_once()
    msg.ack.assert_not_called()
    msg.term.assert_not_called()
    nc.jetstream.assert_not_called()
    assert any(r.name == "aiac.agent.eventbus.consumer" and "nak" in r.getMessage() for r in caplog.records)


def test_not_visible_nak_delay_defaults_to_about_30_seconds(monkeypatch):
    monkeypatch.delenv(_NOT_VISIBLE_NAK_DELAY_ENV, raising=False)

    assert _not_visible_nak_delay() == _NOT_VISIBLE_NAK_DELAY_DEFAULT == 30.0


def test_not_visible_nak_delay_reads_the_env(monkeypatch):
    monkeypatch.setenv(_NOT_VISIBLE_NAK_DELAY_ENV, "12.5")

    assert _not_visible_nak_delay() == 12.5


@pytest.mark.parametrize("raw", ["", "abc", "0", "-1", "nan", "inf"])
def test_not_visible_nak_delay_falls_back_to_the_default_on_a_bad_value(monkeypatch, raw):
    # A bad value must not crash the callback. A delay of 0 (or less) is bad too: nats-py then sends
    # a plain nak, and NATS redelivers at once.
    monkeypatch.setenv(_NOT_VISIBLE_NAK_DELAY_ENV, raw)

    assert _not_visible_nak_delay() == _NOT_VISIBLE_NAK_DELAY_DEFAULT


def test_start_with_retry_retries_on_failure_then_succeeds():
    consumer = AiacEventConsumer()
    attempts = AsyncMock(side_effect=[RuntimeError("connect failed"), RuntimeError("connect failed"), None])

    with (
        patch.object(consumer, "start", attempts),
        patch("aiac.agent.eventbus.consumer.asyncio.sleep", new=AsyncMock()) as sleep,
    ):
        asyncio.run(consumer.start_with_retry())

    assert attempts.call_count == 3
    assert sleep.call_count == 2


def test_start_connects_and_subscribes_with_expected_config():
    consumer = AiacEventConsumer()
    fake_js = AsyncMock()
    fake_nc = MagicMock()
    fake_nc.jetstream.return_value = fake_js
    # The parent mock records the order of the three calls.
    calls = MagicMock()
    calls.ensure_stream = AsyncMock()
    calls.ensure_consumer = AsyncMock()
    calls.subscribe = fake_js.subscribe = AsyncMock()

    with (
        patch("aiac.agent.eventbus.consumer.nats.connect", AsyncMock(return_value=fake_nc)) as connect,
        patch("aiac.agent.eventbus.consumer.ensure_stream", calls.ensure_stream),
        patch("aiac.agent.eventbus.consumer.ensure_consumer", calls.ensure_consumer),
    ):
        asyncio.run(consumer.start())

    connect.assert_called_once_with(consumer._nats_url, max_reconnect_attempts=-1)
    calls.ensure_stream.assert_called_once_with(fake_js)
    # The start updates an existing durable consumer to the config of the code BEFORE the subscribe,
    # because nats-py binds to an existing durable consumer with its old config.
    calls.ensure_consumer.assert_called_once_with(fake_js)
    assert [c[0] for c in calls.mock_calls] == ["ensure_stream", "ensure_consumer", "subscribe"]
    _, kwargs = fake_js.subscribe.call_args
    assert kwargs["subject"] == "aiac.apply.>"
    assert kwargs["queue"] == CONSUMER_NAME
    assert kwargs["durable"] == CONSUMER_NAME
    assert kwargs["stream"] == STREAM_NAME
    assert kwargs["manual_ack"] is True
    assert kwargs["cb"] == consumer._dispatch
    config = kwargs["config"]
    assert config.filter_subjects == CONSUMER_FILTER_SUBJECTS
    assert config.ack_policy == AckPolicy.EXPLICIT
    assert config.max_deliver == MAX_DELIVER
    assert config.ack_wait == ACK_WAIT_SECONDS
    assert consumer._nc is fake_nc
    assert consumer._sub is fake_js.subscribe.return_value


def test_lifespan_awaits_cancelled_task_before_stopping_consumer():
    # Regression test for the shutdown race: task.cancel() alone doesn't wait for the
    # task to actually finish, so consumer.stop() could previously run while
    # start_with_retry (or _dispatch, mid-message) was still executing.
    events = []

    class FakeConsumer:
        async def start_with_retry(self):
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                events.append("task_cancelled")
                raise

        async def stop(self):
            events.append("stopped")

    async def run():
        # The start sequence (check #4, resync) is covered in test/unit/agent/controller/test_start.py.
        with (
            patch("aiac.agent.eventbus.consumer.run_start_sequence"),
            patch("aiac.agent.eventbus.consumer.AiacEventConsumer", return_value=FakeConsumer()),
        ):
            async with lifespan(MagicMock()):
                await asyncio.sleep(0)  # let the background task actually start

    asyncio.run(run())

    assert events == ["task_cancelled", "stopped"]


def test_dispatch_does_not_term_when_dlq_publish_fails():
    consumer = AiacEventConsumer()
    consumer._nc = _fake_nc()
    consumer._nc.jetstream.return_value.publish.side_effect = RuntimeError("dlq publish failed")
    msg = _fake_msg("aiac.apply.service.svc-1", num_delivered=MAX_DELIVER)

    with (
        patch("aiac.agent.eventbus.consumer.onboard_and_apply", side_effect=RuntimeError("boom")),
        pytest.raises(RuntimeError, match="dlq publish failed"),
    ):
        asyncio.run(consumer._dispatch(msg))

    msg.ack.assert_not_called()
    msg.term.assert_not_called()
