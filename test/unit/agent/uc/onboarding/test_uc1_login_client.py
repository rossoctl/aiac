"""``uc1_onboard.hold_direct_access_grants`` turns on the password grant of the login client for the
session, and ``release_direct_access_grants`` turns it off again at session end if the harness turned it
on — pure unit tests.

The harness mints user tokens through the login client ``rossoctl`` with the password grant, so the
client needs Direct Access Grants on. ``_clean_slate`` (shared by ``onboarded_stack`` and
``pristine_stack``) holds the grant before its first mutation, and ``test/system/conftest.py`` releases
it at session end. The harness writes a marker attribute with the grant, so a run that is killed before
its release is undone by the next run, and a grant that someone else turned on is never turned off. A
grant that cannot be read or written is a skip with the cause. These tests use a stateful fake admin (no
Keycloak) that applies the partial-update rules of Keycloak 26. They import the system harness like
``test_uc1_subject_scope.py`` does.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from keycloak.exceptions import KeycloakError

HERE = Path(__file__).resolve().parent  # test/unit/agent/uc/onboarding/
REPO_ROOT = HERE.parents[4]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from test.system import uc1_onboard as uc1  # noqa: E402

LOGIN_UUID = "uuid-1"
MARKER = uc1.DAG_MARKER_ATTRIBUTE


@pytest.fixture(autouse=True)
def _no_holds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test starts a fresh session: no login client is held."""
    monkeypatch.setattr(uc1, "_dag_holds", {})


def _login(enabled: bool, *, marked: bool = False, client_id: str = uc1.KEYCLOAK_CLIENT_ID) -> dict:
    attributes = {"keep.me": "yes", **({MARKER: "true"} if marked else {})}
    return {"clientId": client_id, "id": LOGIN_UUID, "directAccessGrantsEnabled": enabled, "attributes": attributes}


def _admin(client: dict | None) -> MagicMock:
    """A ``KeycloakAdmin`` stand-in over one stored client. Its filtered ``clientId`` query finds the
    client (or nothing), and ``update_client`` applies a partial update as Keycloak 26 does: only the
    given fields change; in ``attributes`` only the given keys change, and ``""`` removes a key."""
    admin = MagicMock(name="KeycloakAdmin")
    admin.stored = client

    def _update(uuid: str, fields: dict) -> None:
        stored = admin.stored
        for key, value in fields.items():
            if key != "attributes":
                stored[key] = value
                continue
            for name, attr in value.items():
                if attr == "":
                    stored["attributes"].pop(name, None)
                else:
                    stored["attributes"][name] = attr

    admin.get_client_id.side_effect = lambda client_id: (
        admin.stored["id"] if admin.stored is not None and client_id == admin.stored["clientId"] else None
    )
    admin.get_client.side_effect = lambda uuid: {**admin.stored, "attributes": dict(admin.stored["attributes"])}
    admin.update_client.side_effect = _update
    return admin


def _grant_writes(admin: MagicMock) -> list[bool]:
    return [call.args[1]["directAccessGrantsEnabled"] for call in admin.update_client.call_args_list]


# ======================================================================================
# login_client — a filtered read, not a list of every client
# ======================================================================================


def test_the_login_client_is_found_with_a_filtered_query() -> None:
    admin = _admin(_login(True))
    assert uc1.login_client(admin, "rossoctl") == _login(True)
    admin.change_current_realm.assert_called_with("rossoctl")
    admin.get_client_id.assert_called_once_with(uc1.KEYCLOAK_CLIENT_ID)
    admin.get_clients.assert_not_called()


def test_a_missing_login_client_is_none() -> None:
    admin = _admin(None)
    assert uc1.login_client(admin, "rossoctl") is None
    admin.get_client.assert_not_called()


# ======================================================================================
# hold_direct_access_grants — the entry half, once per session
# ======================================================================================


def test_the_grant_is_enabled_with_the_marker_in_one_partial_update() -> None:
    admin = _admin(_login(False))
    uc1.hold_direct_access_grants(admin, "rossoctl")
    admin.change_current_realm.assert_called_with("rossoctl")
    admin.update_client.assert_called_once_with(
        LOGIN_UUID, {"directAccessGrantsEnabled": True, "attributes": {MARKER: "true"}}
    )
    assert admin.stored["attributes"]["keep.me"] == "yes"  # other attributes are not written


def test_a_grant_that_is_on_with_no_marker_is_not_written_and_not_released() -> None:
    admin = _admin(_login(True))
    uc1.hold_direct_access_grants(admin, "rossoctl")
    uc1.release_direct_access_grants()
    admin.update_client.assert_not_called()


def test_the_grant_is_read_and_written_once_per_session() -> None:
    admin = _admin(_login(False))
    for _ in range(3):  # three stacks (three test modules) in one session
        uc1.hold_direct_access_grants(admin, "rossoctl")
    uc1.release_direct_access_grants()
    assert admin.get_client_id.call_count == 1
    assert _grant_writes(admin) == [True, False]


def test_a_marker_left_by_a_killed_run_is_taken_over_and_released() -> None:
    """The case of the review: an earlier run turned the grant on and was killed before its release. The
    marker is still on the client, so this session turns the grant off at its end."""
    admin = _admin(_login(True, marked=True))
    uc1.hold_direct_access_grants(admin, "rossoctl")
    admin.update_client.assert_not_called()  # already on: nothing to write at entry
    uc1.release_direct_access_grants()
    assert admin.stored["directAccessGrantsEnabled"] is False
    assert MARKER not in admin.stored["attributes"]


def test_a_missing_login_client_skips_and_is_not_created() -> None:
    admin = _admin(None)
    with pytest.raises(pytest.skip.Exception, match=uc1.KEYCLOAK_CLIENT_ID):
        uc1.hold_direct_access_grants(admin, "rossoctl")
    admin.update_client.assert_not_called()
    admin.create_client.assert_not_called()


def test_a_missing_realm_skips_with_that_cause() -> None:
    admin = _admin(_login(False))
    admin.get_client_id.side_effect = KeycloakError(error_message="Realm not found.", response_code=404)
    with pytest.raises(pytest.skip.Exception, match="realm 'rossoctl' does not exist"):
        uc1.hold_direct_access_grants(admin, "rossoctl")
    admin.update_client.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [KeycloakError(error_message="forbidden", response_code=403), ConnectionError("reset"), TypeError("not a list")],
)
def test_a_failed_read_skips_with_the_cause(error: Exception) -> None:
    admin = _admin(_login(False))
    admin.get_client_id.side_effect = error
    with pytest.raises(pytest.skip.Exception, match=f"cannot read the login client.*{error}"):
        uc1.hold_direct_access_grants(admin, "rossoctl")
    admin.update_client.assert_not_called()


def test_a_refused_update_skips_with_the_cause_and_writes_nothing_more() -> None:
    admin = _admin(_login(False))
    admin.update_client.side_effect = KeycloakError(error_message="forbidden", response_code=403)
    with pytest.raises(pytest.skip.Exception, match="cannot enable Direct Access Grants.*forbidden"):
        uc1.hold_direct_access_grants(admin, "rossoctl")
    assert admin.update_client.call_count == 1  # the read again finds no marker: nothing to undo
    assert uc1._dag_holds == {}


def test_an_update_that_was_applied_but_lost_its_response_is_undone_before_the_skip() -> None:
    """The case of the review: the PUT is applied, but the response times out or the connection resets."""
    admin = _admin(_login(False))
    apply = admin.update_client.side_effect

    def _applied_then_reset(uuid: str, fields: dict) -> None:
        apply(uuid, fields)
        if admin.update_client.call_count == 1:
            raise ConnectionError("connection reset")

    admin.update_client.side_effect = _applied_then_reset
    with pytest.raises(pytest.skip.Exception, match="cannot enable Direct Access Grants.*connection reset"):
        uc1.hold_direct_access_grants(admin, "rossoctl")
    assert admin.stored["directAccessGrantsEnabled"] is False
    assert MARKER not in admin.stored["attributes"]
    assert uc1._dag_holds == {}


def test_another_login_client_can_be_held() -> None:
    admin = _admin(_login(False, client_id="other-login"))
    uc1.hold_direct_access_grants(admin, "rossoctl", client_id="other-login")
    admin.get_client_id.assert_called_once_with("other-login")
    assert _grant_writes(admin) == [True]


def test_provision_realm_and_users_does_not_touch_the_login_client() -> None:
    admin = _admin(_login(False))
    admin.create_user.side_effect = lambda payload, exist_ok=False: f"id-{payload['username']}"
    admin.get_user.return_value = {"email": "e", "firstName": "f", "lastName": "l"}
    assert uc1.provision_realm_and_users(admin, "rossoctl") is None
    admin.update_client.assert_not_called()


# ======================================================================================
# release_direct_access_grants — the exit half at session end, best-effort
# ======================================================================================


def test_the_release_reads_again_and_turns_the_grant_and_the_marker_off() -> None:
    admin = _admin(_login(False))
    uc1.hold_direct_access_grants(admin, "rossoctl")
    admin.get_client.reset_mock()
    uc1.release_direct_access_grants()
    admin.get_client.assert_called_once_with(LOGIN_UUID)  # the UUID comes from the hold
    assert admin.update_client.call_args.args == (
        LOGIN_UUID,
        {"directAccessGrantsEnabled": False, "attributes": {MARKER: ""}},
    )
    assert admin.stored == _login(False)
    assert uc1._dag_holds == {}


def test_a_grant_that_someone_took_over_during_the_run_is_not_turned_off() -> None:
    """The case of the review: during the run an operator enables the grant on purpose (the runbook
    snippet), which removes the marker. The release reads the client again and leaves the grant on."""
    admin = _admin(_login(False))
    uc1.hold_direct_access_grants(admin, "rossoctl")
    admin.update_client(LOGIN_UUID, {"directAccessGrantsEnabled": True, "attributes": {MARKER: ""}})  # the operator
    admin.update_client.reset_mock()
    uc1.release_direct_access_grants()
    admin.update_client.assert_not_called()
    assert admin.stored["directAccessGrantsEnabled"] is True


@pytest.mark.parametrize("error", [KeycloakError(error_message="forbidden", response_code=403), ConnectionError()])
def test_a_failed_release_is_logged_not_raised(caplog: pytest.LogCaptureFixture, error: Exception) -> None:
    admin = _admin(_login(False))
    uc1.hold_direct_access_grants(admin, "rossoctl")
    admin.update_client.side_effect = error
    uc1.release_direct_access_grants()  # never masks a teardown failure
    assert "cannot turn Direct Access Grants off again" in caplog.text
    assert uc1._dag_holds == {}


def test_a_release_with_nothing_held_does_nothing() -> None:
    uc1.release_direct_access_grants()


# ======================================================================================
# _clean_slate — the slate and teardown that onboarded_stack and pristine_stack share
# ======================================================================================

_SLATE_STEPS = (
    "hold_direct_access_grants",
    "capture_aiac_crs",
    "undeploy_workload",
    "_scrub_to_pristine",
    "reenable_provisioned_clients",
    "provision_realm_and_users",
    "verify_login_subject",
)


@pytest.fixture
def steps(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Every step of ``_clean_slate`` replaced by a recorder; the polls succeed at once."""
    recorder = MagicMock(name="steps")
    for name in _SLATE_STEPS:
        monkeypatch.setattr(uc1, name, getattr(recorder, name))
    monkeypatch.setattr(uc1, "poll_until", lambda *a, **k: True)
    monkeypatch.setattr(uc1, "workload_clients_present", lambda admin: set())
    monkeypatch.setattr(uc1, "no_authpolicies_remain", lambda: True)
    monkeypatch.setattr(uc1, "_capture_label", lambda: "rung")
    return recorder


def _step_names(recorder: MagicMock) -> list[str]:
    return [call[0] for call in recorder.mock_calls]


def test_the_slate_holds_the_grant_before_its_first_mutation(steps: MagicMock) -> None:
    with uc1._clean_slate(MagicMock(), ["github-agent"], keycloak_url="http://kc"):
        assert _step_names(steps)[0] == "hold_direct_access_grants"
        assert _step_names(steps)[-1] == "verify_login_subject"
    assert _step_names(steps)[-2:] == ["undeploy_workload", "_scrub_to_pristine"]


def test_a_skip_at_the_hold_mutates_nothing(steps: MagicMock) -> None:
    steps.hold_direct_access_grants.side_effect = pytest.skip.Exception("no login client")
    body = MagicMock(name="body")
    with pytest.raises(pytest.skip.Exception):
        with uc1._clean_slate(MagicMock(), ["github-agent"], keycloak_url="http://kc"):
            body()
    body.assert_not_called()
    assert _step_names(steps) == ["hold_direct_access_grants"]


@pytest.mark.parametrize("error", [RuntimeError("did not converge"), pytest.skip.Exception("no token")])
def test_the_body_failing_still_runs_the_teardown(steps: MagicMock, error: BaseException) -> None:
    with pytest.raises(type(error)):
        with uc1._clean_slate(MagicMock(), ["github-agent", "github-tool"], keycloak_url="http://kc"):
            steps.reset_mock()
            raise error
    assert steps.mock_calls[0].args == ("teardown",)  # the CR capture comes first
    assert [c.args[0] for c in steps.undeploy_workload.call_args_list] == ["github-tool", "github-agent"]
    steps._scrub_to_pristine.assert_called_once()
