"""``uc1_onboard.direct_access_grants`` turns on the password grant of the login client for the life of
a fixture, and turns it off again at exit if it was off — pure unit tests.

The harness mints user tokens through the login client ``rossoctl`` with the password grant, so the
client needs Direct Access Grants on. ``onboarded_stack``, ``pristine_stack`` and the disabled
cross-service test enter ``direct_access_grants`` before their first mutation. Its own ``finally``
turns the grant off again, so a teardown step that raises cannot leave the grant on. A grant that
cannot be written is a skip with the cause. These tests use a ``MagicMock`` admin (no Keycloak). They
import the system harness like ``test_uc1_subject_scope.py`` does.
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


def _admin(client: dict | None) -> MagicMock:
    """A ``KeycloakAdmin`` stand-in whose filtered ``clientId`` query finds ``client`` (or nothing)."""
    admin = MagicMock(name="KeycloakAdmin")
    admin.get_client_id.side_effect = lambda client_id: (
        client["id"] if client is not None and client_id == client["clientId"] else None
    )
    admin.get_client.side_effect = lambda uuid: dict(client)
    return admin


def _login(enabled: bool) -> dict:
    return {"clientId": uc1.KEYCLOAK_CLIENT_ID, "id": LOGIN_UUID, "directAccessGrantsEnabled": enabled}


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
# ensure_direct_access_grants — the entry half
# ======================================================================================


def test_the_grant_is_enabled_with_a_partial_update() -> None:
    admin = _admin(_login(False))
    assert uc1.ensure_direct_access_grants(admin, "rossoctl") == LOGIN_UUID
    admin.change_current_realm.assert_called_with("rossoctl")
    admin.update_client.assert_called_once_with(LOGIN_UUID, {"directAccessGrantsEnabled": True})


def test_a_grant_that_is_on_is_not_written() -> None:
    admin = _admin(_login(True))
    assert uc1.ensure_direct_access_grants(admin, "rossoctl") is None
    admin.update_client.assert_not_called()


def test_a_missing_login_client_skips_and_is_not_created() -> None:
    admin = _admin(None)
    with pytest.raises(pytest.skip.Exception, match=uc1.KEYCLOAK_CLIENT_ID):
        uc1.ensure_direct_access_grants(admin, "rossoctl")
    admin.update_client.assert_not_called()
    admin.create_client.assert_not_called()


def test_a_refused_read_skips_with_the_cause() -> None:
    admin = _admin(_login(False))
    admin.get_client_id.side_effect = KeycloakError(error_message="forbidden", response_code=403)
    with pytest.raises(pytest.skip.Exception, match="cannot read the login client.*forbidden"):
        uc1.ensure_direct_access_grants(admin, "rossoctl")
    admin.update_client.assert_not_called()


def test_a_refused_update_skips_with_the_cause() -> None:
    admin = _admin(_login(False))
    admin.update_client.side_effect = KeycloakError(error_message="forbidden", response_code=403)
    with pytest.raises(pytest.skip.Exception, match="cannot enable Direct Access Grants.*forbidden"):
        uc1.ensure_direct_access_grants(admin, "rossoctl")


def test_provision_realm_and_users_does_not_touch_the_login_client() -> None:
    admin = _admin(_login(False))
    admin.create_user.side_effect = lambda payload, exist_ok=False: f"id-{payload['username']}"
    admin.get_user.return_value = {"email": "e", "firstName": "f", "lastName": "l"}
    assert uc1.provision_realm_and_users(admin, "rossoctl") is None
    admin.update_client.assert_not_called()


# ======================================================================================
# restore_direct_access_grants — the exit half, best-effort
# ======================================================================================


def test_the_restore_turns_the_grant_off_with_a_partial_update_and_no_read() -> None:
    admin = _admin(_login(True))
    uc1.restore_direct_access_grants(admin, "rossoctl", LOGIN_UUID)
    admin.change_current_realm.assert_called_with("rossoctl")
    admin.update_client.assert_called_once_with(LOGIN_UUID, {"directAccessGrantsEnabled": False})
    admin.get_client_id.assert_not_called()  # the UUID comes from the enable


@pytest.mark.parametrize("error", [KeycloakError(error_message="forbidden", response_code=403), ConnectionError()])
def test_a_refused_restore_is_logged_not_raised(caplog: pytest.LogCaptureFixture, error: Exception) -> None:
    admin = _admin(_login(True))
    admin.update_client.side_effect = error
    uc1.restore_direct_access_grants(admin, "rossoctl", LOGIN_UUID)  # never masks a teardown failure
    assert "cannot turn Direct Access Grants off again" in caplog.text


# ======================================================================================
# direct_access_grants — the context manager: the restore is in its own ``finally``
# ======================================================================================


def test_the_context_turns_on_a_grant_that_was_off_and_turns_it_off_at_exit() -> None:
    admin = _admin(_login(False))
    with uc1.direct_access_grants(admin, "rossoctl"):
        assert _grant_writes(admin) == [True]
    assert _grant_writes(admin) == [True, False]


def test_the_context_does_not_write_a_grant_that_was_on() -> None:
    admin = _admin(_login(True))
    with uc1.direct_access_grants(admin, "rossoctl"):
        pass
    admin.update_client.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [AssertionError("clear_policy_store: HTTP 500"), KeycloakError(error_message="token refused", response_code=401)],
)
def test_a_teardown_step_that_raises_still_restores_the_grant(error: Exception) -> None:
    """The case of the review: a scrub step of the fixture teardown raises (for example
    ``clear_policy_store`` or ``cleanup_provisioned``). The grant is still turned off, and the error
    propagates unchanged."""
    admin = _admin(_login(False))
    with pytest.raises(type(error)) as raised:
        with uc1.direct_access_grants(admin, "rossoctl"):
            try:
                pass  # the fixture body
            finally:
                raise error  # a teardown step of the body
    assert raised.value is error
    assert _grant_writes(admin) == [True, False]


def test_a_skip_in_the_body_still_restores_the_grant() -> None:
    admin = _admin(_login(False))
    with pytest.raises(pytest.skip.Exception):
        with uc1.direct_access_grants(admin, "rossoctl"):
            pytest.skip("verify_login_subject cannot mint a token")
    assert _grant_writes(admin) == [True, False]


def test_a_failed_restore_does_not_mask_the_body_error() -> None:
    admin = _admin(_login(False))
    admin.update_client.side_effect = [None, KeycloakError(error_message="forbidden", response_code=403)]
    with pytest.raises(RuntimeError, match="teardown did not restore pristine"):
        with uc1.direct_access_grants(admin, "rossoctl"):
            raise RuntimeError("teardown did not restore pristine")


def test_a_skip_at_entry_writes_nothing() -> None:
    admin = _admin(None)
    body = MagicMock(name="body")
    with pytest.raises(pytest.skip.Exception):
        with uc1.direct_access_grants(admin, "rossoctl"):
            body()
    body.assert_not_called()
    admin.update_client.assert_not_called()
