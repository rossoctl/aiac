"""``uc1_onboard.ensure_direct_access_grants`` turns on the password grant of the login client, and
``restore_direct_access_grants`` turns it off again — pure unit tests.

The harness mints user tokens through the login client ``rossoctl`` with the password grant, so the
client needs Direct Access Grants on. ``provision_realm_and_users`` turns it on, so each setup path
(``onboarded_stack``, ``pristine_stack`` and the disabled cross-service test) gets it, and each
teardown turns it off again when the setup turned it on. A grant that cannot be written is a skip with
the cause. These tests use a
``MagicMock`` admin (no Keycloak). They import the system harness like ``test_uc1_subject_scope.py``
does.
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


def _admin(client: dict | None) -> MagicMock:
    admin = MagicMock(name="KeycloakAdmin")
    admin.get_clients.return_value = [{"clientId": "other", "id": "x"}] + ([] if client is None else [client])
    return admin


def _login(enabled: bool) -> dict:
    return {"clientId": uc1.KEYCLOAK_CLIENT_ID, "id": "uuid-1", "directAccessGrantsEnabled": enabled}


def test_the_grant_is_enabled_with_a_partial_update() -> None:
    admin = _admin(_login(False))
    assert uc1.ensure_direct_access_grants(admin, "rossoctl") is True
    admin.change_current_realm.assert_called_with("rossoctl")
    admin.update_client.assert_called_once_with("uuid-1", {"directAccessGrantsEnabled": True})


def test_a_grant_that_is_on_is_not_written() -> None:
    admin = _admin(_login(True))
    assert uc1.ensure_direct_access_grants(admin, "rossoctl") is False
    admin.update_client.assert_not_called()


def test_a_missing_login_client_skips_and_is_not_created() -> None:
    admin = _admin(None)
    with pytest.raises(pytest.skip.Exception, match=uc1.KEYCLOAK_CLIENT_ID):
        uc1.ensure_direct_access_grants(admin, "rossoctl")
    admin.update_client.assert_not_called()
    admin.create_client.assert_not_called()


def test_a_refused_read_skips_with_the_cause() -> None:
    admin = _admin(_login(False))
    admin.get_clients.side_effect = KeycloakError(error_message="forbidden", response_code=403)
    with pytest.raises(pytest.skip.Exception, match="cannot read the login client.*forbidden"):
        uc1.ensure_direct_access_grants(admin, "rossoctl")
    admin.update_client.assert_not_called()


def test_a_refused_update_skips_with_the_cause() -> None:
    admin = _admin(_login(False))
    admin.update_client.side_effect = KeycloakError(error_message="forbidden", response_code=403)
    with pytest.raises(pytest.skip.Exception, match="cannot enable Direct Access Grants.*forbidden"):
        uc1.ensure_direct_access_grants(admin, "rossoctl")


def test_provision_realm_and_users_enables_the_grant() -> None:
    admin = _admin(_login(False))
    admin.create_user.side_effect = lambda payload, exist_ok=False: f"id-{payload['username']}"
    admin.get_user.return_value = {"email": "e", "firstName": "f", "lastName": "l"}
    assert uc1.provision_realm_and_users(admin, "rossoctl") is True
    admin.update_client.assert_called_once_with("uuid-1", {"directAccessGrantsEnabled": True})


def test_the_restore_turns_the_grant_off_with_a_partial_update() -> None:
    admin = _admin(_login(True))
    uc1.restore_direct_access_grants(admin, "rossoctl")
    admin.change_current_realm.assert_called_with("rossoctl")
    admin.update_client.assert_called_once_with("uuid-1", {"directAccessGrantsEnabled": False})


def test_a_refused_restore_is_logged_not_raised(caplog: pytest.LogCaptureFixture) -> None:
    admin = _admin(_login(True))
    admin.update_client.side_effect = KeycloakError(error_message="forbidden", response_code=403)
    uc1.restore_direct_access_grants(admin, "rossoctl")  # never masks a teardown failure
    assert "cannot turn Direct Access Grants off again" in caplog.text


def test_the_restore_of_a_missing_login_client_writes_nothing() -> None:
    admin = _admin(None)
    uc1.restore_direct_access_grants(admin, "rossoctl")
    admin.update_client.assert_not_called()
