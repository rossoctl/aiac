"""``uc1_onboard.provision_realm_and_users`` gives each scenario user a full profile — pure unit tests.

Keycloak 26 refuses a password grant (``invalid_grant``: "Account is not fully set up") for a user
that lacks an attribute that the realm's user profile requires. A fresh ``rossoctl`` realm requires
``email``, ``firstName`` and ``lastName``. These tests use a ``MagicMock`` admin (no Keycloak). They
import the system harness like ``test_uc1_subject_scope.py`` does.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

HERE = Path(__file__).resolve().parent  # test/unit/agent/uc/onboarding/
REPO_ROOT = HERE.parents[4]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from test.system import scenario_uc1 as scn  # noqa: E402
from test.system import uc1_onboard as uc1  # noqa: E402

_PROFILE = ("email", "firstName", "lastName")


def _admin(existing: dict[str, dict] | None = None) -> MagicMock:
    """A ``KeycloakAdmin`` stand-in. ``existing`` maps a username to the stored user representation;
    a user that is not in it is new (the create returns its id, and its read gives the created
    representation)."""
    existing = existing or {}
    created: dict[str, dict] = {}
    admin = MagicMock(name="KeycloakAdmin")

    def create_user(payload, exist_ok=False):
        name = payload["username"]
        if name not in existing:
            created[name] = dict(payload)
        return f"id-{name}"

    admin.create_user.side_effect = create_user
    admin.get_user.side_effect = lambda user_id: {**(existing.get(user_id[3:]) or created[user_id[3:]])}
    return admin


def test_a_new_user_is_created_with_the_full_profile() -> None:
    admin = _admin()
    uc1.provision_realm_and_users(admin, "rossoctl")
    for call in admin.create_user.call_args_list:
        payload = call.args[0]
        assert all(payload.get(key) for key in _PROFILE), payload
        assert payload["emailVerified"] is True
    assert {c.args[0]["username"] for c in admin.create_user.call_args_list} == set(scn.USERS)
    admin.update_user.assert_not_called()


def test_an_existing_user_without_a_profile_gets_the_missing_fields() -> None:
    username = next(iter(scn.USERS))
    admin = _admin({username: {"username": username, "enabled": True}})
    uc1.provision_realm_and_users(admin, "rossoctl")
    (call,) = [c for c in admin.update_user.call_args_list if c.args[0] == f"id-{username}"]
    payload = call.args[1]
    assert payload["username"] == username and payload["enabled"] is True
    assert all(payload.get(key) for key in _PROFILE)


def test_an_existing_full_profile_is_not_changed() -> None:
    # The platform's own dev-user keeps its names: only a missing field is written.
    profiles = {
        name: {"username": name, "enabled": True, "email": f"{name}@example.org", "emailVerified": True,
               "firstName": "First", "lastName": "Last"}
        for name in scn.USERS
    }
    admin = _admin(profiles)
    uc1.provision_realm_and_users(admin, "rossoctl")
    admin.update_user.assert_not_called()
