"""The subject-scope check of the UC-1 system-test harness (D31) — pure unit tests.

Every token that reaches an AIAC-managed agent or tool must have ``sub`` = the username (D31). The
login token gets it from the login client's own ``username-to-sub`` mapper; the token that an agent
exchanges gets it from the client scope ``aiac-username-sub``, which AIAC links as a default scope to
each client it onboards. The harness checks that link (``uc1_onboard.require_subject_scope``) right
after each workload converges, and rung 2 decodes a real exchanged token
(``uc1_onboard.exchanged_subject`` over ``launcher.exchange_token``).

These tests pin the offline parts, with no cluster and no Keycloak: the pure
``subject_scope_problems`` (each problem names the object), the live reader and
``require_subject_scope`` over a ``MagicMock`` admin, the RFC 8693 request of ``exchange_token`` and
its client-authentication classification (``requests.post`` stubbed), and the skip / raise contract of
``exchanged_subject``.

They import the system harness like ``test_uc1_cr_capture.py`` does
(``from test.system import uc1_onboard``): that harness does **no** cluster I/O at import time.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from keycloak.exceptions import KeycloakError

HERE = Path(__file__).resolve().parent  # test/unit/agent/uc/onboarding/
REPO_ROOT = HERE.parents[4]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from test.system import launcher  # noqa: E402
from test.system import scenario_uc1 as scn  # noqa: E402
from test.system import uc1_onboard as uc1  # noqa: E402

SCOPE_ID = "scope-uuid"
PROFILE_ID = "profile-uuid"
AGENT_UUID = "agent-uuid"
TOOL_UUID = "tool-uuid"
LOGIN_UUID = "login-uuid"
AGENT_NAME = f"{uc1.NAMESPACE}/{scn.AGENT_WORKLOAD}"
TOOL_NAME = f"{uc1.NAMESPACE}/{scn.TOOL_WORKLOAD}"
AGENT_CLIENT_ID = f"spiffe://{uc1.TRUST_DOMAIN}/ns/{uc1.NAMESPACE}/sa/{scn.AGENT_WORKLOAD}"

# The mapper as the IdP service creates it (the full D31 representation).
SUBJECT_MAPPER = {
    "name": "username-to-sub",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-property-mapper",
    "config": {
        "user.attribute": "username",
        "claim.name": "sub",
        "jsonType.label": "String",
        "access.token.claim": "true",
        "id.token.claim": "true",
        "userinfo.token.claim": "true",
        "introspection.token.claim": "true",
    },
}


def _scope(**attributes: object) -> dict:
    """The ``aiac-username-sub`` client-scope representation, with ``attributes``."""
    base = {"include.in.token.scope": "false", "display.on.consent.screen": "false"}
    return {
        "id": SCOPE_ID,
        "name": uc1.SUBJECT_SCOPE,
        "protocol": "openid-connect",
        "attributes": {**base, **attributes},
    }


def _mapper(**config: str) -> dict:
    """``SUBJECT_MAPPER`` with ``config`` pairs changed."""
    return {**SUBJECT_MAPPER, "config": {**SUBJECT_MAPPER["config"], **config}}


def _problems(
    *,
    scope: dict | None = None,
    mappers: list[dict] | None = None,
    defaults: dict[str, set[str] | None] | None = None,
    login: set[str] | None = None,
    optional: dict[str, set[str]] | None = None,
) -> list[str]:
    """``subject_scope_problems`` over the correct state, with the given parts changed."""
    return uc1.subject_scope_problems(
        _scope() if scope is None else scope,
        [SUBJECT_MAPPER] if mappers is None else mappers,
        {AGENT_NAME: {SCOPE_ID, PROFILE_ID}, TOOL_NAME: {SCOPE_ID}} if defaults is None else defaults,
        {PROFILE_ID} if login is None else login,
        client_optional_scope_ids=optional,
    )


# ======================================================================================
# subject_scope_problems — pure
# ======================================================================================


def test_correct_state_has_no_problem() -> None:
    assert _problems() == []


def test_constants_match_the_d31_contract() -> None:
    """The harness repeats the IdP service's names (it never imports ``aiac``)."""
    assert uc1.SUBJECT_SCOPE == "aiac-username-sub"
    assert uc1.SUBJECT_MAPPER == "username-to-sub"
    assert uc1.SUBJECT_MAPPER_TYPE == "oidc-usermodel-property-mapper"
    assert uc1.SUBJECT_MAPPER_CONFIG == {
        "user.attribute": "username",
        "claim.name": "sub",
        "access.token.claim": "true",
    }


def test_missing_scope_is_one_problem_that_names_the_scope_and_the_clients() -> None:
    problems = uc1.subject_scope_problems(None, [], {AGENT_NAME: {PROFILE_ID}, TOOL_NAME: set()}, set())
    assert len(problems) == 1
    assert uc1.SUBJECT_SCOPE in problems[0] and "does not exist" in problems[0]
    assert AGENT_NAME in problems[0] and TOOL_NAME in problems[0]


@pytest.mark.parametrize("marker", ["true", ["true"]], ids=["client-scope-string", "role-list"])
def test_marked_scope_is_a_problem(marker: object) -> None:
    """A scope with the ``aiac.managed`` marker would break Assumption 2 (it is linked to many
    clients) and become an own scope of each linked service."""
    problems = _problems(scope=_scope(**{"aiac.managed": marker}))
    assert len(problems) == 1
    assert uc1.SUBJECT_SCOPE in problems[0] and "aiac.managed" in problems[0]


def test_marker_set_to_false_is_not_a_problem() -> None:
    assert _problems(scope=_scope(**{"aiac.managed": "false"})) == []


def test_wrong_claim_is_a_problem_that_names_the_scope_and_the_mapper() -> None:
    """A mapper that writes ``preferred_username`` (not ``sub``) leaves ``sub`` = the user ID."""
    problems = _problems(mappers=[_mapper(**{"claim.name": "preferred_username"})])
    assert len(problems) == 1
    assert uc1.SUBJECT_SCOPE in problems[0] and "username-to-sub" in problems[0]
    assert "preferred_username" in problems[0]  # the mapper that is there, in the message


@pytest.mark.parametrize(
    "mapper",
    [
        _mapper(**{"user.attribute": "email"}),
        _mapper(**{"access.token.claim": "false"}),
        {**SUBJECT_MAPPER, "protocolMapper": "oidc-hardcoded-claim-mapper"},
        {**SUBJECT_MAPPER, "config": {}},
    ],
    ids=["other-attribute", "not-in-access-token", "other-type", "no-config"],
)
def test_other_wrong_mappers_are_a_problem(mapper: dict) -> None:
    problems = _problems(mappers=[mapper])
    assert len(problems) == 1 and uc1.SUBJECT_SCOPE in problems[0]


def test_no_mapper_is_a_problem() -> None:
    problems = _problems(mappers=[])
    assert len(problems) == 1 and uc1.SUBJECT_SCOPE in problems[0] and "none" in problems[0]


def test_mapper_is_found_by_its_mapping_not_its_name() -> None:
    """A renamed mapper with the right type and config still sets ``sub``; extra config keys are free."""
    renamed = {**SUBJECT_MAPPER, "name": "something-else"}
    assert _problems(mappers=[{"name": "other", "protocolMapper": "x", "config": {}}, renamed]) == []


def test_client_without_the_link_is_a_problem_that_names_the_client() -> None:
    problems = _problems(defaults={AGENT_NAME: {SCOPE_ID}, TOOL_NAME: {PROFILE_ID}})
    assert len(problems) == 1
    assert TOOL_NAME in problems[0] and uc1.SUBJECT_SCOPE in problems[0] and "default scope" in problems[0]
    assert AGENT_NAME not in problems[0]


def test_optional_only_link_counts_as_missing() -> None:
    """The mapper of an optional scope runs only when the token request names the scope, so an
    optional link leaves ``sub`` = the user ID: it is a problem, and the message says "optional"."""
    problems = _problems(
        defaults={AGENT_NAME: {PROFILE_ID}, TOOL_NAME: {SCOPE_ID}},
        optional={AGENT_NAME: {SCOPE_ID}, TOOL_NAME: set()},
    )
    assert len(problems) == 1
    assert AGENT_NAME in problems[0] and "optional" in problems[0]


def test_optional_only_link_without_the_optional_ids_is_still_a_problem() -> None:
    """The decision uses only the default links; the optional ids only sharpen the message."""
    problems = _problems(defaults={AGENT_NAME: {PROFILE_ID}, TOOL_NAME: {SCOPE_ID}})
    assert len(problems) == 1 and AGENT_NAME in problems[0]


def test_unregistered_client_is_a_problem_that_names_the_client() -> None:
    problems = _problems(defaults={AGENT_NAME: {SCOPE_ID}, TOOL_NAME: None})
    assert len(problems) == 1 and TOOL_NAME in problems[0] and "not registered" in problems[0]


@pytest.mark.parametrize("login", [{SCOPE_ID}, {PROFILE_ID, SCOPE_ID}], ids=["only", "with-others"])
def test_login_client_linking_the_scope_is_a_problem(login: set[str]) -> None:
    """``rossoctl`` keeps its own ``username-to-sub`` mapper; the scope too would be two mappers that
    write the same claim."""
    problems = _problems(login=login)
    assert len(problems) == 1
    assert uc1.KEYCLOAK_CLIENT_ID in problems[0] and uc1.SUBJECT_SCOPE in problems[0]


def test_every_problem_is_listed() -> None:
    problems = _problems(
        scope=_scope(**{"aiac.managed": "true"}),
        mappers=[],
        defaults={AGENT_NAME: set(), TOOL_NAME: None},
        login={SCOPE_ID},
    )
    assert len(problems) == 5


def test_login_subject_mapper_needs_only_the_mapping() -> None:
    """The login client's manual mapper (runbook Prerequisites) is checked only for its mapping."""
    runbook = {
        "name": "username-to-sub",
        "protocolMapper": "oidc-usermodel-property-mapper",
        "config": {"user.attribute": "username", "claim.name": "sub", "jsonType.label": "String"},
    }
    assert uc1.is_login_subject_mapper(runbook)
    assert not uc1.is_login_subject_mapper(_mapper(**{"claim.name": "preferred_username"}))
    assert uc1.is_subject_mapper(SUBJECT_MAPPER) and not uc1.is_subject_mapper(runbook)  # no access.token.claim


# ======================================================================================
# The live reader and require_subject_scope — over a MagicMock admin (no Keycloak)
# ======================================================================================


def _admin(
    *,
    scopes: list[dict] | None = None,
    defaults: dict[str, list[str]] | None = None,
    optionals: dict[str, list[str]] | None = None,
    clients: list[dict] | None = None,
) -> MagicMock:
    """A ``KeycloakAdmin`` stand-in for the correct state, with the given parts changed. The default and
    optional scopes are given as ``{client uuid: [scope id, ...]}``."""
    admin = MagicMock(name="KeycloakAdmin")
    admin.get_clients.return_value = (
        [
            {
                "id": AGENT_UUID,
                "name": AGENT_NAME,
                "clientId": AGENT_CLIENT_ID,
                "clientAuthenticatorType": uc1.CLIENT_SECRET_AUTHENTICATOR,
            },
            {"id": TOOL_UUID, "name": TOOL_NAME, "clientId": f"spiffe://x/sa/{scn.TOOL_WORKLOAD}"},
            {"id": LOGIN_UUID, "name": "rossoctl", "clientId": uc1.KEYCLOAK_CLIENT_ID},
        ]
        if clients is None
        else clients
    )
    admin.get_client_scopes.return_value = (
        [{"id": PROFILE_ID, "name": "profile"}, _scope()] if scopes is None else scopes
    )
    admin.get_mappers_from_client_scope.return_value = [SUBJECT_MAPPER]
    default_map = {AGENT_UUID: [SCOPE_ID, PROFILE_ID], TOOL_UUID: [SCOPE_ID], LOGIN_UUID: [PROFILE_ID]}
    default_map.update(defaults or {})
    optional_map = {AGENT_UUID: [], TOOL_UUID: [], LOGIN_UUID: []}
    optional_map.update(optionals or {})
    admin.get_client_default_client_scopes.side_effect = lambda uuid: [{"id": i} for i in default_map[uuid]]
    admin.get_client_optional_client_scopes.side_effect = lambda uuid: [{"id": i} for i in optional_map[uuid]]
    return admin


def test_live_reader_gives_no_problem_for_the_correct_state() -> None:
    admin = _admin()
    assert uc1.subject_scope_link_problems(admin, [scn.AGENT_WORKLOAD, scn.TOOL_WORKLOAD]) == []
    admin.get_mappers_from_client_scope.assert_called_with(SCOPE_ID)


def test_live_reader_is_read_only() -> None:
    """Only reads (``get_*``) and the realm switch — no admin write."""
    admin = _admin()
    uc1.subject_scope_link_problems(admin, [scn.AGENT_WORKLOAD, scn.TOOL_WORKLOAD])
    called = {name for name, _args, _kwargs in admin.method_calls}
    assert called and all(name.startswith("get_") or name == "change_current_realm" for name in called), called


def test_live_reader_sees_an_optional_only_link() -> None:
    admin = _admin(defaults={TOOL_UUID: []}, optionals={TOOL_UUID: [SCOPE_ID]})
    problems = uc1.subject_scope_link_problems(admin, scn.TOOL_WORKLOAD)
    assert len(problems) == 1 and TOOL_NAME in problems[0] and "optional" in problems[0]


def test_live_reader_sees_the_login_client_link() -> None:
    admin = _admin(optionals={LOGIN_UUID: [SCOPE_ID]})
    problems = uc1.subject_scope_link_problems(admin, scn.AGENT_WORKLOAD)
    assert len(problems) == 1 and uc1.KEYCLOAK_CLIENT_ID in problems[0]


def test_live_reader_sees_a_login_client_default_link() -> None:
    """A default link on ``rossoctl`` is the likeliest form of the forbidden link (two mappers that
    write ``sub``): the reader reads the login client's default scopes too, not only its optional ones."""
    admin = _admin(defaults={LOGIN_UUID: [PROFILE_ID, SCOPE_ID]})
    problems = uc1.subject_scope_link_problems(admin, scn.AGENT_WORKLOAD)
    assert len(problems) == 1 and uc1.KEYCLOAK_CLIENT_ID in problems[0]


def test_live_reader_sees_a_missing_scope() -> None:
    admin = _admin(scopes=[{"id": PROFILE_ID, "name": "profile"}])
    problems = uc1.subject_scope_link_problems(admin, scn.AGENT_WORKLOAD)
    assert len(problems) == 1 and "does not exist" in problems[0]
    admin.get_mappers_from_client_scope.assert_not_called()


def test_require_subject_scope_passes_for_the_correct_state() -> None:
    uc1.require_subject_scope(_admin(), scn.AGENT_WORKLOAD)
    uc1.require_subject_scope(_admin(), [scn.AGENT_WORKLOAD, scn.TOOL_WORKLOAD])


def test_require_subject_scope_raises_naming_the_workload_and_the_fix() -> None:
    """A missing link is AIAC's own fault, so it raises (never skips), names the workload's client, and
    points at D31 and the likely cause: the workload converged, so Provision ran without the link — a
    stale aiac-agent image (a failed link would have failed Provision before this check)."""
    admin = _admin(defaults={TOOL_UUID: [PROFILE_ID]})
    with pytest.raises(RuntimeError) as info:
        uc1.require_subject_scope(admin, scn.TOOL_WORKLOAD)
    message = str(info.value)
    assert TOOL_NAME in message and uc1.SUBJECT_SCOPE in message
    assert "D31" in message and "aiac-agent" in message and "link_subject_scope" in message
    assert "/subject-scope" in message


def test_require_subject_scope_raises_for_an_unregistered_client() -> None:
    admin = _admin(clients=[{"id": LOGIN_UUID, "name": "rossoctl", "clientId": uc1.KEYCLOAK_CLIENT_ID}])
    with pytest.raises(RuntimeError, match="not registered"):
        uc1.require_subject_scope(admin, scn.AGENT_WORKLOAD)


# ======================================================================================
# launcher.exchange_token — the RFC 8693 request and the client-authentication classification
# ======================================================================================


class _Response:
    """A ``requests.Response`` stand-in: ``status_code``, ``text`` and ``json()``."""

    def __init__(self, status: int, body: object) -> None:
        self.status_code = status
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self) -> object:
        return json.loads(self.text)


def _stub_post(monkeypatch: pytest.MonkeyPatch, response: _Response) -> list[dict]:
    """Replace ``requests.post`` in the launcher; return the list of the calls (url + kwargs)."""
    calls: list[dict] = []

    def fake(url: str, **kwargs: object) -> _Response:
        calls.append({"url": url, **kwargs})
        return response

    monkeypatch.setattr(launcher.requests, "post", fake)
    return calls


def _exchange() -> str:
    return launcher.exchange_token(
        "subject-jwt",
        keycloak_url="http://kc.example:8080/",
        realm="rossoctl",
        client_id=AGENT_CLIENT_ID,
        client_secret="s3cret",
        audience="spiffe://x/ns/team1/sa/github-tool",
        scope="openid agent-team1-github-tool-aud",
    )


def test_exchange_token_sends_the_rfc8693_request(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _stub_post(monkeypatch, _Response(200, {"access_token": "exchanged-jwt"}))
    assert _exchange() == "exchanged-jwt"
    assert len(calls) == 1
    assert calls[0]["url"] == "http://kc.example:8080/realms/rossoctl/protocol/openid-connect/token"
    assert calls[0]["data"] == {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": "subject-jwt",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "audience": "spiffe://x/ns/team1/sa/github-tool",
        "scope": "openid agent-team1-github-tool-aud",
        "client_id": AGENT_CLIENT_ID,
        "client_secret": "s3cret",
    }


@pytest.mark.parametrize(
    ("status", "body", "refused"),
    [
        (401, {"error": "invalid_client", "error_description": "Invalid client credentials"}, True),
        (400, {"error": "invalid_client"}, True),
        (400, {"error": "unauthorized_client"}, True),
        (400, {"error": "invalid_scope"}, False),
        (400, {"error": "invalid_request", "error_description": "Requested audience not available"}, False),
        (403, {"error": "access_denied"}, False),
        (500, {"error": "invalid_client"}, False),
        (502, "<html>bad gateway</html>", False),
    ],
)
def test_exchange_token_failure_tells_a_refused_client_authentication(
    monkeypatch: pytest.MonkeyPatch, status: int, body: object, refused: bool
) -> None:
    _stub_post(monkeypatch, _Response(status, body))
    with pytest.raises(launcher.TokenExchangeError) as info:
        _exchange()
    assert info.value.status == status
    assert info.value.client_auth_refused is refused
    assert f"HTTP {status}" in str(info.value)  # the status and the body are in the message


def test_exchange_token_error_is_a_runtime_error() -> None:
    assert issubclass(launcher.TokenExchangeError, RuntimeError)


# ======================================================================================
# uc1_onboard.exchanged_subject — skip only for a client that does not use its secret, raise otherwise
# ======================================================================================


def _jwt(claims: dict) -> str:
    """An unsigned JWT with ``claims`` (``jwt_claim`` does not check the signature)."""
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"e30.{payload}.sig"


def _ctx(admin: MagicMock) -> dict:
    return {"admin": admin, "keycloak_url": "http://kc.example:8080", "realm": "rossoctl"}


def _stub_exchange(monkeypatch: pytest.MonkeyPatch, result: str | Exception) -> list[dict]:
    """Stub the login mint and the exchange in the harness; return the exchange calls."""
    calls: list[dict] = []
    monkeypatch.setattr(uc1, "mint_token", lambda *args, **kwargs: "login-jwt")

    def fake(subject_token: str, **kwargs: object) -> str:
        calls.append({"subject_token": subject_token, **kwargs})
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(uc1, "exchange_token", fake)
    return calls


def _secret_admin(secret: object = "s3cret") -> MagicMock:
    admin = _admin()
    if isinstance(secret, Exception):
        admin.get_client_secrets.side_effect = secret
    else:
        admin.get_client_secrets.return_value = {"type": "secret", "value": secret}
    return admin


def test_exchanged_subject_exchanges_as_the_agent_to_the_tool_audience(monkeypatch: pytest.MonkeyPatch) -> None:
    """The request of AuthBridge's route: the agent client, the tool's SPIFFE audience, and
    ``openid`` + the tool's audience scope; the result is the exchanged token's ``sub``."""
    calls = _stub_exchange(monkeypatch, _jwt({"sub": "dev-user"}))
    admin = _secret_admin()
    assert uc1.exchanged_subject(_ctx(admin), "dev-user") == "dev-user"
    admin.get_client_secrets.assert_called_once_with(AGENT_UUID)
    assert calls == [
        {
            "subject_token": "login-jwt",
            "keycloak_url": "http://kc.example:8080",
            "realm": "rossoctl",
            "client_id": AGENT_CLIENT_ID,
            "client_secret": "s3cret",
            "audience": uc1._tool_audience(),
            "scope": f"openid {uc1._tool_aud_scope()}",
        }
    ]


def test_exchanged_subject_gives_the_user_id_when_the_link_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The probe reports the ``sub`` as it is; the rung-2 test compares it with the username."""
    _stub_exchange(monkeypatch, _jwt({"sub": "2a4e729b-0000-4000-8000-000000000000"}))
    assert uc1.exchanged_subject(_ctx(_secret_admin()), "dev-user") == "2a4e729b-0000-4000-8000-000000000000"


@pytest.mark.parametrize(
    "refusal",
    [
        launcher.TokenExchangeError(401, '{"error":"invalid_client"}', "invalid_client"),
        launcher.TokenExchangeError(400, '{"error":"unauthorized_client"}', "unauthorized_client"),
    ],
    ids=["invalid_client", "unauthorized_client"],
)
def test_exchanged_subject_fails_on_a_refused_client_secret_authentication(
    monkeypatch: pytest.MonkeyPatch, refusal: launcher.TokenExchangeError
) -> None:
    """The agent client uses the ``client-secret`` authenticator (``k8s/opa-kind-enable.sh`` sets the
    AuthBridge ``token-exchange`` identity to ``client-secret``), so a refused secret is a real fault:
    a failure, never a skip that hides it."""
    _stub_exchange(monkeypatch, refusal)
    with pytest.raises(AssertionError, match="refused the client-secret authentication"):
        uc1.exchanged_subject(_ctx(_secret_admin()), "dev-user")


@pytest.mark.parametrize("authenticator", ["federated-jwt", "client-jwt", None])
def test_exchanged_subject_skips_for_another_client_authenticator(
    monkeypatch: pytest.MonkeyPatch, authenticator: str | None
) -> None:
    """A client that does not authenticate with its secret (for example a SPIFFE JWT-SVID through
    ``federated-jwt``) cannot be used by the harness: a clean skip, and no exchange is sent."""
    calls = _stub_exchange(monkeypatch, _jwt({"sub": "dev-user"}))
    admin = _secret_admin()
    for client in admin.get_clients.return_value:
        if client["id"] == AGENT_UUID:
            client["clientAuthenticatorType"] = authenticator
    with pytest.raises(pytest.skip.Exception, match="client authenticator"):
        uc1.exchanged_subject(_ctx(admin), "dev-user")
    assert calls == []
    admin.get_client_secrets.assert_not_called()


@pytest.mark.parametrize(
    "secret",
    [None, "", KeycloakError(error_message="unknown_error", response_code=400)],
    ids=["no-value", "empty", "unreadable"],
)
def test_exchanged_subject_skips_without_a_readable_secret(monkeypatch: pytest.MonkeyPatch, secret: object) -> None:
    calls = _stub_exchange(monkeypatch, _jwt({"sub": "dev-user"}))
    with pytest.raises(pytest.skip.Exception, match="client secret"):
        uc1.exchanged_subject(_ctx(_secret_admin(secret)), "dev-user")
    assert calls == []  # no exchange without a secret


def test_exchanged_subject_raises_on_any_other_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exchange failure that is not a refused client authentication (for example the tool's
    audience scope not linked to the agent) is a real failure: it raises with the HTTP status."""
    _stub_exchange(monkeypatch, launcher.TokenExchangeError(400, '{"error":"invalid_scope"}', "invalid_scope"))
    with pytest.raises(launcher.TokenExchangeError, match="HTTP 400"):
        uc1.exchanged_subject(_ctx(_secret_admin()), "dev-user")


def test_exchanged_subject_raises_without_a_sub(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_exchange(monkeypatch, _jwt({"azp": AGENT_CLIENT_ID}))
    with pytest.raises(AssertionError, match="no string 'sub'"):
        uc1.exchanged_subject(_ctx(_secret_admin()), "dev-user")


def test_exchanged_subject_raises_without_the_agent_client(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_exchange(monkeypatch, _jwt({"sub": "dev-user"}))
    admin = _admin(clients=[])
    with pytest.raises(AssertionError, match=scn.AGENT_WORKLOAD):
        uc1.exchanged_subject(_ctx(admin), "dev-user")
