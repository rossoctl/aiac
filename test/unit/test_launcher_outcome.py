"""How the UC-1 system-test harness classifies a live response — pure unit tests.

An outbound refusal by the exchange plugin (``token-exchange-aiac``) means the request never reached
OPA. ``token-exchange-aiac`` answers a target not granted to the caller with ``policy.forbidden``, the
same error code OPA uses, so the classifier must go by the named ``plugin`` and never report that
refusal as an OPA ``deny`` (a false pass for a deny expectation).

The module under test is test infra (``test/system/launcher.py``), so the file sits at the
``test/unit/`` root, like ``test_launcher_combiner.py``. The harness does no cluster I/O at import time.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]  # -> aiac/
if str(REPO_ROOT) not in sys.path:  # so ``import test.system.*`` resolves
    sys.path.insert(0, str(REPO_ROOT))

from test.system import launcher  # noqa: E402
from test.unit.pipeline_configs import CONFIG as _CONFIG  # noqa: E402
from test.unit.pipeline_configs import PASSING as _PASSING  # noqa: E402
from test.unit.pipeline_configs import SKIPPING as _SKIPPING  # noqa: E402
from test.unit.pipeline_configs import TEMPLATE as _TEMPLATE  # noqa: E402


def _frame(data: dict) -> str:
    """A JSON-RPC error frame, as the forward proxy renders a rejected MCP request (HTTP 200)."""
    return json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "x", "data": data}})


OPA_DENY = {"error": "policy.forbidden", "plugin": "opa"}
NOT_GRANTED = {"error": "policy.forbidden", "plugin": "token-exchange-aiac"}
EXCHANGE_FAILED = {"error": "upstream.token-exchange-failed", "plugin": "token-exchange-aiac"}
LEGACY_EXCHANGE_FAILED = {"error": "upstream.token-exchange-failed", "plugin": "token-exchange"}


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        (OPA_DENY, True),
        # no plugin named: not AuthBridge's OPA (cortex stamps the plugin on every rejection)
        ({"error": "policy.forbidden"}, False),
        ({"error": "upstream.unreachable", "plugin": "opa"}, False),  # OPA with no bundle: no verdict
        ({"plugin": "opa"}, False),
        (NOT_GRANTED, False),
        (EXCHANGE_FAILED, False),
        ({"plugin": "jwt-validation", "error": "policy.forbidden"}, False),
        (None, False),
    ],
)
def test_is_opa_violation_goes_by_the_named_plugin(doc: object, expected: bool) -> None:
    assert launcher.is_opa_violation(doc) is expected


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        (NOT_GRANTED, True),
        (EXCHANGE_FAILED, True),
        (LEGACY_EXCHANGE_FAILED, True),
        ({"error": "upstream.token-exchange-failed"}, True),
        (OPA_DENY, False),
        ("not a dict", False),
        ({"plugin": ["token-exchange-aiac"]}, False),  # an unhashable plugin value does not raise
        ({"plugin": {"name": "x"}}, False),
    ],
)
def test_is_exchange_refusal(doc: object, expected: bool) -> None:
    assert launcher.is_exchange_refusal(doc) is expected


@pytest.mark.parametrize(
    ("code", "body", "expected"),
    [
        (200, _frame(OPA_DENY), "deny"),
        (403, json.dumps(OPA_DENY), "deny"),
        (200, _frame(NOT_GRANTED), "error"),
        (403, json.dumps(NOT_GRANTED), "error"),
        (200, _frame(EXCHANGE_FAILED), "error"),
        (200, _frame(LEGACY_EXCHANGE_FAILED), "error"),
        (503, json.dumps(EXCHANGE_FAILED), "error"),
        (200, json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}), "allow"),
        # AuthBridge's minimal and constant fallback frames name no plugin: rejected, never an allow.
        (200, json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "x"}}), "error"),
        (200, '{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"request rejected"}}', "error"),
        # The full frame of a reject with no violation data: ``data`` is present, but null.
        (
            200,
            json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "x", "data": None}}),
            "error",
        ),
        # A JSON-RPC error of the tool itself (another code) means the call got through.
        (200, json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "bad"}}), "allow"),
        # A 403 that names no OPA (a mesh RBAC deny, another plugin) is no OPA verdict.
        (403, "RBAC: access denied", "error"),
        (403, json.dumps({"error": "auth.forbidden", "plugin": "jwt-validation"}), "error"),
        (401, json.dumps({"error": "auth.unauthorized", "plugin": "jwt-validation"}), "error"),
        # A frame from another AuthBridge plugin is a rejection, but neither an OPA verdict nor an allow.
        (200, _frame({"error": "auth.unauthorized", "plugin": "jwt-validation"}), "error"),
        # AuthBridge's code with data that names no plugin, or empty data: rejected, never an allow.
        (200, _frame({"error": "auth.unauthorized"}), "error"),
        (200, _frame({}), "error"),
        # OPA with no bundle yet answers, but decides nothing: not a deny.
        (
            200,
            _frame({"error": "upstream.unreachable", "plugin": "opa", "message": "opa policy engine not initialized"}),
            "error",
        ),
        (503, json.dumps({"error": "upstream.unreachable", "plugin": "opa"}), "error"),
        (403, json.dumps({"error": "upstream.unreachable", "plugin": "opa"}), "error"),
    ],
)
def test_outbound_outcome_never_reports_an_exchange_refusal_as_an_opa_deny(code: int, body: str, expected: str) -> None:
    assert launcher.outbound_outcome(code, body) == expected


def test_deny_origin_ignores_an_exchange_refusal() -> None:
    assert launcher.deny_origin(200, _frame(NOT_GRANTED)) is None
    assert launcher.deny_origin(403, json.dumps(NOT_GRANTED)) is None
    assert launcher.deny_origin(200, _frame(OPA_DENY)) == launcher.DENY_ORIGIN_AGENT_OUTBOUND
    assert launcher.deny_origin(403, json.dumps(OPA_DENY)) == launcher.DENY_ORIGIN_TOOL_INBOUND
    # A 403 that carries a JSON-RPC frame is neither shape.
    assert launcher.deny_origin(403, _frame(OPA_DENY)) is None


@pytest.mark.parametrize(
    ("code", "body", "expected"),
    [
        (200, _frame(OPA_DENY), OPA_DENY),
        (403, json.dumps(NOT_GRANTED), NOT_GRANTED),
        (403, _frame(OPA_DENY), None),  # a frame is rendered only at HTTP 200
        (200, json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}), None),
        (200, json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000}}), None),
        (503, json.dumps(EXCHANGE_FAILED), None),
        (403, "not json", None),
        (None, "", None),
    ],
)
def test_rejection_doc_unwraps_both_rejection_shapes(code: int | None, body: str, expected: dict | None) -> None:
    assert launcher.rejection_doc(code, body) == expected


def _reason(config: str) -> str | None:
    return launcher.pipeline_check(config, namespace="team1")[0]


@pytest.mark.parametrize("config", ["", "not: [yaml", "- a list", "just text"])
def test_pipeline_check_names_a_config_that_is_not_yaml(config: str) -> None:
    """A config that does not parse (a truncated ConfigMap, or stderr mixed into it) is reported as such,
    not as a missing ``opa``, which would point at the wrong fix."""
    reason = _reason(config)
    assert reason is not None and "not a YAML mapping" in reason


@pytest.mark.parametrize("config", _PASSING)
def test_pipeline_check_passes_the_enabled_wiring(config: str) -> None:
    if config is not _PASSING[0]:
        assert config != _CONFIG, "this case's replace no longer matches the fixture: it tests nothing"
    assert launcher.pipeline_check(config, namespace="team1") == (None, "localtest.me")


@pytest.mark.parametrize("config", _SKIPPING)
def test_pipeline_check_skips_any_other_wiring(config: str) -> None:
    assert config != _CONFIG, "this case's replace no longer matches the fixture: it tests nothing"
    reason, trust_domain = launcher.pipeline_check(config, namespace="team1")
    assert reason is not None and "k8s/opa-kind-enable.sh" in reason
    assert trust_domain is None  # a skipped run never gets a trust domain to exchange for


@pytest.mark.parametrize(
    ("code", "body", "expected"),
    [
        (200, _frame(NOT_GRANTED), True),
        (403, json.dumps(NOT_GRANTED), True),
        # A failed exchange proves nothing about the caller's grants: not a refusal.
        (200, _frame(EXCHANGE_FAILED), False),
        (503, json.dumps(EXCHANGE_FAILED), False),
        (200, _frame(OPA_DENY), False),
        (403, json.dumps(OPA_DENY), False),
        (None, "outbound probe exec failed", False),
        (403, "not json", False),
    ],
)
def test_exchange_refusal_is_only_keycloak_not_granting(code: int | None, body: str, expected: bool) -> None:
    assert launcher.exchange_refusal(code, body) is expected


def _disabled(code: int) -> str:
    """``token-exchange-aiac``'s refusal of a disabled target, as cortex renders it at ``code``."""
    msg = launcher.target_disabled_message()
    if code == 200:
        return json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": msg, "data": NOT_GRANTED}})
    return json.dumps({**NOT_GRANTED, "message": msg})


def _not_granted(code: int) -> str:
    """The same refusal for a target not granted to the caller."""
    msg = "this workload is not granted the destination's audience"
    if code == 200:
        return json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": msg, "data": NOT_GRANTED}})
    return json.dumps({**NOT_GRANTED, "message": msg})


@pytest.mark.parametrize(
    ("code", "body", "expected"),
    [
        (200, _disabled(200), True),
        (403, _disabled(403), True),
        # Not granted (for example a lost default-scope link) proves nothing about the target's client.
        (200, _not_granted(200), False),
        (403, _not_granted(403), False),
        (200, _frame(EXCHANGE_FAILED), False),
        (403, json.dumps({**OPA_DENY, "message": launcher.target_disabled_message()}), False),
        (None, "", False),
    ],
)
def test_target_disabled_refusal_is_only_a_disabled_target(code: int | None, body: str, expected: bool) -> None:
    assert launcher.target_disabled_refusal(code, body) is expected


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        (_CONFIG.replace(_TEMPLATE, '"spiffe://example.org/ns/{namespace}/sa/{service}"'), "example.org"),
        (_CONFIG.replace(f"          audience_template: {_TEMPLATE}\n", ""), None),  # no audience_template
        (_CONFIG.replace(_TEMPLATE, '"{service}"'), None),
        (_CONFIG.replace(_TEMPLATE, '"spiffe:///ns/{namespace}/sa/{service}"'), None),  # an empty trust domain
        (
            _CONFIG.replace(f"        config:\n          audience_template: {_TEMPLATE}\n", "        config: [1]\n"),
            None,
        ),
    ],
)
def test_pipeline_check_gives_the_trust_domain_of_the_outbound_template(config: str, expected: str | None) -> None:
    """The harness exchanges for the trust domain of the live template; with none the run skips."""
    reason, trust_domain = launcher.pipeline_check(config, namespace="team1")
    assert trust_domain == expected
    assert (reason is None) is (expected is not None)


@pytest.mark.parametrize(
    ("code", "body", "expected"),
    [
        (202, "", "allow"),
        (200, "", "allow"),
        (403, json.dumps(OPA_DENY), "deny"),
        # An exchange refusal of a notification is not an OPA verdict.
        (403, json.dumps(NOT_GRANTED), "error"),
        (403, "", "error"),
        (503, json.dumps(EXCHANGE_FAILED), "error"),
        (None, "", "error"),
    ],
)
def test_notification_outcome_counts_only_an_opa_403_as_deny(code: int | None, body: str, expected: str) -> None:
    assert launcher.notification_outcome(code, body) == expected


def _stub_cluster(monkeypatch: pytest.MonkeyPatch, *, config: tuple[bool, str, str]) -> None:
    """A wired cluster for ``pipeline_unwired_reason``, except the ``authbridge-runtime-config`` read,
    which answers ``config`` (``(ok, stdout, stderr)``)."""
    monkeypatch.setattr(launcher.shutil, "which", lambda _: "/usr/bin/kubectl")
    monkeypatch.setattr(launcher, "combiner_reason", lambda *_, **__: None)

    def kubectl_try(*args, **_):
        if "configmap" in args:
            return config
        if "authorizationpolicy" in args:
            return True, "{}", ""
        return True, "Running", ""

    monkeypatch.setattr(launcher, "_kubectl_try", kubectl_try)


def test_pipeline_unwired_reason_gives_the_trust_domain_of_the_config_it_approved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The harness exchanges for the trust domain of the one config read the gate approved."""
    _stub_cluster(monkeypatch, config=(True, _CONFIG.replace("localtest.me", "example.org"), ""))
    assert launcher.pipeline_unwired_reason(namespace="team1", workloads=[]) == (None, "example.org")


@pytest.mark.parametrize(
    ("config", "reason"),
    [
        ((False, "", "connection refused"), "authbridge-runtime-config not found"),
        ((True, _CONFIG.replace(_TEMPLATE, '"{service}"'), ""), "audience_template"),
    ],
)
def test_pipeline_unwired_reason_skips_without_a_trust_domain(
    monkeypatch: pytest.MonkeyPatch, config: tuple[bool, str, str], reason: str
) -> None:
    """A config that cannot be read, or names no trust domain, skips before any cluster change."""
    _stub_cluster(monkeypatch, config=config)
    got, trust_domain = launcher.pipeline_unwired_reason(namespace="team1", workloads=[])
    assert got is not None and reason in got
    assert trust_domain is None


@pytest.mark.parametrize(
    ("code", "body", "expected"),
    [
        (403, json.dumps(NOT_GRANTED), NOT_GRANTED),
        (200, _frame(NOT_GRANTED), NOT_GRANTED),
        # A non-MCP exchange 503 carries a plain body, which ``rejection_doc`` does not read.
        (503, json.dumps(EXCHANGE_FAILED), EXCHANGE_FAILED),
        (403, json.dumps(OPA_DENY), None),
        (200, _frame(OPA_DENY), None),
        (503, "upstream connect error", None),
        # A refused subject token: token-exchange-aiac's plain 401.
        (
            401,
            json.dumps({"error": "auth.unauthorized", "plugin": "token-exchange-aiac"}),
            {
                "error": "auth.unauthorized",
                "plugin": "token-exchange-aiac",
            },
        ),
        (401, json.dumps({"error": "auth.unauthorized", "plugin": "jwt-validation"}), None),
        (None, "", None),
    ],
)
def test_classify_names_only_the_exchange(code: int | None, body: str, expected: dict | None) -> None:
    """The demo probe gives a refusal or failure of the exchange its own verdict, never a deny, and its
    outcome is the harness's ``outbound_outcome`` for the same answer."""
    outcome, exchange_doc = launcher._rejection().classify(code, body)
    assert exchange_doc == expected
    assert outcome == launcher.outbound_outcome(code, body)
    if exchange_doc is not None:
        assert outcome == "error"


def test_pipeline_check_skips_when_the_shared_rule_is_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A checkout without ``k8s/authbridge-pipeline-check.py`` skips with the file named; it never crashes."""
    monkeypatch.setattr(launcher, "K8S_DIR", tmp_path)
    monkeypatch.delitem(sys.modules, "_aiac_k8s_authbridge_pipeline_check", raising=False)
    reason, trust_domain = launcher.pipeline_check(_CONFIG, namespace="team1")
    assert reason is not None and "authbridge-pipeline-check.py is missing" in reason
    assert trust_domain is None


def test_pipeline_check_skips_without_pyyaml(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no PyYAML the gate skips, naming it; it never crashes ``require_pipeline``."""
    monkeypatch.setitem(sys.modules, "yaml", None)  # ``import yaml`` then raises ImportError
    reason, trust_domain = launcher.pipeline_check(_CONFIG, namespace="team1")
    assert reason is not None and "yaml" in reason
    assert trust_domain is None


def test_a_broken_shared_file_is_an_import_error_naming_it(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A shared ``k8s/`` file that does not load (a syntax error) skips the gate with its name, as a
    missing one does; the gate catches ``ImportError`` only."""
    (tmp_path / "authbridge-pipeline-check.py").write_text("def broken(:\n")
    monkeypatch.setattr(launcher, "K8S_DIR", tmp_path)
    monkeypatch.delitem(sys.modules, "_aiac_k8s_authbridge_pipeline_check", raising=False)
    reason, trust_domain = launcher.pipeline_check(_CONFIG, namespace="team1")
    assert reason is not None and "authbridge-pipeline-check.py does not load: SyntaxError" in reason
    assert trust_domain is None


def test_importing_the_launcher_does_not_need_k8s(tmp_path: Path) -> None:
    """The launcher loads ``k8s/authbridge-rejection.py`` only when an outbound classifier is used, so
    a ``test/`` without ``k8s/`` still imports (the eval suites need only its skip gates)."""
    copy = tmp_path / "repo"
    (copy / "test" / "system").mkdir(parents=True)
    (copy / "test" / "__init__.py").write_text("")
    (copy / "test" / "system" / "__init__.py").write_text("")
    (copy / "test" / "system" / "launcher.py").write_text((REPO_ROOT / "test" / "system" / "launcher.py").read_text())
    # Importing the classifier names (as uc1_onboard does) binds wrappers and loads nothing; only a call
    # needs the file, and then fails naming it.
    script = (
        "from test.system.launcher import require_env_or_skip, outbound_outcome, target_disabled_refusal\n"
        "print(require_env_or_skip.__name__)\n"
        "try:\n"
        "    outbound_outcome(403, '{}')\n"
        "except ImportError as exc:\n"
        "    print('call:', 'authbridge-rejection.py is missing' in str(exc))\n"
    )
    run = subprocess.run([sys.executable, "-c", script], cwd=copy, capture_output=True, text=True, check=True)
    assert run.stdout.split() == ["require_env_or_skip", "call:", "True"]


@pytest.mark.parametrize(
    ("code", "body", "expected"),
    [
        (403, json.dumps(NOT_GRANTED), "EXCHANGE_REFUSED 403 policy.forbidden"),
        (
            200,
            _frame({"error": "auth.unauthorized", "plugin": "token-exchange-aiac"}),
            "EXCHANGE_REFUSED 200 auth.unauthorized",
        ),
        (503, json.dumps(EXCHANGE_FAILED), "EXCHANGE_REFUSED 503 upstream.token-exchange-failed"),
        (403, json.dumps(OPA_DENY), "DENIED_HTTP 403"),
        (200, _frame(OPA_DENY), "DENIED_JSONRPC"),
        (200, json.dumps({"jsonrpc": "2.0", "id": "1", "result": {}}), "ALLOWED_RESULT"),
        (403, "RBAC: access denied", "UNEXPECTED 403 - RBAC: access denied"),
        # the parsed error code comes first, so a long body cannot push it out of the verdict
        (
            200,
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "1",
                    "error": {
                        "code": -32000,
                        "data": {"description": "x" * 300, "error": "upstream.unreachable", "plugin": "opa"},
                    },
                }
            ),
            "UNEXPECTED 200 upstream.unreachable ",
        ),
    ],
)
def test_verdict_is_one_mapping_for_both_demo_probes(code: int, body: str, expected: str) -> None:
    """The demo driver's two probes print ``verdict``; a deny is an OPA verdict only, never a refusal."""
    got = launcher._rejection().verdict(code, body)
    assert got.startswith(expected) if expected.endswith(" ") else got == expected


def test_pipeline_check_skips_when_the_classifier_file_is_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The gate also loads ``k8s/authbridge-rejection.py``: without it the live suite skips up front, not
    in a convergence poll."""
    real = launcher.K8S_DIR
    (tmp_path / "authbridge-pipeline-check.py").write_text((real / "authbridge-pipeline-check.py").read_text())
    monkeypatch.setattr(launcher, "K8S_DIR", tmp_path)
    for key in ("_aiac_k8s_authbridge_pipeline_check", "_aiac_k8s_authbridge_rejection"):
        monkeypatch.delitem(sys.modules, key, raising=False)
    reason, trust_domain = launcher.pipeline_check(_CONFIG, namespace="team1")
    assert reason is not None and "authbridge-rejection.py is missing" in reason
    assert trust_domain is None


@pytest.mark.parametrize(
    ("template", "expected"),
    [
        ('"spiffe://localtest.me/ns/{namespace}/sa/{service}"', "localtest.me"),
        ('"spiffe://localtest.me/ns/team1/sa/github-tool"', None),  # one fixed audience for every call
    ],
)
def test_pipeline_check_needs_the_service_in_the_template(template: str, expected: str | None) -> None:
    config = _CONFIG.replace('"spiffe://localtest.me/ns/{namespace}/sa/{service}"', template)
    assert launcher.pipeline_check(config, namespace="team1")[1] == expected


def test_a_tool_error_with_data_is_still_an_allow() -> None:
    """A JSON-RPC error of the tool itself (FastMCP, its own code) may carry ``data`` with an ``error``:
    the call was let through. Only AuthBridge's code, or a ``data`` that names a plugin, is a rejection."""
    tool_error = {"jsonrpc": "2.0", "id": "1", "error": {"code": -32602, "message": "bad", "data": {"error": "x"}}}
    assert launcher.outbound_outcome(200, json.dumps(tool_error)) == "allow"
    plugin_code = {"jsonrpc": "2.0", "id": "1", "error": {"code": -32099, "data": {"plugin": "cpex", "error": "y"}}}
    assert launcher.outbound_outcome(200, json.dumps(plugin_code)) == "error"
    # The tool's own error whose data happens to say policy.forbidden is still the tool's, not OPA's.
    lookalike = {"jsonrpc": "2.0", "id": "1", "error": {"code": -32602, "data": {"error": "policy.forbidden"}}}
    assert launcher.outbound_outcome(200, json.dumps(lookalike)) == "allow"
    assert launcher.deny_origin(200, json.dumps(lookalike)) is None


def test_pipeline_check_names_a_missing_jwt_validation() -> None:
    """A leg without its identity plugin is reported as missing, not as a plugin-order problem."""
    config = _CONFIG.replace("      - name: jwt-validation\n      - name: opa\n", "      - name: opa\n")
    reason = _reason(config)
    assert reason is not None and "has no jwt-validation" in reason


def test_grant_exchange_scope_takes_a_409_as_an_existing_link(monkeypatch: pytest.MonkeyPatch) -> None:
    """The operator's realm default scope can link the tool's audience at the agent's creation (#248), so
    Keycloak may answer the default-link PUT with 409: that is an existing link, not a failure."""
    from unittest.mock import MagicMock

    from keycloak.exceptions import KeycloakError

    from test.system import uc1_onboard as uc1

    admin = MagicMock()
    agent_cid = f"spiffe://localtest.me/ns/{uc1.NAMESPACE}/sa/{uc1.scn.AGENT_WORKLOAD}"
    admin.get_clients.return_value = [{"id": "agent-uuid", "clientId": agent_cid}]
    admin.get_client_scopes.return_value = [{"id": "s1", "name": uc1.workload_aud_scope(uc1.scn.TOOL_WORKLOAD)}]
    admin.get_client_optional_client_scopes.return_value = []
    admin.add_client_default_client_scope.side_effect = KeycloakError("Conflict", response_code=409)
    uc1.grant_exchange_scope(admin)  # no raise

    admin.add_client_default_client_scope.side_effect = KeycloakError("Server error", response_code=500)
    with pytest.raises(RuntimeError, match="could not link"):
        uc1.grant_exchange_scope(admin)
