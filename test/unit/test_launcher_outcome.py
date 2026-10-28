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
        ({"error": "policy.forbidden"}, True),  # no plugin named: the OPA error code alone
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


# ``authbridge-runtime-config`` as ``k8s/opa-kind-enable.sh`` renders it.
_CONFIG = """pipeline:
  inbound:
    plugins:
      - name: jwt-validation
      - name: opa
  outbound:
    plugins:
      - name: mcp-parser
      - name: token-exchange-aiac
        config:
          namespace_file: /var/run/secrets/kubernetes.io/serviceaccount/namespace
      - name: opa
"""


def _legs(config: str) -> dict:
    return launcher.pipeline_plugins(config)


def test_pipeline_plugins_reads_each_leg() -> None:
    assert _legs(_CONFIG) == {
        "inbound": ["jwt-validation", "opa"],
        "outbound": ["mcp-parser", "token-exchange-aiac", "opa"],
    }


@pytest.mark.parametrize("config", ["", "not: [yaml", "pipeline: 3"])
def test_pipeline_plugins_of_a_bad_config_is_empty(config: str) -> None:
    assert _legs(config) == {"inbound": [], "outbound": []}


_PASSING = [
    _CONFIG,
    _CONFIG.replace("name: token-exchange-aiac", 'name: "token-exchange-aiac"'),
    _CONFIG + "# - name: token-exchange\n",  # a comment is not a plugin
]


@pytest.mark.parametrize("config", _PASSING)
def test_exchange_plugin_reason_passes_one_aiac_exchange_outbound(config: str) -> None:
    assert launcher.exchange_plugin_reason(_legs(config), namespace="team1") is None


_SKIPPING = [
    _CONFIG.replace("name: token-exchange-aiac", "name: token-exchange"),  # an older pipeline
    _CONFIG.replace("      - name: opa\n", "      - name: token-exchange\n      - name: opa\n", 2).replace(
        "      - name: token-exchange\n      - name: opa\n", "      - name: opa\n", 1
    ),  # half migrated
    _CONFIG.replace("- name: token-exchange-aiac", "- name: token-exchange-aiac\n      - name: token-exchange-aiac"),
    # only on the inbound leg, where it exchanges nothing the harness sends
    _CONFIG.replace(
        "      - name: token-exchange-aiac\n        config:\n"
        "          namespace_file: /var/run/secrets/kubernetes.io/serviceaccount/namespace\n",
        "",
    ).replace("      - name: jwt-validation\n", "      - name: jwt-validation\n      - name: token-exchange-aiac\n"),
    "",
]


@pytest.mark.parametrize("config", _SKIPPING)
def test_exchange_plugin_reason_skips_any_other_exchange_wiring(config: str) -> None:
    reason = launcher.exchange_plugin_reason(_legs(config), namespace="team1")
    assert reason is not None and "k8s/opa-kind-enable.sh" in reason


_VERIFY_HELPER = REPO_ROOT / "k8s" / "outbound-exchange-plugins.py"


@pytest.mark.parametrize("config", _PASSING + _SKIPPING)
def test_verify_helper_agrees_with_the_harness_gate(config: str) -> None:
    """``k8s/opa-kind-verify.sh`` (via ``outbound-exchange-plugins.py``) and the system lane's skip gate
    give one verdict on every config."""
    run = subprocess.run(
        [sys.executable, "-I", str(_VERIFY_HELPER)], input=config, capture_output=True, text=True, check=False
    )
    verify_passes = run.stdout.strip() == "token-exchange-aiac=1 token-exchange=0"
    assert verify_passes is (launcher.exchange_plugin_reason(_legs(config), namespace="team1") is None)


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
    msg = launcher.TARGET_DISABLED_MESSAGE
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
        (403, json.dumps({**OPA_DENY, "message": launcher.TARGET_DISABLED_MESSAGE}), False),
        (None, "", False),
    ],
)
def test_target_disabled_refusal_is_only_a_disabled_target(code: int | None, body: str, expected: bool) -> None:
    assert launcher.target_disabled_refusal(code, body) is expected


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        (
            _CONFIG.replace(
                "        config:\n",
                '        config:\n          audience_template: "spiffe://example.org/ns/{namespace}/sa/{service}"\n',
            ),
            "example.org",
        ),
        (_CONFIG, None),  # no audience_template
        (_CONFIG.replace("        config:\n", '        config:\n          audience_template: "{service}"\n'), None),
        (
            _CONFIG.replace("        config:\n          namespace_file", "        config: x\n          namespace_file"),
            None,
        ),
        ("pipeline:\n  outbound:\n    plugins:\n      - name: token-exchange-aiac\n        config: [1]\n", None),
        ("not: [yaml", None),
        ("", None),
    ],
)
def test_exchange_trust_domain_reads_the_outbound_template(config: str, expected: str | None) -> None:
    assert launcher.exchange_trust_domain(config) == expected


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
