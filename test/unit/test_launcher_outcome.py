"""How the UC-1 system-test harness classifies a live response — pure unit tests.

An outbound refusal by the exchange plugin (``discovery-exchange``) means the request never reached
OPA. ``discovery-exchange`` answers a target not granted to the caller with ``policy.forbidden``, the
same error code OPA uses, so the classifier must go by the named ``plugin`` and never report that
refusal as an OPA ``deny`` (a false pass for a deny expectation).

The module under test is test infra (``test/system/launcher.py``), so the file sits at the
``test/unit/`` root, like ``test_launcher_combiner.py``. The harness does no cluster I/O at import time.
"""

from __future__ import annotations

import json
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
NOT_GRANTED = {"error": "policy.forbidden", "plugin": "discovery-exchange"}
EXCHANGE_FAILED = {"error": "upstream.token-exchange-failed", "plugin": "discovery-exchange"}
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
        ({"plugin": ["discovery-exchange"]}, False),  # an unhashable plugin value does not raise
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
    ],
)
def test_outbound_outcome_never_reports_an_exchange_refusal_as_an_opa_deny(code: int, body: str, expected: str) -> None:
    assert launcher.outbound_outcome(code, body) == expected


def test_deny_origin_ignores_an_exchange_refusal() -> None:
    assert launcher.deny_origin(200, _frame(NOT_GRANTED)) is None
    assert launcher.deny_origin(403, json.dumps(NOT_GRANTED)) is None
    assert launcher.deny_origin(200, _frame(OPA_DENY)) == launcher.DENY_ORIGIN_AGENT_OUTBOUND


# The outbound leg of ``authbridge-runtime-config`` as ``k8s/opa-kind-enable.sh`` renders it.
_DX_LEG = "  outbound:\n    plugins:\n      - name: mcp-parser\n      - name: discovery-exchange\n      - name: opa\n"
_TX_LEG = _DX_LEG.replace("discovery-exchange", "token-exchange")


@pytest.mark.parametrize(
    "config",
    [_DX_LEG, _DX_LEG.replace("name: discovery-exchange", 'name: "discovery-exchange"')],
)
def test_exchange_plugin_reason_passes_one_discovery_exchange(config: str) -> None:
    assert launcher.exchange_plugin_reason(config, namespace="team1") is None


@pytest.mark.parametrize(
    "config",
    [
        _TX_LEG,  # an older pipeline
        _DX_LEG + "      - name: token-exchange\n",  # half migrated
        _DX_LEG + "      - name: discovery-exchange\n",  # twice
        "",
    ],
)
def test_exchange_plugin_reason_skips_any_other_exchange_wiring(config: str) -> None:
    reason = launcher.exchange_plugin_reason(config, namespace="team1")
    assert reason is not None and "k8s/opa-kind-enable.sh" in reason
