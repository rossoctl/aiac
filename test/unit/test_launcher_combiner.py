"""Unit coverage for ``launcher.combiner_reason`` — the **pure** skip gate of the global combiner (D20).

It uses the rules of the Controller's start check #4 (``aiac.agent.controller.start.combiner_problems``),
so the system tests skip on each combiner that the Controller refuses. The module under test is test
infra (``test/system/launcher.py``), so the file sits at the ``test/unit/`` root, like
``test_launcher_event_path.py``."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]  # -> aiac/
if str(REPO_ROOT) not in sys.path:  # so ``import test.system.*`` resolves
    sys.path.insert(0, str(REPO_ROOT))

from test.system.launcher import combiner_reason  # noqa: E402

_AIAC = {
    d: f"package authbridge.client.{d}.request\ndefault client_ok := false\nclient_ok if data.authbridge.client.{d}.request.allow\n"
    for d in ("inbound", "outbound")
}


def _cr(*entries: tuple[str, str]) -> dict:
    return {"spec": {"policies": [{"path": path, "content": content} for path, content in entries]}}


def _aiac_cr(*extra: tuple[str, str]) -> dict:
    return _cr(("inbound/request.rego", _AIAC["inbound"]), ("outbound/request.rego", _AIAC["outbound"]), *extra)


def test_the_aiac_combiner_returns_none():
    assert combiner_reason(_aiac_cr()) is None


def test_a_missing_cr_is_a_reason():
    assert "missing" in combiner_reason(None)


def test_a_missing_package_is_a_reason():
    assert "outbound/request.rego is missing" in combiner_reason(_cr(("inbound/request.rego", _AIAC["inbound"])))


def test_the_stock_fallback_line_is_a_reason():
    stock = _AIAC["inbound"] + "client_ok if not data.authbridge.client.inbound.request\n"
    reason = combiner_reason(_cr(("inbound/request.rego", stock), ("outbound/request.rego", _AIAC["outbound"])))
    assert reason and "client_ok if not data.authbridge.client.inbound.request" in reason


def test_an_equivalent_fail_open_rule_in_another_form_is_a_reason():
    # The gate is an allowlist, not a search for the stock line.
    other = _AIAC["outbound"] + "client_ok if {\n  not data.authbridge.client.outbound.request.allow\n}\n"
    reason = combiner_reason(_cr(("inbound/request.rego", _AIAC["inbound"]), ("outbound/request.rego", other)))
    assert reason and "outbound/request.rego has the rule" in reason


def test_a_fail_open_entry_of_a_repeated_path_is_a_reason():
    # Each entry of a path counts: a later safe entry must not hide an earlier fail-open one.
    stock = "client_ok if not data.authbridge.client.inbound.request\n"
    first = ("inbound/request.rego", stock)
    reason = combiner_reason(
        _cr(first, ("inbound/request.rego", _AIAC["inbound"]), ("outbound/request.rego", _AIAC["outbound"]))
    )
    assert reason and "inbound/request.rego has the rule" in reason


def test_a_package_with_no_client_ok_rule_is_a_reason():
    empty = ("inbound/request.rego", "package authbridge.client.inbound.request\n")
    reason = combiner_reason(_cr(empty, ("outbound/request.rego", _AIAC["outbound"])))
    assert reason and "no client_ok rule" in reason
