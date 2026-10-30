"""Tell whose rejection an AuthBridge outbound answer is: OPA's, the token exchange's, or neither.

Standard library only, so the onboarding demo driver can send this file into the
agent pod with its probe, and the system harness loads it
(``test/system/launcher.py``): the two classify an answer by one rule.

AuthBridge renders a rejection in two shapes: a JSON-RPC error frame at HTTP 200,
whose ``error.data`` is the rejection document (the forward proxy, for an
MCP-shaped request: ``writeMCPRejection``), and a plain JSON body at HTTP 403
(``httpx.WriteRejection``). The document names the ``plugin`` that rejected.
"""

from __future__ import annotations

import json

# The outbound exchange plugins, either of which may sit before OPA on the agent's outbound leg
# (``k8s/opa-kind-enable.sh`` wires ``token-exchange-aiac``), and the error code of a failed exchange.
EXCHANGE_PLUGINS = frozenset({"token-exchange", "token-exchange-aiac"})
EXCHANGE_FAILED_ERROR = "upstream.token-exchange-failed"

# The JSON-RPC error code of every rejection AuthBridge's forward proxy renders (cortex
# ``httpx.jsonRPCServerError``), its minimal fallback frames included.
AUTHBRIDGE_RPC_ERROR = -32000


def json_or_none(body: str) -> object:
    """``json.loads(body)``, or ``None`` when the body is not JSON."""
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


def rejection_doc(code: int | None, body: str) -> dict | None:
    """The rejection document of an outbound answer ``(code, body)``. **Pure.**

    * HTTP 200 with a JSON-RPC error frame -> its ``error.data``;
    * HTTP 403 with a plain JSON body that is not a JSON-RPC frame -> the body;
    * anything else (an allow, a ``result`` frame, a transport error, a non-JSON body) -> ``None``."""
    return _rejection_doc(code, json_or_none(body))


def _rejection_doc(code: int | None, doc: object) -> dict | None:
    if not isinstance(doc, dict):
        return None
    if code == 200:
        err = doc.get("error")
        data = err.get("data") if isinstance(err, dict) else None
        return data if isinstance(data, dict) else None
    if code == 403 and "jsonrpc" not in doc:
        return doc
    return None


def is_opa_violation(doc: object) -> bool:
    """True when ``doc`` (a rejection document) is an OPA **policy verdict**: ``error ==
    "policy.forbidden"`` and ``plugin == "opa"``. cortex's pipeline names the plugin on every rejection
    (``pipeline.stampPluginName``), so a document that names none is not AuthBridge's OPA: it is another
    hop's body (a gateway, the tool's own handler). A named non-OPA plugin never counts either:
    ``token-exchange-aiac`` also answers ``policy.forbidden`` (a target not granted to the caller), and
    that refusal is not an OPA verdict. Nor does an OPA answer with another error: OPA with no bundle yet
    answers ``upstream.unreachable`` ("opa policy engine not initialized", cortex ``core/plugins/opa``),
    which decides nothing."""
    return isinstance(doc, dict) and doc.get("error") == "policy.forbidden" and doc.get("plugin") == "opa"


def is_exchange_refusal(doc: object) -> bool:
    """True when ``doc`` (a rejection document) is a refusal or a failure of the outbound token
    exchange — the request never reached OPA."""
    if not isinstance(doc, dict):
        return False
    plugin = doc.get("plugin")
    return (isinstance(plugin, str) and plugin in EXCHANGE_PLUGINS) or doc.get("error") == EXCHANGE_FAILED_ERROR


def exchange_refusal(code: int | None, body: str) -> bool:
    """True when the outbound answer ``(code, body)`` is the exchange plugin's **refusal**: Keycloak
    answered and did not grant the tool's audience to the caller (``policy.forbidden``, as a JSON-RPC
    error frame in an HTTP 200 or as a plain 403 reject body). **Pure.** A failed exchange
    (``upstream.token-exchange-failed``, an IdP that errored or was unreachable) is **not** a refusal:
    it proves nothing about the caller's grants."""
    doc = rejection_doc(code, body)
    return is_exchange_refusal(doc) and doc.get("error") == "policy.forbidden"


# ``token-exchange-aiac`` answers both "not granted" and "target disabled" with ``policy.forbidden``; only
# the message tells them apart (cortex ``core/plugins/tokenexchangeaiac/plugin.go``, the ``deny`` of
# ``outcomeTargetDisabled``). The response carries no reason code, so a reworded message there must be
# copied here; the rollback test then fails as ``error``, never passes wrongly. Key on a machine-readable
# reason once cortex puts one in the rejection (rossoctl/cortex#1570).
TARGET_DISABLED_MESSAGE = "the destination's client is disabled"


def target_disabled_refusal(code: int | None, body: str) -> bool:
    """True when the outbound answer ``(code, body)`` is the exchange plugin's refusal **because the
    target's client is disabled** (``target_disabled``), not any other refusal. **Pure.** A refusal for a
    target not granted to the caller (``audience_not_granted``) proves nothing about the target's
    client, so it does not count."""
    if not exchange_refusal(code, body):
        return False
    doc = json_or_none(body)
    # A frame at HTTP 200 carries the message in ``error.message`` (``httpx.MarshalMCPRejectionBody``);
    # a plain 403 body carries it at the top (``pipeline.Violation.Render``).
    holder = doc.get("error") if code == 200 else doc
    return isinstance(holder, dict) and holder.get("message") == TARGET_DISABLED_MESSAGE


def outbound_outcome(code: int | None, body: str) -> str:
    """Classify an outbound ``tools/call`` answer by **body** (``k8s/opa-kind-runbook.md`` "Reading a
    decision"): ``"allow"``, ``"deny"`` (an OPA verdict) or ``"error"`` (anything else). **Pure.**

    A denied ``tools/call`` has one of two shapes:

    * **The callee's inbound** — the agent's outbound is a pass-through (PRD D24), and the callee's
      inbound OPA (github-tool's reverse proxy) decides. The reverse proxy renders a rejection with
      ``httpx.WriteRejection``: **HTTP 403** and a plain JSON body (``{"error": "policy.forbidden",
      "message": …, "plugin": "opa"}``), which the agent's forward proxy relays as it is. A 403 whose
      body names OPA -> ``"deny"``; a 403 with any other body -> ``"error"``.
    * **The agent's forward proxy** — a plugin on the agent's outbound rejects the request (for
      example the agent's OPA, with the PRD D20 combiner deny when the agent has no CR). On an
      MCP-shaped request AuthBridge renders **any** rejection as a JSON-RPC error frame **at HTTP 200**
      (``writeMCPRejection``), code ``AUTHBRIDGE_RPC_ERROR`` unless the plugin set its own, and the
      frame's ``error.data`` — not the status — names the plugin.

    The ``error.data`` of a frame at HTTP 200 decides the class:

    * an OPA **policy verdict** (``is_opa_violation``: ``error == "policy.forbidden"``, from OPA or
      no plugin named) -> ``"deny"``. Not the tool check: on a pass-through outbound it comes only from
      a fault. ``deny_origin`` (``test/system/launcher.py``) tells it apart from the callee's deny.
    * any other AuthBridge rejection -> ``"error"``: code ``AUTHBRIDGE_RPC_ERROR`` (AuthBridge's own
      code; its minimal fallback frame has no ``data`` at all), or a ``data`` that names a plugin (the
      pipeline fills it in, also when a plugin sets its own code). That covers the exchange plugin
      (``token-exchange-aiac`` or a legacy ``token-exchange``, which broke before OPA), OPA with no
      bundle yet (``upstream.unreachable``), and any other plugin (``jwt-validation``, a parser):
      AuthBridge rejected it, but not by policy.

    Any other HTTP 200 body (a ``result`` frame, or a JSON-RPC error of the tool itself, with another
    code and no AuthBridge ``data``, which means the call was let through) -> ``"allow"``. ``None`` or any other status
    (a transport break, a 401 of the callee's ``jwt-validation``, a 503 before the first bundle loads,
    a non-MCP exchange 503) -> ``"error"``. Classify by the body, never the transport status alone."""
    return _outcome(code, json_or_none(body))


def _outcome(code: int | None, parsed: object) -> str:
    doc = _rejection_doc(code, parsed)
    if code == 403:
        return "deny" if is_opa_violation(doc) else "error"
    frame = parsed if code == 200 else None
    if not isinstance(frame, dict):
        return "error"
    err = frame.get("error")
    if not isinstance(err, dict):
        return "allow"  # a result frame
    # An AuthBridge rejection frame: its code, or — when a plugin set its own code — a ``data`` that names
    # the plugin (the pipeline always fills it in). Anything else is a JSON-RPC error of the tool itself
    # (FastMCP), even one whose ``data`` happens to say ``policy.forbidden``: the call was let through.
    authbridge = err.get("code") == AUTHBRIDGE_RPC_ERROR or (isinstance(doc, dict) and doc.get("plugin") is not None)
    if not authbridge:
        return "allow"
    return "deny" if is_opa_violation(doc) else "error"  # an OPA verdict, or another AuthBridge rejection


def classify(code: int | None, body: str) -> tuple[str, dict | None]:
    """``(outcome, exchange_doc)`` of an outbound answer, from one parse. **Pure.** ``outcome`` is
    ``outbound_outcome``'s class. ``exchange_doc`` is the rejection document when the answer is a refusal
    **or a failure** of the token exchange (OPA was never consulted, for any reason), else ``None``. It
    is wider than ``exchange_refusal`` (a refusal only, which proves the caller holds no grant): beside
    ``rejection_doc``'s shapes it reads a plain body at any status other than 200 (a ``503`` of a failed
    exchange, a ``401`` of a refused subject token), which ``outbound_outcome`` counts ``error``
    whatever its body; ``exchange_doc`` names whose they are."""
    parsed = json_or_none(body)
    doc = _rejection_doc(code, parsed)
    if doc is None and code is not None and code != 200 and isinstance(parsed, dict) and "jsonrpc" not in parsed:
        doc = parsed
    return _outcome(code, parsed), (doc if is_exchange_refusal(doc) else None)


def verdict(code: int | None, body: str) -> str:
    """The demo driver's verdict string of an answer to a ``tools/call``. **Pure.** One mapping for its
    two probes (through the agent, and straight to github-tool), from ``classify``:

    * ``EXCHANGE_REFUSED <code> <error>`` — the token exchange refused or failed: OPA was never consulted;
    * ``DENIED_HTTP 403`` — an OPA verdict in a plain 403 (github-tool's inbound; the agent relays it);
    * ``DENIED_JSONRPC`` — an OPA verdict in a frame at HTTP 200 (the agent's own outbound OPA);
    * ``ALLOWED_RESULT`` — let through;
    * ``UNEXPECTED <code> <error> <body>`` — anything else (a 403 that names no OPA, OPA with no bundle
      yet, AuthBridge's fallback frame, a 401 of github-tool's ``jwt-validation``). ``<error>`` is the
      rejection's parsed ``error`` code (``-`` when there is none), then the first 200 characters."""
    outcome, failure = classify(code, body)
    if failure is not None:
        return f"EXCHANGE_REFUSED {code} {failure.get('error')}"
    if outcome == "deny":
        return "DENIED_HTTP 403" if code == 403 else "DENIED_JSONRPC"
    if outcome == "allow":
        return "ALLOWED_RESULT"
    # The parsed error code first, so a caller can match it however long the body is (cortex marshals the
    # keys sorted, so ``description`` and ``details`` come before ``error``), then the start of the body.
    doc = _rejection_doc(code, json_or_none(body))
    if doc is None and code not in (None, 200):
        plain = json_or_none(body)
        doc = plain if isinstance(plain, dict) else None
    error = doc.get("error") if isinstance(doc, dict) else None
    return f"UNEXPECTED {code} {error or '-'} {body[:200]}"
