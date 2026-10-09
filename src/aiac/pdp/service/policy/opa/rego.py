"""Rego package generation for the PDP Policy Writer (OPA).

Renders the two request packages of one client CR (``ClientPolicies``) for each
entry of a policy model. Three CR renderers, one per kind of entry:

- ``render_target_side(spm)`` — target side, one stored SPM: the tool inbound or the
  agent inbound, and a pass-through outbound (the callee decides);
- ``render_agent_side(apm)`` — agent side, one APM: the agent inbound and the agent
  outbound;
- ``render_pass_through()`` — agent side, one managed tool: a pass-through in both
  tiers.

Four package kinds:

- **tool inbound** (target side, D26) — ``render_target_side`` of a tool's SPM;
- **agent inbound** (both sides, D26a) — ``render_target_side`` of an agent's SPM,
  or ``generate_inbound_rego`` of an APM (agent side); one shared renderer, so one
  SPM gives the same inbound under both sides (D18b);
- **agent outbound** (agent side) — ``generate_outbound_rego`` of an APM. Known
  limit: it denies the agent's A2A and LLM calls through the outbound proxy;
- **pass-through** (D24) — ``generate_pass_through_rego``: ``allow := true``. Under
  target side the outbound of every service is one: the callee decides. Under agent
  side both packages of every managed tool are one.

The target-side render input is the stored SPM of the callee, through
``project_inbound`` (D18b). The agent-side render input is the APM, which the PCE
derives. The writer does no join.

Both packages use **fixed** names — ``authbridge.client.inbound.request`` and
``authbridge.client.outbound.request`` (each ``import rego.v1``). Per-service
isolation is at the CR/bundle level (the bundle-service looks a CR up by
namespace+name), never in the package name. The bundle-service combiner requires
the exact path ``data.authbridge.client.<tier>``, so no slug ever appears in the
package name.

The Rego ``input`` follows the live plugin shape:

- ``input.identity.subject`` — the delegated user (``sub`` claim).
- ``input.identity.client_id`` — the calling client: on an agent inbound the
  source, on a tool inbound the calling agent (or, for UC-1 discovery, the tool's
  own client).
- ``input.identity.service_id`` — the downstream target audience the exchanged
  token was minted for (a full SPIFFE ID); agent outbound only.
- ``input.mcp.method`` — the MCP JSON-RPC method (``tools/call``, ``tools/list``,
  …); tool inbound and agent outbound.
- ``input.mcp.params.name`` — the **bare** invoked MCP tool name (e.g.
  ``source-read``), carried by ``tools/call``; tool inbound and agent outbound.

**ALLOW gates and DENY gates, always deny by default (D25).** Every rules-based
package ends with ``default allow := false``: a request that no rule allows is
denied. A request is permitted iff every ALLOW gate passes and no DENY gate
matches::

    # agent inbound
    allow if { subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok }
    # tool inbound — tools/call, per invoked tool; the session messages; self-discovery
    allow if { input.mcp.method == "tools/call"; tool_ok(input.mcp.params.name) }
    allow if { input.mcp.method in session_methods; some tool in owned_tools; tool_ok(tool) }
    allow if { input.mcp.method in session_methods; input.identity.client_id == self_client_id }
    # agent outbound — tools/call, per invoked tool; the session messages
    allow if { input.mcp.method == "tools/call"; subject_allow_ok; target_allow_ok;
               not subject_deny_ok; not target_deny_ok }
    allow if { input.mcp.method in session_methods;
               some tool in object.get(target_allow_scopes, input.identity.service_id, []); tool_ok(tool) }

**The MCP session.** ``initialize``, ``notifications/initialized``, ``ping`` and
``tools/list`` carry no tool name. On a tool inbound they are allowed iff at least
one tool of the service passes ``tool_ok`` (the user gate and the calling-agent
gate allow it, no deny vetoes it), or the caller is the tool's own client (the
self-discovery rule of UC-1, checkpoint B1; never ``tools/call``). On an agent
outbound they are allowed to a target iff at least one tool of that target passes
``tool_ok``. Every other MCP method, and a request with no method, is denied.

**No request without identity passes a rules-based inbound (D27).** Both inbound
packages need a subject that holds a role. A tool inbound has no platform-client
bypass; an agent inbound bypasses the source gate only (``platform_clients``).

The identity maps (``subject_roles`` / ``source_roles``) are **effect-agnostic**,
so a principal that appears only in a DENY rule still resolves and its
prohibition fires.
"""

import json
import re
from typing import Literal, NamedTuple

from aiac.idp.configuration.models import Scope, ServiceType
from aiac.policy.model.models import AgentPolicyModel, PolicyRule, ServicePolicyModel
from aiac.policy.model.projection import InboundProjection, project_inbound

__all__ = [
    "ClientPolicies",
    "identity_ref",
    "generate_inbound_rego",
    "generate_outbound_rego",
    "generate_pass_through_rego",
    "render_agent_side",
    "render_pass_through",
    "render_target_side",
]

# The two request tiers of a client CR, and their fixed package headers (Q2).
Tier = Literal["inbound", "outbound"]
_PACKAGES: dict[str, str] = {
    "inbound": "package authbridge.client.inbound.request\nimport rego.v1",
    "outbound": "package authbridge.client.outbound.request\nimport rego.v1",
}

_SPIFFE_RE = re.compile(r"^spiffe://[^/]+/ns/(?P<ns>[^/]+)/sa/(?P<name>[^/]+)$")

# A DNS-1123 label: lowercase alphanumerics and '-', starting/ending alphanumeric.
_DNS1123_LABEL_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")


def _valid_label(segment: str) -> bool:
    """True when ``segment`` is a valid DNS-1123 label (<=63 chars)."""
    return len(segment) <= 63 and _DNS1123_LABEL_RE.fullmatch(segment) is not None


def identity_ref(service_id: str) -> tuple[str, str]:
    """``(namespace, name)`` of the CR of the service (agent or tool) whose clientId is ``service_id``.

    Accepts a SPIFFE URI (``spiffe://<trust-domain>/ns/<ns>/sa/<name>``) or a
    plain ``<ns>/<name>``. Both segments are validated as DNS-1123 labels
    (``^[a-z0-9]([-a-z0-9]*[a-z0-9])?$``, <=63 chars).

    Raises ``ValueError`` when no namespace is derivable (e.g. a bare
    ``github-agent`` with no ``/``) or either segment is not a valid label —
    there is **no** fallback.
    """
    match = _SPIFFE_RE.match(service_id)
    if match:
        namespace, name = match["ns"], match["name"]
    else:
        parts = service_id.split("/")
        if len(parts) != 2:
            raise ValueError(
                f"service id {service_id!r} has no derivable namespace (expected "
                "SPIFFE spiffe://td/ns/<ns>/sa/<name> or plain <ns>/<name>)"
            )
        namespace, name = parts
    if not _valid_label(namespace) or not _valid_label(name):
        raise ValueError(
            f"service id {service_id!r} yields invalid DNS-1123 label(s): namespace={namespace!r}, name={name!r}"
        )
    return namespace, name


def _lookup(var: str, *keys: str) -> str:
    """Render a read of the map ``var`` at ``keys`` as ``object.get`` with an empty default.

    An empty map renders as ``{}`` (``_render_map``), and OPA 1.21 types ``{}`` as an object with
    no keys: a direct index ``var[key]`` into it is a type error (``undefined ref``) that stops the
    whole bundle from activating, so the sidecar denies every request. ``object.get`` takes any
    object, and a missing key gives the default ``[]``, which matches nothing — the same result as
    the undefined index. Two keys use the path form ``object.get(var, [k1, k2], [])``."""
    key = keys[0] if len(keys) == 1 else "[" + ", ".join(keys) + "]"
    return f"object.get({var}, {key}, [])"


def _render_list(var: str, values: list[str]) -> str:
    """Render ``{var} := ["a", "b"]`` as Rego (empty-safe: ``[]``).

    Each value is emitted via ``json.dumps`` so quotes/newlines/backslashes are escaped —
    Rego string syntax is JSON-compatible, and this prevents Rego injection / broken output."""
    inner = ", ".join(json.dumps(v) for v in values)
    return f"{var} := [{inner}]"


def _render_map(var: str, mapping: dict[str, list[str]]) -> str:
    """Render ``{var} := { "key": ["a", "b"], ... }`` as Rego (empty-safe: ``{}``).

    Keys and values are emitted via ``json.dumps`` so quotes/newlines/backslashes are escaped
    (JSON-compatible Rego string syntax) — this prevents Rego injection / broken output."""
    if not mapping:
        return f"{var} := {{}}"
    lines = [f"{var} := {{"]
    for key, values in mapping.items():
        inner = ", ".join(json.dumps(v) for v in values)
        lines.append(f"    {json.dumps(key)}: [{inner}],")
    lines.append("}")
    return "\n".join(lines)


def _render_nested_map(var: str, mapping: dict[str, dict[str, list[str]]]) -> str:
    """Render ``{var} := { "key": { "inner": ["a", "b"], ... }, ... }`` as Rego (empty-safe: ``{}``).

    The two-level counterpart of ``_render_map``, with the same ``json.dumps`` escaping of every
    key and value."""
    if not mapping:
        return f"{var} := {{}}"
    lines = [f"{var} := {{"]
    for key, inner_map in mapping.items():
        lines.append(f"    {json.dumps(key)}: {{")
        for inner_key, values in inner_map.items():
            inner = ", ".join(json.dumps(v) for v in values)
            lines.append(f"        {json.dumps(inner_key)}: [{inner}],")
        lines.append("    },")
    lines.append("}")
    return "\n".join(lines)


def _deprefix(scope) -> str:
    """De-prefix a scope value to the bare MCP tool name (agent outbound, tool inbound).

    Provisioned scope names are prefixed with their owning workload
    (``github-tool.source-read``, ``github-agent.source_operations``), but the
    value that arrives in ``input.mcp.params.name`` at runtime is the **bare**
    tool name (``source-read``). Strip a leading ``"<owner>."`` where ``owner =
    identity_ref(scope.serviceId).name``.

    Fall back to ``scope.name`` unchanged when ``serviceId`` is missing /
    underivable or the ``"<owner>."`` prefix is not present — no partial strip.
    """
    service_id = getattr(scope, "serviceId", "") or ""
    if service_id:
        try:
            _, owner = identity_ref(service_id)
        except ValueError:
            return scope.name
        prefix = f"{owner}."
        if scope.name.startswith(prefix):
            return scope.name[len(prefix) :]
    return scope.name


def _group_rules(rules: list[PolicyRule]) -> dict[str, list[str]]:
    """Group rules into ``{role.name: [scope.name, ...]}`` preserving first-seen order."""
    grouped: dict[str, list[str]] = {}
    for rule in rules:
        scopes = grouped.setdefault(rule.role.name, [])
        if rule.scope.name not in scopes:
            scopes.append(rule.scope.name)
    return grouped


def _group_rules_deprefixed(rules: list[PolicyRule]) -> dict[str, list[str]]:
    """Like ``_group_rules`` but de-prefixes each scope value.

    Groups ``{role.name: [_deprefix(scope), ...]}`` — used for the agent outbound
    ``agent_role_scopes`` map and for the four role maps of the tool inbound,
    whose values must match the bare ``input.mcp.params.name``."""
    grouped: dict[str, list[str]] = {}
    for rule in rules:
        scopes = grouped.setdefault(rule.role.name, [])
        value = _deprefix(rule.scope)
        if value not in scopes:
            scopes.append(value)
    return grouped


def _group_rules_by_target(rules: list[PolicyRule]) -> dict[str, dict[str, list[str]]]:
    """Group the outbound subject rules into ``{role.name: {target: [tool, ...]}}`` (LIM-02).

    A bare tool name alone does not name a tool: two targets can each have a ``source-read``. So
    each rule decides only on the copy of the scope that it names (``scope.serviceId``): the key is
    the **full** service id of the copy's owner (it matches ``input.identity.service_id``), and the
    tool is the de-prefixed name of that copy, so it is the value that the target gate of that
    target has. A rule of another scope (another scope id) with the same bare name never decides
    there. A scope with no ``serviceId`` names no target.

    A shared scope (D32) has one copy for each owner, and each copy has the user rules of its own
    SPM. So a grant or a deny decides only on its own copy, as under target side: a grant on one copy
    must not admit the user on a copy whose SPM has no grant (fail-open), and a deny on one copy must
    not block the user on a copy whose SPM has no deny. A copy with no rule gets no entry, also when
    the agent may call that copy. The PCE keeps one outbound subject rule for each copy (role, scope
    id, copy owner, effect), so a rule that two copies have is in the APM for each copy, and each
    copy gets its entry. First-seen order is kept.
    """
    grouped: dict[str, dict[str, list[str]]] = {}
    for rule in rules:
        if not rule.scope.serviceId:
            continue
        tools = grouped.setdefault(rule.role.name, {}).setdefault(rule.scope.serviceId, [])
        value = _deprefix(rule.scope)
        if value not in tools:
            tools.append(value)
    return grouped


def _names(items) -> list[str]:
    """Extract the ``.name`` of each entity in a list."""
    return [item.name for item in items]


def _name_map(mapping) -> dict[str, list[str]]:
    """Turn ``{id: [entity, ...]}`` into ``{id: [entity.name, ...]}``."""
    return {key: _names(values) for key, values in mapping.items()}


def _name_map_deprefixed(mapping) -> dict[str, list[str]]:
    """Like ``_name_map`` but de-prefixes each value (outbound ``target_*_scopes``).

    Keys stay the **full** target service id (they match
    ``input.identity.service_id``, a full SPIFFE ID); only the scope *values*
    de-prefix to the bare MCP tool names carried in ``input.mcp.params.name``."""
    return {key: [_deprefix(scope) for scope in scopes] for key, scopes in mapping.items()}


# --- agent inbound gate templates -------------------------------------------
#
# The inbound subject gate is emitted twice against the SAME shape: an
# ``*_allow_ok`` gate reads the ALLOW scope map, a symmetric ``*_deny_ok`` gate
# reads the DENY scope map. Both require the matched scope to be one of the
# agent's own ``agent_scopes`` (the inbound audience), compared internally with
# FULL scope names — never against ``input.mcp.params.name``. A subject/source
# that only appears in a DENY rule still resolves because the identity maps
# (``subject_roles`` / ``source_roles``) are effect-agnostic.


def _inbound_subject_gate(gate: str, scope_map: str) -> str:
    return (
        f"{gate} if {{\n"
        f"    some role in {_lookup('subject_roles', 'input.identity.subject')}\n"
        f"    some scope in {_lookup(scope_map, 'role')}\n"
        "    scope in agent_scopes\n"
        "}"
    )


def _inbound_source_allow_gate(platform_clients: tuple[str, ...]) -> str:
    """The inbound source ALLOW gate.

    Passes when there is no calling ``client_id`` (end-user traffic), when the
    ``client_id`` is one of ``platform_clients`` (the mandatory bypass — one rule
    per client; without it end-user traffic, which carries the platform client,
    would be denied), or when that client holds a role granting an agent scope.
    """
    rules = ["source_allow_ok if { not input.identity.client_id }"]
    for client in platform_clients:
        rules.append(f"source_allow_ok if {{ input.identity.client_id == {json.dumps(client)} }}")
    rules.append(
        "source_allow_ok if {\n"
        f"    some role in {_lookup('source_roles', 'input.identity.client_id')}\n"
        f"    some scope in {_lookup('source_role_allow_scopes', 'role')}\n"
        "    scope in agent_scopes\n"
        "}"
    )
    return "\n".join(rules)


def _inbound_source_deny_gate() -> str:
    """The inbound source DENY gate.

    An absent client_id (or a platform client) has no roles here, so this gate
    simply never fires for it — the ALLOW-side bypass is not undone by a deny.
    """
    return (
        "source_deny_ok if {\n"
        f"    some role in {_lookup('source_roles', 'input.identity.client_id')}\n"
        f"    some scope in {_lookup('source_role_deny_scopes', 'role')}\n"
        "    scope in agent_scopes\n"
        "}"
    )


# --- agent outbound gate templates (agent side) ------------------------------
#
# The outbound decision is a per-tool two-gate AND (the delegated user reaching a
# downstream target):
#   subject gate    — the delegated user's role admits the tool on this target
#   capability gate — the target service admits the tool
# Both gates are keyed by the target (``input.identity.service_id``): a bare tool
# name alone does not name a tool, because two targets can each have one with
# that name (LIM-02).
# Each gate is emitted twice (allow/deny) as a Rego FUNCTION over a bare tool
# name, so ``tools/call`` (the invoked ``input.mcp.params.name``) and the MCP
# session (any tool of the target) use one definition of the per-tool check.
# ``allow`` holds only when both ALLOW gates pass on the tool and neither DENY gate
# matches it.

# The MCP messages that carry no tool name and open / keep a session with a tool (the agent
# outbound and the tool inbound).
_SESSION_METHODS = ("initialize", "notifications/initialized", "ping", "tools/list")


def _render_session_methods() -> str:
    return "session_methods := {" + ", ".join(json.dumps(m) for m in _SESSION_METHODS) + "}"


def _outbound_subject_gate(fn: str, gate: str, scope_map: str) -> str:
    return (
        f"{fn}(tool) if {{\n"
        f"    some role in {_lookup('subject_roles', 'input.identity.subject')}\n"
        f"    tool in {_lookup(scope_map, 'role', 'input.identity.service_id')}\n"
        "}\n"
        f"{gate} if {{ {fn}(input.mcp.params.name) }}"
    )


def _outbound_target_gate(fn: str, gate: str, scope_map: str) -> str:
    return (
        f"{fn}(tool) if {{\n    tool in {_lookup(scope_map, 'input.identity.service_id')}\n}}\n"
        f"{gate} if {{ {fn}(input.mcp.params.name) }}"
    )


def _outbound_tool_ok() -> str:
    """The full per-tool check as one function: ``tool_ok(tool)``."""
    return (
        "tool_ok(tool) if {\n"
        "    subject_allows(tool)\n"
        "    target_allows(tool)\n"
        "    not subject_denies(tool)\n"
        "    not target_denies(tool)\n"
        "}"
    )


# --- trailing decision block -------------------------------------------------
#
# CRITICAL: the generator assumes disjoint ALLOW/DENY per (role, scope). A
# genuine grant/deny overlap on the same pair is an upstream policy conflict
# surfaced as HTTP 422 (PRB ``PolicyContradictionError``) and is NEVER
# reconciled here. The inline ``not …_deny_ok`` guards resolve
# co-occurring-but-disjoint denies at request time (a subject holding multiple
# roles; the outbound two-gate decision) — each individual (role, scope) stays
# allow-XOR-deny.


def _decision_block(*allow_bodies: str) -> str:
    """Render the trailing ``allow`` decision: ``default allow := false`` plus one
    ``allow if { <body> }`` rule per body (each an allow-conjunction with inline ``not …_deny_ok``
    guards). The default is always DENY — a request that no rule allows is denied."""
    return "\n".join(["default allow := false"] + [f"allow if {{ {body} }}" for body in allow_bodies])


class ClientPolicies(NamedTuple):
    """The two request packages of one client CR (D20): ``inbound/request.rego`` and
    ``outbound/request.rego``."""

    inbound: str
    outbound: str


# --- tool inbound (target side, D26) -----------------------------------------
#
# Today's agent-outbound per-tool check, moved to the callee. The callee is the key (the CR
# belongs to the tool), so there is no ``target_*_scopes[input.identity.service_id]`` map. Two
# gates, each a pair of functions over a bare tool name: the user gate
# (``input.identity.subject``) and the calling-agent gate (``input.identity.client_id``).


def _tool_gate(fn: str, identity_map: str, identity_field: str, scope_map: str) -> str:
    return (
        f"{fn}(tool) if {{\n"
        f"    some role in {_lookup(identity_map, f'input.identity.{identity_field}')}\n"
        f"    tool in {_lookup(scope_map, 'role')}\n"
        "}"
    )


def _tool_inbound_rego(spm: ServicePolicyModel) -> str:
    """Render the tool inbound package — "who may call which tool of this service" (D26).

    ``tool_ok(tool)``: the user gate allows the tool, the calling-agent gate allows it, and
    neither gate denies it. ``tools/call`` is checked on the invoked tool; a session message is
    allowed iff some tool of the service (``owned_tools``) passes ``tool_ok``, or the caller is the
    tool's own client (``self_client_id`` = the SPM ``service_id``; the UC-1 discovery token is
    minted as that client — checkpoint B1). Both gates are mandatory: no platform-client bypass,
    and a request with no identity is denied (D27).
    """
    projection = project_inbound(spm)
    owned_tools = _render_list("owned_tools", [_deprefix(scope) for scope in spm.owned_scopes])
    declarations = "\n".join(
        [
            _render_map("subject_roles", _name_map(projection.subject_roles)),
            _render_map("source_roles", _name_map(projection.source_roles)),
            _render_map("subject_role_allow_scopes", _group_rules_deprefixed(projection.subject_allow_rules)),
            _render_map("subject_role_deny_scopes", _group_rules_deprefixed(projection.subject_deny_rules)),
            _render_map("source_role_allow_scopes", _group_rules_deprefixed(projection.source_allow_rules)),
            _render_map("source_role_deny_scopes", _group_rules_deprefixed(projection.source_deny_rules)),
            _render_session_methods(),
            f"self_client_id := {json.dumps(spm.service_id)}",
        ]
    )
    rules = "\n".join(
        [
            _tool_gate("subject_allows", "subject_roles", "subject", "subject_role_allow_scopes"),
            _tool_gate("subject_denies", "subject_roles", "subject", "subject_role_deny_scopes"),
            _tool_gate("source_allows", "source_roles", "client_id", "source_role_allow_scopes"),
            _tool_gate("source_denies", "source_roles", "client_id", "source_role_deny_scopes"),
            "tool_ok(tool) if {\n"
            "    subject_allows(tool)\n"
            "    source_allows(tool)\n"
            "    not subject_denies(tool)\n"
            "    not source_denies(tool)\n"
            "}",
            _decision_block(
                'input.mcp.method == "tools/call"; tool_ok(input.mcp.params.name)',
                "input.mcp.method in session_methods; some tool in owned_tools; tool_ok(tool)",
                "input.mcp.method in session_methods; input.identity.client_id == self_client_id",
            ),
        ]
    )
    return "\n\n".join([_PACKAGES["inbound"], owned_tools, declarations, rules]) + "\n"


def render_target_side(spm: ServicePolicyModel, platform_clients: tuple[str, ...] = ("rossoctl",)) -> ClientPolicies:
    """Render the two request packages of the target-side CR of ``spm``'s service.

    The stored SPM is the render input; the writer does no join. The inbound is the tool inbound
    (D26) or the agent inbound (D26a), by ``spm.service_type``; ``platform_clients`` feeds the
    agent inbound's bypass only. The outbound is a pass-through (D24): the callee decides.
    """
    if spm.service_type == ServiceType.TOOL:
        inbound = _tool_inbound_rego(spm)
    else:
        inbound = _agent_inbound_rego(spm.owned_scopes, project_inbound(spm), platform_clients)
    return ClientPolicies(inbound=inbound, outbound=generate_pass_through_rego("outbound"))


def generate_pass_through_rego(tier: Tier) -> str:
    """Render the pass-through package of ``tier`` (D24): the header and ``allow := true``.

    The pass-throughs are the only ALLOW packages (D25). Under target side the outbound of every
    service is one: the callee decides."""
    return f"{_PACKAGES[tier]}\n\nallow := true\n"


def render_agent_side(apm: AgentPolicyModel, platform_clients: tuple[str, ...] = ("rossoctl",)) -> ClientPolicies:
    """Render the two request packages of the agent-side CR of ``apm``'s agent.

    The APM is the render input (the PCE derives it; the writer does no join). The inbound is the
    agent inbound (agent-level, D26a); ``platform_clients`` feeds its bypass. The outbound is the
    agent outbound: the per-tool checks and the MCP session rule. Known limit: it denies the
    agent's A2A and LLM calls through the outbound proxy (``b435aa1``).
    """
    return ClientPolicies(
        inbound=generate_inbound_rego(apm, platform_clients=platform_clients),
        outbound=generate_outbound_rego(apm),
    )


def render_pass_through() -> ClientPolicies:
    """Render the two request packages of a pass-through CR: a pass-through in both tiers (D24).

    Agent side: the CR of each managed tool (``pass_through[]``). AIAC checks nothing on it, but a
    pod with no CR is denied (D20), also on its outbound."""
    return ClientPolicies(
        inbound=generate_pass_through_rego("inbound"), outbound=generate_pass_through_rego("outbound")
    )


def generate_inbound_rego(model: AgentPolicyModel, platform_clients: tuple[str, ...] = ("rossoctl",)) -> str:
    """Render the agent inbound package (``authbridge.client.inbound.request``) from an APM.

    The agent side input. Under target side, ``render_target_side`` renders the same package from
    the agent's SPM; both call one renderer, so one SPM gives the same inbound under both sides
    (D18b). See ``_agent_inbound_rego`` for the gates.
    """
    gates = InboundProjection(
        subject_allow_rules=model.inbound_subject_allow_rules,
        subject_deny_rules=model.inbound_subject_deny_rules,
        source_allow_rules=model.inbound_source_allow_rules,
        source_deny_rules=model.inbound_source_deny_rules,
        subject_roles=model.subject_roles,
        source_roles=model.source_roles,
    )
    return _agent_inbound_rego(model.agent_scopes, gates, platform_clients)


def _agent_inbound_rego(agent_scopes: list[Scope], gates: InboundProjection, platform_clients: tuple[str, ...]) -> str:
    """Render the agent inbound package — "who may call this agent" (agent-level, D26a).

    Gates a caller reaching the agent. A matching DENY gate blocks the request:
    ``allow`` requires ``subject_allow_ok`` (the subject holds a role granting
    >=1 of ``agent_scopes`` via the ALLOW map) AND ``source_allow_ok``, and
    fires only when neither ``subject_deny_ok`` nor ``source_deny_ok`` matches.

    ``source_allow_ok`` passes when there is no calling ``client_id`` (end-user
    traffic), when the ``client_id`` is one of ``platform_clients`` (the
    mandatory bypass), or when that client holds a role granting an agent scope.
    The subject gate is mandatory, so a request with no identity is denied (D27).
    Values are **not** de-prefixed — the gates compare scopes internally
    against ``agent_scopes``, never against ``input.mcp.params.name``.
    """
    declarations = "\n".join(
        [
            _render_map("subject_roles", _name_map(gates.subject_roles)),
            _render_map("source_roles", _name_map(gates.source_roles)),
            _render_map("subject_role_allow_scopes", _group_rules(gates.subject_allow_rules)),
            _render_map("subject_role_deny_scopes", _group_rules(gates.subject_deny_rules)),
            _render_map("source_role_allow_scopes", _group_rules(gates.source_allow_rules)),
            _render_map("source_role_deny_scopes", _group_rules(gates.source_deny_rules)),
        ]
    )
    rules = "\n".join(
        [
            _inbound_subject_gate("subject_allow_ok", "subject_role_allow_scopes"),
            _inbound_subject_gate("subject_deny_ok", "subject_role_deny_scopes"),
            _inbound_source_allow_gate(platform_clients),
            _inbound_source_deny_gate(),
            _decision_block("subject_allow_ok; source_allow_ok; not subject_deny_ok; not source_deny_ok"),
        ]
    )
    parts = [
        _PACKAGES["inbound"],
        _render_list("agent_scopes", _names(agent_scopes)),
        declarations,
        rules,
    ]
    return "\n\n".join(parts) + "\n"


def generate_outbound_rego(model: AgentPolicyModel) -> str:
    """Render the agent outbound package (``authbridge.client.outbound.request``) from an APM.

    Agent side only; under target side the outbound of every service is a pass-through.

    Gates the agent's token-exchanged call to a downstream target, per invoked
    tool. A matching DENY gate blocks the request, on the **same** ``input.mcp.params.name``:
    ``allow`` requires ``subject_allow_ok`` (the delegated user's role admits the
    tool on this target, via de-prefixed ``subject_role_allow_scopes[role][target]``)
    AND ``target_allow_ok`` (the target service admits the tool, via de-prefixed
    ``target_allow_scopes[target]``), and fires only when neither ``subject_deny_ok``
    nor ``target_deny_ok`` matches. ``target`` is the full ``input.identity.service_id``
    SPIFFE id in all four gates, so a grant or a deny for one target never decides on
    another target that has a tool with the same bare name (LIM-02). A grant or a
    deny of a shared scope (D32) decides only on the copy that it names, as under
    target side; the APM has one outbound subject rule for each copy (see
    ``_group_rules_by_target``).

    ``agent_roles`` / ``agent_role_scopes`` are emitted for debugging but are
    **not** referenced by ``allow`` — ``target_allow_scopes[input.identity.service_id]``
    already *is* the capability gate. This package emits neither ``agent_scopes``
    nor the inbound scope gates.

    A ``tools/call`` is checked per invoked tool. The MCP session messages
    (``initialize``, ``notifications/initialized``, ``ping``, ``tools/list``) carry
    no tool name; they are allowed to a target iff at least one tool of that target
    passes the same per-tool check (``tool_ok``). Every other method is denied.
    """
    declarations = "\n".join(
        [
            _render_list("agent_roles", _names(model.agent_roles)),
            _render_map("subject_roles", _name_map(model.subject_roles)),
            _render_nested_map(
                "subject_role_allow_scopes",
                _group_rules_by_target(model.outbound_subject_allow_rules),
            ),
            _render_nested_map(
                "subject_role_deny_scopes",
                _group_rules_by_target(model.outbound_subject_deny_rules),
            ),
            # agent_role_scopes is emitted for debugging/observability only; the
            # allow decision never references it (target_allow_scopes is the
            # capability gate). The leading Rego comment says so in the bundle.
            "# informational/debugging only — not referenced by allow\n"
            + _render_map(
                "agent_role_scopes",
                _group_rules_deprefixed(model.outbound_target_allow_rules),
            ),
            _render_map("target_allow_scopes", _name_map_deprefixed(model.target_allow_scopes)),
            _render_map("target_deny_scopes", _name_map_deprefixed(model.target_deny_scopes)),
            _render_session_methods(),
        ]
    )
    rules = "\n".join(
        [
            _outbound_subject_gate("subject_allows", "subject_allow_ok", "subject_role_allow_scopes"),
            _outbound_subject_gate("subject_denies", "subject_deny_ok", "subject_role_deny_scopes"),
            _outbound_target_gate("target_allows", "target_allow_ok", "target_allow_scopes"),
            _outbound_target_gate("target_denies", "target_deny_ok", "target_deny_scopes"),
            _outbound_tool_ok(),
            _decision_block(
                'input.mcp.method == "tools/call"; '
                "subject_allow_ok; target_allow_ok; not subject_deny_ok; not target_deny_ok",
                "input.mcp.method in session_methods; "
                f"some tool in {_lookup('target_allow_scopes', 'input.identity.service_id')}; tool_ok(tool)",
            ),
        ]
    )
    parts = [
        _PACKAGES["outbound"],
        declarations,
        rules,
    ]
    return "\n\n".join(parts) + "\n"
