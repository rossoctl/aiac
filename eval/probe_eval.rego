package probe.inbound_eval

import rego.v1

# The inbound package of the callee: the tool that owns the scope. The callee's own CR is the key,
# so each scope map is keyed by role only. The eval does not use this probe for an agent inbound:
# that gate is agent-level (D26a), so the eval evaluates its allow rule.
gen := data.authbridge.client.inbound.request

tokens(s) := {lower(t) | some t in regex.split(`[._-]+`, s)}

# input.function_name soft-matches one of the tool names: case and separators are ignored.
soft_match(tools) if {
	some tool in tools
	tokens(tool) == tokens(input.function_name)
}

# The user gate reads input.subject, and the calling-agent gate reads input.client_id. Each map is
# read with object.get, as the real gate does: OPA 1.21 rejects a direct index into an empty map ({}).
subject_ok if {
	some role in object.get(gen.subject_roles, input.subject, [])
	soft_match(object.get(gen.subject_role_allow_scopes, role, []))
}

subject_denied if {
	some role in object.get(gen.subject_roles, input.subject, [])
	soft_match(object.get(gen.subject_role_deny_scopes, role, []))
}

source_ok if {
	some role in object.get(gen.source_roles, input.client_id, [])
	soft_match(object.get(gen.source_role_allow_scopes, role, []))
}

source_denied if {
	some role in object.get(gen.source_roles, input.client_id, [])
	soft_match(object.get(gen.source_role_deny_scopes, role, []))
}

default allow := false

# As the real gate: the two allow gates match, and no deny gate matches the same name.
allow if {
	subject_ok
	source_ok
	not subject_denied
	not source_denied
}
