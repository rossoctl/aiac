package probe.outbound_eval

import rego.v1

gen := data.authbridge.client.outbound.request

tokens(s) := {lower(t) | some t in regex.split(`[._-]+`, s)}

# input.function_name soft-matches one of the tool names: case and separators are ignored.
soft_match(tools) if {
	some tool in tools
	tokens(tool) == tokens(input.function_name)
}

# The two subject maps are keyed by role and then by the full target service id (LIM-02):
# a role's grant or deny decides only on the target that it is keyed by.
subject_ok if {
	some role in gen.subject_roles[input.subject]
	soft_match(gen.subject_role_allow_scopes[role][input.target])
}

subject_denied if {
	some role in gen.subject_roles[input.subject]
	soft_match(gen.subject_role_deny_scopes[role][input.target])
}

target_ok if soft_match(gen.target_allow_scopes[input.target])

target_denied if soft_match(gen.target_deny_scopes[input.target])

default allow := false

# As the real gate: the two allow gates match, and no deny gate matches the same name.
allow if {
	subject_ok
	target_ok
	not subject_denied
	not target_denied
}
