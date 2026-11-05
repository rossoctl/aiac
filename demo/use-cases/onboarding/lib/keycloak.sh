# shellcheck shell=bash
# lib/keycloak.sh — the Keycloak and operator-name helpers that driver.sh and restore.sh share, one
# copy each. Sourced, not run. The sourcing script sets NS, AIAC_DIR, KC and REALM, and runs under
# `set -euo pipefail`; every helper here prints "" (exit 0) on a failed read rather than letting a
# python3 traceback abort it, so the caller decides what a failed read means.

# json_eval <python-expr> — evaluate <python-expr> over the JSON on stdin (bound to `d`; env vars via
# `os.environ`) and print the result (one line per item when it returns a newline-joined string).
# Prints "" (exit 0) instead of raising when the body is not the expected JSON — a Keycloak error
# object, an empty list, an unreachable server — so the caller's guard reports it, or a half-torn-down
# cluster degrades to "nothing found", rather than `set -e` killing the script on a traceback.
json_eval() {
  python3 -c '
import sys, json, os
try:
    d = json.load(sys.stdin)
    r = eval(sys.argv[1])
except Exception:
    r = ""
print("" if r is None else r)' "$1"
}

# aud_scope <workload> — the operator's audience client scope of <workload> in $NS
# (k8s/operator-names.py, the one copy of the operator's naming rule).
aud_scope() { python3 "${AIAC_DIR}/k8s/operator-names.py" aud-scope "$NS" "$1"; }

# realm_client_scopes <admin_token> — the realm's client-scopes as JSON ("" when the read fails); read
# it once and look several names up in it with scope_id_in.
realm_client_scopes() {
  curl -s -H "Authorization: Bearer $1" "${KC}/admin/realms/${REALM}/client-scopes" || true
}

# scope_id_in <name> — the id of the realm client-scope <name>, from the client-scopes JSON on stdin:
# "absent" when the list was read and has no such scope; "" when the list could not be read (callers
# check both), so a failed read never reads as "not there".
scope_id_in() {
  SCOPE_NAME="$1" json_eval 'next((s["id"] for s in d if s.get("name") == os.environ["SCOPE_NAME"]), "absent") if isinstance(d, list) else ""'
}
