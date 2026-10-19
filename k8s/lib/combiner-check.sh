# shellcheck shell=bash
# combiner-check.sh — the one shell copy of the AIAC Controller start check #4 (D30), shared by the
# scripts that need the changed global combiner (D20) in place: k8s/opa-kind-enable.sh,
# k8s/opa-kind-verify.sh, demo/use-cases/onboarding/enable.sh and driver.sh. Source it; it defines
# functions only. test/unit/k8s/test_combiner_check_sh.py checks it against start.py.
#
# The same allowlist as the Controller's start check #4 (src/aiac/agent/controller/start.py): the
# `default` AuthorizationPolicy must have each request package, and in each entry of it every
# client_ok rule (comments dropped, string text dropped, white-space runs as one space) must be
# `client_ok if data.authbridge.client.<dir>.request.allow` or `default client_ok := false`, and
# there must be at least one. A search for the stock fail-open line only would pass a fail-open rule
# in another form, and the Controller would then stop at its start.

# The full resource name: Istio's AuthorizationPolicy (security.istio.io) shares the short name.
COMBINER_POLICY_CR="authorizationpolicies.agent.rossoctl.dev"

# client_ok_rules — read Rego on stdin, print each line that can start a client_ok rule.
# A rule start is each line that names client_ok and starts outside every bracket (a rule head can
# span lines, so a line that is only `client_ok` there is a rule too); unbalanced brackets print the
# whole content, which is not a safe rule. See `_client_ok_rules` in start.py.
client_ok_rules() {
  awk '
    { text = text $0 "\n" }
    END {
      n = length(text); code = ""; depth = 0; bad = 0; raw = 0
      for (i = 1; i <= n; i++) {
        c = substr(text, i, 1)
        if (raw) { if (c == "`") { raw = 0; code = code "``" } else if (c == "\n") code = code c; continue }
        if (c == "`") { raw = 1; continue }
        if (c == "#") { while (i < n && substr(text, i + 1, 1) != "\n") i++; continue }
        if (c == "\"") {
          for (i++; i <= n && substr(text, i, 1) != "\"" && substr(text, i, 1) != "\n"; i++)
            if (substr(text, i, 1) == "\\") i++
          code = code "\"\""
          if (substr(text, i, 1) == "\n") i--
          continue
        }
        code = code c
      }
      m = split(code, lines, "\n")
      for (j = 1; j <= m; j++) {
        line = lines[j]; gsub(/[ \t]+/, " ", line); sub(/^ /, "", line); sub(/ $/, "", line)
        if (depth == 0 && line ~ /(^|[^A-Za-z0-9_])client_ok([^A-Za-z0-9_]|$)/) out[++k] = line
        for (x = 1; x <= length(line); x++) {
          c = substr(line, x, 1)
          if (index("{[(", c)) depth++
          else if (index("}])", c)) depth--
          if (depth < 0) break
        }
        if (depth < 0) break
      }
      if (depth != 0) { gsub(/[ \t\n]+/, " ", text); print text; exit }
      for (j = 1; j <= k; j++) print out[j]
    }'
}

# client_ok_problems <dir> — read the content of one <dir>/request.rego entry on stdin, print each
# reason it can allow a pod that has no client CR (nothing when it cannot). <dir>: inbound | outbound.
client_ok_problems() {
  local dir="$1" rules bad rule
  rules="$(client_ok_rules)"
  if [ -z "$rules" ]; then
    echo "${dir}/request.rego has no client_ok rule"
    return 0
  fi
  bad="$(printf '%s\n' "$rules" | grep -vxF \
    -e "client_ok if data.authbridge.client.${dir}.request.allow" \
    -e "default client_ok := false" || true)"
  [ -n "$bad" ] || return 0
  while IFS= read -r rule; do
    echo "${dir}/request.rego has the rule '${rule}'"
  done <<<"$bad"
}

# combiner_problems <namespace> — print each reason why the `default` AuthorizationPolicy in
# <namespace> fails start check #4, one per line; nothing when it passes. A CR that is missing, or
# that cannot be read, is a problem too, so the check fails closed. Always returns 0, so call it as
# `problems="$(combiner_problems "$ns")"` and test for empty output.
combiner_problems() {
  local ns="$1" err paths dir i path content found
  if ! err="$(kubectl get "$COMBINER_POLICY_CR" default -n "$ns" -o name 2>&1 >/dev/null)"; then
    case "$err" in
      *NotFound*|*"not found"*) echo "the AuthorizationPolicy 'default' is missing in ${ns}" ;;
      *) echo "cannot read the AuthorizationPolicy 'default' in ${ns}: ${err}" ;;
    esac
    return 0
  fi
  if ! paths="$(kubectl get "$COMBINER_POLICY_CR" default -n "$ns" \
      -o jsonpath='{range .spec.policies[*]}{.path}{"\n"}{end}' 2>&1)"; then
    echo "cannot read the AuthorizationPolicy 'default' in ${ns}: ${paths}"
    return 0
  fi
  for dir in inbound outbound; do
    # Every entry of the path, by index: a CR that lists a path two times must not hide a fail-open entry.
    i=0; found=0
    while IFS= read -r path; do
      if [ "$path" = "${dir}/request.rego" ]; then
        found=1
        if ! content="$(kubectl get "$COMBINER_POLICY_CR" default -n "$ns" \
            -o jsonpath="{.spec.policies[${i}].content}" 2>&1)"; then
          echo "cannot read the AuthorizationPolicy 'default' in ${ns}: ${content}"
          return 0
        fi
        printf '%s\n' "$content" | client_ok_problems "$dir"
      fi
      i=$((i + 1))
    done <<<"$paths"
    [ "$found" = 1 ] || echo "${dir}/request.rego is missing"
  done
  return 0
}
