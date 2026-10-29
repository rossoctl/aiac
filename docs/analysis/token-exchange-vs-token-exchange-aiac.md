# `token-exchange` vs `token-exchange-aiac`

AuthBridge's outbound leg (`app → parsers → <exchange plugin> → opa → destination`) now uses
`token-exchange-aiac` in place of `token-exchange`. `k8s/opa-kind-enable.sh` wires it.
`k8s/opa-kind-verify.sh` checks that the outbound leg has exactly one `token-exchange-aiac` and no
`token-exchange`.

## The core difference

| | `token-exchange` (before) | `token-exchange-aiac` (now) |
|---|---|---|
| Which hosts get exchanged | Only hosts listed in the `authproxy-routes` ConfigMap. Every other host passes through. | Every in-cluster host. Keycloak decides whether the host is a target. |
| How the audience is chosen | The route's `target_audience` | Derived from the Host header: `spiffe://<td>/ns/<namespace>/sa/<service>` |
| `scope` in the RFC 8693 request | Sent when the route sets `token_scopes` | Never sent, so only the caller's **default** client scopes apply |
| Config | `default_policy: passthrough`, `identity: client-secret`, plus routes | `audience_template`, `namespace` (for short host names), `no_token_policy: deny` (the default, as in `token-exchange`). Unknown keys are rejected. |
| How to add a target | Edit `authproxy-routes`, then restart the agent (routes are read once at startup) | Change Keycloak only. No restart is needed, except to clear a cached "unknown audience" (5 min): a caller that called the target before its client existed keeps passing through un-exchanged for up to 5 min, so restart it. |
| Default behaviour | Pass through | Exchange |
| Reading the bearer | `auth.ExtractBearer`, `resolve_placeholders` | The same: `auth.ExtractBearer`, `resolve_placeholders` |
| `no_token_policy` | `allow` / `deny` / `client-credentials`, default `deny` | The same values and default |

## Cases where behaviour changed

| Case | Before (`token-exchange`) | Now (`token-exchange-aiac`) |
|---|---|---|
| In-cluster host with no route | Passed through, no `identity` or `delegation` | Exchanged if Keycloak grants the derived audience to the caller |
| Host outside the cluster (LLM API, telemetry, IP literal) | Passed through (no route) | Passed through, Keycloak is not asked (`skip / host_not_in_cluster`) |
| Keycloak has **no client** for the destination | Passed through when there was no route. With a route, the exchange failed (503). | Passed through and remembered for 5 min (`skip / audience_unknown`) |
| Client exists but is **not granted** to the caller | Passed through when there was no route. With a route, 503. | **403**, `plugin: "token-exchange-aiac"`, `policy.forbidden`. OPA is not consulted. |
| Keycloak down, timeout, or bad credentials | 503 `upstream.token-exchange-failed` | 503 `upstream.token-exchange-failed` (`deny / exchange_failed`). Unchanged. |
| Sidecar credentials not yet in `/shared/` | Not covered by the old docs | 503, and the pod is held not-ready (`credentials_not_ready`) |
| Request with **no** bearer | Chart default (no `no_token_policy` was set): `deny`, 401. | AIAC sets `deny` (the default): a target answers 401 `auth.unauthorized` (`token-exchange` sends `upstream.token-exchange-failed` for the same 401). A destination with no Keycloak client still passes through. `client-credentials` is not used: it would let any process in the pod that sends no bearer reach a target as the agent. |
| Target granted only as an **optional** client scope | Worked, because the route asked for the scope through `token_scopes` | 403 (`audience_not_granted`). The scope must be a **default** scope. |
| Extra scope the target reads (for example `github-full-access`) | Asked for in the route's `token_scopes` | Must be a default scope of the caller's client |
| Service name ≠ ServiceAccount name (demo `MCP_URL` host `github-tool-mcp`, its plain hand-made client ID `github-tool`, not a SPIFFE ID) | Exchanged through the route `github-tool-mcp → github-tool` | The derived audience names no client, so the call **passes through un-exchanged**. The fix is on the tool's side: a ServiceAccount `github-tool-mcp` and an enrollment, so the operator registers `…/sa/github-tool-mcp` (rossoctl/cortex#1540). Do not point `MCP_URL` at `github-tool`: that is the UC-1 stub. |
| Short host name | Not applicable (the route named the audience) | The namespace is the calling pod's own, read from its service-account mount (`namespace_file`) |
| Outbound `input.identity.subject` | Best-effort decode of the incoming bearer's `sub`, unverified, so the workload can choose it | `sub` of the token Keycloak issued: the user, or `service-account-<clientId>` when there was no bearer |
| Outbound `input.identity.scopes` | Scopes of the minted token, per target | The issued token's `scope` claim. It lists **all** of the caller's default scopes, so don't treat it as per-target. |
| `input.delegation` hop `strategy` | `"token-exchange"` | `"token-exchange-aiac"` |

## What changed in this repo

- **Demo agent** (`demo/assets/agents/github_agent/k8s/`): the `authproxy-routes` ConfigMap is
  removed, and the wiring invariant is now *Service = ServiceAccount = Keycloak client*.
- **UC-1 harness** (`test/system/uc1_onboard.py`):
  - `ensure_github_tool_route` is removed.
  - `grant_exchange_scope` assigns the tool's `*-aud` scope as a **default** scope, not an optional
    one.
  - `restart_agent` now restarts the agent to clear the unknown-audience cache, not to reload
    routes.
  - `exchange_token` sends no `scope` by default.
- **Outcome classification** (`test/system/launcher.py`):
  - `is_exchange_refusal` accepts either plugin name, or `upstream.token-exchange-failed`, and
    classifies that as `error`.
  - `is_opa_deny` counts only `plugin == "opa"`, because `token-exchange-aiac` also answers
    `policy.forbidden`.
- **Docs**: the PRD, the OPA writer spec, the demo specs, the runbook (new *Outbound token exchange*
  section) and the testing docs now describe the route-less model.
