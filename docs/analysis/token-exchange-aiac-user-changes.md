# token-exchange-aiac vs token-exchange: what changes 
## 1. No routes, no Keycloak config

| | token-exchange | token-exchange-aiac |
|---|---|---|
| No client for the target | Passed through, not exchanged | Passed through, not exchanged. |
| The target's client exists, but it isn't granted to the agent | Passed through, not exchanged | **403** `plugin: "token-exchange-aiac"`. OPA is not consulted. |

**What you notice:** a call that used to go through untouched now fails with 403 if the target has
a Keycloak client. 

## 2. Routes specified, Keycloak configured

| | token-exchange | token-exchange-aiac |
|---|---|---|
| The route | Chose the host, the audience and the scopes | Ignore |
| Target granted as an **optional** scope, and the route asks for it in `token_scopes` | Exchanged | **optional** scopes not supported. |
| Target granted as a **default** scope | Exchanged | Exchanged |
| Extra scopes in `token_scopes` (for example `github-full-access`) | Added to the token | Ignored |

**What you notice:** an exchange that worked can stop when the grant is optional.

## 3. No routes, Keycloak configured

Keycloak configured means all of the following:
- the target's client exists;
- the target is granted to the agent as a **default** scope;

| token-exchange | token-exchange-aiac |
|---|---|
| Passed through, not exchanged. The target got the agent's original token. | **Exchanged** with no extra config. The target gets a token for its own audience. |

**What you notice:** token is always exchanged, never passed through

## 4. Bearer token

Both plugins read the bearer the same way: the same `Bearer ` parsing, the same
`no_token_policy` values (`allow`, `deny`, `client-credentials`) and default
(`deny`), and the same `resolve_placeholders` option.

| Request | token-exchange | token-exchange-aiac |
|---|---|---|
| No bearer, `no_token_policy` unset | 401 | 401 |
| No bearer, `client-credentials` (AIAC's setting) | The workload's `client_credentials` token is sent | The workload's own token is **exchanged** for the target, so the target gets a token for its own audience only |

**What you notice:** nothing, as long as `no_token_policy: client-credentials`
stays set. The 401 body names `auth.unauthorized` instead of
`upstream.token-exchange-failed`.
