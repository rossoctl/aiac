# Local issue: Keycloak `basic` client scope missing from declarative realm provisioning

**Status:** diagnosed, fix not yet applied. Parked 2026-09-03, pick up whenever.

**Not filed to any GitHub tracker** — this spans two repos
(`s-and-p-team/kagenti` and `s-and-p-team/kagenti-operator`) with no
documented issue-tracking convention for either (unlike `cortex/aiac`, which
tracks on `s-and-p-team/cortex`, see `cortex/aiac/docs/agents/issue-tracker.md`).
File to whichever tracker(s) make sense once ready to act.

## Root cause

Every access token issued by the `rossoctl` Keycloak realm is missing the
`sub` claim (confirmed realm-wide, not client-specific — a throwaway vanilla
client with zero custom config showed the same gap; `/userinfo` correctly
returns `sub` because Keycloak computes that from the authenticated session
directly, independent of protocol-mapper config, but the access token
strictly follows protocol-mapper config).

Cause: Keycloak's built-in `basic` client scope (which normally carries the
"Subject (sub)" `oidc-sub-mapper`) is a special scope that Keycloak's Admin
Console realm-creation wizard auto-creates, but which does **not** get
backfilled by a realm import/`--import-realm` that hand-authors its
`clientScopes` array. This realm is provisioned that way, in two duplicated
locations:

- **Kind/Helm path**: `rossoctl/charts/rossoctl-deps/templates/keycloak-realm-init.yaml` — Helm template rendering a ConfigMap consumed via Keycloak's `--import-realm` flag
- **OpenShift/operator path**: `operator/operator/internal/bootstrap/keycloak.go:629-838` (`const realmTemplate`, built into a `KeycloakRealmImport` CR by `buildRealmSpec` at line 431)

Both files explicitly enumerate `clientScopes` as exactly six entries —
`openid`, `email`, `profile`, `roles`, `web-origins`, `rossoctl-platform-audience`
— and list the same six in `defaultDefaultClientScopes`. Neither references
`basic` or a `sub`/"Subject" protocol mapper anywhere. Confirmed via
`/admin/realms/rossoctl/client-scopes`: 14 scopes total (the six above, plus
`offline_access` and the `github-tool.*`/`github-agent.access` scopes AIAC
added at runtime) — no `basic`.

Ruled out as the cause: the AIAC Keycloak SPI jar — decompiled
`META-INF/services`, it only registers an `EventListenerProviderFactory`
(plus bundled BouncyCastle providers), nothing that touches token building.

## Fix

Add a `basic` client scope with an `oidc-sub-mapper` (protocol mapper
type `oidc-sub-mapper`, mapping the user's `id` to the `sub` claim), and add
`"basic"` to `defaultDefaultClientScopes`, in **both** of the files above.
Mechanical and low-risk, but must be applied identically in both — the Kind
and OpenShift install paths would otherwise drift.

## Acceptance criteria

- [ ] `basic` scope + `oidc-sub-mapper` added to `keycloak-realm-init.yaml`
- [ ] Same scope + mapper added to the `realmTemplate` constant in `operator/operator/internal/bootstrap/keycloak.go`
- [ ] Fresh realm provisioned via each path (Kind and OpenShift) issues an access token containing `sub`
- [ ] No regression in existing token consumers that might have been (incorrectly) relying on `sub`'s absence

## Related

- Independent, separately-broken bug that this does NOT fix on its own: even once `sub` is present, AIAC's generated Rego still won't match it, because it keys `subject_roles` by Keycloak username, not `sub`. See `cortex/aiac/docs/handoffs/01-subject-identity-mismatch.md`.
