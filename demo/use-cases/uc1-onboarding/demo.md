# UC-1: Onboarding an agent and a tool

**Nobody wrote these access rules.** AIAC discovered a GitHub agent and a GitHub tool already
running in the cluster, read a two-line plain-English policy, and generated enforceable
least-privilege authorization for both — who may call the agent, and which of the tool's operations
a user may call through the agent.

## The policy

This is the entire input a human wrote. No YAML, no scope tables, no per-endpoint rules:

```
Grant access on a least-privilege basis: allow only what this policy states; deny by default.

- Developers may read and modify source, and read issues.
- Testers may read and modify issues.
```

## What comes out the other side

AIAC writes one `AuthorizationPolicy` CR per managed service — one for the agent and one for the
tool — derived from the policy text plus the realm-role descriptions already in Keycloak and the
tool's own discovered capabilities. Each CR carries two Rego packages, with the fixed AuthBridge
names (`authbridge.client.{inbound,outbound}.request`) the live OPA plugin evaluates. Under the
default **target side** enforcement, each service checks the calls to itself:

- `github-agent`'s inbound package decides who may call the agent (`input.identity.subject`);
- `github-tool`'s inbound package decides each tool call — which user may call which tool, and
  through which agent (`input.identity.subject`, `input.identity.client_id`,
  `input.mcp.params.name`);
- the outbound package of every service is a pass-through (`allow := true`): the callee decides.

An excerpt of the generated tool inbound package:

```rego
package authbridge.client.inbound.request
import rego.v1

owned_tools := ["source-read", "source-write", "issues-read", "issues-write"]

subject_roles := {
    "dev-user": ["developer"],
    "test-user": ["tester"],
}
source_roles := {
    "spiffe://localtest.me/ns/team1/sa/github-agent": ["github-agent.source_operations", "github-agent.issue_operations"],
}
subject_role_allow_scopes := {
    "developer": ["source-read", "source-write", "issues-read"],
    "tester": ["issues-read", "issues-write"],
}
source_role_allow_scopes := {
    "github-agent.source_operations": ["source-read", "source-write"],
    "github-agent.issue_operations": ["issues-read", "issues-write"],
}

tool_ok(tool) if {
    subject_allows(tool)
    source_allows(tool)
    not subject_denies(tool)
    not source_denies(tool)
}
default allow := false
allow if { input.mcp.method == "tools/call"; tool_ok(input.mcp.params.name) }
```

Every tool call is a two-gate AND on the same invoked tool (`input.mcp.params.name`, the **bare**
MCP tool name such as `source-read`): the calling user's role must be granted the tool
(`subject_allows`), *and* the calling agent's own roles must reach it (`source_allows`, keyed by the
agent's clientId in `input.identity.client_id`); a deny on either gate vetoes it. A developer can
read and write source and read issues; a tester can read and write issues but never touches source
— exactly the two-line policy, and nothing it didn't say.

Under **agent side** enforcement (`AIAC_ENFORCEMENT_SIDE=agent-side`), the same per-tool check is in
`github-agent`'s outbound package instead (keyed by the exchange target
`input.identity.service_id`), and `github-tool` gets a pass-through CR. The demo reads the side from
the captured CRs (see [How the demo sources the generated Rego](#how-the-demo-sources-the-generated-rego)).

## Running it

Everything below is a real cluster, a real Keycloak, a real LLM call, and a real RFC 8693 token
exchange — there is no offline mode. Bring up a rossoctl cluster with SPIRE + Keycloak + the
rossoctl operator first (see [../../assets/INSTALL.md](../../assets/INSTALL.md) and
[../../../k8s/aiac-deployment-guide.md](../../../k8s/aiac-deployment-guide.md) for reference, not as a
manual checklist — `make prereqs` below verifies and, where safe, installs what's missing).

You do **not** need to export the Keycloak variables by hand. `make keycloak`
(`init/00-discover-keycloak.sh`) port-forwards the in-cluster Keycloak to a local port and reads the
admin credentials from the `keycloak-admin-secret`, exporting `KEYCLOAK_URL` /
`KEYCLOAK_ADMIN_USERNAME` / `KEYCLOAK_ADMIN_PASSWORD` for the step that runs it. Every
Keycloak-touching target self-runs it first, so you rarely call it directly — the forward is set up
once and reused across the run. If you already export those three variables (e.g. to point at a
Keycloak this can't reach), your values win.

```bash
make keycloak  # (optional) port-forward Keycloak + discover admin creds; the targets below self-run it
make prereqs   # verify/install cluster + AIAC stack + demo workloads; wait for Keycloak registration
make clear     # reset to a clean slate
make setup     # provision demo users/roles, mount policy.md, configure token exchange
```

To tear down the port-forward afterwards: `pkill -f 'port-forward .*keycloak-service'`.

**Pause 1 — baseline.** `make show` reports three users with roles, no `github-*` roles or scopes
yet, and no generated `.rego` at all. Nothing has been onboarded; there is nothing to enforce yet.

```bash
make agent   # AIAC discovers github-agent, reads policy.md, writes the agent's CR (its inbound gate)
make show
```

**Pause 2 — the agent alone.** The agent's inbound gate is now populated: developers and testers
can reach the agent's discovered scopes. The agent's outbound package is a pass-through. The tool
has no CR yet — it is not onboarded, so there is no tool call to allow. (Under the changed combiner,
D20, a pod with no CR is denied.)

```bash
make tool    # AIAC discovers github-tool's capabilities and writes the tool's CR (its inbound gate)
make show
```

**Pause 3 — both onboarded.** `make diff PRIOR=01-after-agent`
shows the tool's CR appear: its inbound gate, with the user gate (`subject_role_allow_scopes`), the
calling-agent gate (`source_roles` keyed by the agent's SPIFFE identity), and per-role grants for
every discovered tool. The agent's CR does not change. This is the moment least-privilege access to
a downstream tool exists — generated, not hand-written.

Now drive real users through it:

```bash
make dev      # dev-user: read a file, commit a fix, read an issue (allowed) / close an issue (denied)
make test     # test-user: read/file issues (allowed) / read source (denied)
make devops   # devops-user: blocked at the inbound gate — no role sources any agent scope
```

Each target does a real `grant_type=password` login, checks the agent's inbound gate, performs a
real RFC 8693 token exchange for the tool's audience, and checks the tool-call gate per intent — the
tool's inbound package under target side, the agent's outbound package under agent side — printing a
result table. `devops-user`'s inbound denial is the intended story, not a failure: nothing in the
policy grants devops-user access to the agent at all.

### One-shot: `make demo`

The individual targets above are grouped into three phase aggregates, so you can run a whole phase
at once or the entire demo end to end:

| Phase target | Steps | What it does |
|--------------|-------|--------------|
| `make init`    | `00`–`03` | discover Keycloak → verify prereqs → clear → setup |
| `make onboard` | `04`–`05` | onboard the agent, then the tool |
| `make run`     | —         | drive all three users (developer, tester, devops) |

`make demo` chains all three (`init → onboard → run`) with no narrated pauses — use it when you just
want the full run:

```bash
make demo     # init (00-03) -> onboard (04-05) -> run (dev/test/devops)
```

Or drive one phase — or one user — at a time:

```bash
make init     # or step-by-step: make prereqs / clear / setup
make onboard  # or: make agent / make tool
make run      # or a single user: make dev / make test / make devops
```

## Architecture

```
 dev-user/test-user/devops-user
        │  grant_type=password
        ▼
   Keycloak  ──────────────────────────────┐
        │  access_token                    │ RFC 8693 token exchange
        ▼                                  │ (subject token -> tool-audience token)
  [agent inbound gate: may this user       │
   call the agent? — github-agent's CR]    │
        │                                  ▼
        ▼                            [tool inbound gate: may this user call
   github-agent ── outbound:          this tool, through this agent? —
        │          pass-through       github-tool's CR, from policy.md + tool capabilities]
        │                                  │
        └──────────────────────────────────┴──► github-tool
```

The gates are plain Rego, evaluated with `opa eval` against the policy content AIAC's writer
produces — this demo runs them the same way a live enforcement point would query them, but does
not itself sit in the request path (see the appendix).

### How the demo sources the generated Rego

The reworked PDP Policy Writer is **CR-backed**: for each managed service — agent and tool — it
server-side-applies one `AuthorizationPolicy` custom resource (`agent.rossoctl.dev/v1alpha1`, named
`<name>` in namespace `<ns>` — here `github-agent` and `github-tool` in `team1`) whose
`spec.policies[]` carry the inbound and outbound Rego as `content`. In production it writes **CRs
only** — no `.rego` files on disk (`k8s/pdp-interface-deployment.yaml` keeps
`POLICY_WRITER_DUMP_REGO` off and mounts no `/rego`).

So this demo reads its Rego **straight from the CRs** — the same artifact a live enforcement point
consumes — rather than from a debug file dump:

```bash
kubectl get authorizationpolicies.agent.rossoctl.dev github-agent github-tool -n team1 -o json
```

`onboard/04`/`05` fetch those CRs (the tool's exists only after `make tool`) and write each
`spec.policies[].content` into `generated/<snapshot>/team1/<name>/{inbound,outbound}/request.rego`
(mirroring the CR's `policies[].path`), then `opa eval` those files. `make clear` deletes both CRs
(a re-onboard server-side-applies fresh ones). This keeps the demo honest against the real artifact
and needs no demo-only deployment overlay to re-enable the optional `.rego` dump.

The run targets read the enforcement side from the captured CRs: if `github-agent`'s outbound
package is a pass-through (`allow := true` and no other rule), the side is target side and
`github-tool`'s inbound package decides each tool call; else the side is agent side and
`github-agent`'s outbound package decides it.

> The snapshots under `generated/` are not committed (`.gitignore`): each `make agent` / `make tool`
> captures them again from the live CRs, which are the authoritative source of truth.
> `docs/examples/opa-team1-policy.yaml` shows the two target-side CRs of this scenario as the **real**
> generator (`src/aiac/pdp/service/policy/opa/rego.py`) renders them. The after-tool snapshot under
> target side has the same packages, modulo the list order that the PRB gives and the cluster's
> actual trust domain.

## Troubleshooting

- **`make prereqs` hangs waiting on client registration** — Keycloak client registration is async
  after the operator injects a workload; give it a couple of minutes, then check the operator's
  webhook logs.
- **`make agent`/`make tool` times out** — onboarding drives the Policy Rules
  Builder's LLM calls and can genuinely take minutes; re-run with a larger `AIAC_ONBOARD_TIMEOUT` if
  your LLM endpoint is slow.
- **`make setup` / `make dev` fails with a Keycloak profile error** — Keycloak 26's declarative user
  profile requires `email`/`firstName`/`lastName` before `grant_type=password` succeeds; `03-setup.py`
  sets these, so this points at a realm that was provisioned some other way.
- **A `run-*` target aborts with "no policy found"** — the drivers always run against
  `generated/02-after-tool/`; run `make agent && make tool` first.

## Appendix: known gaps

- The generated Rego is enforced by evaluating it directly with `opa eval`, mirroring how a gateway
  would query it — this demo does not itself sit in front of live agent/tool traffic (that gateway
  integration is separate, ongoing work).
- `run-*.py` performs a real token exchange to prove the RFC 8693 flow end to end, but does not feed
  the exchanged token into a live call against `github-tool` — the tool-call verdict is read from the
  same generated Rego, not from an intercepted request.
