# Integration Test: shared roles and scopes — `test_shared_roles.py`

> **One spec among several.** This document specifies a **single** test: the first test of the
> `integration` lane. Test specs live **one spec per test** under `docs/testing/`; the taxonomy is in
> [testing-strategy.md](testing-strategy.md), and the PRD's *Test & evaluation specifications*
> section ([../specs/PRD.md](../specs/PRD.md#test--evaluation-specifications)) is the index.

## Location

`test/integration/policy/computation/test_shared_roles.py`, with the fakes in
`test/integration/policy/computation/fakes.py`. The module has `pytestmark = pytest.mark.integration`.
The path mirrors the main module under test, `aiac.policy.computation`.

## Description

The test checks D32 (shared roles and scopes across services, [PRD §5](../specs/PRD.md)) from the
onboarding to the rendered CR. One policy covers the whole realm, so services in different namespaces
(or an admin, in one namespace) share a realm role or a client scope by name. The test checks that:

- every holder of a shared role gets the grants of that role;
- the PRB decides a shared scope one time (the prompt lists a shared scope and a shared role once);
- each owner of a shared scope gets the rule in its own SPM, for its own copy of the scope;
- the holders of a role in a CR (agents and users) are the **current** holders, not the copy from the
  onboarding that stored the rule.

### What runs real, and what is faked

The AIAC code between the library seams is real: the focal-entity resolver, the Service Policy
Builder with the real PRB graphs, the PCE (`compute_and_apply`, `rerender_role`, `resync`) and the
PDP Policy Writer app with its Rego render. The fakes stand in for the services behind the seams:

| Fake | Replaces |
|---|---|
| `FakeRealm` | Keycloak behind the IdP library `Configuration`. It gives the real models in the shapes of the IdP Configuration Service, and it records one role-members event for each role mapping (`REALM_ROLE_MAPPING` create or delete), as the SPI publishes it. |
| `FakeStore` | The Policy Model Store service behind the store library (SPMs as JSON rows, an empty SPM on a 404, the by-role scan). |
| `FakeCluster` | The Kubernetes API behind the writer: the `AuthorizationPolicy` CRs that the real writer app applies. |
| `FakePdp` | The PDP library (`apply_policy`, `replace_policy`, `delete_service_cr`). It sends each policy model to the real writer app in process, so the CRs hold the real Rego. |
| `FakeLlm` | The PRB LLM seam (`_structured_call`). It decides each focal entity from a fixed table and records every prompt. |

The library HTTP transports fail the test if a call gets past a fake, so no call reaches a real
service. The test asserts on the CR content that the writer renders: the Rego maps `source_roles`,
`subject_roles` and the scope maps.

The `Stack` harness drives the real code as the Controller does: `bring_up` provisions a workload,
delivers its role-members events (`rerender_role` for each) and onboards it (`ServicePolicyBuilder`,
then `compute_and_apply` with the clientId as `focus_service`). `drop_role_events` loses the events,
so that the resync must repair the CRs.

## Scenario

Workloads: `team1/github-agent` and `team2/github-agent` (the shared agent realm role
`github-agent.source_operations`), `team1/github-tool` and `team2/github-tool` (the shared client
scopes `github-tool.source-read` and `github-tool.source-write`), and `team1/review-agent`. The user
role is `developer`. The policy: agents that operate on source repositories may read source files and
must not write them; developers may read source files and use the agents of the team.

| Case | Class | What it checks |
|---|---|---|
| 1. Across namespaces | `TestAcrossNamespaces` | For three onboarding orders (`agents-first`, `tools-first`, `interleaved`): both agents are sources of each tool CR (allow `source-read`, deny `source-write`); each tool SPM has the rule for its own scope copy; under agent side, every holder gets the outbound gates. In one fixed order each, the PRB prompt lists a shared scope once (`tools-first`) and a shared role once (`agents-first`). |
| 2. In one namespace | `TestInOneNamespace` | An admin assigns the shared role to `team1/review-agent`. Both holders are sources of the tool CR, with the tool onboarded first or last. |
| 3. User role members | `TestUserRoleMembers` | After the rules are stored, a user gets `developer` and another user loses it. The event path (`rerender_role`) and the resync (a missed event) render the current members, with no PRB run. |
| 4. A later and a removed holder | `TestLaterAndRemovedHolder` | After the rules are stored, an admin gives the shared role to `team1/review-agent` and removes it from `team1/github-agent`. The event path and the resync render the current holders, with no PRB run. |
| 5. Self-mapping across namespaces | `TestSelfMapping` | `team1/github-agent` and `team2/github-agent` hold the shared role and each owns a copy of the shared scope of the same name. For both agent orders: the PRB prompt of both passes gets the shared pair (D32 allows a self-mapping; no filter removes it); under target side, the CR of each copy gives every holder the grant, its own copy included; under agent side, each holder's outbound allows every copy. |
| 6. Self-mapping in one namespace | `TestAdminAssignedSelfMapping` | An admin assigns `github-agent`'s role to `team1/review-agent`, and `review-agent` is onboarded again. Both passes of the re-onboarding get a self-mapping pair; both SPMs keep the grant, and each CR gives every holder access (target side); each holder's outbound allows both skills (agent side). |

Before D32 (on `2069752`), `aiac.policy.computation` has no `rerender_role`, so every test stops in
`Stack.deliver_role_events` with an `AttributeError`. With a no-op `rerender_role` stub, 12 of the
17 tests fail and 5 pass:

- cases 1 and 2 fail by an assertion: an agent that holds the shared role is missing from the
  `source_roles` of the tool CR. Also, the PRB prompt lists a shared scope more than once, and under
  agent side (except in the `tools-first` order) a holder does not get the outbound allow for every
  tool;
- cases 3 and 4 fail: the CRs keep the role holders of the run that stored the rules;
- these pass, because the code before D32 already did them: each owner SPM gets the rule for its
  own scope copy (all three orders), the PRB prompt lists a shared role once, and agent side in the
  `tools-first` order.

## Configuration (env)

None. The lane is offline: no cluster, no LLM endpoint, no environment variables.

## Runbook

```bash
.venv/bin/pytest -m integration          # the whole integration lane
.venv/bin/pytest -m integration -k shared_roles
```

The default `pytest` deselects the lane (`addopts` in `pyproject.toml`). See
[`docs/agents/test.md`](../agents/test.md).

## Out of scope

- The live SPI event path (the platform Keycloak image publishes `aiac.apply.role-members.{role-id}`).
  The SPI JUnit tests under `keycloak-spi/` cover the publish, and the system lane covers the cluster.
- A role held through a group or a composite parent role, and an unmarked user role (known limits of
  D32, PRD §6).
