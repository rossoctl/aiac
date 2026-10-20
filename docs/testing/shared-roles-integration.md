# Integration Test: shared roles and scopes — `test_shared_roles.py`

> **One spec among several.** This document specifies a **single** test: the first test of the
> `integration` lane. Test specs live **one spec per test** under `docs/testing/`; the taxonomy is in
> [testing-strategy.md](testing-strategy.md), and the PRD's *Test & evaluation specifications*
> section ([../specs/PRD.md](../specs/PRD.md#test--evaluation-specifications)) is the index.

## Location

`test/integration/policy/computation/test_shared_roles.py`, with the fakes in
`test/integration/policy/computation/fakes.py`. The module has `pytestmark = pytest.mark.integration`.
The path mirrors the main module under test, `aiac.policy.computation`.

Three more files of the lane use the same harness (the `Stack` and the fakes of
`test_shared_roles.py`) and have the same marker. See [The other files of the lane](#the-other-files-of-the-lane).

## Description

The test checks D32 (shared roles and scopes across services, [PRD §5](../specs/PRD.md)) from the
onboarding to the rendered CR. One policy covers the whole realm, so services in different namespaces
(or an admin, in one namespace) share a realm role or a client scope by name. The test checks that:

- every holder of a shared role gets the grants of that role;
- the PRB decides a shared scope one time (the prompt lists a shared scope and a shared role once);
- each owner of a shared scope gets the rule in its own SPM, for its own copy of the scope;
- the holders of a role in a CR (agents and users) are the **current** holders, not the copy from the
  onboarding that stored the rule;
- a user rule (a grant or a deny) on one copy of a shared scope decides only on that copy: the
  inbound of each copy renders the SPM of its own owner.

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
| 1. Across namespaces | `TestAcrossNamespaces` | For three onboarding orders (`agents-first`, `tools-first`, `interleaved`): both agents are sources of each tool CR (allow `source-read`, deny `source-write`); each tool SPM has the rule for its own scope copy. In one fixed order each, the PRB prompt lists a shared scope once (`tools-first`) and a shared role once (`agents-first`). |
| 2. In one namespace | `TestInOneNamespace` | An admin assigns the shared role to `team1/review-agent`. Both holders are sources of the tool CR, with the tool onboarded first or last. |
| 3. User role members | `TestUserRoleMembers` | After the rules are stored, a user gets `developer` and another user loses it. The event path (`rerender_role`) and the resync (a missed event) render the current members, with no PRB run. |
| 4. A later and a removed holder | `TestLaterAndRemovedHolder` | After the rules are stored, an admin gives the shared role to `team1/review-agent` and removes it from `team1/github-agent`. The event path and the resync render the current holders, with no PRB run. |
| 5. Self-mapping across namespaces | `TestSelfMapping` | `team1/github-agent` and `team2/github-agent` hold the shared role and each owns a copy of the shared scope of the same name. For both agent orders: the PRB prompt of both passes gets the shared pair (D32 allows a self-mapping; no filter removes it); the CR of each copy gives every holder the grant, its own copy included. |
| 6. Self-mapping in one namespace | `TestAdminAssignedSelfMapping` | An admin assigns `github-agent`'s role to `team1/review-agent`, and `review-agent` is onboarded again. Both passes of the re-onboarding get a self-mapping pair; both SPMs keep the grant, and each CR gives every holder access, its own skill included. |
| 7. The Provision event of a new holder | `TestProvisionEventOfANewHolder` | The SPM of `team1/review-agent` has an edge of the shared role. Then `team2/github-agent` is provisioned and gets the role. Its onboarding routes no rule to `review-agent`, so only the role-members event of the Provision role mapping puts the new holder into the CR of `review-agent`. The event comes before the onboarding (`event-first`) or after it (`onboarding-first`). |
| 8. Divergent copies of a shared scope | `TestDivergentCopiesOfASharedScope` | The onboarding of one tool grants `developer` on its copy of `github-tool.source-read`. The onboarding of the other tool gives `developer` no rule on its copy. Then `team1/github-agent` is onboarded, and it may call both copies. For each copy that has the grant: only that tool CR has the `developer` entry in `subject_role_allow_scopes`, and `opa eval` on the inbound of each copy (alice through `team1/github-agent`) allows alice on that copy and denies her on the other copy. A grant on one copy and a deny of the same role on the other copy is not in this case: the second onboarding's PRB raises a policy conflict for the pair. |
| 9. A deny on the copies of a shared scope | `TestDenyOnCopiesOfASharedScope` | The team1 copy denies `developer`. The team2 copy grants `tester`, and it also denies `developer` or has no rule for it. alice holds `developer` and `tester`; carol holds `tester` only. Both tool onboarding orders are tested (the PCE reads the SPMs in that order). `opa eval` on the inbound of each copy gives the verdict for each user through `team1/github-agent`. When both copies deny, the SPM of each copy has the deny of `developer`, alice is denied on both copies, and carol is allowed on the team2 copy only. When only the team1 copy denies, alice is denied on the team1 copy and allowed on the team2 copy (through her `tester` grant), and carol is allowed on the team2 copy only. |

The file has 30 tests.

## The other files of the lane

| File | Class | What it checks |
|---|---|---|
| `test_quarantine_lift.py` | `TestTheLiftPutsTheHolderBack`, `TestTheStoreAfterALift`, `TestNoExtraDeploy`, `TestTheReEnableUnderThePceLock` | A failed onboarding of one holder of a shared role quarantines it, and a successful re-onboarding lifts the quarantine (the tests drop the role-members event of the Provision re-map, which Keycloak sends also for a mapping that is already there). Each callee CR of the shared role names the lifted holder again, also a callee that the lift routes no rule to. While every holder of the role is quarantined, the callees keep the edges of the role, and each lift gives the role back to the lifted holder only. The resync after the lift gives the same CRs. The lift writes a stale callee, so a later loss of the role with no event takes the holder out at the next run that touches the callee. The lift of a service that holds no shared role deploys only what its run changed. The re-enable is the `on_applied` of the lift run (under the PCE lock), so a role-members event after the lift keeps the lifted holder. After a failed re-enable (the run raises, and the client stays disabled), the next render takes it out. 10 tests. |
| `test_decommission_shared.py` | `TestALaterHolderIsDecommissioned`, `TestARetriedDecommission` | An admin maps the shared role to `review-agent` after its SPM was written, and the event puts `review-agent` in the CRs. A decommission of `review-agent` takes it out of every CR of the role at once, and writes only the delete of `SPM(review-agent)`. A decommission that fails at the redeploy (one CR patch fails) keeps `SPM(review-agent)`, and its retry takes `review-agent` out of every CR of the role, the tool CRs included. 2 tests. |
| `test_snapshot_repair.py` | `TestADuplicateRuleRepairsTheCr` | A `rerender_role` puts a later holder in the tool CR (no write), and the holder then loses the role with no event. A re-onboarding whose rule on the tool is a duplicate takes the holder out of the CR. 1 test. |

New with the D32 fixes: `test_decommission_shared.py`, `test_snapshot_repair.py`, and in
`test_quarantine_lift.py` the class `TestTheReEnableUnderThePceLock` and the test
`test_a_callee_that_no_lift_routes_a_rule_to_keeps_the_role_while_every_holder_is_quarantined`. The
tests of the decommission gap and of the snapshot repair fail on the code before their fix.
The every-holder-quarantined test pins a path that was already correct: it fails under a mutation of
its path. The whole lane has 43 tests.

## Configuration (env)

None. The lane is offline: no cluster, no LLM endpoint, no environment variables.

## Runbook

```bash
.venv/bin/pytest -m integration          # the whole integration lane
.venv/bin/pytest -m integration -k shared_roles
.venv/bin/pytest -m integration -k "quarantine_lift or decommission_shared or snapshot_repair"
```

The default `pytest` deselects the lane (`addopts` in `pyproject.toml`). See
[`docs/agents/test.md`](../agents/test.md).

## Out of scope

- The live SPI event path (the platform Keycloak image publishes `aiac.apply.role-members.{role-id}`
  since 2026-10-08). The SPI JUnit tests under `keycloak-spi/` cover the publish, and the system lane
  covers the cluster.
- A role held through a group or a composite parent role, and an unmarked user role (known limits of
  D32, PRD §6).
