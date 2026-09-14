# Digested Policy

This document is the committed specification of the **digested-policy** language:
the domain knowledge a policy relies on, the kinds of statements you can write,
and how contradictory statements among them are found and handled. It is a
general description of the language, illustrated throughout with a single running
example — a company with employees, roles, and resources. It is inspired by
[Big ACL](https://big-acl.com).

This spec supersedes the root `DigestedPolicy.md` prototype.

## Terminology

- **Source policy** — the original, human-authored authorization policy as
  provided: free natural-language prose (for example, the text held in the RAG
  knowledge base). It is the raw input a digest is derived from.
- **Digested policy** — a structured restatement of a source policy's intent in
  the language this document defines: domain knowledge plus the three statement
  kinds below. It is an **authoring-layer** artifact — it sits upstream of the
  AIAC rule engine's `PolicyRule`s, which are computed from a digested policy
  only after it has been found conflict-free.

The conflict semantics in this spec are **authoring-layer** semantics: they
describe how a *single digested policy's own statements* combine into intent.
They are distinct from the **engine-layer** conflict semantics that govern
collisions *across* independently authored sources and Policy Rules Builder
passes (see the engine-layer decision
[identify conflicts, never reconcile](components/aiac-agent/policy-rules-builder.md#design-decision-identify-conflicts-never-reconcile)).
Why the two layers may diverge in the future — and why they behave identically
today — is recorded below under
[Design decision: authoring vs engine conflict semantics](#design-decision-authoring-vs-engine-conflict-semantics).

## Policy structure

A policy is made up of three parts:

- Domain knowledge — the concepts the policy talks about.

- Policy statements — the rules that make up the policy, in three categories.

- Conflict detection and resolution — how contradictory statements are found and
  settled.

### Domain knowledge

Domain knowledge — a description of the concepts — including, but not limited to,
subjects, resources, and operations — that are specific to the domain the policy
applies to. It may combine common knowledge with specific data provided by the
customer.

In the running example, the domain knowledge includes the following facts:

- Roles and domains. Every employee role belongs to one or more of the following
  domains: customer-facing, technical, headquarters, and legal and compliance.
  Customer-facing personnel are all employees who come into direct contact with
  clients. Technical personnel are all employees who manage the office hardware
  and software.

- Resources. Every company resource has a department affiliation, a sensitivity
  assignment, and a tier allocation.

- Access monitoring. Every company resource is monitored for read, write, and
  maintenance access. Each access carries the requester's location and an access
  timestamp.

- Office hours. Office hours are 9 AM to 5 PM, Monday to Friday.

- Employee status. An employee's status is one of: contractor, regular, or
  manager.

### Policy statements

Policy statements come in three kinds:

- Direct grants — who may do what to which resources.

- Attribute invariants — constraints on the attributes of a single entity.

- Role-assignment constraints — which roles a single user may not hold at once.

#### Direct grants

Direct grant — a statement that some subjects may — or may not — perform some
operations on some resources, optionally subject to conditions. A direct grant
must reference subjects, operations, and resources, together with any conditions
required for the grant to be allowed or denied.

Rules for direct grants:

- A grant with no conditions is an unconditional grant.

- Conditions may address known attributes of the request — including attributes
  of the subject, the resource, and the access — and conditions are themselves
  unconditional (a condition cannot depend on another condition).

- Direct grants are independent — of each other, of history, and of the
  environment.

- A grant cannot be defined by reference to another grant. For example, you
  cannot write "Developers may write every resource testers can read."

- A grant cannot carry an open-ended exception. For example, you cannot write
  "Developers may access all resources deployed on the development tier unless
  specified otherwise."

- No exclusive language. You cannot write "Only technical personnel may access
  issues." Express exclusivity as two direct grants instead: "Technical personnel
  may access issues" and "Non-technical personnel may not access issues."

Allowed examples:

- Developers may access source code.

- Testers may not write issues.

- Customer-facing personnel may read pricelists.

- Employees in the HR department may access personal data records from protected
  terminals during office hours.

- Managers may view sensitive financial data.

Not allowed — and why:

- "Developers may write every resource testers can read" — defines a grant by
  reference to another grant, so it is not independent.

- "Developers may access all resources deployed on the development tier unless
  specified otherwise" — an open-ended exception that depends on other
  statements.

- "Only technical personnel may access issues" — exclusive language; split it
  into two direct grants (see the rule above).

#### Attribute invariants

Attribute invariant — a constraint on the attributes of a single grant actor — a
subject, a resource, or an access — and on the relationships between those
attributes. An attribute invariant stands on its own, independent of any
particular grant.

Examples:

- Managers may not be contractors (assuming manager and contractor are
  independent attributes).

- All HR data is sensitive.

- No accesses are permitted from protected terminals outside of office hours.

#### Role-assignment constraints

Role-assignment constraint — a rule that limits how real users map to
subject-roles. Role-assignment constraints express incompatible subjects only —
which roles a single user may not hold at the same time. This is classically
known as separation of duties.

Examples:

- Administrators may not hold any additional organizational roles.

- Developers and testers are mutually exclusive roles.

## Conflict detection

Conflict detection operates at the **authoring layer**: it examines a single
digested policy's own statements and reports the contradictions among them. It is
distinct from the engine-layer collision detection described in
[identify conflicts, never reconcile](components/aiac-agent/policy-rules-builder.md#design-decision-identify-conflicts-never-reconcile),
which examines `(role, scope)` `PolicyRule`s produced across independent sources.

Detection recognizes one **named conflict** and two further **violation
classes**. Only the first is called an *authoring-layer conflict*; the other two
are reported as their own kinds so their remedy stays clear.

### Authoring-layer conflict — opposite-effect overlapping direct grants

An **authoring-layer conflict** is two direct grants with opposite effect — one
allows, one denies — whose *subjects*, *operations*, and *resources* all overlap.
On the overlap, the same subject performing the same operation on the same
resource is at once permitted and prohibited, and the policy does not say which
wins.

Overlap is evaluated on the statements' referenced sets after domain knowledge is
applied (a grant that names a role covers every subject in that role; a grant
that names a resource attribute covers every resource carrying it). Two grants
whose conditions can never be simultaneously true do not overlap and are not a
conflict.

Running example — a conflict:

- "Testers may not write issues" and "Testers may write issues" — identical
  subjects, operation, and resource with opposite effect.

Running example — *not* a conflict:

- "Testers may not write issues" and "Testers may read issues" — different
  operations; the referenced sets do not overlap.

### Violation class — dead (vacuous) grant

A **dead grant** is a direct grant whose condition an *attribute invariant*
renders unsatisfiable, so the grant can never fire. It is not a contradiction
between two grants; it is a grant that the domain's invariants have already
emptied.

Running example:

- Grant "Managers who are contractors may view sensitive financial data" against
  the invariant "Managers may not be contractors" — no subject can satisfy the
  condition, so the grant is dead.

### Violation class — unsatisfiable invariant or breached role-assignment set

Two further contradictions are reported against the constraint statements
themselves, not against grants:

- **Unsatisfiable attribute invariants** — a set of attribute invariants that no
  entity can jointly satisfy (for example, one invariant requiring an attribute
  another forbids).

- **Breached role-assignment constraint** — a role-assignment constraint that a
  required subject mapping would violate, i.e. a separation-of-duties rule that
  the rest of the policy forces to be broken (for example, a design that requires
  one user to hold both "developer" and "tester" while those roles are declared
  mutually exclusive).

## Conflict resolution

**There is no automatic conflict resolution.** When conflict detection finds an
authoring-layer conflict (or either violation class above), the digest **reports
it and is not applied**. A human corrects the *source policy* — by removing the
contradiction, narrowing the overlapping grants, or relaxing the invariant — and
the corrected source policy is re-digested. The authoring layer never picks a
winner between two contradictory statements on the author's behalf.

This makes the authoring layer's behaviour, today, identical to the engine's
`identify-never-reconcile` principle: identify the contradiction, surface it,
apply nothing.

### Reserved: deny-overrides (future)

A future revision may let a digested policy resolve an opposite-effect grant
overlap by **deny-overrides** — where an allow-grant and a deny-grant overlap,
the deny wins — with default-deny as the baseline (nothing is permitted unless a
grant allows it). Big ACL leaves this tie-break to its compilation target
(Cedar's *forbid-overrides*) and publishes no combining algorithm of its own;
default-deny plus deny-as-exception is the closest documented stance.

Such a rule would belong **only at this authoring layer** and never at the
engine, because deny-overrides is legitimate only where a single author has
stated how their own statements combine. The engine operates across
independently authored sources where no such combining rule was ever authored,
and so must never reconcile. The full argument — why the resolution rule may
evolve here but not at the engine, and why both layers behave identically until
then — is the next section.

## Design decision: authoring vs engine conflict semantics

The digested-policy conflict semantics above and the AIAC rule engine's
[identify conflicts, never reconcile](components/aiac-agent/policy-rules-builder.md#design-decision-identify-conflicts-never-reconcile)
principle both detect contradictions, and **today both behave identically** —
identify the contradiction, surface it, apply nothing. This section records why
they are nonetheless two distinct layers: the **authoring layer** is the only one
that may ever evolve past identify-and-report to *resolve* conflicts (for example,
by deny-overrides), while the **engine layer** must remain identify-never-reconcile
permanently. The distinction is an asymmetry of *permitted future evolution*, not
a difference in current behaviour.

The reason is **who owns the intent, and over what scope**:

- An **authoring-layer conflict** lives *within a single digested policy* — one
  authored artifact, one author. A combining rule like deny-overrides is itself a
  statement of that author's intent, so resolving an opposite-effect grant overlap
  by "deny wins" would honour a rule the author could legitimately state.
  Resolution here is therefore *conceivable* — reserved as future work rather than
  adopted, but conceivable.

- An **engine-layer conflict** lives *across* independently authored sources and
  Policy Rules Builder passes (within-batch Door B, and cross-service) — an
  `Allow` from one pass and a `Deny` from another on the same `(role, scope)`
  pair. No single author ever stated how those pieces combine. Picking a winner
  there would bury that ambiguity behind a rule the author never stated.
  Resolution here is never legitimate.

So the same refuse-and-report behaviour that both layers show today rests on
different foundations: the engine refuses because reconciling un-authored
collisions would fabricate intent, and it always will; the authoring layer
refuses because we have not *yet* built the authored combining rule that would let
it resolve. A well-formed (conflict-free) digested policy is reported clean before
it is compiled to `PolicyRule`s, so it never itself produces an engine-layer
conflict; the engine's detection then guards only the cross-source collisions the
authoring layer cannot see.

### Consequences

- The **Conflict resolution** section above is deliberately a *reserved-future*
  section, not an unfinished one: it states a definite report-only decision for
  today and names deny-overrides as the reserved direction. It is complete.
- Any future deny-overrides (or other combining rule) is authored and applied
  **within the digest**, upstream of rule compilation — never in the engine, and
  never as a cross-source precedence. The engine's identify-never-reconcile
  principle is unchanged and unaffected by this reservation.
- "Conflict" without qualification continues to mean the **engine-layer**
  `(role, scope)` collision (see `CONTEXT.md`). The within-policy notion is always
  written **authoring-layer conflict** to keep the two from being confused.
