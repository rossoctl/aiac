Domain knowledge
- Roles: Developer, Tester.
- Resources: source repository, issue tracker.
- Operations: read, write.
- Baseline: default-deny — nothing is permitted unless this digested policy explicitly grants it.

Direct grants
- Allow: Developers may read the source repository.
- Allow: Developers may write the source repository.
- Allow: Testers may read the issue tracker.
- Allow: Testers may write the issue tracker.
- Deny: Developers may not read the issue tracker.
- Deny: Developers may not write the issue tracker.
- Deny: Non-testers may not read the issue tracker.
- Deny: Non-testers may not write the issue tracker.

Attribute invariants
- (none)

Role-assignment constraints
- (none)
