Domain knowledge
- Subjects: roles include "Enrollment Advisor" and "Registrar".
- Resources: "Present enrollment status" and "Historical enrollment record"; these are both forms of "enrollment information".
- Operations: "lookup" (read/view) on enrollment information.
- Baseline: default-deny — nothing is permitted unless an explicit allow grant appears in this policy.

Direct grants
- Enrollment Advisors may not lookup any enrollment information (includes both Present enrollment status and Historical enrollment record).
- Registrars may lookup a student's Present enrollment status.
- Registrars may lookup a student's Historical enrollment record.

Attribute invariants
- (none)

Role-assignment constraints
- (none)
