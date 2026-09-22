Domain knowledge
- Roles: "Enrollment Advisor" and "Registrar" are subject roles.
- Resources: Student enrollment information resources are typed as enrollment_information and carry an attribute enrollment_phase with values {present, historical}.
- Operations: The principal operation is read (lookup).
- Access attributes: An access carries a purpose attribute; one recognized value is advisory.
- Default allow policy: Nothing is permitted unless an explicit grant in this policy allows it (default-deny baseline).

Direct grants
- Enrollment Advisors may read resources of type enrollment_information when access.purpose = advisory.
- Registrars may read resources of type enrollment_information when resource.enrollment_phase = present.
- Registrars may read resources of type enrollment_information when resource.enrollment_phase = historical.

Attribute invariants
- For any access where access.purpose = advisory and resource.type = enrollment_information, resource.enrollment_phase = present. (In the advisory context, "enrollment information" denotes only the student's present enrollment status.)
- Every enrollment_information resource has enrollment_phase in {present, historical}.

Role-assignment constraints
- (none)
