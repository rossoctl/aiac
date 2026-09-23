Domain knowledge:
- Roles: "EnrollmentAdvisor" and "Registrar".
- Operations: "read" (includes actions described as "access" or "look up").
- Resources: "enrollment_record" with attribute time_scope ∈ {current, historical}; each enrollment_record pertains to a student.
- Access attributes: each access has a purpose attribute; one recognized value is "advisory".
- Baseline intent: least-privilege — only actions this policy explicitly allows are permitted; any unspecified access is denied.

Direct grants:
1) EnrollmentAdvisor may read enrollment_record
   - Condition: access.purpose = advisory
   - Condition: enrollment_record.time_scope = current

2) Registrar may read enrollment_record
   - Condition: enrollment_record.time_scope ∈ {current, historical}

Attribute invariants:
- If access.purpose = advisory then enrollment_record.time_scope = current.
- enrollment_record.time_scope ∈ {current, historical} (every enrollment_record is labeled current or historical).

Role-assignment constraints:
- (none)
