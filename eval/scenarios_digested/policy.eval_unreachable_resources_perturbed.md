Domain knowledge:
- Roles: front_desk_clerk — employees who staff the facility front desk and interact with patient intake.
- Resources: patient_record — the electronic patient record resource type.
- Operations: read, update.
- Policy baseline: default-deny — nothing is permitted unless explicitly granted by this policy.

Direct grants:
- Allow: subjects = front_desk_clerk; operations = read; resources = patient_record; conditions = none.
- Allow: subjects = front_desk_clerk; operations = update; resources = patient_record; conditions = none.

Attribute invariants:
- (none)

Role-assignment constraints:
- (none)
