Domain knowledge
- Roles: "front desk clerk" is a subject role.
- Resources: "patient records" is a resource class (sensitive health records).
- Operations: read, update.
- Baseline: default-deny — nothing is permitted unless this digested policy explicitly grants it.

Policy statements

Direct grants
- Front desk clerks may not read patient records.
- Front desk clerks may not update patient records.

Attribute invariants
- (none)

Role-assignment constraints
- (none)
