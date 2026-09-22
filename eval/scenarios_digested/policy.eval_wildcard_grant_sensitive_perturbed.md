Domain knowledge
- Baseline: default-deny — nothing is permitted unless a digested direct grant explicitly allows it.
- Subjects: roles include "manager" (managers).
- Resources: inventory resources ("inventory items", inventory catalog entries).
- Operations: inventory operations include (but are not limited to) inventory:read, inventory:write, inventory:update, inventory:delete, inventory:list.

Policy statements

Direct grants
- Managers may not perform any inventory operations (deny: subjects = managers; operations = inventory operations; resources = inventory resources).

Attribute invariants
- (none)

Role-assignment constraints
- (none)
