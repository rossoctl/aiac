Domain knowledge
- Default-deny baseline: nothing is permitted unless an explicit direct grant allows it.
- Subject roles: "Managers" is a subject role representing all users who hold the manager role.
- Resource classification: "Inventory resources" are all resources whose primary function or type is inventory (e.g., stock items, inventory records, inventory catalogs).
- Operations: "Inventory operations" denotes every operation that acts on inventory resources (including, but not limited to, read, list, create, update, delete, and adjust-stock).

Policy statements

Direct grants
- Managers may perform all Inventory operations on all Inventory resources.

Attribute invariants
- (none)

Role-assignment constraints
- (none)
