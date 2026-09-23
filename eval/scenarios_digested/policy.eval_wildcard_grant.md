Domain knowledge
- Roles: "Inventory manager" — employees whose role is to perform inventory-related duties.
- Resources: Inventory resources — stock items, inventory records, warehouse inventory systems.
- Operations: Inventory operations — read, create, update, and delete actions on inventory resources.
- Policy baseline: default-deny — only actions explicitly allowed by this policy are permitted; anything not mentioned is denied.

Policy statements

Direct grants
- Allow: Subjects = Inventory managers; Operations = all inventory operations; Resources = inventory resources; Conditions = none.

Attribute invariants
- (none)

Role-assignment constraints
- (none)
