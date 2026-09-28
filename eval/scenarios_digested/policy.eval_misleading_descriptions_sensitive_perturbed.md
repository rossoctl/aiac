Domain knowledge
- Roles: VIP managers; front desk staff; other employees (every employee is either front desk staff or non-front-desk personnel).
- Resources: reservation_details, guest_notes, master_override_control.
- Operations: read (lookup), call (invoke).
- Baseline: default deny — nothing is permitted unless this policy explicitly allows it.

Direct grants
- Non-front-desk personnel may read reservation_details.
- Non-front-desk personnel may read guest_notes.
- VIP managers may read reservation_details.
- VIP managers may read guest_notes.
- VIP managers may not call master_override_control.
- Front desk staff may not read reservation_details.
- Front desk staff may not read guest_notes.

Attribute invariants
- Invoking master_override_control does not grant, imply, or confer read access to reservation_details or guest_notes.
- master_override_control is a diagnostic resource with no side-effects that change subject privileges.

Role-assignment constraints
- (none)
