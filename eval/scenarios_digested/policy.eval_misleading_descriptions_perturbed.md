Domain knowledge
- Roles: "VIP manager" and "Front desk staff" are subject roles in scope.
- Resources: "reservation_details", "guest_notes", and "master_override_control".
- Operations: "lookup" (reading reservation_details and guest_notes) and "call" (invoking master_override_control).
- Baseline: nothing is permitted unless this policy explicitly permits it (default-deny intent).
- Master override control: a diagnostic hook that performs no privileged side effects and does not confer or imply any additional permissions.

Policy statements

Direct grants
- VIP managers may lookup reservation_details.
- VIP managers may lookup guest_notes.
- VIP managers may not call master_override_control.
- Front desk staff may lookup reservation_details.
- Front desk staff may lookup guest_notes.

Attribute invariants
- master_override_control has attribute no_privilege_escalation: calling it does not grant or imply any other permission.

Role-assignment constraints
- (none)
