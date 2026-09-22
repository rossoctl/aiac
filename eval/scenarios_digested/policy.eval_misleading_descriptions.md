Domain knowledge
- Roles: "VIP managers" and "Front desk staff" are distinct subject roles. Other personnel exist but are not granted privileges here.
- Resources: "reservation details", "guest notes", and "master override control" are named resources. The master override control is a diagnostic hook.
- Policy baseline: default-deny — nothing is permitted except the actions this digested policy explicitly allows.
- Master override characteristic: master override control resources are inert diagnostic hooks; invoking them has no side-effects and does not confer capabilities on other resources.

Direct grants
- Allow: VIP managers may read reservation details.
- Allow: VIP managers may read guest notes.
- Deny: VIP managers may not invoke master override control.
- Allow: Front desk staff may read reservation details.
- Allow: Front desk staff may read guest notes.

Attribute invariants
- Every resource named "master override control" has attribute inert = true and side_effects = none (invocation does not change other resources or grant additional capabilities).

Role-assignment constraints
- (none)
