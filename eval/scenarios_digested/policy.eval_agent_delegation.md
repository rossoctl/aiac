Domain knowledge
- Roles: "shipment-coordinator" and "dock-worker".
- Resources:
  - shipment_manifest — the manifest document associated with a shipment.
  - shipment — the shipment entity for which customs clearance may be carried out.
- Operations:
  - create_manifest (create a shipment_manifest).
  - update_manifest (update a shipment_manifest).
  - initiate_customs_clearance_on_behalf (arrange or authorize customs clearance to be carried out on a shipment's behalf).
- Access attributes:
  - coordinated_process (boolean): true when the action is performed as part of a coordinated process.
- Baseline: least-privilege / default-deny — only actions explicitly allowed by these statements are permitted.

Direct grants
- Allow: Subjects in role shipment-coordinator may perform create_manifest on resources of type shipment_manifest.
- Allow: Subjects in role shipment-coordinator may perform update_manifest on resources of type shipment_manifest.
- Allow: Subjects in role shipment-coordinator may perform initiate_customs_clearance_on_behalf on resources of type shipment when the access attribute coordinated_process = true.
- Allow: Subjects in role dock-worker may perform create_manifest on resources of type shipment_manifest.
- Allow: Subjects in role dock-worker may perform update_manifest on resources of type shipment_manifest.
- Deny: Subjects in role dock-worker may not perform initiate_customs_clearance_on_behalf on resources of type shipment.
- Allow: Subjects in role shipment-coordinator may perform read_manifest on resources of type shipment_manifest.
- Allow: Subjects in role dock-worker may perform read_manifest on resources of type shipment_manifest.

Attribute invariants
- coordinated_process is a boolean attribute of an access; the grant permitting shipment-coordinators to initiate_customs_clearance_on_behalf requires coordinated_process = true.

Role-assignment constraints
- (none)
