Domain knowledge
- Roles: shipment_coordinator, dock_worker.
- Resources: shipment (including shipment manifest as a manipulable document attached to a shipment).
- Operations: create_manifest, update_manifest, request_customs_clearance (having customs clearance carried out on a shipment's behalf).
- Access attributes: coordinated_process (boolean) — true when the customs-clearance action is performed as part of a coordinated process with required operational approvals.
- Baseline: default-deny — nothing is permitted unless a grant in this policy allows it.

Direct grants
- Shipment coordinators may create_manifest and update_manifest on shipment resources.
- Shipment coordinators may not request_customs_clearance on shipment resources.
- Dock workers may create_manifest and update_manifest on shipment resources.
- Dock workers may request_customs_clearance on shipment resources when the access attribute coordinated_process = true.
- Shipment coordinators may read_manifest on shipment resources.
- Dock workers may read_manifest on shipment resources.

Attribute invariants
- Any access whose operation is request_customs_clearance must have access.coordinated_process = true.

Role-assignment constraints
- (none)
