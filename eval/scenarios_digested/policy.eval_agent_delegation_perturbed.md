Domain knowledge
- Roles: "shipment_coordinator", "dock_worker".
- Resources: "shipment_manifest" (represents a shipment's manifest and related delegation actions).
- Operations: create_manifest, update_manifest, delegate_customs_clearance (having customs clearance carried out on the shipment's behalf).
- Access contexts: "coordinated_shipment_process" (delegation performed as part of a coordinator-led process) and "day_to_day_loading" (routine loading/unloading activities).
- Baseline: default-deny — nothing is permitted unless explicitly granted below.

Direct grants
- Allow: subjects in role shipment_coordinator may create_manifest on shipment_manifest.
- Allow: subjects in role shipment_coordinator may update_manifest on shipment_manifest.
- Allow: subjects in role shipment_coordinator may delegate_customs_clearance on shipment_manifest when access.context == "coordinated_shipment_process".
- Allow: subjects in role dock_worker may create_manifest on shipment_manifest.
- Allow: subjects in role dock_worker may update_manifest on shipment_manifest.
- Deny: subjects in role dock_worker may not delegate_customs_clearance on shipment_manifest.
- Allow: subjects in role shipment_coordinator may read_manifest on shipment_manifest.
- Allow: subjects in role dock_worker may read_manifest on shipment_manifest.

Attribute invariants
- access.context is one of {"coordinated_shipment_process", "day_to_day_loading"}.

Role-assignment constraints
- A single user may not hold both shipment_coordinator and dock_worker roles simultaneously.
