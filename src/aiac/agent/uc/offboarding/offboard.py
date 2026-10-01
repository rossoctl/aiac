"""Service Offboarding sub-agent (UC4) — stub.

Counterpart to Service Onboarding. Where onboarding *adds* a service's policy
footprint, offboarding *removes* it: the Controller's ``/apply/offboard`` route
resolves the service key here and then calls the PCE's ``decommission`` directly
(no ``compute_and_apply`` / ``(rules, override)`` tuple — decommission is a
whole-service teardown, not a rule fold).

Identity asymmetry with onboard. Onboarding is keyed by the Keycloak **internal
UUID** (``Service.id``) and the Orchestrator resolves it to the clientId with one
``get_service()`` read before Provision. Offboarding cannot: an offboarded client
is gone from the IdP, so UUID→clientId resolution is impossible. The offboard
contract therefore carries the **clientId (the SPM key)** directly, and this stub
returns it unchanged. The PCE takes only the clientId, so the asymmetry stays at
the HTTP/NATS boundary. Full validation/resolution lands with the UC4
implementation (issue 3.21).
"""

from aiac.idp.configuration.models import ClientId


def offboard_service(service_id: ClientId) -> ClientId:
    return service_id
