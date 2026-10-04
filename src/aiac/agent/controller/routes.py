"""AIAC Agent Controller — FastAPI app factory, the ``/apply/*`` routes and one read-only route.

The Controller is stateless. Each ``/apply/*`` route dispatches to its use-case handler
(orchestrator or sub-agent), receives the ``(list[PolicyRule], override)`` tuple
the handler returns, and makes the **single** ``compute_and_apply(rules, override)``
call to the Policy Computation Engine. No per-use-case business logic, retry
handling, or state assembly lives here.

``GET /policy/services/{service_id:path}`` is a read-only view (D18): the policy model of the
current side with only the entry of one service (by its clientId), or 404 if it has no SPM. It
calls the PCE ``policy_model_for`` and writes nothing.

The app's lifespan (``eventbus.consumer.lifespan``) runs the start sequence first — start check #4
and the PCE resync (see ``controller.start``) — then starts the NATS consumer. A failed step stops
the Controller before it serves.

Responses are bare HTTP status codes: ``200 OK`` on success (no body). Upstream
failures are raised as FastAPI ``HTTPException``s by the handlers; the status
code is authoritative (the accompanying default JSON error body is incidental). The exception
handlers below map the PRB errors (422 / 502 / 500, sanitized or a ``ConflictReport``) and a failed
UC1 precondition check (``EnforcementPreconditionError`` → 409 with ``failed_checks``).
"""

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from aiac.agent.eventbus.consumer import lifespan
from aiac.agent.policy_rules_builder.conflict_detection import (
    PolicyConflictError,
    report_from_contradictions,
)
from aiac.agent.policy_rules_builder.graph import (
    LLMAccessError,
    PolicyContradictionError,
    PolicyRulesBuilderBaseError,
    PolicyRulesBuilderError,
    UnparseableLLMResponseError,
)
from aiac.agent.shared.error_logging import log_by_type
from aiac.agent.uc.offboarding.offboard import offboard_service
from aiac.agent.uc.onboarding.orchestrator import onboard_service, reenable_service
from aiac.agent.uc.onboarding.preconditions import EnforcementPreconditionError
from aiac.agent.uc.policy_update.build import build_policy
from aiac.agent.uc.policy_update.rebuild import rebuild_policy
from aiac.agent.uc.role_update.role import update_role
from aiac.idp.configuration.models import ClientId, ServiceUuid
from aiac.policy.computation import compute_and_apply, decommission, policy_model_for

app = FastAPI(lifespan=lifespan)


# Sanitized-body handlers for the non-``ConflictReport`` PRB failures. Each routes the FULL
# exception (message + traceback + chained root cause) to its per-persona named logger via
# ``log_by_type(exc)`` and returns a STATIC, leak-free summary as the HTTP body. The summary is
# NEVER ``str(exc)``: an endpoint / host / API key embedded in a transport error (or a poisoned
# message) must never reach the client, so the body is a fixed per-type string. The PCE is never
# reached — every one of these fires during rule construction inside the use-case handlers.
def _sanitized(exc: PolicyRulesBuilderBaseError, status_code: int, summary: str) -> JSONResponse:
    log_by_type(exc)
    return JSONResponse(status_code=status_code, content={"detail": summary})


# The auditor rejects the proposed rules after exhausting its retry budget: a policy-input
# problem, not a server fault, so 422 (not an uncaught 500).
@app.exception_handler(PolicyRulesBuilderError)
def _policy_input_error(_request: Request, exc: PolicyRulesBuilderError) -> JSONResponse:
    return _sanitized(exc, 422, "Policy rules could not be built from the provided policy source.")


# The LLM endpoint stayed unreachable after the transport retry budget was exhausted: a bad
# gateway to the upstream model, so 502.
@app.exception_handler(LLMAccessError)
def _llm_access_error(_request: Request, exc: LLMAccessError) -> JSONResponse:
    return _sanitized(exc, 502, "The policy language model endpoint is currently unavailable.")


# The LLM was reachable but returned a response that could not be parsed / failed schema
# validation: still an upstream-model fault the Controller cannot recover from, so 502.
@app.exception_handler(UnparseableLLMResponseError)
def _unparseable_llm_response_error(_request: Request, exc: UnparseableLLMResponseError) -> JSONResponse:
    return _sanitized(exc, 502, "The policy language model returned an unusable response.")


# The two grant/deny conflict mechanisms both surface as a 422 whose body IS a structured
# ``ConflictReport`` (settled design Q15 — one report shape at the boundary):
#   * ``PolicyConflictError`` (cross-pass structural detector, already enriched with verbatim quotes
#     + classified kind before the raise) carries a rich ``ConflictReport`` directly.
#   * ``PolicyContradictionError`` (intra-pass LLM auditor) carries only name-strings, so it is
#     re-shaped into the SAME ``ConflictReport`` (lower-fidelity: no ids/quotes, ``kind=DIRECT``,
#     ``quotes_verified=False``) with ``report_from_contradictions`` — no LLM at the boundary.
# Both are policy findings, not server faults, and both fire before the PCE is reached
# (atomic-by-construction: nothing is persisted).
@app.exception_handler(PolicyConflictError)
def _policy_conflict_error(_request: Request, exc: PolicyConflictError) -> JSONResponse:
    return JSONResponse(status_code=422, content=exc.report.model_dump(mode="json"))


@app.exception_handler(PolicyContradictionError)
def _policy_contradiction_error(_request: Request, exc: PolicyContradictionError) -> JSONResponse:
    report = report_from_contradictions(exc.focal, exc.contradictions)
    return JSONResponse(status_code=422, content=report.model_dump(mode="json"))


# A failed UC1 precondition check (D30): the pod of the service cannot enforce its CR. This is a
# conflict with the state of the cluster that the operator must fix, not a server fault, so 409. The
# body names each failed check, so the operator knows what to fix; the items carry check, pod,
# container and namespace names only (no endpoint, host or key). The checks run before Provision,
# so nothing changed and the PCE is never reached.
@app.exception_handler(EnforcementPreconditionError)
def _enforcement_precondition_error(_request: Request, exc: EnforcementPreconditionError) -> JSONResponse:
    log_by_type(exc)
    return JSONResponse(
        status_code=409,
        content={
            "detail": "The service cannot enforce its access policy: one or more precondition checks failed.",
            "failed_checks": exc.failures,
        },
    )


# Safety net — registered LAST, on purpose. Any ``PolicyRulesBuilderBaseError`` WITHOUT its own
# handler above (a future subclass, or a bare base error) is an unexpected builder fault → 500,
# sanitized the same way (never leaks, full detail logged). Registering the base-class net after
# the specific handlers keeps the intent explicit; resolution itself is by specificity, not order —
# Starlette walks the exception's MRO and picks the most-specific REGISTERED handler, so a mapped
# subclass (``LLMAccessError``, ``UnparseableLLMResponseError``, ``PolicyRulesBuilderError``,
# ``PolicyContradictionError``) always wins over this base handler and never falls through to 500.
@app.exception_handler(PolicyRulesBuilderBaseError)
def _policy_builder_base_error(_request: Request, exc: PolicyRulesBuilderBaseError) -> JSONResponse:
    return _sanitized(exc, 500, "The policy build failed unexpectedly.")


@app.get("/health")
def health() -> dict[str, str]:
    # The Controller is stateless — it holds no local state and opens no
    # connection at rest — so /health is a bare liveness/readiness signal:
    # if the process is accepting requests it is ready. Upstream reachability
    # (IdP, PCE, NATS) is validated per-request by the handlers, not here.
    return {"status": "ok"}


@app.post("/apply/service/{service_id}")
def apply_service(service_id: str) -> Response:
    # service_id is the Keycloak UUID (an IdP key). onboard_service resolves the clientId once; the
    # PCE routing guard takes it as the focus service and keeps its rules while its client is still
    # disabled (a re-onboarding of a quarantined service).
    uuid = ServiceUuid(service_id)
    rules, override, client_id = onboard_service(uuid)
    compute_and_apply(rules, override, focus_service=client_id)
    # Re-enable the client only AFTER the PCE apply succeeds — a compute_and_apply failure above
    # propagates and leaves the client disabled (the failed-service marker), never enabled-with-no-policy.
    reenable_service(uuid)
    return Response(status_code=200)


@app.post("/apply/policy/build")
def apply_policy_build() -> Response:
    rules, override = build_policy()
    compute_and_apply(rules, override)
    return Response(status_code=200)


@app.post("/apply/policy/rebuild")
def apply_policy_rebuild() -> Response:
    rules, override = rebuild_policy()
    compute_and_apply(rules, override)
    return Response(status_code=200)


@app.post("/apply/role/{role_id}")
def apply_role(role_id: str) -> Response:
    rules, override = update_role(role_id)
    compute_and_apply(rules, override)
    return Response(status_code=200)


# Offboard is keyed by the clientId (the SPM key), NOT the Keycloak internal UUID that
# /apply/service/{service_id} carries: an offboarded client is gone from get_services(), so
# UUID→clientId resolution is impossible. The {service_id:path} converter carries slash-bearing
# SPIFFE-URI clientIds. Decommission is a whole-service teardown, so it bypasses the
# (rules, override) → compute_and_apply path and calls the PCE's decommission directly.
@app.post("/apply/offboard/{service_id:path}")
def apply_offboard(service_id: str) -> Response:
    decommission(offboard_service(ClientId(service_id)))
    return Response(status_code=200)


# A read-only view for tests and debugging (D18): the policy model of the current side with only the
# entry of one service, as JSON in the shape of the writer's POST /policy body. Keyed by the clientId
# (the SPM key), as on the offboard path, so the {service_id:path} converter carries a slash-bearing
# SPIFFE URI. 404 if the service has no SPM (it is not in the managed set). It takes no PCE lock and
# writes nothing.
@app.get("/policy/services/{service_id:path}")
def get_service_policy_model(service_id: str) -> JSONResponse:
    model = policy_model_for(ClientId(service_id))
    if model is None:
        raise HTTPException(404, "The service has no policy model (it is not in the managed set).")
    return JSONResponse(status_code=200, content=model.model_dump(mode="json"))


def main() -> None:
    uvicorn.run(app, host="0.0.0.0", port=7070)


if __name__ == "__main__":
    main()
