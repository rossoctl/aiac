"""AIAC Agent Controller — FastAPI app factory + the four ``/apply/*`` routes.

The Controller is stateless. Each route dispatches to its use-case handler
(orchestrator or sub-agent), receives the ``(list[PolicyRule], override)`` tuple
the handler returns, and makes the **single** ``compute_and_apply(rules, override)``
call to the Policy Computation Engine. No per-use-case business logic, retry
handling, or state assembly lives here.

Responses are bare HTTP status codes: ``200 OK`` on success (no body). Upstream
failures are raised as FastAPI ``HTTPException``s by the handlers; the status
code is authoritative (the accompanying default JSON error body is incidental).
"""

import os

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from aiac.agent.eventbus.consumer import lifespan
from aiac.agent.policy_rules_builder.conflict_detection import (
    PolicyConflictError,
    report_from_contradictions,
)
from aiac.agent.policy_rules_builder.graph import (
    PolicyContradictionError,
    PolicyRulesBuilderError,
)
from aiac.agent.uc.offboarding.offboard import offboard_service
from aiac.agent.uc.onboarding.orchestrator import onboard_service
from aiac.agent.uc.policy_update.build import build_policy
from aiac.agent.uc.policy_update.rebuild import rebuild_policy
from aiac.agent.uc.role_update.role import update_role
from aiac.policy.computation import compute_and_apply, decommission
from aiac.policy.model.models import RuleEffect

app = FastAPI(lifespan=lifespan)


# The Policy Rules Builder raises on a policy-input problem, not a server fault: the auditor
# rejects the proposed rules after exhausting its retry budget (``PolicyRulesBuilderError``). That
# is a builder failure with no structured finding, so it surfaces as HTTP 422 with a bare
# ``{"detail": ...}`` body rather than escaping as an uncaught 500. The PCE is never reached — it
# fires during rule construction inside the use-case handlers.
@app.exception_handler(PolicyRulesBuilderError)
def _policy_input_error(_request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})


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


# Live on-ramp for the per-onboarding default_effect. The PCE-threading side (#146) exposes
# default_effect as an onboard_service parameter; the integration harness (#149) requests a
# non-default value by patching AIAC_DEFAULT_EFFECT ("Allow"/"Deny") onto the Controller
# deployment before onboarding. This is the single point where those two halves meet. Absent or
# unrecognised env → DENY, today's least-privilege default, so existing deployments are unchanged.
DEFAULT_EFFECT_ENV = "AIAC_DEFAULT_EFFECT"


def _default_effect_from_env() -> RuleEffect:
    try:
        return RuleEffect(os.environ.get(DEFAULT_EFFECT_ENV, RuleEffect.DENY.value))
    except ValueError:
        return RuleEffect.DENY


@app.get("/health")
def health() -> dict[str, str]:
    # The Controller is stateless — it holds no local state and opens no
    # connection at rest — so /health is a bare liveness/readiness signal:
    # if the process is accepting requests it is ready. Upstream reachability
    # (IdP, PCE, NATS) is validated per-request by the handlers, not here.
    return {"status": "ok"}


@app.post("/apply/service/{service_id}")
def apply_service(service_id: str) -> Response:
    rules, override, default_effect = onboard_service(service_id, _default_effect_from_env())
    compute_and_apply(rules, override, default_effect)
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
    decommission(offboard_service(service_id))
    return Response(status_code=200)


def main() -> None:
    uvicorn.run(app, host="0.0.0.0", port=7070)


if __name__ == "__main__":
    main()
