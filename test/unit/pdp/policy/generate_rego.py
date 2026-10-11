"""Generate the target-side Rego of the github-agent scenario by driving the live PDP Policy Writer (OPA).

Standalone (NOT pytest, NOT CI). Launches the writer as a uvicorn subprocess that also dumps its
Rego to a known local dir (``POLICY_WRITER_DUMP_REGO=1``, ``REGO_OUTPUT_DIR``), applies a
``TargetSidePolicyModel`` through the PDP policy library, shuts the service down, and prints the
dumped files. Inspect the .rego files by hand.

The model holds the two SPMs of the scenario, one per managed service (D20): the agent SPM (its
inbound edges: user role -> agent scope) and the tool SPM (its inbound edges: user role -> tool
scope and agent role -> tool scope). The writer renders one CR per SPM, and dumps each one under
``<REGO_OUTPUT_DIR>/<ns>/<name>/{inbound,outbound}/request.rego``: the agent inbound, the tool
inbound (the tool inbound decides a tool call) and a pass-through outbound for each service.

The writer also server-side-applies each CR, so it needs a reachable Kubernetes API (its
``/health`` lists the CRs). The dump is written only after a CR write succeeds.

The subprocess lifecycle is shared with the 5.3 launcher via ``test.system.launcher``, and
the fixed scenario (the same canonical github-agent worked example) lives in
``test.system.scenario`` so the two launchers cannot drift.

Run:
    .venv/bin/python test/unit/pdp/policy/generate_rego.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]  # -> aiac/
SRC = REPO_ROOT / "src"
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves
sys.path.insert(0, str(SRC))  # so ``import aiac.*`` resolves

from aiac.idp.configuration.models import Role, RoleKind, Scope, ServiceType  # noqa: E402
from aiac.policy.model.models import (  # noqa: E402
    PolicyRule,
    ServicePolicyModel,
    TargetSidePolicyModel,
)
from test.system import scenario as scn  # noqa: E402
from test.system.launcher import (  # noqa: E402
    Service,
    resolve_output_dir,
    running_services,
)

PORT = int(os.environ.get("PORT", "7072"))
BASE_URL = f"http://127.0.0.1:{PORT}"
OUTPUT_DIR = resolve_output_dir(Path(__file__).parent / "rego_out")

# Namespaced client ids (``<ns>/<name>``), so ``identity_ref`` derives the CR coordinates.
NAMESPACE = "team1"
AGENT_CLIENT_ID = f"{NAMESPACE}/{scn.AGENT_ID}"
TOOL_CLIENT_ID = f"{NAMESPACE}/{scn.TOOL_ID}"


def _roles() -> dict[str, Role]:
    """Synthesize a Role per scenario role name (ids stable as ``role-<name>``).

    A user role is a realm role held by the scenario users; an agent role is a client role of the
    agent (its actor is the agent's client id)."""
    roles: dict[str, Role] = {}
    for name in scn.USER_ROLES:
        holders = [user for user, role_name in scn.USERS.items() if role_name == name]
        roles[name] = Role(id=f"role-{name}", name=name, composite=False, kind=RoleKind.USER, actorIds=holders)
    for name in scn.AGENT_ROLES:
        roles[name] = Role(
            id=f"role-{name}", name=name, composite=False, kind=RoleKind.AGENT, actorIds=[AGENT_CLIENT_ID]
        )
    return roles


def _scopes() -> dict[str, Scope]:
    """Synthesize a Scope per scenario scope name (ids stable as ``scope-<name>``), owned by its service."""
    scopes = {name: Scope(id=f"scope-{name}", name=name, serviceId=AGENT_CLIENT_ID) for name in scn.AGENT_SCOPES}
    scopes.update({name: Scope(id=f"scope-{name}", name=name, serviceId=TOOL_CLIENT_ID) for name in scn.TOOL_SCOPES})
    return scopes


def build_model() -> TargetSidePolicyModel:
    """The target-side policy model of the scenario: the agent SPM and the tool SPM."""
    role, scope = _roles(), _scopes()

    def rules(pairs: list[tuple[str, str]]) -> list[PolicyRule]:
        return [PolicyRule(role=role[r], scope=scope[s]) for r, s in pairs]

    agent = ServicePolicyModel(
        service_id=AGENT_CLIENT_ID,
        service_type=ServiceType.AGENT,
        owned_roles=[role[name] for name in scn.AGENT_ROLES],
        owned_scopes=[scope[name] for name in scn.AGENT_SCOPES],
        inbound_allow_rules=rules(scn.INBOUND_PAIRS),
    )
    tool = ServicePolicyModel(
        service_id=TOOL_CLIENT_ID,
        service_type=ServiceType.TOOL,
        owned_roles=[],
        owned_scopes=[scope[name] for name in scn.TOOL_SCOPES],
        # Every rule is an inbound edge on the SPM of the service that owns its scope: the user ->
        # tool edges and the agent -> tool edges both land on the tool SPM.
        inbound_allow_rules=rules(scn.OUTBOUND_SUBJECT_PAIRS) + rules(scn.OUTBOUND_PAIRS),
    )
    return TargetSidePolicyModel(services=[agent, tool])


def print_rego_dir(output_dir: Path) -> None:
    """Print the output directory and each dumped ``<ns>/<name>/{inbound,outbound}/request.rego``."""
    print(f"Rego written to: {output_dir}")
    for path in sorted(output_dir.glob("*/*/*/request.rego")):
        print(f"  {path.relative_to(output_dir)}")


def main() -> None:
    os.environ["AIAC_PDP_POLICY_URL"] = BASE_URL  # consumed by the library
    from aiac.pdp.policy.library.api import apply_policy  # import after env is set

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    opa = Service(
        "aiac.pdp.service.policy.opa.main:app",
        port=PORT,
        env={"REGO_OUTPUT_DIR": str(OUTPUT_DIR), "POLICY_WRITER_DUMP_REGO": "1"},
    )
    with running_services([opa], src=SRC):
        apply_policy(build_model())

    print_rego_dir(OUTPUT_DIR)


if __name__ == "__main__":
    main()
