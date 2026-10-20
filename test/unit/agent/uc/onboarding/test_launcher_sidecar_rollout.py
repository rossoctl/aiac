"""When the UC-1 system-test harness may probe a workload — pure unit tests.

The agent's convergence gate reads one inbound decision through the agent's Service. That decision is
proof that OPA loaded the agent's bundle only when the request goes through AuthBridge. The operator
injects the ``authbridge-proxy`` sidecar after the first pod of a fresh deploy is already up: it
registers the client, patches the Deployment and rolls out a new pod. Until that rollout ends, the
Service can route the probe to the plain first pod, which has no OPA in front of it, so the app answers
200 and the gate reads ``allow`` before AIAC has onboarded anything.

``sidecar_rollout_done`` is the wait's predicate: every live (not terminating) pod has the sidecar
and is Ready. They import the system harness like ``test_launcher_outcome.py`` does: it does no
cluster I/O at import time.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent  # test/unit/agent/uc/onboarding/
REPO_ROOT = HERE.parents[4]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from test.system import launcher  # noqa: E402


def _pod(name: str, containers: list[str], *, ready: bool = True, terminating: bool = False) -> dict:
    """A ``kubectl get pods -o json`` item with these container names."""
    metadata = {"name": name, "creationTimestamp": "2026-10-19T14:05:38Z"}
    if terminating:
        metadata["deletionTimestamp"] = "2026-10-19T14:06:30Z"
    return {
        "metadata": metadata,
        "spec": {"containers": [{"name": c} for c in containers]},
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
        },
    }


PLAIN = ["agent"]
INJECTED = ["agent", launcher.AUTHBRIDGE_CONTAINER]


def test_the_sidecar_container_is_authbridge_proxy():
    assert launcher.AUTHBRIDGE_CONTAINER == "authbridge-proxy"


def test_a_ready_plain_pod_is_not_done():
    # The race of the live runs: the first pod is Ready but has no sidecar.
    assert not launcher.sidecar_rollout_done([_pod("github-agent-78cf9dffd5-zs78l", PLAIN)])


def test_an_injected_pod_that_is_not_ready_yet_is_not_done():
    assert not launcher.sidecar_rollout_done(
        [
            _pod("github-agent-78cf9dffd5-zs78l", PLAIN),
            _pod("github-agent-6b5487d5bb-68dx9", INJECTED, ready=False),
        ]
    )


def test_a_plain_pod_beside_a_ready_injected_pod_is_not_done():
    # The Service still routes to the plain pod until it is gone.
    assert not launcher.sidecar_rollout_done(
        [
            _pod("github-agent-78cf9dffd5-zs78l", PLAIN),
            _pod("github-agent-6b5487d5bb-68dx9", INJECTED),
        ]
    )


def test_a_terminating_plain_pod_beside_a_ready_injected_pod_is_done():
    # A terminating pod is out of the Service endpoints.
    assert launcher.sidecar_rollout_done(
        [
            _pod("github-agent-78cf9dffd5-zs78l", PLAIN, terminating=True),
            _pod("github-agent-6b5487d5bb-68dx9", INJECTED),
        ]
    )


def test_only_ready_injected_pods_is_done():
    assert launcher.sidecar_rollout_done([_pod("github-agent-6b5487d5bb-68dx9", INJECTED)])


def test_no_live_pod_is_not_done():
    assert not launcher.sidecar_rollout_done([])
    assert not launcher.sidecar_rollout_done([_pod("github-agent-6b5487d5bb-68dx9", INJECTED, terminating=True)])
