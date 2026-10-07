"""Kubernetes access seam for the Service Provision sub-agent (UC1), the UC1 precondition checks
(D30) and the Controller start check #4.

Owns the `kubernetes` client seams (`_core_v1`, `_custom_objects`, `_load_kube_config`) and
exposes the small set of read operations the callers need. Each operation wraps its
client call in ``run_upstream`` so transient API failures are retried at the transport
boundary — the callers call these plainly and only map the final failure (``HTTPException(502)``
in UC1). A 404 is not retried (``is_transient``); ``is_not_found`` tells it apart. Unit tests
patch the ``_core_v1`` / ``_custom_objects`` seams here.
"""

from kubernetes import client, config

from aiac.shared.upstream import run_upstream

# The rossoctl CRD group and version: the AgentCard and the AuthorizationPolicy CRs use both.
_ROSSOCTL_GROUP = "agent.rossoctl.dev"
_ROSSOCTL_VERSION = "v1alpha1"
_AGENTCARD_PLURAL = "agentcards"
_AUTHZ_POLICY_PLURAL = "authorizationpolicies"


# --------------------------------------------------------------------------- #
# Seams (patched in unit tests)                                                #
# --------------------------------------------------------------------------- #
def _load_kube_config() -> None:
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()


def _core_v1():
    """CoreV1Api client (pods, services, ConfigMaps)."""
    _load_kube_config()
    return client.CoreV1Api()


def _custom_objects():
    """CustomObjectsApi client (AgentCard and AuthorizationPolicy CRs)."""
    _load_kube_config()
    return client.CustomObjectsApi()


# --------------------------------------------------------------------------- #
# Retrying operations                                                          #
# --------------------------------------------------------------------------- #
def list_pods(namespace: str | None):
    """Pods in ``namespace`` (the ``.items`` list), with bounded transport retries."""
    return run_upstream(lambda: _core_v1().list_namespaced_pod(namespace).items)


def read_service(name: str | None, namespace: str | None):
    """A single Service by name, with bounded transport retries."""
    return run_upstream(lambda: _core_v1().read_namespaced_service(name, namespace))


def list_agentcards(namespace: str | None) -> dict:
    """List AgentCard CRs in ``namespace`` (raw dict response), with bounded transport retries."""
    return run_upstream(
        lambda: _custom_objects().list_namespaced_custom_object(
            group=_ROSSOCTL_GROUP,
            version=_ROSSOCTL_VERSION,
            namespace=namespace,
            plural=_AGENTCARD_PLURAL,
        )
    )


def read_configmap(name: str, namespace: str | None):
    """A single ConfigMap by name (``.data`` holds its keys), with bounded transport retries."""
    return run_upstream(lambda: _core_v1().read_namespaced_config_map(name, namespace))


def read_authorization_policy(name: str, namespace: str) -> dict:
    """A single ``AuthorizationPolicy`` CR by name (raw dict response), with bounded transport retries."""
    return run_upstream(
        lambda: _custom_objects().get_namespaced_custom_object(
            group=_ROSSOCTL_GROUP,
            version=_ROSSOCTL_VERSION,
            namespace=namespace,
            plural=_AUTHZ_POLICY_PLURAL,
            name=name,
        )
    )


def is_not_found(exc: BaseException) -> bool:
    """True for a Kubernetes API 404 (``ApiException.status``): the object does not exist."""
    return getattr(exc, "status", None) == 404
