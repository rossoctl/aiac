"""Unit tests for the changed global combiner (D20), ``k8s/aiac-combiner-default.yaml``.

The bundle service adds the global combiner (the ``default`` AuthorizationPolicy,
``scope: global``, in the bundle-service namespace) to every bundle. The stock
combiner of the operator chart has the rule ``client_ok if not <client package>``
in each of its four packages, so a pod that has no client CR is allowed. The AIAC
combiner removes this rule from the two **request** packages: a pod that has no
client CR is then denied on both request legs. The two response packages keep the
stock rule.

The tests load the four Rego packages from the manifest and evaluate them with
``opa eval``, together with hand-written namespace and client packages (the other
two tiers of a bundle). They skip when ``opa`` is not on PATH.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

# test/unit/pdp/service/policy/opa/ is 6 levels below the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[6]
_MANIFEST = _REPO_ROOT / "k8s" / "aiac-combiner-default.yaml"

_requires_opa = pytest.mark.skipif(not shutil.which("opa"), reason="opa binary not on PATH")


def _combiner_policies() -> dict[str, str]:
    """Return ``{path: content}`` of the ``default`` AuthorizationPolicy in the manifest."""
    docs = [d for d in yaml.safe_load_all(_MANIFEST.read_text()) if d]
    (cr,) = [d for d in docs if d.get("kind") == "AuthorizationPolicy" and d["metadata"]["name"] == "default"]
    return {p["path"]: p["content"] for p in cr["spec"]["policies"]}


def _client_package(direction: str, phase: str, allow: bool) -> str:
    """A client-tier package (the AIAC CR of the pod), with a fixed ``allow``."""
    body = "allow := true" if allow else "default allow := false"
    return f"package authbridge.client.{direction}.{phase}\nimport rego.v1\n{body}\n"


def _combiner_verdict(direction: str, phase: str, extra_modules: list[str]) -> bool:
    """Evaluate ``data.authbridge.<direction>.<phase>.allow`` for one bundle.

    The bundle is the four combiner packages from the manifest plus
    ``extra_modules`` (the namespace and client tiers, if any)."""
    with tempfile.TemporaryDirectory() as tmp:
        modules = list(_combiner_policies().values()) + extra_modules
        for i, module in enumerate(modules):
            (Path(tmp) / f"m{i}.rego").write_text(module)
        out = subprocess.run(
            [
                shutil.which("opa"),
                "eval",
                "-f",
                "json",
                "-d",
                tmp,
                "--stdin-input",
                f"data.authbridge.{direction}.{phase}.allow",
            ],
            input=json.dumps({}),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    return json.loads(out)["result"][0]["expressions"][0]["value"]


@_requires_opa
@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_request_with_no_client_package_is_denied(direction: str) -> None:
    """D20: a pod that has no client CR is denied on both request legs."""
    assert _combiner_verdict(direction, "request", []) is False


def _ns_package(direction: str, *, allow: bool = False, override: bool = False) -> str:
    """A namespace-tier package (a ``scope: namespace`` CR in the pod's namespace)."""
    lines = [f"package authbridge.ns.{direction}.request", "import rego.v1"]
    lines.append("allow := true" if allow else "default allow := false")
    if override:
        lines.append("override := true")
    return "\n".join(lines) + "\n"


# (namespace tier, client tier, expected verdict) for one request leg.
# None = no package of that tier in the bundle. Oracle values come from the
# combiner rules by hand: allow if ns.override; allow if ns_ok and client_ok;
# ns_ok if ns.allow or no ns package; client_ok ONLY if client.allow (D20).
_REQUEST_CASES = [
    pytest.param(None, True, True, id="no-ns-is-ns_ok-client-allows"),
    pytest.param(None, False, False, id="no-ns-client-denies"),
    pytest.param("allow", True, True, id="ns-allows-client-allows"),
    pytest.param("allow", None, False, id="ns-allows-no-client-denies"),
    pytest.param("allow", False, False, id="ns-allows-client-denies"),
    pytest.param("deny", True, False, id="ns-denies-client-allows"),
    pytest.param("deny", None, False, id="ns-denies-no-client"),
    pytest.param("override", None, True, id="ns-override-no-client-allows"),
    pytest.param("override", False, True, id="ns-override-client-denies-allows"),
]


@_requires_opa
@pytest.mark.parametrize("direction", ["inbound", "outbound"])
@pytest.mark.parametrize(("ns", "client", "expected"), _REQUEST_CASES)
def test_request_verdict_by_namespace_and_client_tier(
    direction: str, ns: str | None, client: bool | None, expected: bool
) -> None:
    """The client tier decides only through its ``allow``; the namespace tier works as before."""
    modules = []
    if ns is not None:
        modules.append(_ns_package(direction, allow=ns in ("allow", "override"), override=ns == "override"))
    if client is not None:
        modules.append(_client_package(direction, "request", client))
    assert _combiner_verdict(direction, "request", modules) is expected


@_requires_opa
@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_response_with_no_client_package_is_allowed(direction: str) -> None:
    """The response packages keep the stock fallback: an AIAC CR has no response packages."""
    assert _combiner_verdict(direction, "response", []) is True


@_requires_opa
@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_response_follows_a_client_response_package(direction: str) -> None:
    """A client response package still decides the response, as in the stock combiner."""
    deny = _client_package(direction, "response", False)
    assert _combiner_verdict(direction, "response", [deny]) is False


def test_manifest_is_the_global_default_cr_of_the_bundle_service_namespace() -> None:
    """The CR replaces the stock ``default`` CR; it is not an AIAC-managed CR."""
    docs = [d for d in yaml.safe_load_all(_MANIFEST.read_text()) if d]
    assert len(docs) == 1
    (cr,) = docs
    assert cr["apiVersion"] == "agent.rossoctl.dev/v1alpha1"
    assert cr["kind"] == "AuthorizationPolicy"
    assert cr["metadata"]["name"] == "default"
    # opa-kind-enable.sh replaces this namespace with RELEASE_NAMESPACE.
    assert cr["metadata"]["namespace"] == "rossoctl-system"
    # PUT /policy deletes every CR with the writer's managed-by label.
    assert "app.kubernetes.io/managed-by" not in (cr["metadata"].get("labels") or {})
    assert cr["spec"]["scope"] == "global"
    assert sorted(_combiner_policies()) == [
        "inbound/request.rego",
        "inbound/response.rego",
        "outbound/request.rego",
        "outbound/response.rego",
    ]


@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_request_package_has_no_client_fallback_rule(direction: str) -> None:
    """The same check as the Controller start check #4 (D30)."""
    content = _combiner_policies()[f"{direction}/request.rego"]
    assert f"package authbridge.{direction}.request" in content
    assert f"client_ok if not data.authbridge.client.{direction}.request" not in content
    # The rest of the client tier stays.
    assert f"client_ok if data.authbridge.client.{direction}.request.allow" in content


@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_response_package_keeps_the_client_fallback_rule(direction: str) -> None:
    content = _combiner_policies()[f"{direction}/response.rego"]
    assert f"client_ok if not data.authbridge.client.{direction}.response" in content
