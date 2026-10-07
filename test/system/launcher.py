"""Shared machinery for the integration-test launchers.

Two halves, both live here so a single module import serves every launcher:

* **Subprocess half** — spawn aiac services as ``uvicorn`` subprocesses, poll each ``GET /health``
  until ready, run some work, tear them down. Used by ``test/unit/pdp/policy/generate_rego.py`` (the
  standalone Rego-dump launcher, which is *not* under ``test/system/`` and is out of scope for
  the live-cluster rework). ``Service`` / ``start_service`` / ``wait_until_ready`` /
  ``running_services`` / ``terminate`` / ``resolve_output_dir`` exist for it.

* **Live-cluster half** — drive a real rossoctl/Kind cluster with the AuthBridge OPA pipeline wired
  in (see ``k8s/opa-kind-runbook.md``). ``kubectl`` wrappers + ``port_forward`` + ``resolve_pod``
  onboard through the in-cluster Controller; ``mint_token`` / ``exchange_token`` / ``jwt_claim`` /
  ``inbound_probe`` / ``outbound_probe`` / ``outbound_session_probe`` send **real HTTP requests through
  AuthBridge** (and, for ``exchange_token``, one RFC 8693 token exchange straight to Keycloak) and
  classify the **real OPA plugin's** allow/deny; ``poll_until`` waits for ``bundle-service`` to reflect a CR change; and the
  skip gates (``require_env_or_skip`` / ``require_pipeline`` / ``verify_subject_mapper``) make the
  suite skip cleanly — never false-pass — when the cluster is not wired. ``require_pipeline`` also
  skips when the global combiner (the ``default`` ``AuthorizationPolicy`` in the bundle-service
  namespace) still allows a pod that has no client CR (D20, ``combiner_reason``).

The evaluator is now the deployed plugin, not a standalone OPA-CLI run over dumped ``.rego``: there is
deliberately no ``opa`` binary dependency and no ``.rego``-dump oracle here anymore (handoff 08).

It imports only the standard library and ``requests`` — never ``aiac`` — so a launcher may import
it *before* setting the environment variables the aiac libraries read at import time. ``pytest`` is
imported lazily inside the skip gates (only the live suite uses them, and only under pytest) so the
module stays importable in the standalone launchers.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

import requests

log = logging.getLogger(__name__)


def ensure_on_path(*paths: Path) -> None:
    """Prepend each path to ``sys.path`` (once), so a launcher can import ``aiac`` from ``src``
    and the shared ``test.system`` modules from the repo root."""
    for path in paths:
        entry = str(path)
        if entry not in sys.path:
            sys.path.insert(0, entry)


def require_env(*names: str) -> dict[str, str]:
    """Return the values of the named environment variables, or exit non-zero listing every one
    that is unset or empty. Used by launchers for inputs that have no safe default (Keycloak
    admin creds, LLM endpoint)."""
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        print(
            "error: required environment variable(s) not set: " + ", ".join(missing),
            file=sys.stderr,
        )
        raise SystemExit(2)
    return {name: os.environ[name] for name in names}


def resolve_output_dir(default: Path) -> Path:
    """Resolve ``REGO_OUTPUT_DIR`` (falling back to ``default``) to an absolute path."""
    return Path(os.environ.get("REGO_OUTPUT_DIR", default)).resolve()


@dataclass
class Service:
    """A ``uvicorn``-hostable ASGI app to run as a subprocess."""

    module_app: str  # e.g. "aiac.pdp.service.policy.opa.main:app"
    port: int
    host: str = "127.0.0.1"
    env: dict[str, str] = field(default_factory=dict)  # per-service extra env

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


def start_service(service: Service, *, src: Path) -> subprocess.Popen:
    """Spawn ``service`` as a ``uvicorn`` subprocess with ``src`` on ``PYTHONPATH`` and the
    service's extra env applied on top of the current environment."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src) + os.pathsep + env.get("PYTHONPATH", "")
    env.update(service.env)
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            service.module_app,
            "--host",
            service.host,
            "--port",
            str(service.port),
        ],
        env=env,
    )


def wait_until_ready(base_url: str, *, timeout: float = 30.0) -> None:
    """Poll ``GET {base_url}/health`` until it returns 200, or raise after ``timeout`` seconds."""
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            if requests.get(f"{base_url}/health", timeout=1).status_code == 200:
                return
        except requests.RequestException as exc:
            last_err = exc
        time.sleep(0.3)
    raise RuntimeError(f"service not ready at {base_url} within {timeout}s ({last_err})")


def terminate(proc: subprocess.Popen) -> None:
    """SIGTERM ``proc`` and wait briefly, escalating to SIGKILL if it does not exit."""
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@contextmanager
def running_services(services: list[Service], *, src: Path, timeout: float = 30.0) -> Iterator[None]:
    """Spawn every service, poll each ``/health``, yield, then terminate them all in ``finally``.

    Every spawned subprocess is torn down even if a later spawn or health poll fails.
    """
    procs: list[subprocess.Popen] = []
    try:
        for service in services:
            procs.append(start_service(service, src=src))
        for service in services:
            wait_until_ready(service.base_url, timeout=timeout)
        yield
    finally:
        for proc in procs:
            terminate(proc)


# ======================================================================================
# Cluster helpers (5.4) — kubectl apply/delete/rollout/get/cp + port-forward
# ======================================================================================
#
# Thin wrappers around the ``kubectl`` CLI (no in-process K8s client — keeps launcher.py
# dependency-free and mirrors what an operator would run by hand). Every call honours
# ``KUBECONFIG`` from the environment. Failures raise ``subprocess.CalledProcessError`` with the
# captured stderr, so the caller's assertion message names the failing command.


def kubectl(*args: str, input_text: str | None = None, timeout: float = 60.0) -> str:
    """Run ``kubectl <args>`` and return stdout (raising on non-zero exit). ``input_text`` is
    piped to stdin (e.g. for ``kubectl apply -f -``)."""
    proc = subprocess.run(
        ["kubectl", *args],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, ["kubectl", *args], output=proc.stdout, stderr=proc.stderr)
    return proc.stdout


def kubectl_apply(manifest_path: Path, *, namespace: str | None = None) -> None:
    """``kubectl apply -f <manifest_path>`` (optionally ``-n <namespace>``)."""
    args = ["apply", "-f", str(manifest_path)]
    if namespace:
        args += ["-n", namespace]
    kubectl(*args)


def kubectl_delete(manifest_path: Path, *, namespace: str | None = None, timeout: float = 120.0) -> None:
    """``kubectl delete -f <manifest_path> --ignore-not-found`` — safe to call in teardown even if
    the workloads are already gone."""
    args = ["delete", "-f", str(manifest_path), "--ignore-not-found", "--wait=true"]
    if namespace:
        args += ["-n", namespace]
    kubectl(*args, timeout=timeout)


def kubectl_rollout_status(resource: str, *, namespace: str, timeout: float = 180.0) -> None:
    """Block until ``resource`` (e.g. ``deployment/github-tool``) is rolled out, or raise."""
    kubectl("rollout", "status", resource, "-n", namespace, f"--timeout={int(timeout)}s", timeout=timeout + 10)


def kubectl_get_json(resource: str, *, namespace: str | None = None) -> dict:
    """``kubectl get <resource> -o json`` parsed to a dict (a single object or a ``List``)."""
    args = ["get", resource, "-o", "json"]
    if namespace:
        args += ["-n", namespace]
    return json.loads(kubectl(*args))


def _pod_is_ready(pod: dict) -> bool:
    """True iff ``pod`` is ``Running`` with its ``Ready`` condition ``True``."""
    status = pod.get("status", {})
    if status.get("phase") != "Running":
        return False
    return any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", []))


def select_live_pod(items: list[dict]) -> str | None:
    """Pick the **newest live** pod name from a ``kubectl get pods`` ``items`` list, or ``None``.

    "Live" = **not terminating** (no ``metadata.deletionTimestamp``); among those, prefer the newest
    ``Ready`` pod (by ``creationTimestamp``), else the newest non-terminating one. Pure — no I/O — so
    the selection race behind issue #139 is unit-testable without a cluster."""
    live = [p for p in items if not p.get("metadata", {}).get("deletionTimestamp")]
    if not live:
        return None
    ready = [p for p in live if _pod_is_ready(p)]
    chosen = max(ready or live, key=lambda p: p.get("metadata", {}).get("creationTimestamp", ""))
    return chosen.get("metadata", {}).get("name")


def resolve_pod(selector: str, *, namespace: str) -> str:
    """Return the name of the **newest live** pod matching a label ``selector`` (e.g. ``app=aiac-opa``).

    "Live" = ``status.phase == Running``, the ``Ready`` condition true, and **not terminating** (no
    ``metadata.deletionTimestamp``). This matters during a rolling restart: with ``replicas=1`` and
    ``maxUnavailable=0`` the new pod is created and made Ready *before* the old one is deleted, so the
    old pod lingers ``Terminating`` (up to its grace period) alongside the new one. The old
    ``jsonpath={.items[0]}`` had no ordering or phase filter and could hand back that doomed pod; the
    caller would then pin it (e.g. ``kubectl exec``), the pod would finish terminating, and every
    later exec would fail ``NotFound`` — the intermittent stall behind issue #139. Selecting the
    newest Ready, non-terminating pod (see ``select_live_pod``) avoids that race.

    Falls back to the newest non-terminating pod when none report Ready yet (e.g. resolved mid-startup),
    and raises only when no non-terminating pod matches at all."""
    doc = json.loads(kubectl("get", "pods", "-n", namespace, "-l", selector, "-o", "json"))
    name = select_live_pod(doc.get("items", []))
    if name is None:
        raise RuntimeError(f"no (non-terminating) pod matches selector {selector!r} in namespace {namespace!r}")
    return name


@contextmanager
def port_forward(
    target: str,
    *,
    namespace: str,
    local_port: int,
    remote_port: int,
    ready_url: str | None = None,
    timeout: float = 30.0,
) -> Iterator[str]:
    """Run ``kubectl port-forward <target> <local>:<remote>`` for the duration of the block,
    yielding the local ``http://127.0.0.1:<local_port>`` base URL.

    ``target`` is a kubectl port-forward target (``svc/aiac-controller``, ``deploy/...``, ``pod/...``).
    The forward is not yielded until it is actually up: if ``ready_url`` is given it is polled until
    it answers (any HTTP status); otherwise the tunnel's own ``Forwarding from ...`` line is awaited
    (used for targets that expose no HTTP readiness path). A background thread drains the merged stdout/stderr the
    whole time — both to detect that line and so the OS pipe buffer can never fill and deadlock
    kubectl — and its captured output is surfaced if the forward exits early or never comes up.
    """
    proc = subprocess.Popen(
        ["kubectl", "port-forward", "-n", namespace, target, f"{local_port}:{remote_port}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base_url = f"http://127.0.0.1:{local_port}"
    output: list[str] = []
    forwarding = threading.Event()

    def _drain() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:  # blocks in the thread, never on the main path
            output.append(line)
            if "Forwarding from" in line:
                forwarding.set()

    reader = threading.Thread(target=_drain, daemon=True)
    reader.start()
    try:
        deadline = time.time() + timeout
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                reader.join(timeout=1)
                raise RuntimeError(f"port-forward to {target} exited early: {''.join(output).strip()}")
            if ready_url is None:
                if forwarding.wait(timeout=0.3):  # tunnel announced it is up
                    ready = True
                    break
            else:
                try:
                    requests.get(ready_url, timeout=1)
                    ready = True
                    break
                except requests.RequestException:
                    time.sleep(0.3)
        if not ready:
            raise RuntimeError(f"port-forward to {target} not ready within {timeout}s: {''.join(output).strip()}")
        yield base_url
    finally:
        terminate(proc)
        reader.join(timeout=1)


# ======================================================================================
# Live AuthBridge probes — the real OPA plugin is the evaluator (handoff 08)
# ======================================================================================
#
# The integration suite no longer evaluates ``.rego`` with a standalone ``opa`` binary. It onboards
# (which upserts the ``AuthorizationPolicy`` CR on the live API), waits for ``bundle-service`` to
# recompose the per-pod bundle, then sends **real HTTP requests through AuthBridge** and reads the
# **real OPA plugin's** decision off the response. AuthBridge's own ``jwt-validation`` + ``mcp-parser``
# build ``input.identity.*`` + ``input.mcp.params.name`` — the test never hand-builds an input doc.
#
# Request shaping + outcome classification follow ``k8s/opa-kind-runbook.md`` exactly (Parts A/B).

KEYCLOAK_CLIENT_ID = "rossoctl"  # the platform client the runbook mints user tokens through
_CURL_IMAGE = "curlimages/curl:8.10.1"  # same throwaway image the runbook probes with


def mint_token(
    username: str,
    password: str,
    *,
    keycloak_url: str,
    realm: str,
    client_id: str = KEYCLOAK_CLIENT_ID,
    scope: str = "openid",
    timeout: float = 30.0,
) -> str:
    """Mint a user access token via the OIDC password grant (runbook A.1 / B.4).

    Requires Direct Access Grants enabled on ``client_id`` and the user's password set; a token whose
    ``sub`` is the username further needs the realm's ``username -> sub`` mapper (see
    ``verify_subject_mapper``). Raises ``requests.HTTPError`` on a non-2xx token response so the caller
    can turn a mint failure into a skip."""
    resp = requests.post(
        f"{keycloak_url.rstrip('/')}/realms/{realm}/protocol/openid-connect/token",
        data={
            "client_id": client_id,
            "username": username,
            "password": password,
            "grant_type": "password",
            "scope": scope,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


# RFC 8693 token exchange — the request AuthBridge's ``token-exchange`` plugin sends on the outbound leg.
TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

# The answer of Keycloak when it refuses the client authentication of a token request (RFC 6749 §5.2):
# HTTP 400 or 401 with one of these OAuth ``error`` codes.
CLIENT_AUTH_REFUSED_STATUSES = frozenset({400, 401})
CLIENT_AUTH_REFUSED_ERRORS = frozenset({"invalid_client", "unauthorized_client"})


class TokenExchangeError(RuntimeError):
    """Keycloak did not answer a token exchange (``exchange_token``) with a token. Carries the HTTP
    ``status``, the raw ``body`` and the OAuth ``error`` code (``None`` when the body is not an OAuth
    error document), so that a caller can tell a refused client authentication
    (``client_auth_refused``) from every other failure."""

    def __init__(self, status: int, body: str, error: str | None) -> None:
        self.status = status
        self.body = body
        self.error = error
        super().__init__(f"token exchange failed: HTTP {status}, error={error!r}, body={body[:500]!r}")

    @property
    def client_auth_refused(self) -> bool:
        """True when Keycloak refused the client authentication of the request (HTTP 400/401 with
        ``invalid_client`` / ``unauthorized_client``), not the exchange itself."""
        return self.status in CLIENT_AUTH_REFUSED_STATUSES and self.error in CLIENT_AUTH_REFUSED_ERRORS


def exchange_token(
    subject_token: str,
    *,
    keycloak_url: str,
    realm: str,
    client_id: str,
    client_secret: str,
    audience: str,
    scope: str,
    timeout: float = 30.0,
) -> str:
    """Exchange ``subject_token`` for an access token to ``audience`` (RFC 8693, the Keycloak standard
    token exchange) as the client ``client_id``, and return the new access token.

    The same request that AuthBridge's ``token-exchange`` plugin sends on the agent's outbound leg
    (``audience`` + ``scope`` from the route, ``subject_token_type`` and ``requested_token_type`` =
    access token). The client authenticates with ``client_secret`` (form data, like ``mint_token``),
    as AuthBridge does with the ``client-secret`` identity that ``k8s/opa-kind-enable.sh`` sets. Raises ``TokenExchangeError`` on a non-2xx answer;
    its ``client_auth_refused`` tells a refused client authentication from every other failure."""
    resp = requests.post(
        f"{keycloak_url.rstrip('/')}/realms/{realm}/protocol/openid-connect/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT_TYPE,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "requested_token_type": ACCESS_TOKEN_TYPE,
            "audience": audience,
            "scope": scope,
            "client_id": client_id,
            "client_secret": client_secret,
        },
        timeout=timeout,
    )
    if not (200 <= resp.status_code < 300):
        try:
            doc = resp.json()
        except ValueError:
            doc = None
        error = doc.get("error") if isinstance(doc, dict) else None
        raise TokenExchangeError(resp.status_code, resp.text, error if isinstance(error, str) else None)
    return resp.json()["access_token"]


def jwt_claim(token: str, claim: str) -> object:
    """Best-effort decode of a JWT payload claim (no signature check — for the ``sub`` sanity gate).

    Splits off the payload segment, pads it to a base64url boundary, and returns ``claim`` (``None``
    if absent). Raises on a structurally invalid token."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload)).get(claim)


def _parse_curl_output(stdout: str) -> tuple[int | None, str]:
    """Split a probe pod's stdout into ``(http_code, body)``.

    The probe scripts append a ``HTTP_CODE:<n>`` sentinel after the response body (inbound curl ``-w``)
    or emit an ``AB_HTTP:<n>`` / ``AB_ERR:<msg>`` marker (outbound python). Returns ``(None, stdout)``
    when no code marker is present (a failed probe — classified as ``"error"`` upstream)."""
    code: int | None = None
    body_lines: list[str] = []
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("HTTP_CODE:") or stripped.startswith("AB_HTTP:"):
            try:
                code = int(stripped.split(":", 1)[1])
            except ValueError:
                code = None
            continue
        if stripped.startswith("AB_ERR:"):
            return None, stripped[len("AB_ERR:") :].strip()
        body_lines.append(line)
    return code, "\n".join(body_lines).strip()


def inbound_probe(
    token: str,
    *,
    namespace: str,
    agent_service: str,
    port: int = 8080,
    timeout: float = 120.0,
) -> tuple[int | None, str]:
    """Send an inbound request through AuthBridge as ``token`` and return ``(http_code, body)``.

    Mirrors the runbook's ``probe_as`` (A.2): a throwaway ``curlimages/curl`` pod in ``namespace``
    POSTs a ``ping/nonexistent`` JSON-RPC method to the agent Service — enough to clear
    ``jwt-validation`` + OPA and reach (or be blocked before) the app, without triggering the CrewAI
    flow. ``curl -w`` appends the sentinel ``HTTP_CODE:<n>`` line the caller parses. ``--command`` is
    used to override the image entrypoint robustly (a deliberate deviation from the runbook's bare
    ``-- sh -c``). Any kubectl/scheduling failure returns ``(None, <message>)`` -> classified
    ``"error"`` so a poll keeps waiting rather than crashing."""
    url = f"http://{agent_service}.{namespace}.svc.cluster.local:{port}/"
    script = (
        "curl -s -m 15 -w '\\nHTTP_CODE:%{http_code}\\n' "
        f"-X POST {url} "
        "-H 'Content-Type: application/json' -H \"Authorization: Bearer $TOK\" "
        '-d \'{"jsonrpc":"2.0","id":"1","method":"ping/nonexistent","params":{}}\''
    )
    pod_name = f"probe-inbound-{uuid.uuid4().hex[:8]}"
    try:
        out = kubectl(
            "run",
            pod_name,
            "-n",
            namespace,
            "--image",
            _CURL_IMAGE,
            "--restart=Never",
            "--rm",
            "--attach",
            "--quiet",
            f"--env=TOK={token}",
            "--command",
            "--",
            "sh",
            "-c",
            script,
            timeout=timeout,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        stderr = getattr(exc, "stderr", "") or getattr(exc, "output", "") or str(exc)
        return None, f"inbound probe pod failed: {stderr}".strip()
    return _parse_curl_output(out)


def outbound_probe(
    token: str,
    tool_name: str,
    *,
    namespace: str,
    agent_pod: str,
    tool_url: str = "http://github-tool:9090/mcp",
    container: str = "agent",
    timeout: float = 120.0,
) -> tuple[int | None, str]:
    """Drive an outbound MCP ``tools/call`` through AuthBridge's forward proxy and return
    ``(http_code, body)``.

    Mirrors the runbook's outbound probe (B.4) but invokes a **bare** tool (``params.name = tool_name``,
    e.g. ``source-read``) instead of ``tools/list``, so AuthBridge's ``mcp-parser`` surfaces
    ``input.mcp.params.name`` and OPA's per-tool check is actually exercised (github-tool's inbound
    under target side, the agent's outbound under agent side). The agent app
    container has ``HTTP_PROXY=127.0.0.1:8081`` (the forward proxy) and ``python3``; ``token-exchange``
    uses the carried ``dev-user`` bearer as the RFC 8693 subject token. It is a one-frame
    :func:`outbound_session_probe`. Any exec failure returns ``(None, <message>)`` -> ``"error"``."""
    frame = {"jsonrpc": "2.0", "id": "1", "method": "tools/call", "params": {"name": tool_name, "arguments": {}}}
    return outbound_session_probe(
        token,
        [frame],
        namespace=namespace,
        agent_pod=agent_pod,
        tool_url=tool_url,
        container=container,
        timeout=timeout,
    )[0]


def outbound_session_probe(
    token: str,
    frames: list[dict],
    *,
    namespace: str,
    agent_pod: str,
    tool_url: str = "http://github-tool:9090/mcp",
    container: str = "agent",
    timeout: float = 120.0,
) -> list[tuple[int | None, str]]:
    """Send a sequence of JSON-RPC ``frames`` (an MCP session: ``initialize``,
    ``notifications/initialized``, ``tools/list``, ``tools/call`` …) through AuthBridge's forward proxy,
    in order, from one ``kubectl exec`` into the agent pod; return one ``(http_code, body)`` per frame.

    The forward proxy is ``127.0.0.1:8081``, the user bearer is the token-exchange subject token, and
    the request carries the MCP ``Accept`` header. The frames are sent as given, so a method that
    carries no tool name reaches the MCP session rule of the tool check (github-tool's inbound under
    target side, the agent's outbound under agent side); :func:`outbound_probe` sends one ``tools/call``
    frame. Each frame's output starts
    with an ``AB_MSG:<i>`` line and carries the ``AB_HTTP:<n>`` / ``AB_ERR:<msg>`` markers that
    ``_parse_curl_output`` reads. An exec failure returns ``(None, <message>)`` for every frame."""
    script = (
        "import urllib.request, urllib.error, json\n"
        f"tok = {json.dumps(token)}\n"
        f"url = {json.dumps(tool_url)}\n"
        f"frames = json.loads({json.dumps(json.dumps(frames))})\n"
        "op = urllib.request.build_opener("
        'urllib.request.ProxyHandler({"http": "http://127.0.0.1:8081"}))\n'
        "for i, frame in enumerate(frames):\n"
        '    print("AB_MSG:%d" % i)\n'
        "    req = urllib.request.Request(url, data=json.dumps(frame).encode(), headers={"
        '"Content-Type": "application/json",'
        ' "Accept": "application/json, text/event-stream",'
        ' "Authorization": "Bearer " + tok})\n'
        "    try:\n"
        "        r = op.open(req, timeout=15)\n"
        '        print("AB_HTTP:%d" % r.status)\n'
        '        print(r.read().decode("utf-8", "replace"))\n'
        "    except urllib.error.HTTPError as e:\n"
        '        print("AB_HTTP:%d" % e.code)\n'
        '        print(e.read().decode("utf-8", "replace"))\n'
        "    except Exception as e:\n"
        '        print("AB_ERR:%s" % e)\n'
    )
    try:
        out = kubectl(
            "exec",
            "-i",
            "-n",
            namespace,
            agent_pod,
            "-c",
            container,
            "--",
            "python3",
            "-",
            input_text=script,
            timeout=timeout,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        stderr = getattr(exc, "stderr", "") or getattr(exc, "output", "") or str(exc)
        return [(None, f"outbound probe exec failed: {stderr}".strip())] * len(frames)
    chunks: dict[int, list[str]] = {}
    current: int | None = None
    for line in out.splitlines():
        if line.strip().startswith("AB_MSG:"):
            current = int(line.strip()[len("AB_MSG:") :])
            chunks[current] = []
        elif current is not None:
            chunks[current].append(line)
    return [
        _parse_curl_output("\n".join(chunks[i])) if i in chunks else (None, "no output for frame")
        for i in range(len(frames))
    ]


def notification_outcome(code: int | None) -> str:
    """Classify the response to a JSON-RPC **notification** (a frame with no ``id``, e.g.
    ``notifications/initialized``) sent through the outbound proxy. A notification has no JSON-RPC
    reply to carry an error frame, so AuthBridge renders a rejection as a plain HTTP ``403`` (runbook
    B.4). HTTP 200/202 (the MCP server accepted it) -> ``"allow"``; 403 -> ``"deny"``; anything else
    -> ``"error"``."""
    if code in (200, 202):
        return "allow"
    if code == 403:
        return "deny"
    return "error"


def inbound_outcome(code: int | None) -> str:
    """Classify an inbound probe: HTTP 200 -> ``"allow"`` (reached the app), 403 -> ``"deny"`` (OPA
    blocked it), anything else -> ``"error"`` (runbook A.4)."""
    if code == 200:
        return "allow"
    if code == 403:
        return "deny"
    return "error"


def is_opa_violation(doc: object) -> bool:
    """True when ``doc`` (a parsed rejection body, or the ``error.data`` of a JSON-RPC error frame)
    names the OPA plugin: ``plugin == "opa"`` or ``error == "policy.forbidden"`` (cortex
    ``pipeline.Violation.Render`` / ``httpx.MarshalMCPRejectionBody``)."""
    return isinstance(doc, dict) and (doc.get("plugin") == "opa" or doc.get("error") == "policy.forbidden")


def _json_or_none(body: str) -> object:
    """``json.loads(body)``, or ``None`` when the body is not JSON."""
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


def outbound_outcome(code: int | None, body: str) -> str:
    """Classify an outbound probe by **body**, per runbook B.4.

    A denied ``tools/call`` has one of two shapes, by the enforcement side:

      * **Target side** — the agent's outbound is a pass-through, and the **callee's inbound** OPA
        (github-tool's reverse proxy) decides. The reverse proxy renders a rejection with
        ``httpx.WriteRejection``: **HTTP 403** and a plain JSON body
        (``{"error": "policy.forbidden", "message": …, "plugin": "opa"}``). The agent's forward proxy
        relays that response as it is. A 403 whose body names OPA -> ``"deny"``. A 403 with any other
        body -> ``"error"``: it is not an OPA verdict, so it must not stand in for one.
      * **Agent side** — the agent's **outbound** OPA decides. On an MCP-shaped request (a ``method``
        + ``id``) AuthBridge's forward proxy renders **any** rejection as a JSON-RPC error frame **at
        HTTP 200** (``writeMCPRejection`` — the MCP client sees a single failed tool call, not a
        transport break), so the frame's ``error.data`` — not the HTTP status — carries the reason.

    The reason of a JSON-RPC error frame at HTTP 200 decides the class:

      * **OPA** blocked it — ``error.data.plugin == "opa"`` / ``error.data.error == "policy.forbidden"``
        -> ``"deny"``. This is the real outbound authorization verdict: token-exchange succeeded and the
        request reached OPA, which forbade it. Only tool-onboarded rungs (2 & 3) reach this point.
      * **token-exchange** refused to mint the downstream token — ``error.data.plugin ==
        "token-exchange"`` (``error.data.error == "upstream.token-exchange-failed"``) -> ``"error"``,
        NOT ``"deny"``. A refused RFC 8693 exchange means the outbound authorization decision was
        **never reached** — the exchange broke *before* OPA — so it is not an OPA deny and must not be
        reported as one. Reporting it as ``"error"`` (a) surfaces a genuine token-exchange fault on a
        tool-onboarded rung honestly instead of masking it as ``"allow"`` (its old fall-through) or
        mislabelling it ``"deny"``, and (b) keeps the classifier from ever standing in for OPA. The
        agent-only rung (rung 1) does not probe outbound at all — with no tool there is no real
        ``agent -> tool`` call and token-exchange would short-circuit here anyway — so this frame is
        not an expected verdict on any rung; it always signals a fault worth surfacing.

    So: a plain ``403`` whose body names OPA (the callee's inbound, target side; or the agent's own
    non-MCP-shaped rejection fallback) -> ``"deny"``; any other ``403`` -> ``"error"``; HTTP 200 with an
    OPA error frame -> ``"deny"``; HTTP 200 with a token-exchange error frame -> ``"error"``; HTTP 200
    with any other body (a ``result`` frame, or a tool-level error that means the call was *allowed*
    through) -> ``"allow"``; ``None`` or any other status (a transport break, a 401 from the callee's
    ``jwt-validation``, a 503 before the first bundle loads, or a non-MCP token-exchange ``503``) ->
    ``"error"``. Classify by the body, never the transport status alone."""
    if code is None:
        return "error"
    doc = _json_or_none(body)
    if code == 403:
        return "deny" if is_opa_violation(doc) else "error"
    if code != 200 or doc is None:
        return "error"
    err = doc.get("error") if isinstance(doc, dict) else None
    if isinstance(err, dict):
        data = err.get("data")
        if isinstance(data, dict):
            # token-exchange refusal = the outbound decision was never reached (exchange broke before
            # OPA). Honest class is "error", never "deny" — it must not stand in for an OPA verdict.
            if data.get("plugin") == "token-exchange" or data.get("error") == "upstream.token-exchange-failed":
                return "error"
            # A real OPA verdict — token-exchange succeeded and the request reached the policy.
            if is_opa_violation(data):
                return "deny"
    return "allow"


# Where the deny of a ``tools/call`` comes from (``deny_origin``): the callee's own inbound OPA
# (github-tool's reverse proxy; target side) or the agent's outbound OPA (agent side).
DENY_ORIGIN_TOOL_INBOUND = "tool-inbound"
DENY_ORIGIN_AGENT_OUTBOUND = "agent-outbound"


def deny_origin(code: int | None, body: str) -> str | None:
    """Where the raw response ``(code, body)`` of a **denied** ``tools/call`` (sent through the agent's
    forward proxy) comes from. **Pure** — decides from the response only.

      * HTTP 403 with a plain JSON body that names OPA (no ``jsonrpc`` member) ->
        ``DENY_ORIGIN_TOOL_INBOUND``: github-tool's reverse proxy rejected the call
        (``httpx.WriteRejection``), and the agent's outbound let it through and relayed the response.
      * HTTP 200 with a JSON-RPC error frame whose ``error.data`` names OPA ->
        ``DENY_ORIGIN_AGENT_OUTBOUND``: the agent's forward proxy rejected the MCP-shaped request
        (``httpx.WriteRejectionForRequest``).
      * Anything else (an allow, a token-exchange refusal, a transport error) -> ``None``.

    Only a request frame (``tools/call`` with an ``id``) has two distinct shapes. A notification gets a
    plain 403 from either side, so this helper does not apply to it."""
    doc = _json_or_none(body)
    if not isinstance(doc, dict):
        return None
    if code == 403 and "jsonrpc" not in doc and is_opa_violation(doc):
        return DENY_ORIGIN_TOOL_INBOUND
    if code == 200:
        err = doc.get("error")
        if isinstance(err, dict) and is_opa_violation(err.get("data")):
            return DENY_ORIGIN_AGENT_OUTBOUND
    return None


def poll_until(predicate: Callable[[], bool], *, timeout: float, interval: float = 5.0) -> bool:
    """Poll ``predicate`` until it returns truthy or ``timeout`` seconds elapse; return whether it did.

    Exceptions from ``predicate`` (a probe against an ephemeral pod / a bundle still rebuilding) are
    swallowed and retried — the point is to wait out ``bundle-service``'s rebuild + OPA poll latency
    without ``sleep``-and-hope (handoff 08 §2.2)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception as exc:  # noqa: BLE001 — a transient probe failure is expected while waiting
            log.debug("poll_until: predicate raised (retrying): %s", exc)
        time.sleep(interval)
    return False


# ======================================================================================
# Skip gates — the suite skips (never false-passes) when the live pipeline is not wired
# ======================================================================================


def require_env_or_skip(*names: str) -> dict[str, str]:
    """Like ``require_env`` but ``pytest.skip`` (not exit) when a variable is unset — so a developer
    running the integration marker without the repo-root ``.env`` sourced gets a clean skip, not a
    crash. ``pytest`` is imported lazily so the module stays importable outside pytest."""
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        import pytest

        pytest.skip("integration env not set: " + ", ".join(missing) + " — source .env (see aiac/CLAUDE.md).")
    return {name: os.environ[name] for name in names}


def _kubectl_try(*args: str, timeout: float = 30.0) -> tuple[bool, str, str]:
    """Run ``kubectl`` returning ``(ok, stdout, error)`` instead of raising — for the readiness probe,
    where any failure (unreachable API, absent resource) is a *skip reason*, not a test error."""
    try:
        return True, kubectl(*args, timeout=timeout), ""
    except FileNotFoundError:
        return False, "", "kubectl not found on PATH"
    except subprocess.CalledProcessError as exc:
        return False, exc.output or "", (exc.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return False, "", "kubectl timed out"


# The bundle-service namespace — home of ``bundle-service`` and of the global ``default``
# ``AuthorizationPolicy`` (the combiner). Same env name and default as the Controller's start check #4.
BUNDLE_SERVICE_NAMESPACE = os.environ.get("AIAC_BUNDLE_SERVICE_NAMESPACE", "rossoctl-system")

# D20: in an AIAC setup the combiner's two **request** packages must not carry these fallback lines,
# which allow a pod that has no client CR. ``k8s/opa-kind-enable.sh`` applies the changed ``default``
# CR; a ``helm upgrade`` of the operator puts the lines back. The response packages keep the default.
COMBINER_FALLBACK_LINES: dict[str, str] = {
    "inbound/request.rego": "client_ok if not data.authbridge.client.inbound.request",
    "outbound/request.rego": "client_ok if not data.authbridge.client.outbound.request",
}


def combiner_reason(default_cr: dict | None, *, namespace: str = BUNDLE_SERVICE_NAMESPACE) -> str | None:
    """Return ``None`` when the global combiner denies a pod that has no client CR (D20), else a skip
    reason. **Pure** — decides from the already-read ``default`` ``AuthorizationPolicy`` object
    (``None`` when it is missing), like ``event_path_reason``.

    The combiner is changed when both request packages exist and neither holds its
    ``COMBINER_FALLBACK_LINES`` line (whitespace-normalized). A missing CR or package also fails, as
    in the Controller's start check #4."""
    fix = "run k8s/opa-kind-enable.sh to apply the changed combiner (D20; a helm upgrade of the operator reverts it)"
    if not default_cr:
        return f"the global combiner (AuthorizationPolicy 'default' in {namespace}) is missing — {fix}"
    policies = {p.get("path", ""): p.get("content") or "" for p in (default_cr.get("spec") or {}).get("policies") or []}
    for path, line in COMBINER_FALLBACK_LINES.items():
        if path not in policies:
            return f"the global combiner in {namespace} has no {path} package — {fix}"
        if any(" ".join(raw.split()) == line for raw in policies[path].splitlines()):
            return (
                f"the global combiner in {namespace} still allows a pod that has no client CR "
                f"({path} holds {line!r}) — {fix}"
            )
    return None


def pipeline_unwired_reason(*, namespace: str, workloads: list[str]) -> str | None:
    """Return ``None`` when the live AuthBridge OPA pipeline is fully wired for ``namespace``, else a
    human-readable reason the suite should skip. Checks (cheap -> specific): ``kubectl`` present, the
    ``AuthorizationPolicy`` CRD served, ``bundle-service`` Running, the global combiner changed (D20,
    ``combiner_reason``), the ``opa`` plugin on **both** legs of ``namespace``'s AuthBridge runtime
    config, and each ``workloads`` pod Running."""
    if shutil.which("kubectl") is None:
        return "kubectl not on PATH"

    ok, _, err = _kubectl_try("get", "crd", "authorizationpolicies.agent.rossoctl.dev", "-o", "name")
    if not ok:
        return f"AuthorizationPolicy CRD not served / cluster unreachable ({err or 'no output'})"

    ns = BUNDLE_SERVICE_NAMESPACE
    ok, out, err = _kubectl_try(
        "get",
        "pods",
        "-n",
        ns,
        "-l",
        "app=bundle-service",
        "-o",
        "jsonpath={.items[*].status.phase}",
    )
    if not ok:
        return f"cannot query bundle-service in {ns} ({err})"
    if "Running" not in out:
        return f"bundle-service is not Running in {ns}"

    ok, out, err = _kubectl_try("get", "authorizationpolicy", "default", "-n", ns, "-o", "json", "--ignore-not-found")
    if not ok:
        return f"cannot read the global combiner (AuthorizationPolicy 'default') in {ns} ({err})"
    try:
        default_cr = json.loads(out) if out.strip() else None
    except ValueError:
        return f"cannot parse the global combiner (AuthorizationPolicy 'default') in {ns}"
    reason = combiner_reason(default_cr, namespace=ns)
    if reason:
        return reason

    ok, out, err = _kubectl_try(
        "get",
        "configmap",
        "authbridge-runtime-config",
        "-n",
        namespace,
        "-o",
        r"jsonpath={.data.config\.yaml}",
    )
    if not ok:
        return f"authbridge-runtime-config not found in {namespace} ({err})"
    wired = out.count("name: opa")
    if wired < 2:
        return f"OPA plugin not wired into both legs in {namespace} (found {wired} of 2) — run k8s/opa-kind-enable.sh"

    for workload in workloads:
        ok, out, err = _kubectl_try(
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            f"app.kubernetes.io/name={workload}",
            "-o",
            "jsonpath={.items[*].status.phase}",
        )
        if not ok:
            return f"cannot query workload {workload!r} in {namespace} ({err})"
        if "Running" not in out:
            return f"workload {workload!r} is not Running in {namespace}"

    return None


def require_pipeline(*, namespace: str, workloads: list[str]) -> None:
    """``pytest.skip`` with a clear message when the live pipeline is not wired (acceptance #4)."""
    reason = pipeline_unwired_reason(namespace=namespace, workloads=workloads)
    if reason:
        import pytest

        pytest.skip(
            f"live AuthBridge OPA pipeline not wired: {reason}. Stand it up with "
            "k8s/opa-kind-enable.sh (see k8s/opa-kind-runbook.md)."
        )


def event_path_reason(*, broker_phase: str, realm_config: dict) -> str | None:
    """Return ``None`` when the event-driven onboarding path is wired, else a human-readable skip
    reason. **Pure** — decides from two already-gathered facts (mirrors ``pipeline_unwired_reason`` /
    ``select_live_pod``): the NATS broker pod ``broker_phase`` and the realm's events ``realm_config``
    (its ``eventsListeners`` list + ``adminEventsEnabled`` flag). Kept side-effect-free so it is unit
    testable offline; the I/O to gather those facts lives in ``event_path_unwired_reason``.

    The event path is: deploy -> operator registers a Keycloak client -> Keycloak emits the admin
    event ``CLIENT_CREATED`` -> the AIAC SPI (``aiac-event-listener``) publishes on NATS -> the agent
    consumer runs ``onboard_service``. All three facts must hold or the trigger never fires."""
    if "Running" not in (broker_phase or ""):
        return f"NATS event broker not Running (phase={broker_phase!r})"
    if "aiac-event-listener" not in (realm_config.get("eventsListeners") or []):
        return "Keycloak SPI listener 'aiac-event-listener' not in realm eventsListeners"
    if not realm_config.get("adminEventsEnabled"):
        return "Keycloak adminEventsEnabled is false (CLIENT_CREATED is an admin event)"
    return None


def event_path_unwired_reason(*, admin, realm: str, broker_namespace: str = "aiac-system") -> str | None:
    """Gather the two facts ``event_path_reason`` needs and return its verdict. ``admin`` is the
    ``KeycloakAdmin`` client the harness already builds (``uc1_onboard.connect_admin``) — ``launcher``
    has none of its own. Any failure to read a fact is itself a skip reason, never an error."""
    ok, out, err = _kubectl_try(
        "get",
        "pods",
        "-n",
        broker_namespace,
        "-l",
        "app=aiac-event-broker",
        "-o",
        "jsonpath={.items[*].status.phase}",
    )
    if not ok:
        return f"cannot query NATS event broker in {broker_namespace} ({err})"
    broker_phase = out

    try:
        realm_config = admin.get_realm(realm)
    except Exception as exc:  # noqa: BLE001 — any admin-read failure is a skippable prerequisite gap
        return f"cannot read realm {realm!r} events config from Keycloak ({exc})"

    return event_path_reason(broker_phase=broker_phase, realm_config=realm_config)


def require_event_path(*, admin, realm: str) -> None:
    """``pytest.skip`` with a clear message when the event-driven onboarding path is not wired, so a
    cluster wired for OPA but not for events skips cleanly rather than hanging on a trigger that never
    fires. Pre-built + ``kind load``ed images are a *separate* precondition surfaced later as a pod
    that never becomes Ready (a loud failure via the deploy/convergence poll), not a skip here."""
    reason = event_path_unwired_reason(admin=admin, realm=realm)
    if reason:
        import pytest

        pytest.skip(
            f"event-driven onboarding path not wired: {reason}. Deploy the NATS broker "
            "(k8s/event-broker-deployment.yaml) and install + enable the aiac-event-listener SPI "
            "(keycloak-spi/README.md); the two workload images must also be built + kind-loaded "
            "(demo/assets/kind-load.sh)."
        )


def verify_subject_mapper(
    *, keycloak_url: str, realm: str, user: str, password: str, client_id: str = KEYCLOAK_CLIENT_ID
) -> str:
    """Mint a token for ``user`` and ``pytest.skip`` unless its ``sub`` equals ``user``.

    The live loop keys OPA decisions on ``input.identity.subject`` (the token ``sub``), which equals
    the username only when the realm carries the ``username -> sub`` mapper and Direct Access Grants
    are enabled on ``client_id`` — a one-time Keycloak prerequisite the fixture does **not** provision
    (runbook Prerequisites). Skipping here (rather than failing every decision) keeps a mis-provisioned
    realm from masquerading as a policy bug. Returns the minted token on success.

    This checks only the **login** token: the login client's own ``username-to-sub`` mapper (on
    ``client_id``, by default ``rossoctl``) sets its ``sub``. A token that an agent exchanges gets the
    same mapping from the client scope ``aiac-username-sub``, which AIAC links to each managed client
    at onboarding (D31); ``uc1_onboard.require_subject_scope`` checks that link, and a missing link
    fails the run (it is an AIAC step, not a prerequisite). Together the two checks cover both
    sources of the rule."""
    import pytest

    try:
        token = mint_token(user, password, keycloak_url=keycloak_url, realm=realm, client_id=client_id)
    except Exception as exc:  # noqa: BLE001 — any mint failure is a skippable prerequisite gap
        pytest.skip(
            f"cannot mint a {user!r} token in realm {realm!r} via client {client_id!r}: {exc}. "
            "Enable Direct Access Grants on the client and set the user's password "
            "(see k8s/opa-kind-runbook.md Prerequisites)."
        )
    sub = jwt_claim(token, "sub")
    if sub != user:
        pytest.skip(
            f"login token 'sub' is {sub!r}, not {user!r} — the login client {client_id!r} has no "
            "username->sub protocol mapper (a manual prerequisite; AIAC's aiac-username-sub scope covers "
            "only the exchanged tokens, D31 — see k8s/opa-kind-runbook.md Prerequisites)."
        )
    return token
