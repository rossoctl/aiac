"""Demo-capture shim: record every outbound HTTP call as a ``{cmd, output}`` JSONL line.

**This module exists for the demo-video capture pass (branch ``demo-movie``) and is inert
unless ``AIAC_CAPTURE_FILE`` is set.** It is not part of the product.

Why in-process rather than on the wire: the ``team1`` namespace runs in the Istio ambient
mesh, so ztunnel wraps pod-to-pod traffic in mTLS. The Controller's own MCP ``tools/list``
call to ``github-tool`` — the most interesting hop in the UC-1 onboarding demo — is
plaintext ``http://`` at the call site but ciphertext on the wire, so a packet capture
(tcpdump/Pixie/kubeshark) cannot read its body. Patching the HTTP clients inside the
process captures the payload before TLS, pairs each request with its own response for
free, and works for the external LLM calls too.

Both client libraries are patched because the Controller uses both:
  * ``requests`` — the MCP ``tools/list`` call, the Policy Model Store, the PDP policy library
  * ``httpx``    — the LLM round-trips (via langchain_openai) and the init health probe

Install by importing and calling ``install()`` once at process start; it is idempotent.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

_ENV_FILE = "AIAC_CAPTURE_FILE"
_ENV_MAXLEN = "AIAC_CAPTURE_MAXLEN"

_DEFAULT_MAXLEN = 20000

_installed = False
_lock = threading.Lock()


def _maxlen() -> int:
    try:
        return int(os.environ.get(_ENV_MAXLEN, _DEFAULT_MAXLEN))
    except ValueError:
        return _DEFAULT_MAXLEN


def _truncate(text: str) -> str:
    limit = _maxlen()
    if limit <= 0 or len(text) <= limit:
        return text
    return f"{text[:limit]}\n...[truncated {len(text) - limit} chars]"


def _redact(headers: object) -> dict:
    """Header dict with credential-bearing values masked — the demo sends real bearer
    tokens (RFC 8693 exchanged tokens, the LLM api key) and this file is committed
    alongside the capture bundle."""
    out = {}
    try:
        items = dict(headers or {}).items()  # type: ignore[arg-type]
    except Exception:
        return out
    for key, value in items:
        if key.lower() in ("authorization", "proxy-authorization", "api-key", "x-api-key", "cookie"):
            out[key] = "<redacted>"
        else:
            out[key] = str(value)
    return out


def _body_to_text(body: object) -> str:
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        try:
            return body.decode("utf-8", "replace")
        except Exception:
            return f"<{len(body)} bytes>"
    if isinstance(body, str):
        return body
    try:
        return json.dumps(body, default=str)
    except Exception:
        return str(body)


def _write(record: dict) -> None:
    """Append one JSON object as a line. Best-effort: a capture failure must never break
    the demo run it is observing."""
    path = os.environ.get(_ENV_FILE)
    if not path:
        return
    try:
        line = json.dumps(record, default=str)
    except Exception:
        return
    try:
        with _lock, open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
    except Exception as exc:  # pragma: no cover - diagnostics only
        logger.debug("capture: could not write record: %s", exc)


def _record(
    *,
    library: str,
    method: str,
    url: str,
    req_headers: object,
    req_body: object,
    status: object,
    resp_headers: object,
    resp_body: object,
    elapsed_ms: float,
    error: str | None = None,
) -> None:
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "library": library,
        "cmd": f"{method.upper()} {url}",
        "request": {
            "method": method.upper(),
            "url": url,
            "headers": _redact(req_headers),
            "body": _truncate(_body_to_text(req_body)),
        },
        "response": {
            "status": status,
            "headers": _redact(resp_headers),
            "body": _truncate(_body_to_text(resp_body)),
        },
        "elapsed_ms": round(elapsed_ms, 1),
    }
    # `output` is the flat, human-legible half of plan.md's {cmd, output} pair; the
    # structured `request`/`response` keys above carry the full detail.
    record["output"] = f"{status} — {_truncate(_body_to_text(resp_body))}" if error is None else f"ERROR: {error}"
    if error is not None:
        record["error"] = error
    _write(record)


def _patch_requests() -> None:
    try:
        import requests
    except ImportError:
        return

    original = requests.sessions.Session.request

    def wrapper(self, method, url, *args, **kwargs):  # type: ignore[no-untyped-def]
        started = time.perf_counter()
        body = kwargs.get("json")
        if body is None:
            body = kwargs.get("data")
        try:
            response = original(self, method, url, *args, **kwargs)
        except Exception as exc:
            _record(
                library="requests",
                method=str(method),
                url=str(url),
                req_headers=kwargs.get("headers"),
                req_body=body,
                status=None,
                resp_headers=None,
                resp_body=None,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise
        _record(
            library="requests",
            method=str(method),
            url=str(url),
            req_headers=kwargs.get("headers"),
            req_body=body,
            status=response.status_code,
            resp_headers=getattr(response, "headers", None),
            resp_body=getattr(response, "text", None),
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
        return response

    # Patch at Session.request: every requests.get/post/delete helper and every Session
    # instance funnels through it, so one hook covers module-level helpers and the
    # function-local `import requests` at provision/nodes.py alike.
    requests.sessions.Session.request = wrapper  # type: ignore[method-assign]


def _patch_httpx() -> None:
    try:
        import httpx
    except ImportError:
        return

    sync_original = httpx.Client.send
    async_original = httpx.AsyncClient.send

    def _log(request, response, started, error=None):  # type: ignore[no-untyped-def]
        body = None
        if response is not None:
            try:
                body = response.text
            except Exception:
                body = "<unread stream>"
        req_body = None
        try:
            req_body = request.content
        except Exception:
            pass
        _record(
            library="httpx",
            method=str(request.method),
            url=str(request.url),
            req_headers=getattr(request, "headers", None),
            req_body=req_body,
            status=getattr(response, "status_code", None),
            resp_headers=getattr(response, "headers", None),
            resp_body=body,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            error=error,
        )

    def sync_wrapper(self, request, **kwargs):  # type: ignore[no-untyped-def]
        started = time.perf_counter()
        try:
            response = sync_original(self, request, **kwargs)
        except Exception as exc:
            _log(request, None, started, error=f"{type(exc).__name__}: {exc}")
            raise
        _log(request, response, started)
        return response

    async def async_wrapper(self, request, **kwargs):  # type: ignore[no-untyped-def]
        started = time.perf_counter()
        try:
            response = await async_original(self, request, **kwargs)
        except Exception as exc:
            _log(request, None, started, error=f"{type(exc).__name__}: {exc}")
            raise
        _log(request, response, started)
        return response

    httpx.Client.send = sync_wrapper  # type: ignore[method-assign]
    httpx.AsyncClient.send = async_wrapper  # type: ignore[method-assign]


def install() -> bool:
    """Patch the HTTP clients if ``AIAC_CAPTURE_FILE`` is set. Idempotent; returns whether
    capture is active."""
    global _installed
    if not os.environ.get(_ENV_FILE):
        return False
    if _installed:
        return True
    _patch_requests()
    _patch_httpx()
    _installed = True
    logger.info(
        "capture: HTTP client instrumentation active -> %s (maxlen=%d)",
        os.environ[_ENV_FILE],
        _maxlen(),
    )
    return True
