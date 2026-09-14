#!/usr/bin/env python3
"""Fold the demo's terminal narration together with the in-pod HTTP capture into
``capture.jsonl`` — one JSON object per task, per ``demo/tooling/plan.md``'s schema.

Inputs (both produced by the Pass 2 run):
  * ``logs/<target>.log``  — each ``make`` target's terminal output (Source A)
  * ``raw-capture.jsonl``  — the records the in-process shim wrote (Source B),
    copied out of the agent pod

Output: ``capture.jsonl``, one JSON object per task:

  ``task``     what this unit of work is
  ``steps``    ordered ``{cmd, output, explain?}``:
                 ``cmd``     the request as actually issued
                 ``output``  the response as actually received — NEVER prose
                 ``explain`` (optional) narration for this step: the demo's own prose,
                             plus decoded LLM decisions and other commentary
                 ``caller``  (optional) who issued the request — the demo script on the
                             laptop, or the in-cluster Controller
                 ``elapsed_ms`` (optional) wall-clock duration, when >= 1s
  ``summary``  what the task achieved

``output`` and ``explain`` are deliberately separate: the wire traffic is evidence,
the narration is commentary, and letting commentary sit in ``output`` was the original
defect this split fixes.

Usage:  assemble.py <run-dir> [--from-agent]

  ``--from-agent``  emit only from ``make agent`` onward. The setup phase
                    (keycloak/prereqs/clear/setup) is scaffolding, not the demo.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# --- Source B routing -------------------------------------------------------
# Which onboarding sub-step a captured record belongs to, keyed by its target. The
# URL resolves every hop except propose-vs-audit, which share an endpoint and are
# split by request-body inspection below.
IDP_CONFIG = "aiac-pdp-config-service:7071"
POLICY_WRITER = "aiac-pdp-policy-service:7072"
MODEL_STORE = "aiac-policy-model-store-service:7074"
MCP_MARKER = "/mcp"
LLM_MARKER = "/chat/completions"



# `task` is read on screen like a subtitle, so it stays short. `summary` and `explain`
# aim for the same brevity but are NOT hard-capped: a developer-facing detail (which label
# is authoritative, what makes a write idempotent) is worth more than a clean line length.
# SUBTITLE_HINT is advisory — the assembler reports what exceeds it and emits it anyway.
SUBTITLE_HINT = 90
# `task` is the one field that must stay subtitle-tight; it is the on-screen caption.
TASK_MAX = 90

# Where the demo proper begins; everything before it is setup scaffolding.
FIRST_DEMO_TASK = "Resolve the agent's Keycloak client UUID"


def _subtitle(text: str, limit: int | None = None) -> str:
    """Collapse to a single line. Truncates only when a caller asks for a hard limit —
    trimming a developer-facing explanation to fit a line length loses the detail that
    made it worth writing (an earlier version cut an explain field down to "✓…")."""
    text = " ".join((text or "").split())
    if limit is None or len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut + "…"


def _llm_gist(decoded: str) -> str:
    """A propose/audit response in a few words: the decision, not the reasoning."""
    try:
        obj = json.loads(decoded)
    except Exception:
        return _subtitle(decoded)
    if "approved" in obj:
        verdict = "approved" if obj.get("approved") else "REJECTED"
        reason = " ".join(str(obj.get("reason", "")).split())
        return _subtitle(f"{verdict}" + (f" — {reason}" if reason else ""))
    granted = obj.get("granted") or obj.get("grants") or []
    denied = obj.get("denied") or []
    bits = []
    if granted:
        bits.append("grant " + ", ".join(map(str, granted)))
    if denied:
        bits.append("deny " + ", ".join(map(str, denied)))
    return _subtitle("; ".join(bits) or "no grants")


def annotate_writes(steps: list[dict]) -> list[dict]:
    """Label each state-changing call so a developer can see what proves it worked.

    Mutations here come in two shapes, and they need different notes:

      * `201` WITH the created object in the body — self-evidencing; the response itself is
        the proof, so just say a create happened.
      * a bare `204` with no body — proves nothing on its own. The evidence is the GET that
        follows, so point at it. (That read-back pattern is already in the traffic: it is
        what makes re-running the onboarding idempotent.)

    Without this, a replay shows a line answering `204` and the viewer cannot tell whether
    anything changed, or which of the surrounding reads was the confirmation.
    """
    out = []
    for i, st in enumerate(steps):
        st = dict(st)
        method = st.get("cmd", "").split(" ", 1)[0]
        url = st.get("cmd", "").split(" ", 1)[1] if " " in st.get("cmd", "") else ""
        # POST is not automatically a mutation: the LLM chat-completions calls are queries
        # that happen to use it, and they carry their own decoded-verdict explain.
        is_query_post = LLM_MARKER in url or MCP_MARKER in url
        if method in ("POST", "PUT", "DELETE", "PATCH") and not is_query_post:
            body = (st.get("output") or "").strip()
            status = body.split(" ", 1)[0]
            has_body = "—" in body and len(body.split("—", 1)[1].strip()) > 2
            if has_body:
                note = f"state change — {status}; the response body is the created object"
            else:
                # Only a GET of the SAME resource proves the write. An adjacent GET of a
                # different path proves nothing: after the model-store POST the next call is
                # a filtered list-all that legitimately returns [], and claiming that as the
                # check was simply wrong.
                target = re.sub(r"https?://[^/]+", "", url).rstrip("/")
                nxt = None
                for s2 in steps[i + 1 : i + 6]:
                    c2 = s2.get("cmd", "")
                    if not c2.startswith("GET"):
                        continue
                    p2 = re.sub(r"https?://[^/]+", "", c2.split(" ", 1)[1]).rstrip("/")
                    # Same path, or the parent resource the write modified: binding a role
                    # with POST /services/{id}/roles/{roleId} is confirmed by reading
                    # /services/{id}, which now lists that role. Requiring an exact match
                    # would report "no adjacent check" for a write that is plainly verified.
                    if p2 == target or (target.startswith(p2 + "/") and p2.count("/") >= 1):
                        nxt = s2
                        break
                note = f"state change — {status}, no body"
                if nxt is not None:
                    prev = next(
                        (
                            s0
                            for s0 in reversed(steps[:i])
                            if s0.get("cmd", "").startswith("GET")
                            and re.sub(r"https?://[^/]+", "", s0["cmd"].split(" ", 1)[1]).rstrip("/") == target
                        ),
                        None,
                    )
                    before = (prev.get("output") or "").split("—", 1)[0].strip() if prev else None
                    after = (nxt.get("output") or "").split("—", 1)[0].strip()
                    read_path = re.sub(r"https?://[^/]+", "", nxt["cmd"].split(" ", 1)[1]).rstrip("/")
                    same = read_path == target
                    where = "the same path" if same else f"GET {read_path[:40]}"
                    if before:
                        note += f"; {where} answered {before} before and {after} after"
                    else:
                        note += f"; {where} now answers {after}, showing the change"
                else:
                    note += "; verified later in the run, not by an adjacent call"
            st["explain"] = _subtitle(" ".join(x for x in (st.get("explain"), note) if x))
        out.append(st)
    return out


def idp_phase(recs: list[dict], phase: str) -> list[dict]:
    """Split the IdP-config traffic by CONCERN rather than by HTTP method.

    Splitting on GET-vs-POST looked tidy but misrepresented the run: the provisioning
    writes are interleaved with read-backs (each POST is preceded by a GET that makes the
    create idempotent), so a method split reorders what actually happened. The observed
    sequence has three phases instead:

      provision  — resolve the client, classify it, create+bind a role and scope per skill,
                   ending with POST /services/{id}/type
      candidates — GET /services, then every client's roles and scopes: the full candidate
                   set the policy has to be judged against
      subjects   — GET /subjects and each subject's assignments

    The boundaries are found from the traffic itself, not hardcoded indices.
    """
    idp = [r for r in recs if classify(r) == "idp-config"]
    type_stamp = next(
        (i for i, r in enumerate(idp) if r["request"]["url"].rstrip("/").endswith("/type")),
        -1,
    )
    subjects_start = next(
        (i for i, r in enumerate(idp) if "/subjects" in r["request"]["url"]), len(idp)
    )
    if phase == "provision":
        return [step(r) for r in idp[: type_stamp + 1]]
    if phase == "candidates":
        return [step(r) for r in idp[type_stamp + 1 : subjects_start]]
    if phase == "trailing":
        # Everything after the subject reads: the re-read sweep the PRB does per candidate
        # while it works. Kept separate so it neither pads an earlier phase nor disappears.
        idxs = [i for i, r in enumerate(idp) if "/subjects" in r["request"]["url"]]
        tail_start = (idxs[-1] + 1) if idxs else subjects_start
        return [step(r) for r in idp[tail_start:]]
    if phase == "subjects":
        # All subject reads, from the first to the last — they are interleaved with a
        # /roles lookup, so "contiguous" cannot mean "unbroken run of /subjects URLs".
        idxs = [i for i, r in enumerate(idp) if "/subjects" in r["request"]["url"]]
        if not idxs:
            return []
        return [step(r) for r in idp[idxs[0] : idxs[-1] + 1]]
    return []


def classify(rec: dict) -> str:
    url = rec.get("request", {}).get("url", "")
    if LLM_MARKER in url:
        return "llm-audit" if is_audit(rec) else "llm-propose"
    if MCP_MARKER in url:
        return "mcp-tools-list"
    if IDP_CONFIG in url:
        return "idp-config"
    if POLICY_WRITER in url:
        return "policy-writer"
    if MODEL_STORE in url:
        return "model-store"
    return "other"


def is_audit(rec: dict) -> bool:
    """Propose and audit hit the SAME chat-completions URL, so position alone is not
    reliable (a rejected propose triggers a retry, breaking strict alternation). The
    prompts differ, so classify on the request body instead."""
    body = rec.get("request", {}).get("body", "") or ""
    lowered = body.lower()
    audit_hints = ("auditor", "audit the", "verdict", "approve or reject", "reviewing a proposal")
    return any(hint in lowered for hint in audit_hints)


def llm_content(rec: dict) -> str | None:
    """The model's actual message content, unwrapped from the chat-completions envelope.

    Without this the interesting payload — a propose's grant list, an audit's
    ``{"approved": false, "reason": …}`` — sits JSON-escaped several hundred characters
    into the raw body and is effectively invisible once truncated. The audit REJECTION
    this demo turns on is exactly such a payload, so unwrap it.
    """
    body = rec.get("response", {}).get("body") or ""
    try:
        content = json.loads(body)["choices"][0]["message"]["content"]
    except Exception:
        return None
    try:  # the content is itself JSON for these structured calls
        return json.dumps(json.loads(content), ensure_ascii=False)
    except Exception:
        return content


# Raw responses are kept whole by default. The demo exists to show how much real work the
# system does, and an elided body hides exactly that; `raw-capture.jsonl` is the archive but
# `capture.jsonl` is what gets read. Only absurdly large bodies are trimmed, generously.
DEFAULT_LIMIT = 200_000


def short_output(rec: dict, limit: int = DEFAULT_LIMIT) -> str:
    status = rec.get("response", {}).get("status")
    body = rec.get("response", {}).get("body") or ""
    if len(body) > limit:
        body = body[:limit] + f"…[+{len(body) - limit} chars — full body in raw-capture.jsonl]"
    return f"{status} — {body}" if body else str(status)


def step(rec: dict) -> dict:
    out = {"cmd": rec["cmd"], "output": short_output(rec)}
    # What was SENT is often the substance of a step, not what came back: the Policy Writer
    # POST carries the entire computed policy model and answers only `204`, and the LLM
    # calls carry the prompt. Without this the interesting half of those exchanges is
    # invisible. Only real payloads are attached, so GETs stay uncluttered.
    req_body = rec.get("request", {}).get("body") or ""
    if len(req_body.strip()) > 2:
        out["sent"] = (
            req_body
            if len(req_body) <= DEFAULT_LIMIT
            else req_body[:DEFAULT_LIMIT] + f"…[+{len(req_body) - DEFAULT_LIMIT} chars]"
        )
    # For an LLM call the decision is buried in JSON-escaped `choices[0].message.content`.
    # `output` keeps the verbatim envelope; the decoded decision goes to `explain` so it is
    # readable without rewriting what came back.
    decoded = llm_content(rec)
    if decoded is not None:
        out["explain"] = _subtitle(_llm_gist(decoded))
    # Duration is evidence in its own right for the slow calls — the ~3-minute
    # /apply/service POST is the clearest demonstration that one request drives the
    # entire pipeline, and each LLM round-trip's cost is visible the same way.
    elapsed = rec.get("elapsed_ms")
    if isinstance(elapsed, (int, float)) and elapsed >= 1000:
        out["elapsed_ms"] = round(elapsed)
    return out


def driver_steps(
    raw: list[dict], kind: str, window: str, bounds: tuple[int, int] | None = None
) -> list[dict]:
    """Calls made by the DRIVING SCRIPT rather than by the agent pod.

    The in-cluster shim only observes what the agent pod calls outward, so two of the
    demo's defining requests are invisible to it: ``POST /apply/service/{id}`` (inbound to
    the pod, issued by ``_lib.onboard``) and the Keycloak admin lookups behind
    ``resolve_service_id``. Once the same shim is installed in the driver, those records
    land in the capture too and are identified here by URL shape.
    """
    matchers = {
        "apply-service": lambda u: "/apply/service/" in u,
        "keycloak-admin": lambda u: "/admin/realms/" in u and "/clients" in u,
        "token-exchange": lambda u: "/protocol/openid-connect/token" in u,
    }
    match = matchers.get(kind)
    if match is None:
        return []
    lo, hi = bounds if bounds else (0, len(raw))
    hits = [r for r in raw[lo:hi] if match(r.get("request", {}).get("url", ""))]
    if not hits:
        return []
    if kind == "keycloak-admin":
        # Every call is emitted, each with its COMPLETE response. resolve_service_id
        # iterates the whole client list, and that the agent has to be found among every
        # client in a real realm is part of what the demo is showing — so neither the
        # number of calls nor the size of each response gets reduced. `explain` points at
        # the entry that matters instead.
        want = "github-agent" if window == "agent" else "github-tool"
        steps = []
        for rec in hits:
            s = step(rec)
            hint = _client_hint(rec, want)
            if hint:
                s["explain"] = "\n".join(x for x in (s.get("explain"), hint) if x)
            steps.append(s)
        return steps
    return [step(r) for r in hits]


def _client_hint(rec: dict, workload: str) -> str | None:
    """One-line, subtitle-length pointer to the entry that matters in a big response."""
    try:
        clients = json.loads(rec["response"]["body"])
    except Exception:
        return None
    if not isinstance(clients, list):
        return None
    for client in clients:
        if isinstance(client, dict) and (client.get("name", "") or "").endswith(f"/{workload}"):
            return f"{len(clients)} clients returned; {workload}'s UUID is the service id"
    return f"{len(clients)} clients returned"


# --- state-inspection steps (what `make show` / `make diff` really do) ------
# These targets are demo wrappers, not requests. Under the hood show-state.py makes two
# Keycloak admin calls and reads the generated .rego off disk. Emitting `$ make show` as a
# `cmd` would put a fake request in a field reserved for real ones, so the wrapper is
# dropped and the underlying operations are shown instead.
GENERATED_DIR = Path(
    "/Users/arielf/development/sentry/aiac/demo/use-cases/uc1-onboarding/generated"
)


def state_steps(driver_raw: list[dict], bounds: tuple[int, int]) -> list[dict]:
    """The real Keycloak reads show-state.py performs, within a run window."""
    lo, hi = bounds
    out = []
    for rec in driver_raw[lo:hi]:
        url = rec.get("request", {}).get("url", "")
        method = rec.get("request", {}).get("method", "")
        if method == "GET" and (url.endswith("/roles") or url.endswith("/client-scopes")):
            out.append(step(rec))
    return out


def rego_steps(snapshot: str) -> list[dict]:
    """The generated Rego itself, read from the snapshot the demo captured.

    This is the artifact the whole demo produces, and a live enforcement point reads the
    same content out of the CR — so it belongs in `output` verbatim rather than being
    represented by the path it was written to.
    """
    base = GENERATED_DIR / snapshot / "team1" / "github-agent"
    out = []
    for gate in ("inbound", "outbound"):
        f = base / gate / "request.rego"
        if f.exists():
            out.append(
                {
                    "cmd": f"kubectl get authorizationpolicies.agent.rossoctl.dev github-agent "
                    f"-n team1 -o jsonpath='{{.spec.policies[?(@.path==\"{gate}/request.rego\")].content}}'",
                    "output": f.read_text().strip(),
                    "explain": f"the {gate} gate AuthBridge evaluates on every request",
                }
            )
    return out


# --- Source A: terminal narration ------------------------------------------
CMD_RE = re.compile(r"^\s*\$ (.+)$")


MARKER_CHARS = ("✓", "✗", "▸", "⛔", "•")


def merge_narration(real_steps: list[dict], narrated: list[dict]) -> list[dict]:
    """Attach the demo's own prose to real captured calls as an ``explain`` field.

    The narration and the wire traffic answer different questions — "what is this step
    for" versus "what actually went over the wire" — so the prose must never occupy
    ``output``. ``output`` stays the real response; ``explain`` carries the commentary.
    Matched positionally, since both sequences follow the script's own step order.
    """
    out = []
    for i, s in enumerate(real_steps):
        merged = dict(s)
        if i < len(narrated):
            prose = (narrated[i].get("output") or "").strip()
            if prose:
                merged["explain"] = _subtitle(prose)
        out.append(merged)
    return out


def narration_steps(log_path: Path, make_target: str | None = None) -> list[dict]:
    """The demo's own terminal narration as ``{cmd, output}`` steps.

    Only about a third of the targets echo a literal command (``cmd("Input", …)`` renders
    as ``$ …``); ``show``/``diff``/``keycloak``/``prereqs``/``setup`` print progress and
    state tables with no command line at all. So when no ``$`` line is present, fall back
    to recording the ``make`` invocation as the command and the run's salient output
    (marker-prefixed result lines) as its output — otherwise those tasks land with zero
    steps and the JSONL loses the narration entirely.
    """
    if not log_path.exists():
        return []
    text = log_path.read_text(errors="replace")
    steps: list[dict] = []
    pending: str | None = None
    buffer: list[str] = []
    for raw in text.splitlines():
        match = CMD_RE.match(raw)
        if match:
            if pending:
                steps.append({"cmd": pending, "output": "\n".join(buffer).strip()})
            pending = match.group(1).strip()
            buffer = []
            continue
        stripped = raw.strip()
        if pending and stripped and stripped[0] in MARKER_CHARS:
            buffer.append(stripped)
    if pending:
        steps.append({"cmd": pending, "output": "\n".join(buffer).strip()})
    if steps:
        return steps

    # No echoed command — synthesize one step from the make target plus its salient output.
    salient = [ln.strip() for ln in text.splitlines() if ln.strip()[:1] in MARKER_CHARS]
    if not salient:
        # Last resort: keep the non-boilerplate body so the step is never empty.
        salient = [
            ln.rstrip()
            for ln in text.splitlines()
            if ln.strip() and not ln.startswith("---") and not set(ln.strip()) <= {"-", " "}
        ][:40]
    target = make_target or log_path.stem
    return [{"cmd": f"$ make {target}", "explain": "\n".join(salient).strip()}]


def grants_step(log_path: Path) -> dict:
    """``make show``'s inbound/outbound grants tables — the pause evidence. These tables
    ARE the point of a show step, so they are kept verbatim rather than summarized."""
    if not log_path.exists():
        return {"cmd": "[derived] effective grants", "output": "(log missing)"}
    text = log_path.read_text(errors="replace")
    idx = text.find("inbound grants")
    if idx == -1:
        # Pause 1: nothing onboarded, so no grants tables exist at all.
        tail = "\n".join(ln.rstrip() for ln in text.splitlines()[-6:] if ln.strip())
        return {
            "cmd": "[derived] generated policy state",
            "output": tail or "(no policy generated yet)",
        }
    body = "\n".join(ln.rstrip() for ln in text[idx:].splitlines() if ln.strip())
    return {"cmd": "[derived] effective grants, computed from the state above", "output": body}


def rego_diff_step(log_path: Path) -> dict:
    """The +/- Rego hunks ``make diff`` prints — the demo's headline artifact, kept in full."""
    if not log_path.exists():
        return {"cmd": "[derived] rego diff", "output": "(log missing)"}
    lines = [
        ln.rstrip()
        for ln in log_path.read_text(errors="replace").splitlines()
        if ln.lstrip()[:1] in ("+", "-") and not ln.lstrip().startswith(("+++", "---"))
    ]
    return {
        "cmd": "[derived] diff of the generated Rego: 01-after-agent -> 02-after-tool",
        "output": "\n".join(lines) or "(no differences)",
    }


def result_table(log_path: Path) -> list[str]:
    """The allowed/denied rows a user-run target prints — the enforcement evidence."""
    if not log_path.exists():
        return []
    rows = []
    for raw in log_path.read_text(errors="replace").splitlines():
        stripped = raw.strip()
        if re.search(r"\b(allowed|denied|blocked at inbound)\s*$", stripped) and "->" not in stripped:
            rows.append(re.sub(r"\s{2,}", " | ", stripped))
    return rows


def timing_split(logs: Path, raw: list[dict]) -> int:
    """Index of the first record belonging to ``make tool``.

    The capture records the *pod's* clock (UTC here) while ``logs/*.timing`` records the
    driving shell's local clock, so the two differ by a fixed offset. Rather than assume
    the offset, anchor it: the first captured record must be the first call ``make agent``
    made, so ``record[0].ts - AGENT_START`` gives the skew, which then converts TOOL_START
    into pod time. Falls back to the MCP marker, then to a midpoint, if timing is absent.
    """
    from datetime import datetime

    def parse(path: Path, key: str) -> datetime | None:
        if not path.exists():
            return None
        for line in path.read_text().splitlines():
            if line.startswith(key + "="):
                try:
                    return datetime.fromisoformat(line.split("=", 1)[1].strip())
                except ValueError:
                    return None
        return None

    agent_start = parse(logs / "agent.timing", "AGENT_START")
    tool_start = parse(logs / "tool.timing", "TOOL_START")
    if agent_start and tool_start and raw:
        try:
            first_rec = datetime.fromisoformat(raw[0]["ts"])
        except (KeyError, ValueError):
            first_rec = None
        if first_rec is not None:
            skew = first_rec - agent_start  # pod clock minus shell clock
            tool_start_pod = tool_start + skew
            for i, rec in enumerate(raw):
                try:
                    if datetime.fromisoformat(rec["ts"]) >= tool_start_pod:
                        return i
                except (KeyError, ValueError):
                    continue
    # Fallbacks: the MCP marker is close (a few records late), better than nothing.
    for i, rec in enumerate(raw):
        if classify(rec) == "mcp-tools-list":
            return i
    return len(raw) // 2


def load_raw(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    from_agent = "--from-agent" in sys.argv[1:]
    if len(args) != 1:
        sys.exit("usage: assemble.py <run-dir> [--from-agent] [--no-viewer] [--no-open]")
    run = Path(args[0])
    logs = run / "logs"
    # Two capture sources, tagged so steps can say where each call was observed:
    #   raw-capture.jsonl    — the AGENT POD's outbound calls (idp-config, MCP, LLM, …)
    #   driver-capture.jsonl — the DRIVING SCRIPT's calls (POST /apply/service, Keycloak
    #                          admin lookups, the ROPC login and RFC 8693 exchange)
    # The pod cannot see the second set (they are inbound to it or never touch it), which is
    # why the shim runs in both processes.
    pod_raw = load_raw(run / "raw-capture.jsonl")
    driver_raw = load_raw(run / "driver-capture.jsonl")
    for rec in pod_raw:
        rec["_origin"] = "agent-pod"
    for rec in driver_raw:
        rec["_origin"] = "driver"
    raw = pod_raw

    def marker(fname: str, key: str, default: int) -> int:
        f = logs / fname
        if not f.exists():
            return default
        for line in f.read_text().splitlines():
            if line.startswith(key + "="):
                try:
                    return int(line.split("=", 1)[1].strip())
                except ValueError:
                    return default
        return default

    # Driver-record index boundaries recorded by the run script, so `make agent` and
    # `make tool` records are attributed by position rather than guessed.
    d_agent_lo = marker("agent.timing", "DRIVER_BEFORE_AGENT", 0)
    d_agent_hi = marker("agent.timing", "DRIVER_AFTER_AGENT", len(driver_raw))
    d_tool_lo = marker("tool.timing", "DRIVER_BEFORE_TOOL", d_agent_hi)
    d_tool_hi = len(driver_raw)
    agent_bounds = (d_agent_lo, d_agent_hi)
    tool_bounds = (d_tool_lo, d_tool_hi)

    # Split the capture at the tool-onboarding boundary using the recorded wall-clock
    # windows in logs/*.timing. Do NOT split on the MCP tools/list call: `make tool`
    # resolves the tool's service id (several idp-config reads) BEFORE it probes MCP, so
    # the MCP record sits a few entries *inside* task 8 and using it as the marker
    # misattributes those reads to task 6. Verified on this run: timing gives 150, the
    # MCP marker would have given 156.
    split = timing_split(logs, raw)
    agent_recs, tool_recs = raw[:split], raw[split:]

    def by(recs: list[dict], kind: str) -> list[dict]:
        return [r for r in recs if classify(r) == kind]

    tasks: list[dict] = []

    def normalize(steps: list[dict]) -> list[dict]:
        """Keep only steps the video can actually replay.

        The recording simulates a developer typing each `cmd` and receiving each `output`,
        so a step is usable only if BOTH are real: the command must be executable as
        written, and the output must be the byte-exact response. That rules out two things
        this assembler used to emit — derived views (a grants table, a diff, a result
        table: computed summaries, not commands) and steps with no captured response (the
        local `opa eval` subprocesses, whose stdout the demo never printed). Their content
        survives in `task`/`summary`/`explain`, which is where prose belongs.
        """
        kept = []
        for st in steps:
            st = dict(st)
            cmd = st.get("cmd", "")
            if cmd.startswith("[derived]"):
                continue
            if "output" not in st:
                continue
            body = (st.get("output") or "").strip()
            if body[:1] in ("✓", "✗", "⛔", "▸", "•"):
                # Narration that had slipped into output; it is not a response.
                continue
            if st.get("explain"):
                st["explain"] = _subtitle(st["explain"])
            kept.append(st)
        return kept

    def add(task: str, steps: list[dict], summary: str) -> None:
        # A task with no replayable step has nothing for the video to show. The Pause-3 diff
        # is the clearest case: it was entirely a derived view, and the state it describes is
        # already visible in the Rego read-back tasks either side of it.
        steps = annotate_writes(normalize(steps))
        if not steps:
            return
        tasks.append({"task": task, "steps": steps, "summary": summary})

    # 1-5 — init phase and the clean baseline
    add(
        "make keycloak — discover Keycloak and port-forward it",
        narration_steps(logs / "keycloak.log", "keycloak"),
        "Port-forwarded the in-cluster Keycloak to localhost:18080 and read the admin "
        "credentials from the keycloak-admin-secret, so every later target can reach it.",
    )
    add(
        "make prereqs — verify cluster, AIAC stack, demo workloads, Keycloak registration",
        narration_steps(logs / "prereqs.log", "prereqs"),
        "Confirmed the cluster, the AIAC stack in aiac-system, and the github-agent/"
        "github-tool workloads in team1 were all present, both Keycloak clients registered, "
        "and github-tool's Service carries the protocol.rossoctl.io/mcp label tool discovery needs.",
    )
    add(
        "make clear — reset to a clean slate",
        narration_steps(logs / "clear.log", "clear"),
        "Removed provisioned roles/scopes, deleted the AuthorizationPolicy CR, and cleared "
        "local generated/ snapshots, so this run starts from a known-empty baseline.",
    )
    add(
        "make setup — provision users/roles, mount policy.md, configure token exchange",
        narration_steps(logs / "setup.log", "setup"),
        "Provisioned dev-user/test-user/devops-user with their realm roles, resolved both "
        "workloads' Keycloak client UUIDs, and enabled RFC 8693 token exchange on the agent's client.",
    )
    add(
        "Starting point: no access rules exist",
        state_steps(driver_raw, (0, d_agent_lo)) + [grants_step(logs / "show-1-baseline.log")],
        "Three users with job titles. No rules about what they may reach.",
    )

    # 6 — make agent, split per plan.md
    add(
        "Resolve the agent's Keycloak client UUID",
        driver_steps(driver_raw, "keycloak-admin", window="agent", bounds=agent_bounds)
        or [{"cmd": "GET <keycloak>/admin/realms/rossoctl/clients", "output": "(not captured — see note)"}],
        "Its clientId is a SPIFFE URI; the UUID is what the onboarding route takes.",
    )
    add(
        "Classify the workload, then create a role + scope per declared skill",
        idp_phase(agent_recs, "provision"),
        "Type comes from the pod's rossoctl.io/type label; skills from its AgentCard "
        "resource. Each skill becomes one realm role and one client scope, bound to the client.",
    )
    add(
        "Sweep every client in the realm to build the candidate set",
        idp_phase(agent_recs, "candidates"),
        "Each of the 12 clients queried for roles and scopes, many answering [] — every role "
        "that could reach this agent has to be judged, not just the ones just created.",
    )
    add(
        "Read the relevant users and their role assignments",
        idp_phase(agent_recs, "subjects"),
        "Roles are flattened to their closure first, so a role held through a composite or a group counts the same as one assigned directly.",
    )
    add(
        "Merge per-client role ownership into the realm-wide role list",
        idp_phase(agent_recs, "trailing"),
        "The realm list says a role exists; only the per-client read says who owns it "
        "(kind=Agent, actorIds). Both are needed to know which roles are the agent's own, "
        "so every client resolved costs another pair of reads.",
    )
    add(
        "Proposer pass: an LLM grants per role/scope pair against policy.md",
        [step(r) for r in by(agent_recs, "llm-propose")],
        "One call per pair, deliberately isolated: the model sees a single focal entity and is "
        "told to ignore everything else, so evidence about one role cannot leak into another's "
        "decision. Deny-by-default, so silence in the policy means no grant.",
    )
    add(
        "Evaluator pass: a second LLM independently judges each proposal",
        [step(r) for r in by(agent_recs, "llm-audit")],
        "A separate call re-derives the same decision under the same rules, so an omission or an "
        "over-grant has to survive being checked twice. A rejection sends it back with the "
        "reason attached, up to 3 attempts.",
    )
    add(
        "Compile the decisions to OPA Rego and apply the agent's AuthorizationPolicy",
        [step(r) for r in by(agent_recs, "policy-writer")],
        "The request body is the resolved rule set — allow/deny rules per gate, the subject->role and target->scope maps, default_effect Deny. The writer compiles it to Rego and patches the AuthorizationPolicy that AuthBridge's OPA plugin evaluates.",
    )
    add(
        "Persist the computed policy to the Policy Model Store",
        [step(r) for r in by(agent_recs, "model-store")],
        "The same path answered 404 before the write and returns the stored policy after — that read is the proof it landed. Persisting it lets the next workload build on this one.",
    )
    add(
        "The generated OPA policy, read back from the cluster",
        rego_steps("01-after-agent"),
        "Two independent gates, both default allow := false: inbound answers who may call the agent, outbound what the agent may then do on its behalf.",
    )
    add(
        "State after the agent alone: inbound populated, outbound empty",
        state_steps(driver_raw, (d_agent_hi, d_tool_lo))
        + [grants_step(logs / "show-2-after-agent.log")],
        "No tool is onboarded yet, so every outbound map is still empty.",
    )

    # 8 — make tool, split per plan.md
    add(
        "Resolve the tool's Keycloak client UUID",
        driver_steps(driver_raw, "keycloak-admin", window="tool", bounds=tool_bounds)
        or [{"cmd": "GET <keycloak>/admin/realms/rossoctl/clients", "output": "(not captured — see note)"}],
        "Same lookup; its client.type attribute is Tool, not Agent.",
    )
    add(
        "Call the tool's live MCP endpoint for tools/list",
        [step(r) for r in by(tool_recs, "mcp-tools-list")],
        "Capabilities are discovered by asking the running tool, not read from a manifest someone maintains — so the policy is judged against what the tool actually exposes today.",
    )
    add(
        "Proposer pass over the discovered tool scopes",
        [step(r) for r in by(tool_recs, "llm-propose")],
        "Same policy text and the same one-pair-at-a-time isolation, now applied to capabilities "
        "that were discovered at runtime rather than declared anywhere.",
    )
    add(
        "Evaluator pass over the tool proposals",
        [step(r) for r in by(tool_recs, "llm-audit")],
        "Every tool-scope decision independently re-derived before it is trusted.",
    )
    add(
        "Recompile the AGENT's Rego to fill in its outbound gate",
        [step(r) for r in by(tool_recs, "policy-writer")],
        "A design decision: enforcement lives on the agent's outbound gate, not the tool's inbound. The tool gets no policy of its own — the caller is what gets constrained.",
    )
    add(
        "Persist the updated policy model",
        [step(r) for r in by(tool_recs, "model-store")],
        "Written the same way, and the follow-up read of the same path now returns both workloads' policies.",
    )
    add(
        "The completed OPA policy, read back from the cluster",
        rego_steps("02-after-tool"),
        "Both gates are now populated and the agent and tool are fully configured. Everything below stops changing the system and just exercises it.",
    )
    add(
        "Diff of the two snapshots: the outbound gate filling in",
        state_steps(driver_raw, (d_tool_hi, len(driver_raw))) + [rego_diff_step(logs / "diff.log")],
        "target_allow_scopes keyed by SPIFFE id; grants from two lines of English.",
    )

    # 10-12 — drive real users through the gates
    USER_TASK = {
        "dev": "Test: a user in the developer role exercises the configured system",
        "test": "Test: a user in the tester role, same flow",
        "devops": "Test: a user in a role the policy never mentions",
    }
    for target, summary in (
        ("dev", "Logs in, exchanges a token for the tool, then each intent is checked: source read and write and issue reads allowed, closing an issue denied."),
        ("test", "The mirror image: issue reads and writes allowed, reading source denied."),
        ("devops", "Refused at the inbound gate before any tool call is attempted — no role they hold sources a single scope the agent exposes."),
    ):
        log = logs / f"{target}.log"
        narrated = narration_steps(log)
        # Real HTTP for this user: the ROPC login and the RFC 8693 exchange. The opa eval
        # checks are local subprocesses, not HTTP, so they only exist in the narration —
        # keep those as narration steps rather than pretending they were captured.
        user_calls = [
            r
            for r in driver_raw
            if "/protocol/openid-connect/token" in r.get("request", {}).get("url", "")
            and f"{target}-user" in (r.get("request", {}).get("body") or "")
        ]
        steps = merge_narration([step(r) for r in user_calls], narrated)
        # Whatever narration had no captured counterpart (the opa eval gate checks) is
        # still the evidence for this task, so carry it through explicitly.
        for extra in narrated[len(user_calls) :]:
            steps.append({"cmd": extra["cmd"], "explain": extra.get("output", "")})
        rows = result_table(log)
        if rows:
            steps.append(
                {
                    "cmd": f"[derived] allow/deny outcome per intent for {target}-user",
                    "output": "\n".join(rows),
                    "explain": "The demo's own summary of each intent's allow/deny outcome.",
                }
            )
        add(USER_TASK[target], steps, summary)

    if from_agent:
        # The demo proper starts at `make agent`; keycloak/prereqs/clear/setup are
        # scaffolding that precedes the story.
        # Task labels are logical prose now, so match the first ONBOARDING task by identity
        # rather than by a "make agent" prefix that no longer exists.
        start = next((i for i, t in enumerate(tasks) if t["task"] == FIRST_DEMO_TASK), 0)
        dropped = [t["task"] for t in tasks[:start]]
        tasks = tasks[start:]
        if dropped:
            print(f"--from-agent: dropped {len(dropped)} setup task(s): {', '.join(d.split(' —')[0] for d in dropped)}")

    out = run / "capture.jsonl"
    with out.open("w", encoding="utf-8") as handle:
        for task in tasks:
            handle.write(json.dumps(task, ensure_ascii=False) + "\n")

    long = []
    for t in tasks:
        for field in ("task", "summary"):
            if len(t[field]) > (TASK_MAX if field == "task" else SUBTITLE_HINT):
                long.append(f"{field} ({len(t[field])}): {t[field][:60]}")
        for st in t["steps"]:
            if len(st.get("explain", "")) > SUBTITLE_HINT:
                long.append(f"explain ({len(st['explain'])}): {st['explain'][:60]}")
    if long:
        print(f"note: {len(long)} field(s) exceed the {SUBTITLE_HINT}-char subtitle hint (advisory):")
        for item in long[:10]:
            print("  " + item)

    print(f"wrote {out} — {len(tasks)} tasks")
    print(f"raw records routed: {len(raw)} total, {len(agent_recs)} agent / {len(tool_recs)} tool")
    for task in tasks:
        print(f"  {len(task['steps']):3d} step(s)  {task['task']}")

    if "--no-viewer" not in sys.argv[1:]:
        sys.path.insert(0, str(Path(__file__).parent / "tools"))
        from build_jsonl_viewer import build_viewer

        viewer_path, _ = build_viewer(str(out))
        print(f"wrote {viewer_path}")
        if "--no-open" not in sys.argv[1:] and sys.platform == "darwin":
            import subprocess

            subprocess.run(["open", viewer_path], check=False)


if __name__ == "__main__":
    main()
