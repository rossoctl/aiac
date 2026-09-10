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



# These three fields are read on screen in about two seconds, like a subtitle. Anything
# longer cannot be taken in during playback, so they are hard-capped and the assembler
# reports violations rather than silently emitting a wall of text.
SUBTITLE_MAX = 90

# Where the demo proper begins; everything before it is setup scaffolding.
FIRST_DEMO_TASK = "Identify the agent among everything registered"


def _subtitle(text: str, limit: int = SUBTITLE_MAX) -> str:
    """Collapse to one line and trim to subtitle length at a word boundary."""
    text = " ".join((text or "").split())
    if len(text) <= limit:
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
        """Enforce the schema invariant: ``output`` holds a real response, never prose.

        Steps sourced purely from narration (``kubectl``/``make`` lines the shim never saw,
        because they are subprocesses rather than HTTP) arrive with the demo's commentary in
        ``output``; move it to ``explain`` so a reader can always trust ``output`` to be
        wire truth.
        """
        fixed = []
        for s in steps:
            s = dict(s)
            body = (s.get("output") or "").strip()
            if body and body[:1] in ("✓", "✗", "⛔", "▸", "•"):
                s["explain"] = _subtitle(" ".join(x for x in (s.get("explain"), body) if x))
                del s["output"]
            elif s.get("explain"):
                s["explain"] = _subtitle(s["explain"])
            fixed.append(s)
        return fixed

    def add(task: str, steps: list[dict], summary: str) -> None:
        tasks.append({"task": task, "steps": normalize(steps), "summary": summary})

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
        "Identify the agent among everything registered",
        driver_steps(driver_raw, "keycloak-admin", window="agent", bounds=agent_bounds)
        or [{"cmd": "GET <keycloak>/admin/realms/rossoctl/clients", "output": "(not captured — see note)"}],
        "12 clients in the realm. Which one is the agent, and what is its real id?",
    )
    add(
        "Determine what the agent is and what it can do",
        [step(r) for r in by(agent_recs, "idp-config")],
        "Its capabilities, and every role that might reach them — 118 lookups.",
    )
    add(
        "Decide which roles may use each capability",
        [step(r) for r in by(agent_recs, "llm-propose")],
        "Two lines of English, one decision per role/capability pair.",
    )
    add(
        "Check every decision before trusting it",
        [step(r) for r in by(agent_recs, "llm-audit")],
        "A second opinion on each one, with the power to send it back.",
    )
    add(
        "Express the decisions as machine-enforceable rules",
        [step(r) for r in by(agent_recs, "policy-writer")],
        "The full policy model goes in; enforceable Rego comes out.",
    )
    add(
        "Record the decisions so later work builds on them",
        [step(r) for r in by(agent_recs, "model-store")],
        "So onboarding the next workload does not start from scratch.",
    )
    add(
        "The rules that now guard the agent",
        rego_steps("01-after-agent"),
        "Written by nobody. This is what a request is checked against.",
    )
    add(
        "Halfway: who may call the agent is settled",
        state_steps(driver_raw, (d_agent_hi, d_tool_lo))
        + [grants_step(logs / "show-2-after-agent.log")],
        "What the agent may do downstream is still entirely blank.",
    )

    # 8 — make tool, split per plan.md
    add(
        "Identify the tool the agent will call",
        driver_steps(driver_raw, "keycloak-admin", window="tool", bounds=tool_bounds)
        or [{"cmd": "GET <keycloak>/admin/realms/rossoctl/clients", "output": "(not captured — see note)"}],
        "Same problem again: which registration is the tool?",
    )
    add(
        "Enumerate the tool's actual capabilities",
        [step(r) for r in by(tool_recs, "mcp-tools-list")],
        "Asked the running tool directly. It answers with 4. Nobody typed them in.",
    )
    add(
        "Decide which roles may use each tool capability",
        [step(r) for r in by(tool_recs, "llm-propose")],
        "The same two lines of English, now against real tool capabilities.",
    )
    add(
        "Check those decisions too",
        [step(r) for r in by(tool_recs, "llm-audit")],
        "Every one reviewed a second time.",
    )
    add(
        "Extend the agent's rules to cover the tool",
        [step(r) for r in by(tool_recs, "policy-writer")],
        "The tool needs no rules of its own — it is a target, not an actor.",
    )
    add(
        "Record the tool's decisions",
        [step(r) for r in by(tool_recs, "model-store")],
        "Both workloads now on record.",
    )
    add(
        "The completed rules",
        rego_steps("02-after-tool"),
        "Both gates now populated.",
    )
    add(
        "The result: least privilege, written by nobody",
        state_steps(driver_raw, (d_tool_hi, len(driver_raw))) + [rego_diff_step(logs / "diff.log")],
        "Developers: source + read issues. Testers: issues only. From two lines.",
    )

    # 10-12 — drive real users through the gates
    USER_TASK = {
        "dev": "A developer does their job",
        "test": "A tester does their job",
        "devops": "Someone the policy never mentioned tries",
    }
    for target, summary in (
        ("dev", "Reads and writes source, reads issues — but cannot close one."),
        ("test", "Files and reads issues — but cannot see source."),
        ("devops", "Refused at the door. Nothing ever granted them access."),
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
            if len(t[field]) > SUBTITLE_MAX:
                long.append(f"{field} ({len(t[field])}): {t[field][:60]}")
        for st in t["steps"]:
            if len(st.get("explain", "")) > SUBTITLE_MAX:
                long.append(f"explain ({len(st['explain'])}): {st['explain'][:60]}")
    if long:
        print(f"WARNING: {len(long)} field(s) exceed the {SUBTITLE_MAX}-char subtitle budget:")
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
