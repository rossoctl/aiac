#!/usr/bin/env python3
"""Stage 1 — build the shot list from the capture bundle.

Tasks 1-18 come from capture.jsonl. Tasks 19-21 also read logs/{dev,test,devops}.log,
because the capture holds only their login step (see ../movie.md, Known hazards).
"""
import json, re, os, sys

LOGS = {19: ("dev.log", "dev-user"), 20: ("test.log", "test-user"), 21: ("devops.log", "devops-user")}


def pretty(output):
    """Pretty-print a `NNN — <json>` envelope; pass Rego and bare statuses through."""
    m = re.match(r"^(\d{3})\s*—\s*(.*)$", output.strip(), re.S)
    if not m:
        return output.rstrip()
    status, body = m.group(1), m.group(2).strip()
    if not body:
        return status
    try:
        return f"{status} — " + json.dumps(json.loads(body), indent=2, ensure_ascii=False)
    except Exception:
        return output.rstrip()


def log_steps(bundle, task_no):
    """Extract the (cmd, output) pairs the capture is missing for tasks 19-21."""
    fname, user = LOGS[task_no]
    text = open(os.path.join(bundle, "logs", fname)).read()
    steps = []

    # the opa eval invocation + its inbound verdict
    m = re.search(r"^\s+\$ (opa eval .+?)$", text, re.M)
    verdict = re.search(r"(✓ inbound allowed[^\n]*|⛔[^\n]*)", text)
    if m:
        steps.append({"cmd": m.group(1).strip(), "output": (verdict.group(1).strip() if verdict else "")})

    # the per-intent result table
    rows = re.findall(rf"^\s+{user}\s+(.+)$", text, re.M)
    if rows:
        hdr = re.search(r"^(\s+user\s+.+)$", text, re.M)
        sep = re.search(r"^(\s+-{4,}\s+-{4,}.+)$", text, re.M)
        table = []
        if hdr: table.append(hdr.group(1).rstrip())
        if sep: table.append(sep.group(1).rstrip())
        for r in rows:
            table.append(f"  {user}  " + r.rstrip())
        steps.append({"cmd": None, "output": "\n".join(table), "table": True})
    return steps


def build(bundle):
    tasks = []
    for i, line in enumerate(open(os.path.join(bundle, "capture.jsonl")), 1):
        d = json.loads(line)
        steps = []
        for s in d["steps"]:
            out = pretty(s.get("output", "") or "")
            sent = s.get("sent", "") or ""
            step = {
                "cmd": s.get("cmd", ""),
                "output": out,
                "explain": s.get("explain") or None,
                "sent_bytes": len(sent),
            }
            # A bare status (`204`) says nothing on screen while the substance sits in
            # the request body — the computed policy, up to 12 KB of it. Carry `sent`
            # through so the frame can show what was actually applied. Keyed on the
            # output carrying no substance, never on a task number (see ../adr).
            if sent and len(out.strip()) < 12:
                try:
                    step["sent"] = json.dumps(json.loads(sent), indent=2, ensure_ascii=False)
                except Exception:
                    step["sent"] = sent
            steps.append(step)
        if i in LOGS:
            steps += log_steps(bundle, i)
        tasks.append({
            "n": i,
            "task": d.get("task", ""),
            "summary": d.get("summary", "").replace("---", "").strip(),
            "steps": steps,
        })
    return tasks


if __name__ == "__main__":
    bundle = os.path.abspath(sys.argv[1])
    tasks = build(bundle)
    mdir = os.path.join(bundle, "movie")
    os.makedirs(mdir, exist_ok=True)
    # remember which bundle this build targets, so later stages need no argument
    json.dump({"bundle": bundle},
              open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "bundle.json"), "w"), indent=1)
    out = os.path.join(mdir, "shotlist.json")
    # Preserve measured narration durations and fitted pacing across a re-read:
    # they are expensive to recompute (TTS or a recording session) and dropping them
    # silently breaks render.mjs at task 1.
    if os.path.exists(out):
        try:
            prev = {x["n"]: x for x in json.load(open(out))}
            for t in tasks:
                old = prev.get(t["n"], {})
                for k in ("narration_s", "narration_src", "pace"):
                    if k in old:
                        t[k] = old[k]
        except Exception:
            pass
    json.dump(tasks, open(out, "w"), ensure_ascii=False, indent=1)
    tot = sum(len(t["steps"]) for t in tasks)
    print(f"{len(tasks)} tasks, {tot} steps -> {out}")
    for t in tasks:
        if t["n"] >= 19:
            print(f"  task {t['n']}: {len(t['steps'])} steps (capture + logs)")
