"""Storyline loader — narrative prose for capture.jsonl, sourced from ``storyline.md``.

``assemble.py`` owns *structure* (which HTTP records become which task's steps).
This module owns *prose*: the ``summary`` line under each task. Keeping the two apart
means the demo script can be reviewed and revised as English, in one file, without
touching assembler plumbing.

Contract with ``storyline.md``
-----------------------------
Every ``### <task caption>`` heading is a task key; the paragraphs beneath it are that
task's ``summary``. Headings under the ``## Conventions`` / ``## Applying changes``
sections are ignored (they are documentation, not tasks).

Placeholders
------------
Prose may cite values the run actually produced, written as ``{name}``. They are
substituted from the live capture at assemble time, so a summary cannot drift from the
run it narrates: if the realm reissues a UUID, the sentence follows. An unknown
placeholder is a hard error rather than a silently-empty sentence — a demo script that
claims a value must be able to show it.

See ``values_from_capture`` for the available names.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_DOC_SECTIONS = {"conventions", "applying changes", "placeholders"}
_PLACEHOLDER_RE = re.compile(r"\{([a-z0-9_]+)\}")


class StorylineError(RuntimeError):
    """Raised when storyline.md and the assembler disagree, or a placeholder is unknown."""


def _iter_bodies(text: str):
    """Yield ``(caption, body)`` for each task heading outside the doc sections."""
    section = ""
    caption = None
    buf: list[str] = []
    for line in text.splitlines():
        if line.startswith("## "):
            if caption:
                yield caption, "\n".join(buf).strip()
                caption, buf = None, []
            section = line[3:].strip().lower()
            continue
        if line.startswith("### "):
            if caption:
                yield caption, "\n".join(buf).strip()
            caption, buf = (None if section in _DOC_SECTIONS else line[4:].strip()), []
            continue
        if caption:
            buf.append(line)
    if caption:
        yield caption, "\n".join(buf).strip()


def _normalize_caption(cap: str) -> str:
    """Match captions across cosmetic drift: backticks, em/en dashes, whitespace."""
    cap = cap.replace("`", "").replace("—", "-").replace("–", "-")
    return " ".join(cap.split()).lower()


def _flow(body: str) -> str:
    """Collapse a markdown paragraph to the single line a JSON summary field holds."""
    body = re.sub(r"\n\s*\n", "\x00", body)          # keep paragraph breaks
    body = " ".join(body.split())
    return body.replace("\x00", " ").replace("`", "").strip()


def load(path: Path) -> dict[str, str]:
    """Parse ``storyline.md`` into ``{normalized caption: summary}``."""
    out: dict[str, str] = {}
    for caption, body in _iter_bodies(path.read_text(encoding="utf-8")):
        if not body:
            continue
        key = _normalize_caption(caption)
        if key in out:
            raise StorylineError(f"duplicate storyline heading: {caption!r}")
        out[key] = _flow(body)
    if not out:
        raise StorylineError(f"no task headings found in {path}")
    return out


_SCENARIO_RE = re.compile(r"SCENARIO POLICY:\s*\n(.*?)(?:\n\s*\n\s*(?:FOCAL ENTITY|CANDIDATES)\b|\Z)", re.S)


def _scenario_policy(records: list[dict]) -> str:
    """The scenario policy text, lifted from the LLM prompt the run actually sent.

    The demo mounts ``scenario.POLICY_ABSTRACT`` into the Controller as a ConfigMap
    (``/etc/aiac/policy.md``); the PRB reads that file and embeds it in every proposer
    prompt under a ``SCENARIO POLICY:`` heading. Reading it back out of the captured
    request means the narration quotes the bytes the model was actually judging -- not a
    third copy that can drift from ``scenario.py`` or ``demo.md``.
    """
    for rec in records:
        body = (rec.get("request") or {}).get("body")
        if not isinstance(body, str) or "SCENARIO POLICY:" not in body:
            continue
        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            continue
        for msg in payload.get("messages", []) if isinstance(payload, dict) else []:
            content = msg.get("content") if isinstance(msg, dict) else None
            if not isinstance(content, str):
                continue
            match = _SCENARIO_RE.search(content)
            if match:
                # Collapse to one line: bullets become "; "-joined clauses so the text can
                # sit inside a prose summary without breaking the JSON field.
                lines = [ln.strip() for ln in match.group(1).strip().splitlines() if ln.strip()]
                return " ".join(
                    ln.lstrip("-").strip() if ln.startswith("-") else ln for ln in lines
                )
    return ""


def values_from_capture(records: list[dict]) -> dict[str, str]:
    """Harvest the real values the run observed, for ``{placeholder}`` substitution.

    Everything here is read out of captured HTTP responses -- never hardcoded and never
    inferred -- so a summary that cites a UUID is quoting this run's own traffic.
    """
    clients: dict[str, str] = {}
    roles: dict[str, str] = {}
    scope_names: set[str] = set()

    for rec in records:
        resp = rec.get("response") or {}
        body = resp.get("body")
        if not isinstance(body, str):
            continue
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            continue
        for item in parsed if isinstance(parsed, list) else [parsed]:
            if not isinstance(item, dict):
                continue
            if "clientId" in item and "id" in item:
                clients[str(item["clientId"])] = str(item["id"])
            if "name" in item and "clientRole" in item:
                roles[str(item["name"])] = str(item.get("kind", ""))
            if "name" in item and "protocol" in item and "id" in item:
                scope_names.add(str(item["name"]))

    def spiffe(needle: str) -> tuple[str, str]:
        for cid, uuid in clients.items():
            if cid.startswith("spiffe://") and needle in cid:
                return cid, uuid
        return "", ""

    agent_spiffe, agent_uuid = spiffe("github-agent")
    tool_spiffe, tool_uuid = spiffe("github-tool")

    managed = sorted(n for n in roles if n.startswith(("github-agent.", "github-tool.")))
    agent_roles = [n for n in managed if n.startswith("github-agent.")]

    vals = {
        "agent_spiffe": agent_spiffe,
        "agent_uuid": agent_uuid,
        "tool_spiffe": tool_spiffe,
        "tool_uuid": tool_uuid,
        "client_count": str(len(clients)) if clients else "",
        "agent_roles": ", ".join(agent_roles),
        "agent_role_count": str(len(agent_roles)) if agent_roles else "",
        "tool_scopes": ", ".join(sorted(scope_names)) if scope_names else "",
        "policy_text": _scenario_policy(records),
    }
    return {k: v for k, v in vals.items() if v}


def render(summary: str, values: dict[str, str], *, caption: str) -> str:
    """Substitute ``{placeholder}`` from ``values``; unknown names are a hard error."""
    missing = [n for n in _PLACEHOLDER_RE.findall(summary) if n not in values]
    if missing:
        raise StorylineError(
            f"storyline task {caption!r} cites {missing} but the capture did not yield "
            f"{'them' if len(missing) > 1 else 'it'}. Available: {sorted(values)}"
        )
    return _PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], summary)
