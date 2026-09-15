"""Digest prompt builder.

Composes the two-message list the digest call sends, following the
``policy_rules_builder.prompts`` convention: the static task framing plus the
committed digested-policy specification go in the SYSTEM message, and the variable
input — the source policy — rides the HUMAN message verbatim so it is observable in
tests.

The specification (``docs/specs/digested-policy.md``) is the single source of truth
for the digested-policy language; it is embedded here as the system prompt rather
than restated, so the prompt can never drift from the spec. It is loaded once at
import (static, safe to read eagerly — the same pattern ``prompts.py`` uses for its
bundled ``generic_policy.md``).
"""

from __future__ import annotations

from pathlib import Path

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

# docs/specs/digested-policy.md relative to this module:
# prompts.py -> policy_digester -> agent -> aiac -> src -> <repo root>
_SPEC_PATH = Path(__file__).resolve().parents[4] / "docs" / "specs" / "digested-policy.md"
_SPEC = _SPEC_PATH.read_text(encoding="utf-8").strip()

# Static task framing that heads the system message, before the embedded spec. Names the
# faithfulness contract in-prompt (add/drop/broaden no access) — the same invariant the
# faithfulness eval guards from the outside.
_DIGEST_TASK = (
    "You rewrite a source access-control policy into a DIGESTED policy expressed strictly in the "
    "digested-policy language specified below. Restate the source policy's intent faithfully: add, "
    "drop, or broaden NO access relative to the source. Emit only the digested policy — the domain "
    "knowledge and the three statement kinds the specification defines — and no commentary.\n\n"
    "=== DIGESTED-POLICY SPECIFICATION ===\n\n"
)

_DIGEST_SYSTEM = _DIGEST_TASK + _SPEC


def build_digest_messages(source_policy: str) -> list[BaseMessage]:
    """Compose the digest call's messages: the task framing + digested-policy spec as the SYSTEM
    message, and the raw ``source_policy`` in the HUMAN message (verbatim, so it is test-observable
    and never buried in the static framing)."""
    return [
        SystemMessage(content=_DIGEST_SYSTEM),
        HumanMessage(content=f"SOURCE POLICY:\n{source_policy}"),
    ]
