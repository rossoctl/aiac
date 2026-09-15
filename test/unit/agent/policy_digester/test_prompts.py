"""Unit tests for the policy-digester prompt builder.

``build_digest_messages`` is pure and directly testable (no LLM): it composes the
two-message list the digest call sends. Mirrors the ``policy_rules_builder.prompts``
convention — static framing (here, the committed digested-policy spec) in the
SYSTEM message, and the variable input (the source policy) in the HUMAN message so
it is observable in tests.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage

from aiac.agent.policy_digester.prompts import build_digest_messages

# A distinctive, stable clause from docs/specs/digested-policy.md — an independent
# known-good literal (not recomputed from the file the way the code loads it), so this
# assertion actually disagrees with the code if the spec stops being the system prompt.
_SPEC_MARKER = "There is no automatic conflict resolution."

_SOURCE = "Developers may read and write the source repository. Testers may not write issues."


def test_builds_system_then_human() -> None:
    messages = build_digest_messages(_SOURCE)
    assert [type(m) for m in messages] == [SystemMessage, HumanMessage]


def test_spec_is_the_system_prompt() -> None:
    system, _ = build_digest_messages(_SOURCE)
    assert _SPEC_MARKER in system.content


def test_source_policy_is_verbatim_in_human_message() -> None:
    system, human = build_digest_messages(_SOURCE)
    # The variable input rides the HUMAN message verbatim (observable), and never
    # leaks into the static SYSTEM framing.
    assert _SOURCE in human.content
    assert _SOURCE not in system.content
