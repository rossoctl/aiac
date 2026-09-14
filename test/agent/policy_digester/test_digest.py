"""Unit tests for ``digest_policy`` — the pure source→digested conversion callable.

No live LLM: the tests patch the digester's own LLM seam (``_digest_call``, analogous
to the PRB's ``graph._structured_call``) to observe what it is handed and control what
it returns, and patch the shared ``aiac.agent.llm`` transport to exercise the adapter's
success and sanitized-error paths.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import HumanMessage, SystemMessage

from aiac.agent.llm import LLMAccessError, UnparseableLLMResponseError
from aiac.agent.policy_digester import digest_policy

_SRC = "Developers may read the source repository. Testers may not write issues."
_SEAM = "aiac.agent.policy_digester.digest._digest_call"
_SPEC_MARKER = "There is no automatic conflict resolution."  # stable clause from digested-policy.md


def test_digest_policy_returns_seam_output() -> None:
    with patch(_SEAM, return_value="DIGESTED"):
        assert digest_policy(_SRC) == "DIGESTED"


def test_digest_policy_routes_built_messages_through_seam() -> None:
    captured: dict[str, list] = {}

    def fake(messages):
        captured["messages"] = messages
        return "ok"

    with patch(_SEAM, side_effect=fake):
        digest_policy(_SRC)

    msgs = captured["messages"]
    # digest_policy builds the spec-as-system / source-as-human pair and routes it through the seam.
    assert [type(m) for m in msgs] == [SystemMessage, HumanMessage]
    assert _SPEC_MARKER in msgs[0].content
    assert _SRC in msgs[1].content


def test_digest_policy_returns_model_content() -> None:
    # Through the REAL _digest_call, with only the shared transport patched: the digest is the
    # model's free-text content (no structured schema).
    ai = MagicMock()
    ai.content = "DIGESTED DOCUMENT"
    with (
        patch("aiac.agent.policy_digester.digest.build_llm", return_value=MagicMock()),
        patch("aiac.agent.policy_digester.digest.call_with_retry", return_value=ai),
    ):
        assert digest_policy(_SRC) == "DIGESTED DOCUMENT"


def test_digest_call_sanitizes_transient_as_access_error() -> None:
    with (
        patch("aiac.agent.policy_digester.digest.build_llm", return_value=MagicMock()),
        patch("aiac.agent.policy_digester.digest.call_with_retry", side_effect=ConnectionError("boom")),
    ):
        with pytest.raises(LLMAccessError):
            digest_policy(_SRC)


def test_digest_call_sanitizes_permanent_as_unparseable_error() -> None:
    with (
        patch("aiac.agent.policy_digester.digest.build_llm", return_value=MagicMock()),
        patch("aiac.agent.policy_digester.digest.call_with_retry", side_effect=ValueError("bad")),
    ):
        with pytest.raises(UnparseableLLMResponseError):
            digest_policy(_SRC)
