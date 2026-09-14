"""The Policy Digester: source→digested policy conversion.

``digest_policy`` is a PURE callable — given source-policy text it returns digested-policy
text and does nothing else. It reads no files, no env, and persists nothing: the caller
(a future standalone policy-digester unit, or the ``convert_scenarios`` CLI) owns reading
the source and storing the digest. See ``docs/specs/digested-policy.md`` (the design
decision "digestion is produced out of band") and ``CONTEXT.md`` (Policy Digester,
Faithfulness).

The digest is produced as FREE TEXT (the model's ``.content``), not a structured schema:
a digested policy is a markdown document in the digested-policy language, consumed
downstream exactly like a source policy is today.
"""

from __future__ import annotations

from langchain_core.messages import BaseMessage

from aiac.agent.llm import build_llm, call_with_retry, load_llm_settings, raise_sanitized

from .prompts import build_digest_messages

# The digester's env namespace: reads DIGEST_LLM_* (falling back to the shared LLM_*), so it can run
# on a different model / endpoint / retry budget than the Policy Rules Builder.
_DIGEST_NAMESPACE = "DIGEST"


def _digest_call(messages: list[BaseMessage]) -> str:
    """THE digester seam. Unit tests patch this. Delegates the client build + transport retry to the
    shared ``aiac.agent.llm`` seam (on the digester's own ``DIGEST_LLM_*`` settings profile) and
    returns the model's free-text content, folding any surviving failure into the shared sanitized
    LLM errors (``LLMAccessError`` / ``UnparseableLLMResponseError``) so an endpoint / API key can
    never leak."""
    settings = load_llm_settings(_DIGEST_NAMESPACE)
    try:
        result = call_with_retry(build_llm(settings), messages, settings=settings)
    except Exception as err:
        raise_sanitized(err)
    return result.content


def digest_policy(source_policy: str) -> str:
    """Rewrite a source policy (free natural-language prose) into a digested policy expressed in the
    digested-policy language, restating its intent faithfully (adding, dropping, or broadening no
    access). Pure text→text: no I/O, no env reads, no persistence."""
    return _digest_call(build_digest_messages(source_policy))
