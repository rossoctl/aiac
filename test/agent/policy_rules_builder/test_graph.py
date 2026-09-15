"""Unit tests for aiac.agent.policy_rules_builder.graph.

The LLM is mocked at the module's structured-call boundary
(aiac.agent.policy_rules_builder.graph._structured_call) so no live endpoint is
touched; the policy source is stubbed at graph.get_policy_source. Transport
retries (slice 9) patch graph._build_llm + time.sleep instead.
"""

from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest
from openai import APIConnectionError, APITimeoutError

from aiac.agent.policy_rules_builder.graph import (
    AuditVerdict,
    Contradiction,
    LLMAccessError,
    PolicyContradictionError,
    PolicyRulesBuilderBaseError,
    PolicyRulesBuilderError,
    RoleSelection,
    ScopeSelection,
    UnparseableLLMResponseError,
    build_role_rules,
    build_scope_rules,
)
from aiac.idp.configuration.models import Role, Scope
from aiac.policy.model.models import PolicyRule, RuleEffect
from aiac.shared.upstream import is_transient, max_retries


# --------------------------------------------------------------------------- #
# builders (mirror test/policy/computation/test_engine.py)                    #
# --------------------------------------------------------------------------- #
def _role(id="r-edit", name="editor", composite=False, children=None) -> Role:
    return Role(id=id, name=name, composite=composite, childRoles=children or [])


def _scope(id="s-write", name="write") -> Scope:
    return Scope(id=id, name=name)


class _Source:
    """Stub PolicySource whose fetch() returns a fixed policy string."""

    def __init__(self, text="POLICY"):
        self.text = text

    def fetch(self) -> str:
        return self.text


# --------------------------------------------------------------------------- #
# Slice 1 — tracer: build_role_rules happy path. The proposer grants one       #
# candidate scope by name and the auditor approves; a single PolicyRule for     #
# that (role, scope) pair comes back.                                          #
# --------------------------------------------------------------------------- #
def test_build_role_rules_happy_path():
    role = _role()
    write = _scope("s-write", "write")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(granted_scope_names=["write"], reasoning="r"),
                    AuditVerdict(approved=True),
                ],
            )
        )
        rules = build_role_rules(role, [write])

    assert rules == [PolicyRule(role=role, scope=write)]


# --------------------------------------------------------------------------- #
# Slice 2 — build_scope_rules happy path (mirror). Scope is focal, roles are    #
# the candidates; the proposer names one role, the auditor approves.           #
# --------------------------------------------------------------------------- #
def test_build_scope_rules_happy_path():
    editor = _role("r-edit", "editor")
    scope = _scope("s-write", "write")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    ScopeSelection(roles_with_access_names=["editor"], reasoning="r"),
                    AuditVerdict(approved=True),
                ],
            )
        )
        rules = build_scope_rules([editor], scope)

    assert rules == [PolicyRule(role=editor, scope=scope)]


# --------------------------------------------------------------------------- #
# Slice 3 — precheck drops proposer names not in the candidate set BEFORE the   #
# auditor sees them: the proposer hallucinates "ghost", so the auditor audits   #
# only the real "write" selection and just the write rule is built.            #
# --------------------------------------------------------------------------- #
def test_precheck_drops_hallucinated_names():
    role = _role()
    write = _scope("s-write", "write")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        sc = stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(granted_scope_names=["write", "ghost"], reasoning="r"),
                    AuditVerdict(approved=True),
                ],
            )
        )
        rules = build_role_rules(role, [write])

    assert rules == [PolicyRule(role=role, scope=write)]
    # The auditor (2nd structured call) must see the cleaned selection, not "ghost".
    auditor_msg = sc.call_args_list[1].args[1][1].content
    assert "write" in auditor_msg and "ghost" not in auditor_msg


# --------------------------------------------------------------------------- #
# Slice 4 — an auditor-approved empty selection is a valid [] (deny-by-default) #
# and NOT an error. The proposer grants nothing; the auditor approves.         #
# --------------------------------------------------------------------------- #
def test_approved_empty_selection_returns_empty():
    role = _role()
    write = _scope("s-write", "write")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(granted_scope_names=[], reasoning="policy is silent"),
                    AuditVerdict(approved=True),
                ],
            )
        )
        rules = build_role_rules(role, [write])

    assert rules == []


# --------------------------------------------------------------------------- #
# Slice 5 — auditor rejects the first proposal, the builder re-proposes carrying #
# the rejection reason, then the auditor approves. Rules come back AND the 2nd   #
# proposer call was threaded the prior reason.                                  #
# --------------------------------------------------------------------------- #
def test_auditor_reject_then_approve_threads_feedback():
    role = _role()
    write = _scope("s-write", "write")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        sc = stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(granted_scope_names=["write"], reasoning="r"),
                    AuditVerdict(approved=False, reason="scope X unsupported"),
                    RoleSelection(granted_scope_names=["write"], reasoning="r2"),
                    AuditVerdict(approved=True),
                ],
            )
        )
        rules = build_role_rules(role, [write])

    assert rules == [PolicyRule(role=role, scope=write)]
    # 3rd structured call is the re-proposal; its user message must carry the reason.
    reproposal_msg = sc.call_args_list[2].args[1][1].content
    assert "scope X unsupported" in reproposal_msg


# --------------------------------------------------------------------------- #
# Slice 6 — a persistently-rejecting auditor exhausts the audit budget and the  #
# builder RAISES PolicyRulesBuilderError rather than returning a silent [].     #
# --------------------------------------------------------------------------- #
def test_auditor_rejects_past_budget_raises():
    role = _role()
    write = _scope("s-write", "write")

    def se(schema, messages):
        if schema is AuditVerdict:
            return AuditVerdict(approved=False, reason="never ok")
        return RoleSelection(granted_scope_names=["write"], reasoning="r")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph._structured_call", side_effect=se))
        with pytest.raises(PolicyRulesBuilderError):
            build_role_rules(role, [write])


# --------------------------------------------------------------------------- #
# Slice 9 — a persistently-unavailable LLM is transport-retried LLM_MAX_RETRIES  #
# times (#166 gave the LLM seam its own knob, decoupled from UPSTREAM_MAX_        #
# RETRIES), then #165 surfaces a TYPED LLMAccessError (not the raw transport      #
# error) whose __cause__ chains back to the original ConnectionError.            #
# time.sleep is patched so tenacity's backoff waits are skipped.               #
# --------------------------------------------------------------------------- #
def test_llm_unavailable_raises_after_llm_max_retries(monkeypatch):
    monkeypatch.setenv("LLM_MAX_RETRIES", "2")

    original = ConnectionError("down")
    invoke = MagicMock(side_effect=original)
    runnable = MagicMock()
    runnable.invoke = invoke
    llm = MagicMock()
    llm.with_structured_output.return_value = runnable

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph._build_llm", return_value=llm))
        stack.enter_context(patch("time.sleep"))  # NOT tenacity.nap.sleep (ineffective)
        with pytest.raises(LLMAccessError) as exc:
            build_role_rules(_role(), [_scope("s-write", "write")])

    assert invoke.call_count == 2  # retry cadence unchanged
    assert exc.value.__cause__ is original  # original transient chained, not swallowed


# --------------------------------------------------------------------------- #
# Slice 10 — request-timeout robustness. The openai/langchain_openai timeout    #
# and dropped-connection exceptions must be classified transient so the         #
# _structured_call retry wrapper self-heals instead of letting /apply hang.     #
# --------------------------------------------------------------------------- #
def _openai_request():
    import httpx

    return httpx.Request("POST", "https://llm.example/v1/chat/completions")


@pytest.mark.parametrize(
    "exc",
    [
        APITimeoutError(request=_openai_request()),
        APIConnectionError(request=_openai_request()),
    ],
)
def test_openai_timeout_and_connection_errors_are_transient(exc):
    assert is_transient(exc) is True


def test_llm_timeout_is_retried_then_reraised(monkeypatch):
    """A never-returning LLM that raises APITimeoutError is retried LLM_MAX_RETRIES
    times and then surfaces as a TYPED LLMAccessError (#165) — proving the timeout path
    self-heals rather than wedging, while the original timeout stays chained on __cause__."""
    monkeypatch.setenv("LLM_MAX_RETRIES", "2")

    original = APITimeoutError(request=_openai_request())
    invoke = MagicMock(side_effect=original)
    runnable = MagicMock()
    runnable.invoke = invoke
    llm = MagicMock()
    llm.with_structured_output.return_value = runnable

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph._build_llm", return_value=llm))
        stack.enter_context(patch("time.sleep"))
        with pytest.raises(LLMAccessError) as exc:
            build_role_rules(_role(), [_scope("s-write", "write")])

    assert invoke.call_count == 2
    assert exc.value.__cause__ is original


# NOTE: build_llm / llm_retry_config unit tests moved to test/agent/test_llm.py when the client +
# retry machinery was extracted into the shared aiac.agent.llm seam. The PRB-level seam-integration
# tests (that the PRB drives the dedicated LLM cadence end-to-end) remain below.


# =========================================================================== #
# #165 — the _structured_call seam surfaces TYPED, SANITIZED LLM-access errors  #
# instead of reraising the raw transient/parse exception. From a consumer's     #
# view an unreachable LLM (after retries) and a reachable-but-unparseable        #
# response are two distinct, catchable types, and NEITHER message leaks the      #
# endpoint / host / API key. Exercised at the same seam the transport slices     #
# use: patch _build_llm so the real _structured_call runs against a mock invoke. #
# The underlying error is loaded with a fake endpoint/host/key so the            #
# sanitization assertion is meaningful.                                          #
# =========================================================================== #
_FAKE_ENDPOINT = "https://secret-llm.internal:8443/v1"
_FAKE_HOST = "secret-llm.internal"
_FAKE_KEY = "sk-supersecretapikey0123456789"
_LEAK_SUBSTRINGS = (_FAKE_ENDPOINT, _FAKE_HOST, _FAKE_KEY)


def _run_with_failing_invoke(error, monkeypatch):
    """Drive build_role_rules with a mock LLM whose .invoke() always raises `error`, so the
    real _structured_call runs its retry loop + typed-raise wrapper. Returns the raised
    exception (captured via pytest.raises). Retries are bounded to 2 and backoff sleeps skipped."""
    monkeypatch.setenv("LLM_MAX_RETRIES", "2")
    invoke = MagicMock(side_effect=error)
    runnable = MagicMock()
    runnable.invoke = invoke
    llm = MagicMock()
    llm.with_structured_output.return_value = runnable

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph._build_llm", return_value=llm))
        stack.enter_context(patch("time.sleep"))
        with pytest.raises(PolicyRulesBuilderBaseError) as exc:
            build_role_rules(_role(), [_scope("s-write", "write")])
    return exc.value


def test_transient_exhaustion_raises_sanitized_llm_access_error(monkeypatch):
    # A transient error that never clears (retry budget exhausted) -> LLMAccessError, chained.
    leaky = ConnectionError(f"cannot reach {_FAKE_ENDPOINT} host={_FAKE_HOST} key={_FAKE_KEY}")
    raised = _run_with_failing_invoke(leaky, monkeypatch)

    assert type(raised) is LLMAccessError  # exact type, not the raw ConnectionError
    assert raised.__cause__ is leaky  # original transient chained
    message = str(raised)
    for secret in _LEAK_SUBSTRINGS:
        assert secret not in message  # message is sanitized -- no endpoint/host/key leak


def test_parse_error_raises_sanitized_unparseable_response_error(monkeypatch):
    # A NON-transient failure (reachable LLM, but its response cannot be parsed / fails schema
    # validation) is not retried; #165 surfaces it as UnparseableLLMResponseError, chained + sanitized.
    leaky = ValueError(f"could not parse structured output from {_FAKE_ENDPOINT} host={_FAKE_HOST} key={_FAKE_KEY}")
    raised = _run_with_failing_invoke(leaky, monkeypatch)

    assert type(raised) is UnparseableLLMResponseError  # distinct from LLMAccessError
    assert isinstance(raised, PolicyRulesBuilderBaseError)  # shares the PRB base hierarchy
    assert raised.__cause__ is leaky  # original parse/validation error chained
    message = str(raised)
    for secret in _LEAK_SUBSTRINGS:
        assert secret not in message  # message is sanitized -- no endpoint/host/key leak


# =========================================================================== #
# #123 — deny extraction from natural-language policy text.                    #
# The proposer now returns explicit prohibitions (denied_* name lists) and an  #
# exclusivity flag alongside its grants; build emits ALLOW rules for grants    #
# and DENY rules for prohibitions (+ the derived exclusivity complement),      #
# allows-first then denies, each in candidate order. All cases drive the       #
# existing _structured_call seam — proposer + auditor turns interleaved.       #
# =========================================================================== #


# --------------------------------------------------------------------------- #
# Slice A (tracer) — direct prohibition -> DENY, role direction. "developers    #
# may read but must not touch issues": the proposer grants `read` and denies    #
# `issues`; the auditor approves; an ALLOW(read) + DENY(issues) pair comes back.#
# --------------------------------------------------------------------------- #
def test_direct_prohibition_yields_deny_role_direction():
    role = _role("r-dev", "developer")
    read = _scope("s-read", "read")
    issues = _scope("s-issues", "issues")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(
                        granted_scope_names=["read"],
                        denied_scope_names=["issues"],
                        reasoning="may read but must not touch issues",
                    ),
                    AuditVerdict(approved=True),
                ],
            )
        )
        rules = build_role_rules(role, [read, issues])

    assert rules == [
        PolicyRule(role=role, scope=read, effect=RuleEffect.ALLOW),
        PolicyRule(role=role, scope=issues, effect=RuleEffect.DENY),
    ]


# --------------------------------------------------------------------------- #
# Slice B — symmetric direct prohibition -> DENY, scope direction. The scope is #
# focal, roles are candidates: one role is granted access, another is denied.   #
# --------------------------------------------------------------------------- #
def test_direct_prohibition_yields_deny_scope_direction():
    scope = _scope("s-audit", "audit-log")
    security = _role("r-sec", "security")
    intern = _role("r-int", "intern")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    ScopeSelection(
                        roles_with_access_names=["security"],
                        roles_denied_access_names=["intern"],
                        reasoning="security may reach the audit log; interns must not",
                    ),
                    AuditVerdict(approved=True),
                ],
            )
        )
        rules = build_scope_rules([security, intern], scope)

    assert rules == [
        PolicyRule(role=security, scope=scope, effect=RuleEffect.ALLOW),
        PolicyRule(role=intern, scope=scope, effect=RuleEffect.DENY),
    ]


# --------------------------------------------------------------------------- #
# Selection schemas carry NO exclusivity flag (digested input bans "only", so    #
# there is no derived complement -- see the PRB spec's design decision). This    #
# guards the removal from silently regressing.                                  #
# --------------------------------------------------------------------------- #
def test_selection_schemas_carry_no_exclusivity_flag():
    assert "grant_is_exclusive" not in RoleSelection.model_fields
    assert "access_is_exclusive" not in ScopeSelection.model_fields


# --------------------------------------------------------------------------- #
# A grant with no explicit prohibition imposes nothing on the rest. "developers  #
# may access source" grants source and leaves issues a silent non-grant -- no    #
# DENY(issues), and (exclusivity removed) no derived complement either.         #
# --------------------------------------------------------------------------- #
def test_grant_with_no_explicit_deny_imposes_no_prohibition():
    role = _role("r-dev", "developer")
    source = _scope("s-src", "source")
    issues = _scope("s-iss", "issues")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(
                        granted_scope_names=["source"],
                        denied_scope_names=[],
                        reasoning="developers may access source",
                    ),
                    AuditVerdict(approved=True),
                ],
            )
        )
        rules = build_role_rules(role, [source, issues])

    assert rules == [PolicyRule(role=role, scope=source, effect=RuleEffect.ALLOW)]


# --------------------------------------------------------------------------- #
# Slice F — a genuine grant/deny overlap on the same candidate (a coarse scope   #
# "may read issues but must not modify them", where `issues` covers read+write)  #
# is a contradiction. precheck flags issues in BOTH lists; the auditor           #
# adjudicates it genuine, so the builder RAISES PolicyContradictionError         #
# carrying the focal entity and the contradiction (with its description),        #
# fail-closed -- no rule set is returned.                                       #
# --------------------------------------------------------------------------- #
def test_genuine_overlap_raises_policy_contradiction_error():
    role = _role("r-dev", "developer")
    issues = _scope("s-iss", "issues")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(
                        granted_scope_names=["issues"],
                        denied_scope_names=["issues"],
                        reasoning="may read issues but must not modify them",
                    ),
                    AuditVerdict(
                        approved=False,
                        contradictions=[
                            Contradiction(
                                candidate_name="issues",
                                description="coarse-scope granularity mismatch: issues covers read and write",
                            )
                        ],
                    ),
                ],
            )
        )
        with pytest.raises(PolicyContradictionError) as exc:
            build_role_rules(role, [issues])

    # The raise carries the focal identity (its name appears) and all genuine contradictions,
    # each with its description -- the report IS the raise; no rule set comes back.
    assert role.name in exc.value.focal
    assert [c.candidate_name for c in exc.value.contradictions] == ["issues"]
    assert "coarse-scope" in exc.value.contradictions[0].description


# --------------------------------------------------------------------------- #
# Slice G — multiple genuine contradictions are reported in a SINGLE raise, so   #
# the author can fix them all in one pass (not discover them one at a time).    #
# --------------------------------------------------------------------------- #
def test_multiple_contradictions_reported_in_one_raise():
    role = _role("r-dev", "developer")
    issues = _scope("s-iss", "issues")
    deploy = _scope("s-dep", "deploy")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(
                        granted_scope_names=["issues", "deploy"],
                        denied_scope_names=["issues", "deploy"],
                        reasoning="both coarse scopes are partly permitted and partly forbidden",
                    ),
                    AuditVerdict(
                        approved=False,
                        contradictions=[
                            Contradiction(candidate_name="issues", description="direct policy conflict"),
                            Contradiction(candidate_name="deploy", description="coarse-scope granularity mismatch"),
                        ],
                    ),
                ],
            )
        )
        with pytest.raises(PolicyContradictionError) as exc:
            build_role_rules(role, [issues, deploy])

    assert {c.candidate_name for c in exc.value.contradictions} == {"issues", "deploy"}


# --------------------------------------------------------------------------- #
# Slice H — a generation-error overlap is NOT a policy finding. The auditor      #
# rejects the first proposal with contradictions=[] (ordinary rejection); the    #
# builder threads the reason back, re-proposes cleanly, and the auditor          #
# approves. Rules come back, no PolicyContradictionError is raised.             #
# --------------------------------------------------------------------------- #
def test_generation_error_overlap_retries_then_approves():
    role = _role("r-dev", "developer")
    issues = _scope("s-iss", "issues")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        sc = stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(
                        granted_scope_names=["issues"],
                        denied_scope_names=["issues"],
                        reasoning="accidentally listed issues in both",
                    ),
                    AuditVerdict(approved=False, reason="you listed issues as both granted and denied; pick one"),
                    RoleSelection(
                        granted_scope_names=["issues"],
                        denied_scope_names=[],
                        reasoning="issues is granted only",
                    ),
                    AuditVerdict(approved=True),
                ],
            )
        )
        rules = build_role_rules(role, [issues])

    assert rules == [PolicyRule(role=role, scope=issues, effect=RuleEffect.ALLOW)]
    # The re-proposal (3rd structured call) must carry the auditor's rejection reason.
    reproposal_msg = sc.call_args_list[2].args[1][1].content
    assert "pick one" in reproposal_msg


# --------------------------------------------------------------------------- #
# Slice I — an all-deny result (a prohibition with no current grant) is a valid, #
# first-class output, NOT collapsed to []. It blocks a future broad grant under  #
# deny-overrides.                                                               #
# --------------------------------------------------------------------------- #
def test_all_deny_result_is_first_class():
    role = _role("r-dev", "developer")
    issues = _scope("s-iss", "issues")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(
                        granted_scope_names=[],
                        denied_scope_names=["issues"],
                        reasoning="developers must never touch issues",
                    ),
                    AuditVerdict(approved=True),
                ],
            )
        )
        rules = build_role_rules(role, [issues])

    assert rules == [PolicyRule(role=role, scope=issues, effect=RuleEffect.DENY)]


# --------------------------------------------------------------------------- #
# Slice J — precheck drops a hallucinated DENIED name before the auditor sees it #
# (symmetric with the existing granted-name hallucination-drop slice). "ghost"   #
# is not a candidate, so the auditor audits only the real "issues" prohibition. #
# --------------------------------------------------------------------------- #
def test_precheck_drops_hallucinated_denied_name():
    role = _role("r-dev", "developer")
    issues = _scope("s-iss", "issues")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        sc = stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(
                        granted_scope_names=[],
                        denied_scope_names=["issues", "ghost"],
                        reasoning="must not touch issues",
                    ),
                    AuditVerdict(approved=True),
                ],
            )
        )
        rules = build_role_rules(role, [issues])

    assert rules == [PolicyRule(role=role, scope=issues, effect=RuleEffect.DENY)]
    auditor_msg = sc.call_args_list[1].args[1][1].content
    assert "issues" in auditor_msg and "ghost" not in auditor_msg


# --------------------------------------------------------------------------- #
# Slice K — a single call mixing grants and prohibitions returns BOTH, ordered   #
# deterministically: all ALLOWs first, then all DENYs, each in candidate order   #
# (stable + diffable across runs).                                              #
# --------------------------------------------------------------------------- #
def test_mixed_allow_and_deny_ordered_allows_then_denies_candidate_order():
    role = _role("r-dev", "developer")
    source = _scope("s-src", "source")
    issues = _scope("s-iss", "issues")
    deploy = _scope("s-dep", "deploy")
    audit = _scope("s-aud", "audit")

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(
                        granted_scope_names=["source", "deploy"],
                        denied_scope_names=["issues", "audit"],
                        reasoning="may access source and deploy; must not touch issues or audit",
                    ),
                    AuditVerdict(approved=True),
                ],
            )
        )
        # Candidate order: source, issues, deploy, audit.
        rules = build_role_rules(role, [source, issues, deploy, audit])

    assert rules == [
        PolicyRule(role=role, scope=source, effect=RuleEffect.ALLOW),
        PolicyRule(role=role, scope=deploy, effect=RuleEffect.ALLOW),
        PolicyRule(role=role, scope=issues, effect=RuleEffect.DENY),
        PolicyRule(role=role, scope=audit, effect=RuleEffect.DENY),
    ]


# --------------------------------------------------------------------------- #
# Slice L — prompt content. (a) The proposer AND the auditor are told the        #
# deny/exclusivity contract (a one-sided rule would let them diverge): explicit  #
# prohibitions -> deny, and restrictive "only" closes the set. (b) The POLICY    #
# block labels the baseline as grants-only and the scenario separately, so       #
# deny/exclusivity binds to the scenario layer only. Asserted on the captured    #
# message content at the _structured_call seam.                                 #
# --------------------------------------------------------------------------- #
def _capture_first_two_messages():
    """Run one happy build_role_rules and return (proposer_msgs, auditor_msgs) as captured at the
    seam. Each is [SystemMessage, HumanMessage]."""
    role = _role("r-dev", "developer")
    write = _scope("s-write", "write")
    with ExitStack() as stack:
        stack.enter_context(
            patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source("SCEN-TEXT"))
        )
        sc = stack.enter_context(
            patch(
                "aiac.agent.policy_rules_builder.graph._structured_call",
                side_effect=[
                    RoleSelection(granted_scope_names=["write"], reasoning="r"),
                    AuditVerdict(approved=True),
                ],
            )
        )
        build_role_rules(role, [write])
    return sc.call_args_list[0].args[1], sc.call_args_list[1].args[1]


def test_proposer_and_auditor_share_deny_contract():
    # Digested input: prohibitions arrive as explicit deny direct grants, so BOTH sides get the
    # explicit-prohibition rule -- but the exclusivity ("only") handling is GONE (digested policy
    # bans exclusive language), and both sides are framed as reading DIGESTED policy.
    proposer_msgs, auditor_msgs = _capture_first_two_messages()
    for msgs in (proposer_msgs, auditor_msgs):
        system = msgs[0].content.lower()
        assert "prohibition" in system or "must not" in system  # explicit-prohibition -> deny
        assert "exclusivity flag" not in system  # exclusivity handling removed (no derived complement)
        assert "digested" in system  # prompts are digest-aware


def test_policy_block_labels_baseline_grants_only_and_scenario():
    proposer_msgs, _ = _capture_first_two_messages()
    human = proposer_msgs[1].content
    assert "BASELINE POLICY" in human and "grants only" in human
    assert "SCENARIO POLICY" in human
    # The scenario text sits under the SCENARIO label, after the baseline.
    assert human.index("BASELINE POLICY") < human.index("SCENARIO POLICY") < human.index("SCEN-TEXT")


# =========================================================================== #
# #166 — the PRB LLM seam (_structured_call) gets its OWN retry cadence,        #
# independent of the shared UPSTREAM_MAX_RETRIES that governs the IdP/MCP/K8s   #
# transport seams. Knobs: LLM_MAX_RETRIES (default 3), LLM_RETRY_BACKOFF_MIN    #
# (default 1), LLM_RETRY_BACKOFF_MAX (default 30), each read at call time via    #
# the shared aiac.agent.llm.load_llm_settings() and tolerant of unset /          #
# non-numeric values. Exercised at the same seam the transport slices use: set   #
# the env knobs and patch                                                        #
# _build_llm so the real _structured_call runs its retry loop against a mock     #
# invoke; time.sleep is patched so tenacity's backoff waits are skipped.        #
# =========================================================================== #
def _failing_llm(error):
    """Build a mock LLM whose .invoke() always raises `error`, so the real _structured_call
    runs its retry loop against it. Returns (llm, invoke_mock)."""
    invoke = MagicMock(side_effect=error)
    runnable = MagicMock()
    runnable.invoke = invoke
    llm = MagicMock()
    llm.with_structured_output.return_value = runnable
    return llm, invoke


def test_structured_call_honors_llm_max_retries(monkeypatch):
    # The LLM loop's attempt count comes from LLM_MAX_RETRIES; UPSTREAM_MAX_RETRIES is set high on
    # purpose and must be ignored here (proves the loop reads the dedicated knob, not the shared one).
    monkeypatch.setenv("LLM_MAX_RETRIES", "2")
    monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "5")

    llm, invoke = _failing_llm(ConnectionError("down"))

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph._build_llm", return_value=llm))
        stack.enter_context(patch("time.sleep"))
        with pytest.raises(LLMAccessError):
            build_role_rules(_role(), [_scope("s-write", "write")])

    assert invoke.call_count == 2  # LLM_MAX_RETRIES, not UPSTREAM_MAX_RETRIES (=5)


def test_structured_call_backoff_bounds_from_env(monkeypatch):
    # The exponential-backoff bounds flow from LLM_RETRY_BACKOFF_MIN / _MAX into the retry wait.
    # One attempt (no sleep) is enough: we assert the wait_exponential CONSTRUCTION bounds.
    monkeypatch.setenv("LLM_MAX_RETRIES", "1")
    monkeypatch.setenv("LLM_RETRY_BACKOFF_MIN", "7")
    monkeypatch.setenv("LLM_RETRY_BACKOFF_MAX", "9")

    llm, _ = _failing_llm(ConnectionError("down"))

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph._build_llm", return_value=llm))
        stack.enter_context(patch("time.sleep"))
        # The retry loop (and its wait_exponential) now lives in the shared aiac.agent.llm seam.
        we = stack.enter_context(patch("aiac.agent.llm.wait_exponential"))
        with pytest.raises(LLMAccessError):
            build_role_rules(_role(), [_scope("s-write", "write")])

    assert we.call_args.kwargs["min"] == 7
    assert we.call_args.kwargs["max"] == 9


def test_structured_call_decoupled_from_upstream_max_retries(monkeypatch):
    # Decoupling proof (#166): with LLM_MAX_RETRIES UNSET, the LLM loop uses its OWN default (3) and
    # ignores UPSTREAM_MAX_RETRIES entirely -- while the shared max_retries() STILL reads
    # UPSTREAM_MAX_RETRIES for the IdP/MCP/K8s seams.
    monkeypatch.delenv("LLM_MAX_RETRIES", raising=False)
    monkeypatch.setenv("UPSTREAM_MAX_RETRIES", "2")

    assert max_retries() == 2  # the shared knob is untouched -- other seams keep honoring it

    llm, invoke = _failing_llm(ConnectionError("down"))

    with ExitStack() as stack:
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph.get_policy_source", return_value=_Source()))
        stack.enter_context(patch("aiac.agent.policy_rules_builder.graph._build_llm", return_value=llm))
        stack.enter_context(patch("time.sleep"))
        with pytest.raises(LLMAccessError):
            build_role_rules(_role(), [_scope("s-write", "write")])

    assert invoke.call_count == 3  # LLM default, NOT UPSTREAM_MAX_RETRIES (=2) -> decoupled
