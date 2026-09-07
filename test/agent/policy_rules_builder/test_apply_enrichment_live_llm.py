"""Live-LLM case for the ``/apply`` conflict-report enrichment (#2503).

Mirrors ``test_conflict_check_live_llm.py`` / ``test_graph_live_llm.py``: it runs the **real** LLM
end-to-end through :func:`enrich_report` — the pass ``ServicePolicyBuilder.build()`` invokes ONLY
when the deterministic ``detect_conflicts`` finds a structural conflict — and asserts **structural**
properties of the enriched ``ConflictReport``: the planted colliding pair is present, its ``kind``
is one of the two recognized kinds, and every extracted quote is a verbatim (whitespace-normalized)
substring of the candidate policy text. It deliberately does NOT assert exact quote strings or
explanation wording (model nondeterminism) — only containment + substring-validity.

Nothing but the LLM endpoint is needed: ``enrich_report`` takes the assembled rules + policy text
directly, so there is no catalog / cluster / Keycloak to stub. The structural report is produced by
the real ``detect_conflicts`` over a hand-built allow∩deny overlap, exactly as the build would hand
it to enrichment.

Gating: marked **both** ``integration`` and ``llm`` so the routine ``-m "not integration"`` run
deselects it, while ``-m llm`` selects it cluster-free. The autouse ``require_env_or_skip`` fixture
makes it **skip cleanly** (never crash, never false-pass) when the endpoint is unset.
"""

import pytest

from aiac.agent.policy_rules_builder.conflict_detection import detect_conflicts
from aiac.agent.policy_rules_builder.conflict_enrichment import enrich_report
from aiac.agent.policy_rules_builder.diagnostic import _verify_quote
from aiac.agent.policy_rules_builder.diagnostic_models import ConflictKind, ConflictStatus
from aiac.idp.configuration.models import Role, RoleKind, Scope
from aiac.policy.model.models import PolicyRule, RuleEffect
from test.integration.launcher import require_env_or_skip

pytestmark = [pytest.mark.integration, pytest.mark.llm]


@pytest.fixture(autouse=True)
def _require_llm_env():
    """Skip the whole suite cleanly unless a real LLM endpoint is configured."""
    require_env_or_skip("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")


def test_enrichment_produces_verbatim_substring_quotes_for_the_conflicting_pair():
    # A genuine direct conflict on (tester, issues): the policy both grants and prohibits it. The
    # structural detector surfaces the pair with no quotes; enrichment runs the real explain LLM and
    # must return quotes that are verbatim substrings of the policy (containment + substring-valid).
    tester = Role(
        id="r-tester",
        name="tester",
        composite=False,
        kind=RoleKind.USER,
        description="A member of the QA team who tests the product.",
    )
    issues = Scope(
        id="s-iss",
        name="issues",
        description="Read and manage entries in the issue tracker.",
    )
    policy = "Testers may access the issue tracker. Testers must not access the issue tracker."

    rules = [
        PolicyRule(role=tester, scope=issues, effect=RuleEffect.ALLOW),
        PolicyRule(role=tester, scope=issues, effect=RuleEffect.DENY),
    ]
    structural = detect_conflicts(rules)
    assert structural.status is ConflictStatus.CONFLICTS_FOUND  # pre-condition: detector fired

    report = enrich_report(structural, rules, policy)

    # Containment: the planted pair is still present after enrichment (never dropped/reconciled).
    assert report.status is ConflictStatus.CONFLICTS_FOUND
    assert ("r-tester", "s-iss") in {(c.role.id, c.scope.id) for c in report.conflicts}

    c = next(c for c in report.conflicts if (c.role.id, c.scope.id) == ("r-tester", "s-iss"))
    assert c.kind in (ConflictKind.DIRECT, ConflictKind.COARSE_SCOPE)
    # Substring-validity: whatever quotes the model returned must be verbatim substrings, and when
    # it did return quotes the engine must have marked them verified.
    for quote in c.granting_quotes + c.prohibiting_quotes:
        assert _verify_quote(quote, policy), f"quote not a verbatim substring: {quote!r}"
    if c.granting_quotes or c.prohibiting_quotes:
        assert c.quotes_verified is True
