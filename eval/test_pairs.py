"""Tests for ``eval/pairs.py`` (spec: ``docs/evaluation/eval-framework.md`` §9.1, #2472).

Pure logic, no LLM, no I/O -- unmarked, runs in the default fast pass.
"""

from __future__ import annotations

from eval.pairs import format_pairs, pairs_not_in

# =========================================================================== #
# format_pairs -- shared with eval.conftest._format_pairs_dict                #
# =========================================================================== #


class TestFormatPairs:
    def test_empty_dict_is_none(self) -> None:
        assert format_pairs({}) == "none"

    def test_default_sep_is_single_line(self) -> None:
        pairs = {"inbound": [("role-a", "scope-a")], "outbound": [("role-b", "scope-b")]}
        rendered = format_pairs(pairs)
        assert "\n" not in rendered
        assert "; " in rendered

    def test_custom_sep_for_markdown_rendering(self) -> None:
        pairs = {"inbound": [("role-a", "scope-a")], "outbound": [("role-b", "scope-b")]}
        rendered = format_pairs(pairs, sep="\n", limit=None)
        assert rendered == "inbound: (role-a, scope-a)\noutbound: (role-b, scope-b)"

    def test_pairs_beyond_the_limit_are_summarized_not_dropped_silently(self) -> None:
        """Confirmed as a real finding in PR review: a corpus the size of the Scale suite's
        total-corpus dimension can produce hundreds of pairs for one gate, and the unbounded
        version used to put every single one into one batched LLM request."""
        pairs = {"inbound": [(f"role-{i}", f"scope-{i}") for i in range(25)]}
        rendered = format_pairs(pairs, limit=5)
        assert rendered.count("role-") == 5  # only the first 5 pairs are spelled out
        assert "... and 20 more" in rendered

    def test_no_limit_means_unbounded(self) -> None:
        pairs = {"inbound": [(f"role-{i}", f"scope-{i}") for i in range(25)]}
        rendered = format_pairs(pairs, limit=None)
        assert "..." not in rendered
        assert rendered.count("role-") == 25


# =========================================================================== #
# pairs_not_in                                                                #
# =========================================================================== #


class TestPairsNotIn:
    def test_no_overlap_returns_everything(self) -> None:
        pairs = {"inbound": [("role-a", "scope-a")]}
        assert pairs_not_in(pairs, {}) == pairs

    def test_full_overlap_drops_the_gate_entirely(self) -> None:
        pairs = {"inbound": [("role-a", "scope-a")]}
        assert pairs_not_in(pairs, pairs) == {}

    def test_partial_overlap_keeps_only_the_remainder(self) -> None:
        pairs = {"inbound": [("role-a", "scope-a"), ("role-b", "scope-b")]}
        other = {"inbound": [("role-a", "scope-a")]}
        assert pairs_not_in(pairs, other) == {"inbound": [("role-b", "scope-b")]}

    def test_other_gate_not_present_in_pairs_is_ignored(self) -> None:
        pairs = {"inbound": [("role-a", "scope-a")]}
        other = {"outbound": [("role-b", "scope-b")]}
        assert pairs_not_in(pairs, other) == pairs
