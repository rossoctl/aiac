"""Reusable precision/recall + denial-precision scorer for gate-classified grant-pair sets (spec:
``docs/specs/eval/policy-eval-correctness-prb.md``).

Pure logic, no I/O, no LLM. Generic over any caller's own ``granted``/``denied``/``expected`` gate
dicts (each a mapping of gate name -> ``set[tuple[str, str]]``) — not PRB-specific, so both this
ticket's PRB-direct suite (``test_policy_pipeline_correctness_prb.py``) and a future end-to-end
suite can feed it their own gate-classified pairs without reimplementing any of the scoring.

Terminology, per gate:
    - ``granted``  — pairs the system under test actually allowed (``PolicyRule.effect == ALLOW``).
    - ``denied``   — pairs the system under test explicitly denied (``PolicyRule.effect == DENY``).
    - ``expected`` — the truth table: pairs that *should* be granted.

    - ``true_positives``     = granted & expected
    - ``over_grants``        = granted - expected   (false positives — security-critical)
    - ``under_grants``       = expected - granted    (false negatives — availability, not gated)
    - ``correctly_denied``   = denied - expected     (an explicit deny for a pair that should NOT
      be granted — the deny mechanism doing its job)
    - ``incorrectly_denied`` = denied & expected      (an explicit deny for a pair that SHOULD be
      granted — always a subset of ``under_grants``, diagnosed more precisely)

Zero-tolerance gate: a scenario ``passed`` iff it has no over-grants in any gate. Under-grants and
incorrectly-denied pairs are tracked/reported, never gating (spec: under-grant threshold TBD,
deferred).
"""

from __future__ import annotations

from dataclasses import dataclass

Pair = tuple[str, str]


def _precision(true_positives: frozenset[Pair], over_grants: frozenset[Pair]) -> float:
    granted = len(true_positives) + len(over_grants)
    return 1.0 if granted == 0 else len(true_positives) / granted


def _recall(true_positives: frozenset[Pair], under_grants: frozenset[Pair]) -> float:
    expected = len(true_positives) + len(under_grants)
    return 1.0 if expected == 0 else len(true_positives) / expected


def _denial_precision(correctly_denied: frozenset[Pair], denied: frozenset[Pair]) -> float:
    return 1.0 if not denied else len(correctly_denied) / len(denied)


@dataclass(frozen=True)
class GateScore:
    gate: str
    true_positives: frozenset[Pair]
    over_grants: frozenset[Pair]  # granted - expected (FP)
    under_grants: frozenset[Pair]  # expected - granted (FN)
    correctly_denied: frozenset[Pair]  # denied - expected (TN)
    incorrectly_denied: frozenset[Pair]  # denied & expected (subset of under_grants)
    precision: float  # TP/(TP+FP); 1.0 when granted is empty
    recall: float  # TP/(TP+FN); 1.0 when expected is empty
    denial_precision: float  # |correctly_denied|/|denied|; 1.0 when denied is empty

    @property
    def over_grant_free(self) -> bool:
        return not self.over_grants


@dataclass(frozen=True)
class ScenarioScore:
    scenario: str
    gates: dict[str, GateScore]
    precision: float  # aggregate across all gates' pairs unioned
    recall: float
    denial_precision: float

    @property
    def passed(self) -> bool:
        """Zero-tolerance: no over-grants in any gate."""
        return all(gate.over_grant_free for gate in self.gates.values())

    @property
    def over_grants(self) -> dict[str, frozenset[Pair]]:
        return {name: gate.over_grants for name, gate in self.gates.items() if gate.over_grants}

    @property
    def under_grants(self) -> dict[str, frozenset[Pair]]:
        return {name: gate.under_grants for name, gate in self.gates.items() if gate.under_grants}

    @property
    def incorrectly_denied(self) -> dict[str, frozenset[Pair]]:
        return {name: gate.incorrectly_denied for name, gate in self.gates.items() if gate.incorrectly_denied}


def score_gate(gate: str, granted: set[Pair], denied: set[Pair], expected: set[Pair]) -> GateScore:
    true_positives = frozenset(granted & expected)
    over_grants = frozenset(granted - expected)
    under_grants = frozenset(expected - granted)
    correctly_denied = frozenset(denied - expected)
    incorrectly_denied = frozenset(denied & expected)
    return GateScore(
        gate=gate,
        true_positives=true_positives,
        over_grants=over_grants,
        under_grants=under_grants,
        correctly_denied=correctly_denied,
        incorrectly_denied=incorrectly_denied,
        precision=_precision(true_positives, over_grants),
        recall=_recall(true_positives, under_grants),
        denial_precision=_denial_precision(correctly_denied, frozenset(denied)),
    )


def score_scenario(
    scenario: str,
    granted: dict[str, set[Pair]],
    denied: dict[str, set[Pair]],
    expected: dict[str, set[Pair]],
) -> ScenarioScore:
    """Score every gate in ``expected`` (the union of all three dicts' keys, in case a caller
    passes an empty ``granted``/``denied`` dict for a gate with no rules at all) and aggregate
    precision/recall/denial-precision across each gate's pairs unioned together."""
    gate_names = sorted(set(granted) | set(denied) | set(expected))
    gates = {
        gate: score_gate(gate, granted.get(gate, set()), denied.get(gate, set()), expected.get(gate, set()))
        for gate in gate_names
    }

    all_tp = frozenset().union(*(g.true_positives for g in gates.values())) if gates else frozenset()
    all_over = frozenset().union(*(g.over_grants for g in gates.values())) if gates else frozenset()
    all_under = frozenset().union(*(g.under_grants for g in gates.values())) if gates else frozenset()
    all_correctly_denied = frozenset().union(*(g.correctly_denied for g in gates.values())) if gates else frozenset()
    all_denied = frozenset().union(*(denied.get(gate, set()) for gate in gate_names)) if gates else frozenset()

    return ScenarioScore(
        scenario=scenario,
        gates=gates,
        precision=_precision(all_tp, all_over),
        recall=_recall(all_tp, all_under),
        denial_precision=_denial_precision(all_correctly_denied, all_denied),
    )
