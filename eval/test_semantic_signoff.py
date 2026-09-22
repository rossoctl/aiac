"""Corpus-integrity check for the semantic-perturbation sign-off gate (spec: #2467,
``docs/evaluation/eval-framework.md`` §4).

Every semantic perturbation under ``eval/scenarios_perturbed/`` (``policy.eval_*_perturbed.md``,
both the invariance family's originals and the sensitivity family's ``_sensitive_perturbed``
siblings) requires a human sign-off, recorded in ``eval/scenarios_perturbed/SIGNOFF.md``, before it
enters the corpus. This test enforces that mechanically: every such policy file must have a ledger
row, and that row's recorded ``SHA256`` must match the file's *current* content — an edited
perturbation whose ledger row wasn't refreshed (a new hash + a fresh sign-off) fails loudly here
instead of shipping silently re-signed-off.

Pure-logic, unmarked, no LLM — runs in the default fast unit pass, same convention as
``eval/test_convert_scenarios.py``.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PERTURBED_DIR = _HERE / "scenarios_perturbed"
_SIGNOFF_PATH = _PERTURBED_DIR / "SIGNOFF.md"

# Matches one ledger table row: | <policy file> | `<sha256>` | ... (remaining columns ignored).
_ROW_RE = re.compile(r"^\|\s*(policy\.eval_\S+?\.md)\s*\|\s*`([0-9a-f]{64})`\s*\|", re.MULTILINE)


def _ledger() -> dict[str, str]:
    text = _SIGNOFF_PATH.read_text(encoding="utf-8")
    return dict(_ROW_RE.findall(text))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_every_perturbed_policy_has_a_signoff_row() -> None:
    """Every ``policy.eval_*_perturbed.md`` under ``eval/scenarios_perturbed/`` must appear in the
    sign-off ledger — a perturbation with no row at all is exactly the "shipped without sign-off"
    case the gate exists to catch."""
    ledger = _ledger()
    policy_files = sorted(p.name for p in _PERTURBED_DIR.glob("policy.eval_*_perturbed.md"))
    missing = [name for name in policy_files if name not in ledger]
    assert not missing, (
        f"These perturbed policy files have no SIGNOFF.md row — sign them off before they ship: {missing}"
    )


def test_signoff_hashes_match_current_content() -> None:
    """A ledger row's recorded hash must match the file's current content — catches a perturbation
    edited after sign-off without a fresh hash + review."""
    ledger = _ledger()
    stale: list[str] = []
    for name, recorded_hash in ledger.items():
        path = _PERTURBED_DIR / name
        if not path.exists():
            stale.append(f"{name}: ledger row exists but file is missing")
            continue
        actual_hash = _sha256(path)
        if actual_hash != recorded_hash:
            stale.append(f"{name}: ledger hash {recorded_hash} != current content hash {actual_hash}")
    assert not stale, "SIGNOFF.md rows out of date — re-review and refresh these:\n" + "\n".join(stale)
