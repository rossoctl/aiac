"""Corpus-integrity check for the semantic-perturbation sign-off gate (spec: #2467,
``docs/evaluation/eval-framework.md`` §4).

Every semantic perturbation under ``eval/scenarios_perturbed/`` (``policy.eval_*_perturbed.md``,
both the invariance family's originals and the sensitivity family's ``_sensitive_perturbed``
siblings) requires a human sign-off, recorded in ``eval/scenarios_perturbed/SIGNOFF.md``, before it
enters the corpus. This test enforces that mechanically: every such policy file must have a ledger
row, and that row's two recorded hashes must match the *current* content of both the source prose
under ``eval/scenarios_perturbed/`` (what the human actually read to sign off) and its digested
counterpart under ``eval/scenarios_digested/`` (what ``test_policy_pipeline_robustness.py`` actually
feeds the PRB, via ``digested_policy_path`` — see ``eval/scenarios_digested/__init__.py``). Either
one changing without a fresh hash + sign-off fails loudly here instead of shipping silently
re-signed-off — hashing only the prose would leave the digested file, which is the artifact
actually scored, free to drift unnoticed.

Pure-logic, unmarked, no LLM — runs in the default fast unit pass, same convention as
``eval/test_convert_scenarios.py``.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PERTURBED_DIR = _HERE / "scenarios_perturbed"
_DIGESTED_DIR = _HERE / "scenarios_digested"
_SIGNOFF_PATH = _PERTURBED_DIR / "SIGNOFF.md"

# Matches one ledger table row: | <policy file> | `<source sha256>` | `<digested sha256>` | ...
# (remaining columns ignored).
_ROW_RE = re.compile(
    r"^\|\s*(policy\.eval_\S+?\.md)\s*\|\s*`([0-9a-f]{64})`\s*\|\s*`([0-9a-f]{64})`\s*\|", re.MULTILINE
)


def _ledger() -> dict[str, tuple[str, str]]:
    text = _SIGNOFF_PATH.read_text(encoding="utf-8")
    return {name: (source_hash, digested_hash) for name, source_hash, digested_hash in _ROW_RE.findall(text)}


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
    """A ledger row's two recorded hashes must match the current content of both the source prose
    and its digested counterpart — catches either one edited after sign-off without a fresh hash +
    review, including an edit made directly to the digested file that never touched the prose."""
    ledger = _ledger()
    stale: list[str] = []
    for name, (recorded_source_hash, recorded_digested_hash) in ledger.items():
        source_path = _PERTURBED_DIR / name
        digested_path = _DIGESTED_DIR / name
        if not source_path.exists():
            stale.append(f"{name}: ledger row exists but source file is missing")
            continue
        if not digested_path.exists():
            stale.append(f"{name}: ledger row exists but digested file is missing")
            continue
        actual_source_hash = _sha256(source_path)
        if actual_source_hash != recorded_source_hash:
            stale.append(
                f"{name}: ledger source hash {recorded_source_hash} != current content hash {actual_source_hash}"
            )
        actual_digested_hash = _sha256(digested_path)
        if actual_digested_hash != recorded_digested_hash:
            stale.append(
                f"{name}: ledger digested hash {recorded_digested_hash} != current content hash {actual_digested_hash}"
            )
    assert not stale, "SIGNOFF.md rows out of date — re-review and refresh these:\n" + "\n".join(stale)
