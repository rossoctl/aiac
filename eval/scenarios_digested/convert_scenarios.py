"""Thin CLI: batch-convert the eval scenario source policies into digested policies.

A wrapper over ``aiac.agent.policy_digester.digest_policy`` — the single source of truth
for the digest prompt. This script owns only file plumbing (reading source ``*.md``,
writing the digested ``*.md``); the conversion itself is the shared callable, so the
prompt is never duplicated here.

Usage:
    # Batch: digest every scenario policy under eval/scenarios{,_perturbed}/ into
    # eval/scenarios_digested/ (needs LLM_BASE_URL / LLM_MODEL / LLM_API_KEY):
    python -m eval.scenarios_digested.convert_scenarios

    # Single file (digest SRC, write to DST; omit DST to print to stdout):
    python -m eval.scenarios_digested.convert_scenarios SRC [DST]
"""

from __future__ import annotations

import sys
from pathlib import Path

from aiac.agent.policy_digester import digest_policy

_HERE = Path(__file__).resolve().parent  # eval/scenarios_digested/
_EVAL = _HERE.parent  # eval/

# The source corpora, and where digests land (this package's own directory).
DEFAULT_SOURCE_DIRS: list[Path] = [_EVAL / "scenarios", _EVAL / "scenarios_perturbed"]
DEFAULT_OUTPUT_DIR: Path = _HERE


def convert_file(src: Path, dst: Path) -> None:
    """Digest the source policy at ``src`` and write the digested policy to ``dst`` (utf-8)."""
    dst.write_text(digest_policy(src.read_text(encoding="utf-8")), encoding="utf-8")


def run(source_dirs: list[Path], output_dir: Path) -> list[Path]:
    """Digest every ``*.md`` policy found in ``source_dirs`` into ``output_dir`` (created if
    missing), keeping each file's name. Returns the list of written output paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for source_dir in source_dirs:
        for src in sorted(source_dir.glob("*.md")):
            dst = output_dir / src.name
            convert_file(src, dst)
            written.append(dst)
    return written


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args:
        written = run(DEFAULT_SOURCE_DIRS, DEFAULT_OUTPUT_DIR)
        print(f"Digested {len(written)} policy file(s) into {DEFAULT_OUTPUT_DIR}")
        return 0
    if len(args) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    src = Path(args[0])
    if len(args) == 2:
        convert_file(src, Path(args[1]))
    else:
        print(digest_policy(src.read_text(encoding="utf-8")))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
