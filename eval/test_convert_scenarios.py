"""Unit tests for the ``convert_scenarios`` CLI.

Pure-logic, unmarked — runs in the default fast pass. The CLI is a THIN wrapper over
``aiac.agent.policy_digester.digest_policy`` (the single source of truth for the digest
prompt), so these tests patch ``digest_policy`` and only assert the CLI's file plumbing:
single-file conversion and batch conversion of the ``*.md`` scenario policies.
"""

from __future__ import annotations

from unittest.mock import patch

from eval.scenarios_digested.convert_scenarios import main, run

_DIGEST = "eval.scenarios_digested.convert_scenarios.digest_policy"


def test_main_converts_single_file(tmp_path) -> None:
    src = tmp_path / "policy.eval_x.md"
    src.write_text("SOURCE PROSE", encoding="utf-8")
    dst = tmp_path / "out.md"
    with patch(_DIGEST, return_value="DIGESTED"):
        rc = main([str(src), str(dst)])
    assert rc == 0
    assert dst.read_text(encoding="utf-8") == "DIGESTED"


def test_run_batch_converts_only_md_across_source_dirs(tmp_path) -> None:
    s1 = tmp_path / "scenarios"
    s1.mkdir()
    (s1 / "policy.eval_1.md").write_text("P1", encoding="utf-8")
    (s1 / "scenario_eval_1.py").write_text("# not a policy", encoding="utf-8")  # must be skipped
    s2 = tmp_path / "scenarios_perturbed"
    s2.mkdir()
    (s2 / "policy.eval_2.md").write_text("P2", encoding="utf-8")
    out = tmp_path / "digested"  # does not exist yet — run() must create it

    with patch(_DIGEST, side_effect=lambda text: f"{text}-DIG"):
        written = run([s1, s2], out)

    assert (out / "policy.eval_1.md").read_text(encoding="utf-8") == "P1-DIG"
    assert (out / "policy.eval_2.md").read_text(encoding="utf-8") == "P2-DIG"
    assert not (out / "scenario_eval_1.py").exists()  # only *.md is digested
    assert {p.name for p in written} == {"policy.eval_1.md", "policy.eval_2.md"}
