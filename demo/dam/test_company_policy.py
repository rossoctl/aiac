"""The Sentry on DAM onboarder's company policy and operations, on the demo's story.

Run from the aiac root: ``.venv/bin/pytest demo/dam/test_company_policy.py -p no:cacheprovider``.
The demo's tests live beside it, not under ``test/``, because the repo's tests must not depend on
``demo/``. ``test_split_the_story_policy`` calls the real LLM (``LLM_*``) and skips without it.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import company_policy  # noqa: E402
from onboard_dam_agent import operations  # noqa: E402

TOOLS = json.loads((HERE / "github-mcp-tools.json").read_text())
OPS = {f"github-mcp.{n}": m["description"] for n, m in operations(TOOLS).items()}
AGENTS = {
    "issue-workbench": "Helps the team work on issues in the s-and-p-team demo repositories. It reads and summarizes issues, posts comments, and hands an issue back and forth between the developer and the tester with its labels, ready for testing or needs a fix. It never closes issues.",
    "qa-signoff": "Final QA review. It reads an issue and its history, posts the sign-off comment, and closes the issue as completed, or as not planned. It never relabels issues and never changes what an issue says.",
}
ROLES = ["developer", "tester"]
DG = {"DG-001", "DG-002", "DG-004"}
STORY = ("Developers and testers may read issues, comment on them and label them. Only testers close an issue, "
         "and the QA sign-off agent is used by testers only. Personal data and restricted data must not be sent "
         "to an untrusted external destination.")


def test_issue_write_is_decided_per_operation():
    names = [n for n in OPS if n.startswith("github-mcp.issue_write")]
    assert sorted(names) == [f"github-mcp.issue_write.{op}" for op in ("assign", "close", "create", "edit", "label", "reopen")]
    assert "github-mcp.issue_write" not in OPS
    assert "github-mcp.add_issue_comment" in OPS


def test_a_rule_naming_what_does_not_exist_is_not_enforced_in_part():
    found = company_policy.Split(
        role_rules=[
            company_policy.RoleRule(text="Only testers close an issue.", operations=["github-mcp.issue_write.close"], roles=["tester"]),
            company_policy.RoleRule(text="Only admins delete.", operations=["github-mcp.delete_repository"], roles=["admin"]),
            company_policy.RoleRule(text="Bots never merge.", operations=["github-mcp.merge"], roles=["tester"]),
        ],
        data_rules=[
            company_policy.DataRule(text="PII stays inside.", dg_rules=["DG-001"]),
            company_policy.DataRule(text="Secrets stay inside.", dg_rules=["DG-999"]),
        ],
    )
    out = company_policy.checked(found, OPS, AGENTS, ROLES, DG)
    assert [r.text for r in out.role_rules] == ["Only testers close an issue."]
    assert [r.text for r in out.data_rules] == ["PII stays inside."]
    assert out.unmatched == ["Only admins delete.", "Bots never merge.", "Secrets stay inside."]


def test_render_joins_in_the_holders_and_names_agents_by_id():
    found = company_policy.Split(
        role_rules=[company_policy.RoleRule(text="The QA sign-off agent is used by testers only.", agents=["qa-signoff"], roles=["tester"])],
        data_rules=[company_policy.DataRule(text="Personal data stays inside.", dg_rules=["DG-004", "DG-001"])],
    )
    doc = company_policy.render(found, 4, {"tester": ["bob"]}, {"qa-signoff": "agent-q", "issue-workbench": "agent-w"})
    assert doc["version"] == 4
    assert doc["role_rules"] == [{"id": "R1", "text": "The QA sign-off agent is used by testers only.",
                                  "operations": [], "agents": ["agent-q"], "roles": ["tester"], "holders": ["bob"]}]
    assert doc["dg_rules"] == ["DG-001", "DG-004"]


def test_an_empty_policy_is_no_rules_without_an_llm_call():
    assert company_policy.split("  ", OPS, AGENTS, ROLES, []) == company_policy.Split()


@pytest.mark.llm
def test_split_the_story_policy():
    if not all(os.environ.get(k) for k in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")):
        pytest.skip("needs LLM_BASE_URL, LLM_MODEL and LLM_API_KEY")
    catalog = company_policy.dg_catalog(str(HERE.parents[2] / "lab-data-governance/data_governance/risk/rules/_policy_data/rules_source.json"))
    found = company_policy.checked(company_policy.split(STORY, OPS, AGENTS, ROLES, catalog), OPS, AGENTS, ROLES,
                                   {r["id"] for r in catalog})
    assert found.unmatched == []
    by_ops = {frozenset(r.operations): r for r in found.role_rules if r.operations}
    close = [r for ops, r in by_ops.items() if "github-mcp.issue_write.close" in ops]
    assert close and close[0].roles == ["tester"]
    assert any(r.agents == ["qa-signoff"] and r.roles == ["tester"] for r in found.role_rules)
    base = [r for r in found.role_rules if "github-mcp.add_issue_comment" in r.operations]
    assert base and sorted(base[0].roles) == ROLES and "github-mcp.issue_write.label" in base[0].operations
    assert any("DG-001" in r.dg_rules for r in found.data_rules)
