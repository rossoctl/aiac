# Semantic Perturbation Sign-off Ledger

Per `docs/evaluation/eval-framework.md` §4: every semantic-tier perturbation (LLM-drafted or
hand-authored) requires a **human sign-off** confirming it actually preserves (invariance family)
or changes as intended (sensitivity family) the meaning of its original, before it enters the
corpus — the human review is the real ground-truth authority, not the drafting itself.

One row per perturbed policy `.md` under `eval/scenarios_perturbed/`. `SHA256` is the exact file's
content hash (`sha256sum`) at the time of sign-off — `eval/test_semantic_signoff.py` fails loudly
if a file's current hash no longer matches its row, so an edited-but-not-resigned perturbation
can't silently ship. Regenerate a row's hash and get a fresh sign-off whenever the file changes.

| Policy file | SHA256 | Family | Reviewer | Date | Confirmation |
|---|---|---|---|---|---|
| policy.eval_baseline_perturbed.md | `6202eabec42a9e72d1ced5b4799416a3e217a0f8438b423e45e878e7c1d2ca4a` | invariance | n/a (backfilled) | 2026-09-20 | Preserves meaning. Backfilled: shipped before this ledger existed, via normal PR review (see git history) — not individually re-reviewed for this entry. |
| policy.eval_agent_delegation_perturbed.md | `3c30ee3ceb6b05b4d440a5bf1ad826eb42706f0f46ecc3c0d6d759aaf023d79d` | invariance | n/a (backfilled) | 2026-09-20 | Preserves meaning. Backfilled — see above. |
| policy.eval_unreachable_resources_perturbed.md | `421a2e6fe89e93603977fedb5d9bacd302dcda46359b8bd9df96aa609cea4f8d` | invariance | n/a (backfilled) | 2026-09-20 | Preserves meaning. Backfilled — see above. |
| policy.eval_ambiguous_clause_perturbed.md | `fee339776bcad29d9350c690a5cb890eddc372940661bd082c2ac7398f853401` | invariance | n/a (backfilled) | 2026-09-20 | Preserves meaning. Backfilled — see above. |
| policy.eval_wildcard_grant_perturbed.md | `3f58a3fda642ac6c584c8414c06560422cc2720b7d34541b84e4d3d35ce9c0cb` | invariance | n/a (backfilled) | 2026-09-20 | Preserves meaning. Backfilled — see above. |
| policy.eval_misleading_descriptions_perturbed.md | `5835ab59588da635f89932616ce9971a34c88385e466a69ea08aa643f101124b` | invariance | n/a (backfilled) | 2026-09-20 | Preserves meaning. Backfilled — see above. |
| policy.eval_confusable_agents_perturbed.md | `9081e4f7839f9689e339045077d8e0fa4c92e67c9b9b9f04eba007621e58a713` | invariance | n/a (backfilled) | 2026-09-20 | Preserves meaning. Backfilled — see above. |
| policy.eval_empty_descriptions_perturbed.md | `a3a623a26f51aa79621d1b6867bc8d4f93ec5c0893e537027df8c75359e31c91` | invariance | Amitfre15 | 2026-09-22 | Preserves meaning. Re-signed after renaming the user/agent role from field-operator/groundskeeper to a shared name, grounds-worker (user request) — wording changed, delta unchanged. |
| policy.eval_baseline_sensitive_perturbed.md | `471f029ee17ac2fe3258dbd94f21564db32efabd74470ac1fa368c8a320117e2` | sensitivity | Amitfre15 | 2026-09-20 | Changes meaning as intended: restriction_word — developers lose issue-tracker read access, narrowed to testers only (matches `SENSITIVITY_EDITS["baseline"]`'s delta). |
| policy.eval_agent_delegation_sensitive_perturbed.md | `5f26eb827129a57cd6c63b40656f149bc07bbb7f60c151699b25fef6c8b3bd72` | sensitivity | Amitfre15 | 2026-09-20 | Changes meaning as intended: role_swap — which role may have customs clearance carried out swaps from shipment-coordinator to dock-worker (matches `SENSITIVITY_EDITS["agent_delegation"]`'s delta). |
| policy.eval_unreachable_resources_sensitive_perturbed.md | `060f8602efc2324d2a31a4d223cc6f2cb3dbd7352f86e168e0a776084cec5189` | sensitivity | Amitfre15 | 2026-09-20 | Changes meaning as intended: negation — front desk clerks lose all patient-record access, cascading to the receptionist agent role (matches `SENSITIVITY_EDITS["unreachable_resources"]`'s delta). |
| policy.eval_ambiguous_clause_sensitive_perturbed.md | `a167d48035711e6e07ae03e9b2c39411ec1f8137c4a0436cecb0593f84ac64c2` | sensitivity | Amitfre15 | 2026-09-20 | Changes meaning as intended: negation — enrollment advisors lose all enrollment-lookup access (matches `SENSITIVITY_EDITS["ambiguous_clause"]`'s delta). |
| policy.eval_wildcard_grant_sensitive_perturbed.md | `01eee4aba0bf8eca799148d67859a2d1a54167ee7a97157fe764d38fce7cfbd6` | sensitivity | Amitfre15 | 2026-09-20 | Changes meaning as intended: negation — inventory managers lose the wildcard grant entirely (matches `SENSITIVITY_EDITS["wildcard_grant"]`'s delta). |
| policy.eval_misleading_descriptions_sensitive_perturbed.md | `a87cc9d60cc9b58bcd31b3805d58d22db4d713bc7107744ab13664a062e80cdb` | sensitivity | Amitfre15 | 2026-09-20 | Changes meaning as intended: exception_clause — front desk staff lose reservation/guest-notes access, narrowed to every other role; VIP managers' grant rewritten to stand on its own (matches `SENSITIVITY_EDITS["misleading_descriptions"]`'s delta). |
| policy.eval_confusable_agents_sensitive_perturbed.md | `b25a3a06a9aba3d3fc91e11502875ede475021c7179c14b55d21bfcb33d92080` | sensitivity | Amitfre15 | 2026-09-20 | Changes meaning as intended: negation — team trainers lose all roster/schedule access (matches `SENSITIVITY_EDITS["confusable_agents"]`'s delta). |
| policy.eval_empty_descriptions_sensitive_perturbed.md | `a96e38258ba6e94e54a98db9f86d3b5648f57c028b1982df0def20f26fb8c1f3` | sensitivity | Amitfre15 | 2026-09-22 | Changes meaning as intended: negation — grounds workers (renamed from field-operator/groundskeeper, user request) lose all valve access, cascading to the agent role of the same name (matches `SENSITIVITY_EDITS["empty_descriptions"]`'s delta). |
