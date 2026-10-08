"""Unit tests for the shared pipeline setup of ``eval.test_policy_pipeline_eval``:
``prepare_pipeline`` (the env and services of one in-process PRB+PCE run, used by the
8-scenario pipeline and by the Scale e2e fixtures) and ``_read_back`` (roles and scopes from the
IdP library). Offline: no Keycloak, no LLM, no subprocess. Unmarked, runs in the default fast pass.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from aiac.idp.configuration.models import Role, RoleKind
from eval.test_policy_pipeline_eval import _read_back, prepare_pipeline


def _role(name: str, kind: RoleKind, actor_ids: list[str]) -> Role:
    return Role(id=f"id-{name}", name=name, description="", composite=False, kind=kind, actorIds=actor_ids)


class TestPreparePipeline:
    def test_sets_the_agent_side_and_every_url(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        # The suites score the agents' outbound Rego, which is a pass-through under target side
        # (the PCE default), so every caller must get agent-side -- the Scale suite once did not.
        monkeypatch.delenv("AIAC_ENFORCEMENT_SIDE", raising=False)
        idp, store, opa = prepare_pipeline(
            monkeypatch.setenv,
            realm="r1",
            rego_dir=tmp_path / "rego",
            db_path=tmp_path / "policy_model.db",
            idp=("127.0.0.1", 7600),
            store=("127.0.0.1", 7602),
            opa=("127.0.0.1", 7601),
        )
        assert os.environ["AIAC_ENFORCEMENT_SIDE"] == "agent-side"
        assert os.environ["KEYCLOAK_REALM"] == "r1"
        assert os.environ["AIAC_PDP_CONFIG_URL"] == "http://127.0.0.1:7600"
        assert os.environ["AIAC_POLICY_MODEL_STORE_URL"] == "http://127.0.0.1:7602"
        assert os.environ["AIAC_PDP_POLICY_URL"] == "http://127.0.0.1:7601"
        assert (idp.port, store.port, opa.port) == (7600, 7602, 7601)
        assert opa.env["REGO_OUTPUT_DIR"] == str(tmp_path / "rego")
        assert store.env["SERVICEPOLICY_DB_PATH"] == str(tmp_path / "policy_model.db")
        assert (tmp_path / "rego").is_dir()

    def test_wipes_an_old_rego_dir(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        rego_dir = tmp_path / "rego"
        rego_dir.mkdir()
        (rego_dir / "stale.rego").write_text("package stale")
        prepare_pipeline(
            monkeypatch.setenv,
            realm="r1",
            rego_dir=rego_dir,
            db_path=tmp_path / "policy_model.db",
            idp=("127.0.0.1", 7600),
            store=("127.0.0.1", 7602),
            opa=("127.0.0.1", 7601),
        )
        assert list(rego_dir.iterdir()) == []


class TestReadBack:
    def test_a_role_that_two_services_hold_keeps_both_holders(self) -> None:
        shared = "shared-role"
        config = SimpleNamespace(
            get_roles=lambda: [_role(shared, RoleKind.USER, ["unrelated"])],
            get_services=lambda: [
                SimpleNamespace(roles=[_role(shared, RoleKind.AGENT, ["agent-a"])], scopes=[]),
                SimpleNamespace(roles=[_role(shared, RoleKind.AGENT, ["agent-b"])], scopes=[]),
            ],
        )

        roles, _ = _read_back(config)

        assert roles[shared].kind == RoleKind.AGENT
        assert roles[shared].actorIds == ["agent-a", "agent-b"]

    def test_a_role_that_no_service_holds_keeps_the_flat_entry(self) -> None:
        user_role = _role("user-role", RoleKind.USER, ["alice"])
        config = SimpleNamespace(get_roles=lambda: [user_role], get_services=lambda: [])

        roles, _ = _read_back(config)

        assert roles["user-role"] == user_role
