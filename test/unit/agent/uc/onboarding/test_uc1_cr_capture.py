"""The CR capture of the UC-1 system-test harness (``uc1_onboard.capture_aiac_crs``) — pure unit tests.

Before a teardown deletes or rewrites the AIAC CRs, the harness writes every AIAC CR (the managed-by
label, all namespaces) and the global combiner to the pytest host, for post-mortem debugging of a
wrong allow/deny. These tests pin the offline parts with ``kubectl`` stubbed (no cluster): the
directory and file names, the ``metadata.managedFields`` strip, the empty capture, the read-only
calls, and the best-effort contract (a failure is logged, never raised, so it cannot mask a test
failure or stop a teardown).

They import the system harness like ``test_uc1_grant_set_oracles.py`` does
(``from test.system import uc1_onboard``): that harness does **no** cluster I/O at import time.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import pytest
import yaml

HERE = Path(__file__).resolve().parent  # test/unit/agent/uc/onboarding/
REPO_ROOT = HERE.parents[4]  # -> aiac/
sys.path.insert(0, str(REPO_ROOT))  # so ``import test.system.*`` resolves

from test.system import uc1_onboard as uc1  # noqa: E402

STAMP = datetime(2026, 10, 5, 14, 30, 12, 482913, tzinfo=timezone.utc)
INBOUND_REGO = "package authbridge.client.inbound.request\n\nimport rego.v1\n\ndefault allow := false\n"
OUTBOUND_REGO = "package authbridge.client.outbound.request\n\nimport rego.v1\n\nallow := true\n"


def _cr(namespace: str, name: str, *, scope: str = "client", managed: bool = True) -> dict:
    """An ``AuthorizationPolicy`` object as ``kubectl get -o json`` gives it, with ``managedFields``."""
    labels = {"app.kubernetes.io/managed-by": "aiac-pdp-policy-writer"} if managed else {}
    return {
        "apiVersion": "agent.rossoctl.dev/v1alpha1",
        "kind": "AuthorizationPolicy",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "uid": f"uid-{name}",
            "resourceVersion": "42",
            "labels": labels,
            "managedFields": [{"manager": "aiac-pdp-policy-writer", "operation": "Update", "fieldsV1": {"f:spec": {}}}],
        },
        "spec": {
            "scope": scope,
            "policies": [
                {"path": "inbound/request.rego", "content": INBOUND_REGO},
                {"path": "outbound/request.rego", "content": OUTBOUND_REGO},
            ],
        },
    }


AGENT_CR = _cr("team1", "github-agent")
TOOL_CR = _cr("team1", "github-tool")
COMBINER_CR = _cr("rossoctl-system", "default", scope="global", managed=False)


def _stub_kubectl(
    monkeypatch: pytest.MonkeyPatch,
    *,
    managed: list[dict] | Exception,
    combiner: dict | None | Exception,
) -> list[tuple[str, ...]]:
    """Replace the harness ``kubectl`` with a stub: the label-selector call (``_aiac_cr_items``) gives
    ``managed``, the by-name call (``_combiner_cr_items``) gives ``combiner`` (``None`` = absent); an
    exception value is raised. Returns the list of the argv each call had."""
    calls: list[tuple[str, ...]] = []

    def fake(*args: str, input_text: str | None = None, timeout: float = 60.0) -> str:
        calls.append(args)
        answer = managed if "-l" in args else combiner
        if isinstance(answer, Exception):
            raise answer
        if "-l" in args:
            return json.dumps({"items": answer})
        return json.dumps(answer) if answer else ""  # ``--ignore-not-found``: an absent CR is no output

    monkeypatch.setattr(uc1, "kubectl", fake)
    return calls


def _index(capture: Path) -> dict:
    return yaml.safe_load((capture / uc1.CAPTURE_INDEX_FILE).read_text(encoding="utf-8"))


# ======================================================================================
# Names — the capture directory, the per-CR file, the label
# ======================================================================================


def test_capture_dir_name_is_utc_time_label_phase() -> None:
    assert (
        uc1._capture_dir_name(STAMP, "test_uc1_onboard_resync", "teardown")
        == "20261005T143012.482913Z__test_uc1_onboard_resync__teardown"
    )


def test_capture_dir_name_converts_to_utc() -> None:
    """A time in another zone gives the same UTC name."""
    local = STAMP.astimezone(timezone(timedelta(hours=3)))
    assert uc1._capture_dir_name(local, "rung", "teardown") == uc1._capture_dir_name(STAMP, "rung", "teardown")


def test_capture_dir_names_sort_in_time_order() -> None:
    """The fixed-width UTC time comes first, so a plain sort of the names is the time order (also over
    different labels and phases)."""
    later = STAMP + timedelta(seconds=1)
    first = uc1._capture_dir_name(STAMP, "test_z", "teardown")
    second = uc1._capture_dir_name(later, "test_a", "pre-run-slate")
    assert sorted([second, first]) == [first, second]


def test_capture_dir_name_makes_unsafe_parts_safe() -> None:
    """A label or phase with a path separator or a space cannot escape the root or break the name."""
    name = uc1._capture_dir_name(STAMP, "../a b/c", "")
    assert "/" not in name and " " not in name
    assert name == "20261005T143012.482913Z__a-b-c__capture"


def test_cr_file_name_is_namespace_and_name() -> None:
    assert uc1._cr_file_name(AGENT_CR) == "team1__github-agent.yaml"
    assert uc1._cr_file_name(COMBINER_CR) == "rossoctl-system__default.yaml"


@pytest.mark.parametrize(
    ("current", "label"),
    [
        ("test/system/test_uc1_onboard_resync.py::test_restart_keeps_the_cr_set (setup)", "test_uc1_onboard_resync"),
        (
            "test/system/test_uc1_onboard_side_switch.py::test_start_verdict[inbound-dev-user] (call)",
            "test_uc1_onboard_side_switch",
        ),
    ],
)
def test_capture_label_is_the_running_test_module(monkeypatch: pytest.MonkeyPatch, current: str, label: str) -> None:
    monkeypatch.setenv("PYTEST_CURRENT_TEST", current)
    assert uc1._capture_label() == label


def test_capture_label_outside_a_test(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert uc1._capture_label() == "no-test"


def test_default_root_is_the_gitignored_artifacts_dir() -> None:
    """With no ``AIAC_CR_CAPTURE_DIR`` the captures go under ``test/system/artifacts/`` (gitignored)."""
    if os.environ.get("AIAC_CR_CAPTURE_DIR"):
        pytest.skip("AIAC_CR_CAPTURE_DIR is set in this shell, so the default root is not in use")
    assert uc1.CR_CAPTURE_DIR == REPO_ROOT / "test" / "system" / "artifacts" / "cr-captures"


# ======================================================================================
# Content — managedFields stripped, everything else kept, one YAML per CR + an index
# ======================================================================================


def test_strip_managed_fields_keeps_everything_else() -> None:
    stripped = uc1._strip_managed_fields(AGENT_CR)
    assert "managedFields" not in stripped["metadata"]
    expected = {**AGENT_CR, "metadata": {k: v for k, v in AGENT_CR["metadata"].items() if k != "managedFields"}}
    assert stripped == expected
    assert stripped["spec"]["policies"][0]["content"] == INBOUND_REGO  # the Rego is kept
    assert "managedFields" in AGENT_CR["metadata"]  # the input object is not changed


def test_capture_writes_one_yaml_per_cr_and_an_index(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _stub_kubectl(monkeypatch, managed=[AGENT_CR, TOOL_CR], combiner=COMBINER_CR)
    capture = uc1.capture_aiac_crs("teardown", label="test_uc1_onboard_resync", root=tmp_path)

    assert capture is not None and capture.parent == tmp_path
    assert capture.name.endswith("__test_uc1_onboard_resync__teardown")
    files = {"rossoctl-system__default.yaml", "team1__github-agent.yaml", "team1__github-tool.yaml"}
    assert {p.name for p in capture.iterdir()} == files | {uc1.CAPTURE_INDEX_FILE}

    for cr in (AGENT_CR, TOOL_CR, COMBINER_CR):
        text = (capture / uc1._cr_file_name(cr)).read_text(encoding="utf-8")
        assert yaml.safe_load(text) == uc1._strip_managed_fields(cr)  # the full object, round-trips
        assert "managedFields" not in text
        assert "content: |" in text  # the Rego is a readable block, not one escaped line

    index = _index(capture)
    assert index["label"] == "test_uc1_onboard_resync" and index["phase"] == "teardown"
    assert [entry["file"] for entry in index["crs"]] == sorted(files)
    assert {entry["scope"] for entry in index["crs"]} == {"client", "global"}
    assert index["errors"] == []


def test_capture_is_read_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The capture only reads the cluster: every ``kubectl`` call is a ``get`` — of the managed-by
    label across all namespaces, and of the global combiner by name."""
    calls = _stub_kubectl(monkeypatch, managed=[AGENT_CR], combiner=COMBINER_CR)
    uc1.capture_aiac_crs("teardown", label="rung", root=tmp_path)
    assert calls and all(args[0] == "get" for args in calls)
    assert any("-A" in args and uc1.MANAGED_BY_SELECTOR in args for args in calls)
    assert any(uc1.COMBINER_CR_NAME in args and uc1.BUNDLE_SERVICE_NAMESPACE in args for args in calls)


def test_cr_read_by_both_sources_is_written_once(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A combiner that has the managed-by label by mistake comes from both reads; it is one file."""
    labelled_combiner = _cr("rossoctl-system", "default", scope="global")
    _stub_kubectl(monkeypatch, managed=[labelled_combiner], combiner=labelled_combiner)
    capture = uc1.capture_aiac_crs("teardown", label="rung", root=tmp_path)
    assert capture is not None
    assert [entry["file"] for entry in _index(capture)["crs"]] == ["rossoctl-system__default.yaml"]


def test_empty_capture_is_valid(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No AIAC CR and no combiner is a valid capture: the directory with an empty index, not an error."""
    _stub_kubectl(monkeypatch, managed=[], combiner=None)
    capture = uc1.capture_aiac_crs("pre-run-slate", label="rung", root=tmp_path)
    assert capture is not None
    assert [p.name for p in capture.iterdir()] == [uc1.CAPTURE_INDEX_FILE]
    index = _index(capture)
    assert index["crs"] == [] and index["errors"] == []


def test_same_name_captures_do_not_collide(tmp_path: Path) -> None:
    """Two captures with the same time, label and phase get two directories; neither overwrites."""
    first = uc1._write_cr_capture([AGENT_CR], tmp_path, label="rung", phase="teardown", now=STAMP)
    second = uc1._write_cr_capture([], tmp_path, label="rung", phase="teardown", now=STAMP)
    assert first != second and second.name == f"{first.name}-2"
    assert (first / "team1__github-agent.yaml").is_file()  # the first capture is intact


def test_capture_logs_the_absolute_directory_at_warning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The directory is logged as an absolute path at WARNING (shown in a pytest failure report by
    default), also when the root is given as a relative path."""
    _stub_kubectl(monkeypatch, managed=[AGENT_CR], combiner=COMBINER_CR)
    monkeypatch.chdir(tmp_path)
    with caplog.at_level(logging.WARNING, logger=uc1.log.name):
        capture = uc1.capture_aiac_crs("teardown", label="rung", root=Path("relative-root"))
    assert capture is not None and capture.is_absolute()
    assert capture.parent == tmp_path / "relative-root"
    assert any(rec.levelno == logging.WARNING and str(capture) in rec.getMessage() for rec in caplog.records)


# ======================================================================================
# Best-effort — a failure is logged and noted, never raised
# ======================================================================================


def test_unreadable_source_is_noted_and_the_capture_goes_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """When one read fails (an unreachable API), the other source is still written, and the failure is
    logged and put in the index."""
    refused = subprocess.CalledProcessError(1, ["kubectl", "get"], output="", stderr="connection refused")
    _stub_kubectl(monkeypatch, managed=refused, combiner=COMBINER_CR)
    with caplog.at_level(logging.WARNING, logger=uc1.log.name):
        capture = uc1.capture_aiac_crs("teardown", label="rung", root=tmp_path)
    assert capture is not None
    index = _index(capture)
    assert [entry["file"] for entry in index["crs"]] == ["rossoctl-system__default.yaml"]
    assert len(index["errors"]) == 1 and "connection refused" in index["errors"][0]
    assert any("connection refused" in rec.getMessage() for rec in caplog.records)


ERRORS: list[Callable[[], Exception]] = [
    lambda: subprocess.CalledProcessError(1, ["kubectl"], stderr="Unauthorized"),
    lambda: subprocess.TimeoutExpired(["kubectl"], 30),
    lambda: FileNotFoundError("kubectl"),
    lambda: RuntimeError("anything else"),
]


@pytest.mark.parametrize("make_error", ERRORS, ids=["called-process", "timeout", "no-kubectl", "other"])
def test_no_cluster_still_writes_a_capture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, make_error: Callable[[], Exception]
) -> None:
    """Any ``kubectl`` failure on both reads gives an empty capture with two errors, not an exception."""
    _stub_kubectl(monkeypatch, managed=make_error(), combiner=make_error())
    capture = uc1.capture_aiac_crs("teardown", label="rung", root=tmp_path)
    assert capture is not None
    index = _index(capture)
    assert index["crs"] == [] and len(index["errors"]) == 2


def test_capture_never_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A capture that cannot write (the root is a file) logs a warning and returns ``None`` — it never
    raises, so a ``finally`` that calls it neither masks the test failure nor stops its teardown."""
    _stub_kubectl(monkeypatch, managed=[AGENT_CR], combiner=COMBINER_CR)
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger=uc1.log.name):
        assert uc1.capture_aiac_crs("teardown", label="rung", root=blocker) is None
    assert any("failed" in rec.getMessage() for rec in caplog.records)


def test_capture_in_a_finally_keeps_the_original_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """In a ``finally`` (as in ``onboarded_stack``), a capture that fails does not replace the test's
    own exception, and the teardown step after it still runs."""
    _stub_kubectl(monkeypatch, managed=RuntimeError("API down"), combiner=RuntimeError("API down"))
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    teardown_ran = []
    with pytest.raises(AssertionError, match="the original failure"):
        try:
            raise AssertionError("the original failure")
        finally:
            uc1.capture_aiac_crs("teardown", label="rung", root=blocker)
            teardown_ran.append(True)
    assert teardown_ran == [True]
