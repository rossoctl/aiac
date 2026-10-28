"""The two shared ``k8s/`` scripts, run as the shell scripts run them — unit tests.

``k8s/authbridge-pipeline-check.py`` (the wiring check of ``k8s/opa-kind-verify.sh``, the demo driver and
the system lane's skip gate) and ``k8s/authbridge-rejection.py`` (the outbound classifier the demo driver
sends into the agent pod) are scripts: each test runs one in an isolated interpreter, as a script calls
it, and checks its output and exit code. The configs are those of ``test/unit/test_launcher_outcome.py``,
which tests the same rules through the harness, so that both agree on one set of cases.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# test/unit/k8s/ is 3 levels below the repo root.
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:  # so ``import test.*`` resolves
    sys.path.insert(0, str(REPO_ROOT))

from test.unit.test_launcher_outcome import _CONFIG, _PASSING, _SKIPPING, _reason  # noqa: E402

_PIPELINE_CHECK = REPO_ROOT / "k8s" / "authbridge-pipeline-check.py"
_REJECTION = REPO_ROOT / "k8s" / "authbridge-rejection.py"


@pytest.mark.parametrize("config", _PASSING + _SKIPPING)
def test_pipeline_check_script_gives_the_gate_verdict(config: str) -> None:
    """``k8s/opa-kind-verify.sh`` and the demo driver run ``authbridge-pipeline-check.py`` as a script,
    and the system lane's skip gate loads the same file: its exit code, its output and the gate agree."""
    run = subprocess.run(
        [sys.executable, "-I", str(_PIPELINE_CHECK)], input=config, capture_output=True, text=True, check=False
    )
    gate_passes = _reason(config) is None
    assert (run.returncode == 0) is gate_passes
    assert run.stdout.startswith("ok trust_domain=localtest.me") is gate_passes


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        (_CONFIG, "2"),
        (_CONFIG.replace("      - name: jwt-validation\n      - name: opa\n", "      - name: jwt-validation\n"), "1"),
        (_CONFIG + "# - name: opa\n", "2"),  # a comment is not a plugin
        ("not: [yaml", "0"),
        ("", "0"),
    ],
)
def test_pipeline_check_script_counts_the_opa_legs(config: str, expected: str) -> None:
    """``--opa-legs`` (the teardown status line) counts legs, parsed, and never fails."""
    run = subprocess.run(
        [sys.executable, "-I", str(_PIPELINE_CHECK), "--opa-legs"], input=config, capture_output=True, text=True
    )
    assert (run.returncode, run.stdout.strip()) == (0, expected)


def test_the_rejection_rule_runs_on_the_standard_library_alone() -> None:
    """The demo driver sends ``k8s/authbridge-rejection.py`` into the agent pod, which has no project
    dependencies: an isolated interpreter with no ``site`` packages must load it and classify."""
    script = (
        _REJECTION.read_text() + '\nprint(outbound_outcome(403, \'{"error": "policy.forbidden", "plugin": "opa"}\'))\n'
    )
    run = subprocess.run([sys.executable, "-I", "-S", "-c", script], capture_output=True, text=True, check=True)
    assert run.stdout.strip() == "deny"


@pytest.mark.parametrize("argv", [["--opa-leg"], ["--opa-legs", "-v"], ["--namespace"], ["extra"]])
def test_pipeline_check_script_refuses_an_unknown_argument(argv: list[str]) -> None:
    """A typo never silently runs another check: exit 2 and nothing on stdout."""
    run = subprocess.run(
        [sys.executable, "-I", str(_PIPELINE_CHECK), *argv], input=_CONFIG, capture_output=True, text=True
    )
    assert (run.returncode, run.stdout) == (2, "")


def test_pipeline_check_script_reads_the_configmap_with_kubectl_stderr_apart(tmp_path: Path) -> None:
    """``--namespace`` reads the ConfigMap itself: a kubectl warning on stderr does not break the
    parse, and a failed read is named, never reported as a wiring problem."""
    kubectl = tmp_path / "kubectl"
    kubectl.write_text(
        "#!/bin/sh\n"
        'case "$*" in *" -n bad "*) echo "Error from server (NotFound): namespaces bad" >&2; exit 1 ;; esac\n'
        'case "$*" in *" -n empty "*) exit 0 ;; esac\n'
        'echo "Warning: a discovery hiccup" >&2\n'
        f"cat <<'EOF'\n{_CONFIG}EOF\n"
    )
    kubectl.chmod(0o755)
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin"}

    def run(ns: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-I", str(_PIPELINE_CHECK), "--namespace", ns], capture_output=True, text=True, env=env
        )

    ok = run("team1")
    assert (ok.returncode, ok.stdout.strip()) == (0, "ok trust_domain=localtest.me")
    bad = run("bad")
    assert bad.returncode == 1
    assert bad.stdout.startswith("cannot read configmap authbridge-runtime-config in bad: Error from server")
    empty = run("empty")
    assert (empty.returncode, empty.stdout.strip()) == (
        1,
        "configmap authbridge-runtime-config in empty has no config.yaml",
    )


def test_pipeline_check_script_prints_a_verdict_when_it_fails(tmp_path: Path) -> None:
    """The wiring check always prints a line (the scripts show it), also when PyYAML is missing; the
    ``--opa-legs`` count prints nothing then, and its caller reports it as unknown."""
    (tmp_path / "yaml.py").write_text("raise ImportError('no PyYAML here')\n")
    env = {"PYTHONPATH": str(tmp_path), "PATH": "/usr/bin:/bin"}
    check = subprocess.run(
        [sys.executable, str(_PIPELINE_CHECK)], input=_CONFIG, capture_output=True, text=True, env=env
    )
    assert check.returncode == 1
    assert check.stdout.startswith("authbridge-pipeline-check.py failed: ImportError: no PyYAML here")
    legs = subprocess.run(
        [sys.executable, str(_PIPELINE_CHECK), "--opa-legs"], input=_CONFIG, capture_output=True, text=True, env=env
    )
    assert (legs.returncode, legs.stdout) == (1, "")


def test_pipeline_check_script_does_not_wait_on_a_terminal() -> None:
    """Run with no pipe and no ``--namespace``, it prints usage and exits 2 instead of blocking."""
    import pty

    script = (
        "import os, subprocess, sys\n"
        "pid, fd = os.forkpty()\n"
        "if pid == 0:\n"
        f"    os.execv(sys.executable, [sys.executable, '-I', {str(_PIPELINE_CHECK)!r}])\n"
        "_, status = os.waitpid(pid, 0)\n"
        "print(os.waitstatus_to_exitcode(status))\n"
    )
    assert pty  # the forkpty below needs a POSIX pty
    run = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=20, check=True)
    assert run.stdout.strip() == "2"
