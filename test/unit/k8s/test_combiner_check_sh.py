"""Unit tests for ``k8s/lib/combiner-check.sh``, the shell copy of the Controller start check #4 (D30).

``k8s/opa-kind-enable.sh``, ``k8s/opa-kind-verify.sh`` and the onboarding demo's ``enable.sh`` and
``driver.sh`` source it to stop before the Controller would. Each test runs its ``combiner_problems``
against a fake ``kubectl`` on ``PATH`` that serves one ``default`` CR, and checks that it agrees with
``start.combiner_problems`` (the Controller's own check): the same verdict, and the same request
packages named.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from aiac.agent.controller import start
from test.unit.agent.controller.test_start import _SPLIT_FAIL_OPEN_RULES, _combiner, _package

# test/unit/k8s/ is 3 levels below the repo root.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_LIB = _REPO_ROOT / "k8s" / "lib" / "combiner-check.sh"

pytestmark = pytest.mark.skipif(not shutil.which("bash") or not shutil.which("awk"), reason="needs bash and awk")

# A fake kubectl: serves the CR in $FAKE_CR for the three reads combiner_problems makes, and answers
# NotFound when the file is missing.
_FAKE_KUBECTL = """\
import json, os, re, sys
args = sys.argv[1:]
path = os.environ["FAKE_CR"]
if not os.path.exists(path):
    sys.stderr.write('Error from server (NotFound): authorizationpolicies "default" not found\\n')
    sys.exit(1)
cr = json.load(open(path))
out = args[args.index("-o") + 1]
policies = cr["spec"]["policies"]
if out == "name":
    print("authorizationpolicy.agent.rossoctl.dev/default")
elif out.startswith("jsonpath={range"):
    sys.stdout.write("".join(p["path"] + "\\n" for p in policies))
else:
    i = int(re.fullmatch(r"jsonpath=\\{\\.spec\\.policies\\[(\\d+)\\]\\.content\\}", out).group(1))
    sys.stdout.write(policies[i]["content"])
"""


def _with_inbound(content: str) -> dict:
    cr = _combiner()
    cr["spec"]["policies"][0]["content"] = content
    return cr


_SAFE = _package("inbound", "request", fail_open=False)

_CASES = {
    "aiac-combiner": _combiner(),
    "default-false": _with_inbound(_SAFE + "default client_ok := false\n"),
    "commented-out-line": _with_inbound(_SAFE + "# client_ok if not data.authbridge.client.inbound.request\n"),
    "stock-combiner": _combiner(inbound_fail_open=True, outbound_fail_open=True),
    "outbound-line": _combiner(outbound_fail_open=True),
    "no-inbound-package": _combiner(drop=("inbound/request.rego",)),
    "no-outbound-package": _combiner(drop=("outbound/request.rego",)),
    "multi-line-body": _with_inbound(_SAFE + "client_ok if {\n    not data.authbridge.client.inbound.request\n}\n"),
    "not-allow": _with_inbound(_SAFE + "client_ok if not data.authbridge.client.inbound.request.allow\n"),
    "default-true": _with_inbound(_SAFE + "default client_ok := true\n"),
    "constant": _with_inbound(_SAFE + "client_ok := true\n"),
    "unbalanced-brackets": _with_inbound(_SAFE + "x if {\n"),
    "no-client-ok-rule": _with_inbound(
        _SAFE.replace("client_ok if data.authbridge.client.inbound.request.allow\n", "")
    ),
    **{f"split-head-{i}": _with_inbound(_SAFE + rule + "\n") for i, rule in enumerate(_SPLIT_FAIL_OPEN_RULES)},
}


def _repeated_path() -> dict:
    cr = _combiner()
    fail_open = {"path": "inbound/request.rego", "content": _package("inbound", "request", fail_open=True)}
    cr["spec"]["policies"].insert(0, fail_open)
    return cr


_CASES["repeated-path-with-a-fail-open-entry"] = _repeated_path()


@pytest.fixture
def shell_problems(tmp_path):
    """Run the shell ``combiner_problems`` against a CR (``None``: no CR) and return its lines."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "kubectl"
    fake.write_text(f"#!{sys.executable}\n{_FAKE_KUBECTL}")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    cr_file = tmp_path / "cr.json"

    def run(cr: dict | None) -> list[str]:
        if cr is not None:
            cr_file.write_text(json.dumps(cr))
        env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_CR": str(cr_file)}
        out = subprocess.run(
            ["bash", "-c", f'set -euo pipefail; . "{_LIB}"; combiner_problems rossoctl-system'],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        return [line for line in out.stdout.splitlines() if line]

    return run


def _paths(problems: list[str]) -> set[str]:
    return {p.split(" ", 1)[0] for p in problems}


@pytest.mark.parametrize("cr", list(_CASES.values()), ids=list(_CASES))
def test_the_shell_check_agrees_with_start_check_4(shell_problems, cr):
    expected = start.combiner_problems(cr)
    got = shell_problems(cr)
    assert bool(got) == bool(expected), f"shell: {got}, start.py: {expected}"
    assert _paths(got) == _paths(expected)


def test_a_missing_cr_is_a_problem(shell_problems):
    assert shell_problems(None) == ["the AuthorizationPolicy 'default' is missing in rossoctl-system"]
