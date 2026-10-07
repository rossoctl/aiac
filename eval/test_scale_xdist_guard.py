"""Unit test for ``test_policy_pipeline_scale.py``'s own pytest-xdist guard (spec:
``docs/evaluation/policy-eval-scale.md``, #2469).

``_skip_if_xdist`` is pure control flow (check one env var, ``pytest.skip``) -- worth protecting
directly, offline, rather than only ever exercised by actually running the live-LLM suite under
``-n``. Unmarked, runs in the default fast pass. Importing ``eval.test_policy_pipeline_scale`` is
safe at collection time -- its own live-LLM/Keycloak calls are all deferred into fixture bodies,
same assumption that already lets plain ``pytest`` collect that file without those services
running.
"""

from __future__ import annotations

import pytest

from eval.test_policy_pipeline_scale import _skip_if_xdist


def test_skips_when_pytest_xdist_worker_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw0")
    with pytest.raises(pytest.skip.Exception):
        _skip_if_xdist()


def test_does_not_skip_outside_xdist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    _skip_if_xdist()  # must not raise
