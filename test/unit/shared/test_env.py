"""Unit tests for aiac.shared.env — the tolerant numeric environment knob ``env_num``."""

import pytest

from aiac.shared.env import env_num

_NAME = "AIAC_TEST_ENV_NUM"


@pytest.mark.parametrize(("raw", "expected"), [("2.5", 2.5), ("0", 0.0), ("-1", 9.0), ("abc", 9.0), ("inf", 9.0)])
def test_a_value_below_the_minimum_or_bad_falls_back_to_the_default(monkeypatch, raw, expected):
    monkeypatch.setenv(_NAME, raw)
    assert env_num(_NAME, 9.0, float, minimum=0.0) == expected


@pytest.mark.parametrize(("raw", "expected"), [("2.5", 2.5), ("0", 9.0), ("-1", 9.0), ("nan", 9.0)])
def test_exclusive_also_refuses_a_value_equal_to_the_minimum(monkeypatch, raw, expected):
    monkeypatch.setenv(_NAME, raw)
    assert env_num(_NAME, 9.0, float, minimum=0.0, exclusive=True) == expected


def test_an_unset_value_gives_the_default(monkeypatch):
    monkeypatch.delenv(_NAME, raising=False)
    assert env_num(_NAME, 3, int, minimum=1) == 3
