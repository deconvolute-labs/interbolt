from __future__ import annotations

import pytest

from interbolt.constants import (
    AUDIT_FINDINGS_MAX,
    AUDIT_MAX_TRACKED_RUNS,
    AUDIT_MIN_MATCH_LENGTH,
    CONTAINER_TYPES,
    DEFAULT_RECURSION_DEPTH,
    ENV_RECURSION_DEPTH,
    EVENT_SCHEMA_VERSION,
    RECURSION_DEPTH_MAX,
    _resolve_recursion_depth,
)
from interbolt.errors import InterboltConfigError


def test_default_recursion_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_RECURSION_DEPTH, raising=False)
    assert _resolve_recursion_depth() == DEFAULT_RECURSION_DEPTH


def test_valid_env_var_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_RECURSION_DEPTH, "7")
    assert _resolve_recursion_depth() == 7


def test_boundary_min_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_RECURSION_DEPTH, "1")
    assert _resolve_recursion_depth() == 1


def test_boundary_max_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_RECURSION_DEPTH, "10")
    assert _resolve_recursion_depth() == 10


def test_zero_raises_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_RECURSION_DEPTH, "0")
    with pytest.raises(InterboltConfigError):
        _resolve_recursion_depth()


def test_eleven_raises_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_RECURSION_DEPTH, "11")
    with pytest.raises(InterboltConfigError):
        _resolve_recursion_depth()


def test_negative_raises_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_RECURSION_DEPTH, "-1")
    with pytest.raises(InterboltConfigError):
        _resolve_recursion_depth()


def test_non_integer_raises_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_RECURSION_DEPTH, "abc")
    with pytest.raises(InterboltConfigError, match="abc"):
        _resolve_recursion_depth()


def test_constant_values() -> None:
    assert DEFAULT_RECURSION_DEPTH == 4
    assert RECURSION_DEPTH_MAX == 10
    assert AUDIT_MIN_MATCH_LENGTH == 12
    assert EVENT_SCHEMA_VERSION == 4
    assert AUDIT_FINDINGS_MAX == 10_000
    assert AUDIT_MAX_TRACKED_RUNS == 1_000


def test_container_types_value() -> None:
    assert CONTAINER_TYPES == (list, tuple, set, frozenset)
