from __future__ import annotations

import logging
from pathlib import Path

import pytest

from interbolt.utils import cache_dir, get_logger


class TestGetLogger:
    def test_no_name_returns_interbolt_logger(self) -> None:
        log = get_logger()
        assert log.name == "interbolt"

    def test_with_name_returns_child_logger(self) -> None:
        log = get_logger("enforcement")
        assert log.name == "interbolt.enforcement"

    def test_child_logger_parent_is_root_library_logger(self) -> None:
        log = get_logger("some.sub.module")
        # getChild chains parents; effective root is "interbolt"
        assert log.name.startswith("interbolt.")

    def test_no_name_returns_same_instance_each_call(self) -> None:
        assert get_logger() is get_logger()

    def test_returns_logging_logger_instance(self) -> None:
        assert isinstance(get_logger(), logging.Logger)


class TestCacheDir:
    def test_no_env_var_returns_path_instance(self) -> None:
        result = cache_dir()
        assert isinstance(result, Path)

    def test_no_env_var_path_contains_interbolt(self) -> None:
        result = cache_dir()
        assert "interbolt" in str(result)

    def test_env_var_overrides_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("INTERBOLT_CACHE_DIR", "/custom/cache/path")
        result = cache_dir()
        assert result == Path("/custom/cache/path")

    def test_env_var_returns_path_instance(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("INTERBOLT_CACHE_DIR", "/custom/test/cache")
        result = cache_dir()
        assert isinstance(result, Path)

    def test_env_var_empty_string_falls_through_to_platformdirs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # An empty env var is falsy; platformdirs path is used instead.
        monkeypatch.setenv("INTERBOLT_CACHE_DIR", "")
        result = cache_dir()
        assert "interbolt" in str(result)
