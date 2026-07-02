from __future__ import annotations

import logging

from interbolt.utils import get_logger


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
