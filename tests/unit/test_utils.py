from __future__ import annotations

import inspect
import logging

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

from interbolt.errors import InterboltConfigError
from interbolt.utils import bind_arguments, current_trace_context, get_logger
from interbolt.utils.names import qualify_tool_name

_tracer = TracerProvider().get_tracer("test_utils")


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


class TestBindArguments:
    def test_bind_positional_and_keyword_args(self) -> None:
        def fn(a: str, b: int) -> str:
            return a

        sig = inspect.signature(fn)
        result = bind_arguments(sig, ("hello",), {"b": 42})
        assert result == {"a": "hello", "b": 42}

    def test_bind_applies_defaults(self) -> None:
        def fn(a: str, b: int = 99) -> str:
            return a

        sig = inspect.signature(fn)
        result = bind_arguments(sig, ("hello",), {})
        assert result == {"a": "hello", "b": 99}

    def test_bind_all_kwargs(self) -> None:
        def fn(x: str, y: str) -> str:
            return x + y

        sig = inspect.signature(fn)
        result = bind_arguments(sig, (), {"x": "a", "y": "b"})
        assert result == {"x": "a", "y": "b"}


class TestCurrentTraceContext:
    def test_no_active_span_returns_none(self) -> None:
        assert trace.get_current_span() is trace.INVALID_SPAN
        assert current_trace_context() is None

    def test_active_span_returns_hex_trace_and_span_ids(self) -> None:
        with _tracer.start_as_current_span("s") as span:
            result = current_trace_context()
            ctx = span.get_span_context()
        assert result is not None
        trace_id, span_id = result
        assert trace_id == format(ctx.trace_id, "032x")
        assert span_id == format(ctx.span_id, "016x")
        assert len(trace_id) == 32
        assert len(span_id) == 16


class TestQualifyToolName:
    def test_bare_name_gets_default_namespace(self) -> None:
        assert qualify_tool_name("foo") == "default.foo"

    def test_explicit_qualified_name_preserved(self) -> None:
        assert qualify_tool_name("ns.tool") == "ns.tool"

    def test_dotted_namespace_raises(self) -> None:
        # "a.b.c" -> rpartition -> namespace="a.b", tool="c" -> "a.b" has a dot -> error
        with pytest.raises(InterboltConfigError):
            qualify_tool_name("a.b.c")

    def test_bare_name_with_allowed_chars(self) -> None:
        assert qualify_tool_name("my_tool") == "default.my_tool"

    def test_qualified_name_with_underscores(self) -> None:
        assert qualify_tool_name("my_ns.my_tool") == "my_ns.my_tool"
