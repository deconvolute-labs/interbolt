"""`scan/registry.py`: dynamic-registration blind spots, by call and by decorator."""

from __future__ import annotations

import ast
import textwrap

from interbolt.scan.artifact import UndetectedKind
from interbolt.scan.registry import detect_registration


def _trees(**files: str) -> dict[str, ast.Module]:
    return {path: ast.parse(textwrap.dedent(source)) for path, source in files.items()}


class TestRegistrationByCall:
    def test_bare_register_tool_call_flagged(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                def lookup(x: str) -> str: ...

                register_tool(lookup)
                """
            }
        )
        undetected = detect_registration(trees)
        assert len(undetected) == 1
        assert undetected[0].kind == UndetectedKind.DYNAMIC_REGISTRATION

    def test_bare_add_tool_add_tools_and_register_calls_all_flagged(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                def lookup(x: str) -> str: ...

                add_tool(lookup)
                add_tools([lookup])
                register(lookup)
                """
            }
        )
        undetected = detect_registration(trees)
        assert len(undetected) == 3

    def test_dotted_tool_call_outside_decorator_position_flagged(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                def lookup(x: str) -> str: ...

                mcp.tool()(lookup)
                """
            }
        )
        undetected = detect_registration(trees)
        assert len(undetected) == 1
        assert undetected[0].kind == UndetectedKind.DYNAMIC_REGISTRATION

    def test_dotted_register_call_not_flagged(self) -> None:
        # An attribute call ending in `.register(` (not `.tool(`) is not a
        # recognized registration pattern; only a bare `register(...)` name
        # call is, so `functools.singledispatch`'s `x.register(...)` idiom
        # does not false-positive.
        trees = _trees(
            **{
                "a.py": """
                def lookup(x: str) -> str: ...

                registry.register(lookup)
                """
            }
        )
        undetected = detect_registration(trees)
        assert undetected == []


class TestRegistrationByDecorator:
    def test_register_prefixed_decorator_flagged(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                @registry.register_tool
                def lookup(x: str) -> str: ...
                """
            }
        )
        undetected = detect_registration(trees)
        assert len(undetected) == 1
        assert undetected[0].kind == UndetectedKind.DYNAMIC_REGISTRATION

    def test_tool_suffixed_decorator_flagged(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                @registry.action
                def lookup(x: str) -> str: ...
                """
            }
        )
        undetected = detect_registration(trees)
        assert len(undetected) == 1

    def test_call_tool_and_list_tools_decorators_flagged(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                @server.call_tool
                def handle_call(x: str) -> str: ...

                @server.list_tools
                def handle_list() -> list: ...
                """
            }
        )
        undetected = detect_registration(trees)
        assert len(undetected) == 2

    def test_core_allowlisted_decorators_never_flagged(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import guard
                from langchain_core.tools import tool
                from agents import function_tool

                @guard
                def a(x: str) -> None: ...

                @tool
                def b(x: str) -> None: ...

                @function_tool
                def c(x: str) -> None: ...
                """
            }
        )
        undetected = detect_registration(trees)
        assert undetected == []

    def test_bare_register_decorator_not_flagged(self) -> None:
        # `register` alone (no underscore, no `_tool` suffix) is excluded so
        # `functools.singledispatch`'s `@handle.register` decorator idiom
        # does not false-positive.
        trees = _trees(
            **{
                "a.py": """
                @handle.register
                def _(x: int) -> None: ...
                """
            }
        )
        undetected = detect_registration(trees)
        assert undetected == []
