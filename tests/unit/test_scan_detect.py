"""`scan/detect.py`: decorator matching, name resolution, and collisions."""

from __future__ import annotations

import ast
import textwrap

from interbolt.scan.artifact import Discovery
from interbolt.scan.detect import detect_decorated_tools


def _trees(**files: str) -> dict[str, ast.Module]:
    return {path: ast.parse(textwrap.dedent(source)) for path, source in files.items()}


class TestDecoratorForms:
    def test_langchain_bare_tool_uses_function_name(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from langchain_core.tools import tool

                @tool
                def send_alert(x: str) -> None: ...
                """
            }
        )
        tools, collisions, undetected = detect_decorated_tools(trees)
        assert not collisions
        assert not undetected
        assert [t.qualified_name for t in tools] == ["default.send_alert"]
        assert tools[0].discovery is Discovery.DECORATOR
        assert tools[0].detector_detail == "langchain @tool"
        assert tools[0].guarded is False
        assert tools[0].declared is False
        assert tools[0].capabilities == ()

    def test_langchain_positional_string_wins_over_function_name(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from langchain_core.tools import tool

                @tool("crm.query_customers")
                def query(x: str) -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert [t.qualified_name for t in tools] == ["crm.query_customers"]
        assert tools[0].detector_detail == 'langchain @tool("crm.query_customers")'

    def test_langchain_name_keyword(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from langchain_core.tools import tool

                @tool(name="crm.query_customers")
                def query(x: str) -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert [t.qualified_name for t in tools] == ["crm.query_customers"]
        assert tools[0].detector_detail == 'langchain @tool(name="crm.query_customers")'

    def test_openai_function_tool_name_override(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from agents import function_tool

                @function_tool(name_override="lookup")
                def do_lookup(x: str) -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert [t.qualified_name for t in tools] == ["default.lookup"]
        assert (
            tools[0].detector_detail
            == 'openai agents sdk @function_tool(name_override="default.lookup")'
        )

    def test_fastmcp_dotted_tool_uses_name_keyword(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from fastmcp import FastMCP

                mcp = FastMCP()

                @mcp.tool(name="lookup")
                def do_lookup(x: str) -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert [t.qualified_name for t in tools] == ["default.lookup"]
        assert tools[0].detector_detail == 'fastmcp @mcp.tool(name="default.lookup")'

    def test_fastmcp_dotted_tool_falls_back_to_function_name(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                @server.tool()
                def ping() -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert [t.qualified_name for t in tools] == ["default.ping"]
        assert tools[0].detector_detail == "fastmcp @server.tool"

    def test_interbolt_bare_guard_sets_guarded(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import guard

                @guard
                def send_email(to: str) -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert [t.qualified_name for t in tools] == ["default.send_email"]
        assert tools[0].guarded is True
        assert tools[0].detector_detail == "interbolt @guard"

    def test_interbolt_guard_tool_keyword(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import guard

                @guard(tool="email.send_email")
                def send_email(to: str) -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert [t.qualified_name for t in tools] == ["email.send_email"]
        assert tools[0].guarded is True
        assert tools[0].detector_detail == 'interbolt @guard(tool="email.send_email")'

    def test_agent_handle_dotted_guard(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                support = agent("support-agent")

                @support.guard(tool="email.send_email")
                def send_email(to: str) -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert [t.qualified_name for t in tools] == ["email.send_email"]
        assert tools[0].guarded is True
        assert (
            tools[0].detector_detail
            == 'interbolt @support.guard(tool="email.send_email")'
        )

    def test_unrecognized_decorator_is_ignored(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                @dataclass
                def not_a_tool() -> None: ...
                """
            }
        )
        tools, collisions, undetected = detect_decorated_tools(trees)
        assert tools == []
        assert collisions == []
        assert undetected == []


class TestAsyncParity:
    def test_async_def_discovered_identically_to_def(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import guard

                @guard
                async def send_email(to: str) -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert [t.qualified_name for t in tools] == ["default.send_email"]
        assert tools[0].definition is not None
        assert tools[0].definition.symbol == "send_email"


class TestMethodInClass:
    def test_method_qualified_by_name_only_class_ignored(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import guard

                class SupportAgent:
                    @guard
                    def send(self, x: str) -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert [t.qualified_name for t in tools] == ["default.send"]

    def test_two_classes_same_method_name_collide(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import guard

                class A:
                    @guard
                    def send(self, x: str) -> None: ...

                class B:
                    @guard
                    def send(self, x: str) -> None: ...
                """
            }
        )
        tools, collisions, _ = detect_decorated_tools(trees)
        assert tools == []
        assert [c.qualified_name for c in collisions] == ["default.send"]
        assert len(collisions[0].definitions) == 2


class TestCollisions:
    def test_two_files_same_qualified_name_collide_and_are_excluded_from_tools(
        self,
    ) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import guard

                @guard(tool="email.send_email")
                def send_a(to: str) -> None: ...
                """,
                "b.py": """
                from interbolt import guard

                @guard(tool="email.send_email")
                def send_b(to: str) -> None: ...
                """,
            }
        )
        tools, collisions, _ = detect_decorated_tools(trees)
        assert tools == []
        assert len(collisions) == 1
        assert collisions[0].qualified_name == "email.send_email"
        assert {d.path for d in collisions[0].definitions} == {"a.py", "b.py"}

    def test_no_collision_when_names_differ(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import guard

                @guard(tool="email.send_email")
                def send_a(to: str) -> None: ...
                """,
                "b.py": """
                from interbolt import guard

                @guard(tool="email.send_alert")
                def send_b(to: str) -> None: ...
                """,
            }
        )
        tools, collisions, _ = detect_decorated_tools(trees)
        assert collisions == []
        assert {t.qualified_name for t in tools} == {
            "email.send_email",
            "email.send_alert",
        }


class TestMultipleDecoratorsOnOneFunction:
    def test_interbolt_decorator_is_authoritative_over_framework_decorator(
        self,
    ) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import guard
                from langchain_core.tools import tool

                @tool("send_alert")
                @guard(tool="email.send_email")
                def send(to: str) -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert len(tools) == 1
        assert tools[0].qualified_name == "email.send_email"
        assert tools[0].guarded is True


class TestSortOrder:
    def test_tools_sorted_by_qualified_name(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import guard

                @guard(tool="zzz.last")
                def z(x: str) -> None: ...

                @guard(tool="aaa.first")
                def a(x: str) -> None: ...
                """
            }
        )
        tools, _, _ = detect_decorated_tools(trees)
        assert [t.qualified_name for t in tools] == ["aaa.first", "zzz.last"]
