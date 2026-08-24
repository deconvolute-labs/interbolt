"""`scan/literal.py`: `tools=[...]` list detection in its three element shapes."""

from __future__ import annotations

import ast
import textwrap

from interbolt.scan.artifact import Discovery, UndetectedKind
from interbolt.scan.literal import (
    collect_schema_literal_matches,
    index_module_functions,
)


def _trees(**files: str) -> dict[str, ast.Module]:
    return {path: ast.parse(textwrap.dedent(source)) for path, source in files.items()}


class TestIndexModuleFunctions:
    def test_indexes_every_module_level_function_across_files(self) -> None:
        trees = _trees(
            **{
                "a.py": "def query(x: str) -> str: ...\n",
                "b.py": "def send(x: str) -> None: ...\n",
            }
        )
        index = index_module_functions(trees)
        assert set(index) == {"query", "send"}

    def test_same_name_in_two_files_produces_two_candidates(self) -> None:
        trees = _trees(
            **{
                "a.py": "def query(x: str) -> str: ...\n",
                "b.py": "def query(x: str) -> str: ...\n",
            }
        )
        index = index_module_functions(trees)
        assert len(index["query"]) == 2


class TestReferenceElements:
    def test_same_file_bare_name_reference_resolved(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                def query_customers(name: str) -> str:
                    return name

                def register(client) -> None:
                    client.register(tools=[query_customers])
                """
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert undetected == []
        match = matches["default.query_customers"][0]
        assert match.discovery is Discovery.TOOL_LIST_REFERENCE
        assert match.definition.symbol == "query_customers"

    def test_cross_file_import_reference_resolved(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                from tools.crm import query_customers

                def register(client) -> None:
                    client.register(tools=[query_customers])
                """,
                "tools/crm.py": """
                def query_customers(name: str) -> str:
                    return name
                """,
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert undetected == []
        match = matches["default.query_customers"][0]
        assert match.definition.path == "tools/crm.py"

    def test_module_attribute_reference_resolved(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                import tools.crm as crm

                def register(client) -> None:
                    client.register(tools=[crm.query_customers])
                """,
                "tools/crm.py": """
                def query_customers(name: str) -> str:
                    return name
                """,
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert undetected == []
        match = matches["default.query_customers"][0]
        assert match.definition.path == "tools/crm.py"

    def test_unimported_reference_falls_back_to_unique_cross_tree_match(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def register(client) -> None:
                    client.register(tools=[query_customers])
                """,
                "tools/crm.py": """
                def query_customers(name: str) -> str:
                    return name
                """,
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert undetected == []
        match = matches["default.query_customers"][0]
        assert match.definition.path == "tools/crm.py"


class TestModuleConstantList:
    def test_bare_name_resolving_to_module_level_list_constant(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def query_customers(name: str) -> str:
                    return name

                TOOLS = [query_customers]

                def register(client) -> None:
                    client.register(tools=TOOLS)
                """
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert undetected == []
        match = matches["default.query_customers"][0]
        assert match.discovery is Discovery.TOOL_LIST_CONSTANT

    def test_unresolvable_bare_name_reports_unresolved_tool_list(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def register(client) -> None:
                    client.register(tools=UNKNOWN_TOOLS)
                """
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert matches == {}
        assert len(undetected) == 1
        assert undetected[0].kind == UndetectedKind.UNRESOLVED_TOOL_LIST


class TestSchemaLiteralElements:
    def test_openai_shaped_dict_resolved_by_unique_name(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def register(client) -> None:
                    client.register(tools=[{
                        "type": "function",
                        "function": {"name": "query_customers"},
                    }])
                """,
                "tools.py": """
                def query_customers(name: str) -> str:
                    return name
                """,
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert undetected == []
        match = matches["default.query_customers"][0]
        assert match.discovery is Discovery.SCHEMA_LITERAL

    def test_anthropic_shaped_dict_resolved_by_unique_name(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def register(client) -> None:
                    client.register(tools=[{"name": "send_alert"}])
                """,
                "tools.py": """
                def send_alert(message: str) -> None: ...
                """,
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert undetected == []
        assert "default.send_alert" in matches

    def test_schema_name_with_no_matching_function_is_unresolved_implementation(
        self,
    ) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def register(client) -> None:
                    client.register(tools=[{"name": "ghost_tool"}])
                """
            }
        )
        # The element also fails to resolve as part of the list, so the
        # unresolved single-element list gets its own partial-list entry
        # alongside the specific per-name diagnosis.
        matches, undetected = collect_schema_literal_matches(trees)
        assert matches == {}
        kinds = {u.kind for u in undetected}
        assert UndetectedKind.UNRESOLVED_IMPLEMENTATION in kinds
        assert UndetectedKind.UNRESOLVED_TOOL_LIST in kinds

    def test_schema_name_matching_two_functions_is_ambiguous_implementation(
        self,
    ) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def register(client) -> None:
                    client.register(tools=[{"name": "query_customers"}])
                """,
                "a.py": "def query_customers(name: str) -> str:\n    return name\n",
                "b.py": "def query_customers(name: str) -> str:\n    return name\n",
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert matches == {}
        kinds = {u.kind for u in undetected}
        assert UndetectedKind.AMBIGUOUS_IMPLEMENTATION in kinds
        assert UndetectedKind.UNRESOLVED_TOOL_LIST in kinds

    def test_bidi_override_in_schema_name_rejected(self) -> None:
        bidi = "‮"  # RIGHT-TO-LEFT OVERRIDE, the Trojan Source character
        trees = _trees(
            **{
                "agent.py": f"""
                def register(client) -> None:
                    client.register(tools=[{{"name": "send{bidi}email"}}])
                """
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert matches == {}
        kinds = {u.kind for u in undetected}
        assert UndetectedKind.REJECTED_NAME in kinds
        assert bidi not in str(undetected)


class TestPartialResolution:
    def test_partially_resolved_list_names_resolved_and_unresolved_elements(
        self,
    ) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def query_customers(name: str) -> str:
                    return name

                def register(client) -> None:
                    client.register(tools=[query_customers, build_dynamic_tool()])
                """
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert "default.query_customers" in matches
        assert len(undetected) == 1
        assert undetected[0].kind == UndetectedKind.UNRESOLVED_TOOL_LIST
        assert "query_customers" in undetected[0].detail
        # A call expression has no name of its own; it's named by its kind.
        assert "a call expression" in undetected[0].detail

    def test_fully_resolved_list_reports_nothing(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def query_customers(name: str) -> str:
                    return name

                def register(client) -> None:
                    client.register(tools=[query_customers])
                """
            }
        )
        _, undetected = collect_schema_literal_matches(trees)
        assert undetected == []


class TestUnresolvableShapes:
    def test_call_expression_reports_unresolved_tool_list(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def register(client) -> None:
                    client.register(tools=build_tools())
                """
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert matches == {}
        assert len(undetected) == 1
        assert undetected[0].kind == UndetectedKind.UNRESOLVED_TOOL_LIST

    def test_concatenation_reports_unresolved_tool_list(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def register(client) -> None:
                    client.register(tools=BASE_TOOLS + EXTRA_TOOLS)
                """
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert matches == {}
        assert len(undetected) == 1
        assert undetected[0].kind == UndetectedKind.UNRESOLVED_TOOL_LIST


class TestPassThroughSites:
    def test_tools_bound_to_function_parameter_is_not_reported(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                def create_deep_agent(model, tools, other=None):
                    return register(tools=tools)
                """
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert matches == {}
        assert undetected == []

    def test_tools_bound_to_attribute_access_is_not_reported(self) -> None:
        trees = _trees(
            **{
                "agent.py": """
                class Agent:
                    def register(self) -> None:
                        client.register(tools=self.tools)
                """
            }
        )
        matches, undetected = collect_schema_literal_matches(trees)
        assert matches == {}
        assert undetected == []
