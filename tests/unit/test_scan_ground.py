"""`scan/ground.py`: recovering a tool from a policy sink key alone."""

from __future__ import annotations

import ast
import textwrap

from interbolt.models.core import Capability
from interbolt.policy import Policy, compile_policy
from interbolt.policy.schema import Defaults, PolicyDocument, SinkDeclaration
from interbolt.scan.artifact import Discovery
from interbolt.scan.ground import ground_policy_names


def _trees(**files: str) -> dict[str, ast.Module]:
    return {path: ast.parse(textwrap.dedent(source)) for path, source in files.items()}


def _policy(sinks: dict[str, SinkDeclaration]) -> Policy:
    document = PolicyDocument(
        version="2.0", defaults=Defaults(), sources=(), sinks=sinks
    )
    return Policy(document=document, compiled_sinks=compile_policy(document))


class TestGrounding:
    def test_unique_function_name_resolved(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                def query_customers(name: str) -> str:
                    return name
                """
            }
        )
        policy = _policy({"crm.query_customers": SinkDeclaration()})
        resolved = ground_policy_names(trees, policy, discovered=set())
        assert len(resolved) == 1
        assert resolved[0].qualified_name == "crm.query_customers"
        assert resolved[0].discovery is Discovery.POLICY_NAME
        assert resolved[0].definition is not None
        assert resolved[0].definition.symbol == "query_customers"

    def test_already_discovered_name_skipped(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                def query_customers(name: str) -> str:
                    return name
                """
            }
        )
        policy = _policy({"crm.query_customers": SinkDeclaration()})
        resolved = ground_policy_names(
            trees, policy, discovered={"crm.query_customers"}
        )
        assert resolved == []

    def test_zero_matches_left_unresolved(self) -> None:
        trees = _trees(**{"a.py": "x = 1\n"})
        policy = _policy({"crm.query_customers": SinkDeclaration()})
        resolved = ground_policy_names(trees, policy, discovered=set())
        assert resolved == []

    def test_ambiguous_match_left_unresolved(self) -> None:
        trees = _trees(
            **{
                "a.py": "def query_customers(name: str) -> str:\n    return name\n",
                "b.py": "def query_customers(name: str) -> str:\n    return name\n",
            }
        )
        policy = _policy({"crm.query_customers": SinkDeclaration()})
        resolved = ground_policy_names(trees, policy, discovered=set())
        assert resolved == []

    def test_sink_key_declaring_capabilities_still_resolves(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                def send_email(to: str) -> None: ...
                """
            }
        )
        policy = _policy(
            {
                "email.send_email": SinkDeclaration(
                    capabilities=(Capability.REACHES_EXTERNAL,)
                )
            }
        )
        resolved = ground_policy_names(trees, policy, discovered=set())
        assert [t.qualified_name for t in resolved] == ["email.send_email"]

    def test_results_sorted_by_qualified_name(self) -> None:
        trees = _trees(
            **{
                "a.py": (
                    "def query_customers(name: str) -> str:\n    return name\n\n"
                    "def send_alert(message: str) -> None: ...\n"
                )
            }
        )
        policy = _policy(
            {
                "zzz.send_alert": SinkDeclaration(),
                "aaa.query_customers": SinkDeclaration(),
            }
        )
        resolved = ground_policy_names(trees, policy, discovered=set())
        assert [t.qualified_name for t in resolved] == [
            "aaa.query_customers",
            "zzz.send_alert",
        ]
