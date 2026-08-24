"""`scan/source.py`: literal `taint(source=...)` call-site discovery."""

from __future__ import annotations

import ast
import textwrap

from interbolt.scan.artifact import UndetectedKind
from interbolt.scan.source import detect_taint_sources


def _trees(**files: str) -> dict[str, ast.Module]:
    return {path: ast.parse(textwrap.dedent(source)) for path, source in files.items()}


class TestBareAndAttributeForms:
    def test_bare_taint_call_recorded(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import taint

                def handle(raw: str) -> None:
                    taint(raw, source="web_search")
                """
            }
        )
        sources, undetected = detect_taint_sources(trees)
        assert undetected == ()
        assert len(sources) == 1
        assert sources[0].name == "web_search"
        assert sources[0].declared is False
        assert len(sources[0].sites) == 1
        assert sources[0].sites[0].path == "a.py"

    def test_attribute_chain_taint_call_recorded(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                import interbolt

                def handle(raw: str) -> None:
                    interbolt.taint(raw, source="web_search")
                """
            }
        )
        sources, _ = detect_taint_sources(trees)
        assert [s.name for s in sources] == ["web_search"]


class TestGrouping:
    def test_multiple_sites_for_same_name_grouped(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import taint

                def handle_one(raw: str) -> None:
                    taint(raw, source="web_search")

                def handle_two(raw: str) -> None:
                    taint(raw, source="web_search")
                """
            }
        )
        sources, _ = detect_taint_sources(trees)
        assert len(sources) == 1
        assert len(sources[0].sites) == 2
        assert [s.line for s in sources[0].sites] == sorted(
            s.line for s in sources[0].sites
        )

    def test_sources_sorted_by_name(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import taint

                def handle(raw: str) -> None:
                    taint(raw, source="zzz")
                    taint(raw, source="aaa")
                """
            }
        )
        sources, _ = detect_taint_sources(trees)
        assert [s.name for s in sources] == ["aaa", "zzz"]


class TestNonLiteralSourceSkipped:
    def test_computed_source_name_skipped_without_being_reported(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from interbolt import taint

                def handle(raw: str, source_name: str) -> None:
                    taint(raw, source=source_name)
                """
            }
        )
        sources, undetected = detect_taint_sources(trees)
        assert sources == ()
        assert undetected == ()


class TestRejectedNames:
    def test_bidi_override_in_source_name_rejected(self) -> None:
        bidi = "‮"  # RIGHT-TO-LEFT OVERRIDE, the Trojan Source character
        trees = _trees(
            **{
                "a.py": f"""
                from interbolt import taint

                def handle(raw: str) -> None:
                    taint(raw, source="web{bidi}search")
                """
            }
        )
        sources, undetected = detect_taint_sources(trees)
        assert sources == ()
        assert len(undetected) == 1
        assert undetected[0].kind == UndetectedKind.REJECTED_NAME
