"""`scan/evidence.py`: import-table resolution, depth-following, and dedup."""

from __future__ import annotations

import ast
import textwrap

from interbolt.scan.detect import detect_decorated_tools
from interbolt.scan.evidence import collect_all_evidence


def _trees(**files: str) -> dict[str, ast.Module]:
    return {path: ast.parse(textwrap.dedent(source)) for path, source in files.items()}


def _evidence(
    trees: dict[str, ast.Module], depth: int = 1
) -> list[tuple[str, str, int, int]]:
    tools, _, _ = detect_decorated_tools(trees)
    tools, undetected = collect_all_evidence(tools, trees, depth)
    assert undetected == []
    assert len(tools) == 1
    return [(e.symbol, e.path, e.line, e.depth) for e in tools[0].evidence]


class TestImportTableResolution:
    def test_import_module_then_attribute_call(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                import smtplib
                from interbolt import guard

                @guard
                def send_email(to: str) -> None:
                    smtplib.SMTP()
                """
            }
        )
        assert _evidence(trees) == [("smtplib.SMTP", "a.py", 7, 0)]

    def test_from_import_bare_name_call(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                from httpx import post
                from interbolt import guard

                @guard
                def send_alert(to: str) -> None:
                    post("http://example.com")
                """
            }
        )
        assert _evidence(trees) == [("httpx.post", "a.py", 7, 0)]

    def test_aliased_import(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                import httpx as h
                from interbolt import guard

                @guard
                def send_alert(to: str) -> None:
                    h.post("http://example.com")
                """
            }
        )
        assert _evidence(trees) == [("httpx.post", "a.py", 7, 0)]

    def test_local_variable_method_call_not_recorded(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                import httpx
                from interbolt import guard

                @guard
                def send_alert(to: str) -> None:
                    client = httpx.Client()
                    client.post("http://example.com")
                """
            }
        )
        # Only the resolved `httpx.Client` call is recorded; the subsequent
        # `client.post(...)` is a method call on a local variable and is
        # silently skipped.
        assert _evidence(trees) == [("httpx.Client", "a.py", 7, 0)]

    def test_stdlib_symbols_recorded_not_filtered(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                import subprocess
                from interbolt import guard

                @guard
                def run_cmd(cmd: str) -> None:
                    subprocess.run(cmd)
                """
            }
        )
        assert _evidence(trees) == [("subprocess.run", "a.py", 7, 0)]


class TestDepthFollowing:
    def test_depth_one_follows_same_file_helper(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                import smtplib
                from interbolt import guard

                @guard
                def send_email(to: str) -> None:
                    _deliver(to)

                def _deliver(to: str) -> None:
                    smtplib.SMTP()
                """
            }
        )
        assert _evidence(trees, depth=1) == [("smtplib.SMTP", "a.py", 10, 1)]

    def test_depth_zero_does_not_follow(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                import smtplib
                from interbolt import guard

                @guard
                def send_email(to: str) -> None:
                    _deliver(to)

                def _deliver(to: str) -> None:
                    smtplib.SMTP()
                """
            }
        )
        assert _evidence(trees, depth=0) == []

    def test_depth_two_required_for_second_hop(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                import smtplib
                from interbolt import guard

                @guard
                def send_email(to: str) -> None:
                    _hop1(to)

                def _hop1(to: str) -> None:
                    _hop2(to)

                def _hop2(to: str) -> None:
                    smtplib.SMTP()
                """
            }
        )
        assert _evidence(trees, depth=1) == []
        assert _evidence(trees, depth=2) == [("smtplib.SMTP", "a.py", 13, 2)]

    def test_cross_file_absolute_import_followed(self) -> None:
        trees = _trees(
            **{
                "tools/notify.py": """
                from interbolt import guard
                from tools._deliver import send_via_smtp

                @guard(tool="email.send_email")
                def send_email(to: str) -> None:
                    send_via_smtp(to)
                """,
                "tools/_deliver.py": """
                import smtplib

                def send_via_smtp(to: str) -> None:
                    smtplib.SMTP()
                """,
            }
        )
        assert _evidence(trees) == [("smtplib.SMTP", "tools/_deliver.py", 5, 1)]

    def test_cross_file_relative_import_followed(self) -> None:
        trees = _trees(
            **{
                "tools/notify.py": """
                from interbolt import guard
                from ._deliver import send_via_smtp

                @guard(tool="email.send_email")
                def send_email(to: str) -> None:
                    send_via_smtp(to)
                """,
                "tools/_deliver.py": """
                import smtplib

                def send_via_smtp(to: str) -> None:
                    smtplib.SMTP()
                """,
            }
        )
        assert _evidence(trees) == [("smtplib.SMTP", "tools/_deliver.py", 5, 1)]

    def test_recursion_guard_prevents_infinite_loop(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                import smtplib
                from interbolt import guard

                @guard
                def send_email(to: str) -> None:
                    _a(to)

                def _a(to: str) -> None:
                    smtplib.SMTP()
                    _b(to)

                def _b(to: str) -> None:
                    _a(to)
                """
            }
        )
        # Must terminate rather than looping forever; the mutual recursion
        # between _a and _b is cut off by the visited-function guard.
        assert _evidence(trees, depth=10) == [("smtplib.SMTP", "a.py", 10, 1)]


class TestDedup:
    def test_duplicate_symbol_path_line_deduped(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                import smtplib
                from interbolt import guard

                @guard
                def send_email(to: str) -> None:
                    for _ in range(2):
                        smtplib.SMTP()
                """
            }
        )
        assert _evidence(trees) == [("smtplib.SMTP", "a.py", 8, 0)]


class TestSortOrder:
    def test_evidence_sorted_by_depth_then_path_then_line_then_symbol(self) -> None:
        trees = _trees(
            **{
                "a.py": """
                import httpx
                import smtplib
                from interbolt import guard

                @guard
                def send_email(to: str) -> None:
                    smtplib.SMTP()
                    httpx.post("x")
                    _deliver(to)

                def _deliver(to: str) -> None:
                    httpx.get("y")
                """
            }
        )
        assert _evidence(trees) == [
            ("smtplib.SMTP", "a.py", 8, 0),
            ("httpx.post", "a.py", 9, 0),
            ("httpx.get", "a.py", 13, 1),
        ]
