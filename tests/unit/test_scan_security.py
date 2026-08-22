"""the scanner's own security invariants."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from interbolt.scan.artifact import UndetectedKind
from interbolt.scan.scanner import scan_repository
from interbolt.scan.security import (
    is_forbidden_text,
    resolve_within_root,
    walk_ast_bounded,
)

SCAN_PACKAGE = Path(__file__).parent.parent.parent / "src" / "interbolt" / "scan"

_BANNED_IMPORTS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "importlib",
        "pickle",
        "marshal",
        "runpy",
        "subprocess",
    }
)


class TestNoBannedApis:
    def test_no_banned_import_anywhere_in_scan_package(self) -> None:
        violations = []
        for path in sorted(SCAN_PACKAGE.glob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_level = alias.name.split(".")[0]
                        if top_level in _BANNED_IMPORTS:
                            violations.append(f"{path.name}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    top_level = node.module.split(".")[0]
                    if top_level in _BANNED_IMPORTS:
                        violations.append(f"{path.name}: from {node.module} import ...")
        assert violations == []

    def test_no_eval_exec_or_literal_eval_call_anywhere_in_scan_package(self) -> None:
        # Bare-name calls only: `eval`/`exec`/`compile`/`__import__` are
        # builtins, always called bare in legitimate code, unlike `re.compile`
        # or `ast.literal_eval`'s namesake-but-unrelated `.compile`. Only
        # `ast.literal_eval` is checked via attribute access, since that one
        # genuinely is always spelled with its module prefix.
        banned_bare = frozenset({"eval", "exec", "compile", "__import__"})
        violations = []
        for path in sorted(SCAN_PACKAGE.glob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Name) and func.id in banned_bare:
                    violations.append(f"{path.name}:{node.lineno} calls {func.id}")
                elif isinstance(func, ast.Attribute) and func.attr == "literal_eval":
                    violations.append(f"{path.name}:{node.lineno} calls literal_eval")
        assert violations == []

    def test_no_unsafe_yaml_load(self) -> None:
        for path in sorted(SCAN_PACKAGE.glob("*.py")):
            source = path.read_text()
            assert "yaml.load(" not in source


class TestNoExecutionOfScannedCode:
    def test_a_module_that_writes_a_file_opens_a_socket_and_raises_is_never_run(
        self, tmp_path: Path
    ) -> None:
        marker = tmp_path / "side_effect_marker.txt"
        (tmp_path / "evil.py").write_text(
            "import socket\n"
            f"open({marker.as_posix()!r}, 'w').write('ran')\n"
            "socket.socket().connect(('example.com', 80))\n"
            "raise RuntimeError('module-level import should never run')\n"
        )
        artifact = scan_repository(str(tmp_path))
        assert not marker.exists()
        assert artifact is not None


class TestRejectedNames:
    def test_bidi_override_in_decorator_argument_is_rejected(
        self, tmp_path: Path
    ) -> None:
        bidi = "‮"  # RIGHT-TO-LEFT OVERRIDE, the Trojan Source character
        (tmp_path / "agent.py").write_text(
            "from langchain_core.tools import tool\n\n"
            f'@tool("send{bidi}email")\n'
            "def send_email(to: str) -> None: ...\n"
        )
        artifact = scan_repository(str(tmp_path))
        assert artifact.tools == ()
        assert len(artifact.undetected) == 1
        assert artifact.undetected[0].kind == UndetectedKind.REJECTED_NAME
        # The offending string itself is never carried into the artifact.
        assert bidi not in str(artifact.model_dump(mode="json"))

    def test_control_character_in_decorator_argument_is_rejected(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "agent.py").write_text(
            "from langchain_core.tools import tool\n\n"
            '@tool("send\\x00email")\n'
            "def send_email(to: str) -> None: ...\n"
        )
        artifact = scan_repository(str(tmp_path))
        assert artifact.tools == ()
        assert artifact.undetected[0].kind == UndetectedKind.REJECTED_NAME


class TestTraversalBound:
    def test_deeply_nested_expression_truncates_rather_than_raising(
        self, tmp_path: Path
    ) -> None:
        depth = 400
        nested = "1" + "+1" * depth
        (tmp_path / "agent.py").write_text(
            "from interbolt import guard\n\n"
            "@guard\n"
            f"def compute(x: str) -> int:\n    return {nested}\n"
        )
        # Must not raise RecursionError; must report the truncation.
        artifact = scan_repository(str(tmp_path))
        assert any(
            u.kind == UndetectedKind.TRAVERSAL_TRUNCATED for u in artifact.undetected
        )


class TestPathContainment:
    def test_symlinked_file_outside_scan_root_is_not_read(
        self, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        outside = tmp_path_factory.mktemp("outside")
        (outside / "secret.py").write_text(
            "from interbolt import guard\n\n@guard\ndef leaked() -> None: ...\n"
        )
        (tmp_path / "linked.py").symlink_to(outside / "secret.py")
        artifact = scan_repository(str(tmp_path))
        assert artifact.tools == ()

    def test_resolve_within_root_rejects_escaping_path(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside.py"
        outside.write_text("x = 1\n")
        assert resolve_within_root(outside, root) is None

    def test_resolve_within_root_accepts_contained_path(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        (root / "sub").mkdir(parents=True)
        inside = root / "sub" / "a.py"
        inside.write_text("x = 1\n")
        assert resolve_within_root(inside, root) == "sub/a.py"

    def test_resolve_within_root_rejects_symlinked_file(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        root.mkdir()
        real = tmp_path / "real.py"
        real.write_text("x = 1\n")
        link = root / "link.py"
        link.symlink_to(real)
        assert resolve_within_root(link, root) is None


class TestIsForbiddenText:
    def test_control_character_rejected(self) -> None:
        assert is_forbidden_text("a\x00b") is True

    def test_bidi_override_rejected(self) -> None:
        assert is_forbidden_text("a‮b") is True

    def test_line_separator_rejected(self) -> None:
        assert is_forbidden_text("a b") is True

    def test_unicode_letters_not_rejected(self) -> None:
        assert is_forbidden_text("aktualisieren") is False
        assert is_forbidden_text("Ürün") is False


class TestWalkAstBounded:
    def test_truncates_and_reports_once_per_deep_branch(self) -> None:
        depth = 50
        source = "1" + "+1" * depth
        tree = ast.parse(source)
        truncated_nodes = [
            node
            for node, _depth, truncated in walk_ast_bounded(tree, max_depth=5)
            if truncated
        ]
        assert len(truncated_nodes) >= 1

    def test_no_truncation_within_bound(self) -> None:
        tree = ast.parse("x = 1 + 2\n")
        truncated_nodes = [
            node
            for node, _depth, truncated in walk_ast_bounded(tree, max_depth=200)
            if truncated
        ]
        assert truncated_nodes == []
