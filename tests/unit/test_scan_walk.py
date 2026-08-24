"""`scan/walk.py`: scan root resolution, exclusion, bounds, and parse skipping."""

from __future__ import annotations

from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from interbolt.scan.walk import (
    parse_python_file,
    resolve_scan_root,
    walk_python_files,
)


class TestResolveScanRoot:
    def test_explicit_path_used_as_is(self, tmp_path: Path) -> None:
        target = tmp_path / "somewhere"
        target.mkdir()
        assert resolve_scan_root(str(target)) == target.resolve()

    def test_src_preferred_when_present(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        (tmp_path / "src").mkdir()
        mocker.patch("pathlib.Path.cwd", return_value=tmp_path)
        assert resolve_scan_root(None) == (tmp_path / "src").resolve()

    def test_cwd_used_when_no_src(self, tmp_path: Path, mocker: MockerFixture) -> None:
        mocker.patch("pathlib.Path.cwd", return_value=tmp_path)
        assert resolve_scan_root(None) == tmp_path.resolve()


class TestWalkPythonFiles:
    def test_finds_py_files_recursively(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "b.py").write_text("y = 2\n")
        (tmp_path / "readme.md").write_text("not python\n")
        files, truncated = walk_python_files(tmp_path, ())
        assert not truncated
        assert {f.relative_to(tmp_path).as_posix() for f in files} == {
            "a.py",
            "sub/b.py",
        }

    def test_default_exclusions_skip_known_dirs(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n")
        for excluded in (".venv", "node_modules", "__pycache__", "tests", "test"):
            d = tmp_path / excluded
            d.mkdir()
            (d / "hidden.py").write_text("z = 1\n")
        files, _ = walk_python_files(tmp_path, ())
        assert {f.relative_to(tmp_path).as_posix() for f in files} == {"a.py"}

    def test_user_exclude_glob_is_additive(self, tmp_path: Path) -> None:
        (tmp_path / "keep.py").write_text("x = 1\n")
        (tmp_path / "examples").mkdir()
        (tmp_path / "examples" / "drop.py").write_text("y = 1\n")
        files, _ = walk_python_files(tmp_path, ("examples/*",))
        assert {f.relative_to(tmp_path).as_posix() for f in files} == {"keep.py"}

    def test_symlinked_file_not_followed(self, tmp_path: Path) -> None:
        real = tmp_path / "real.py"
        real.write_text("x = 1\n")
        link = tmp_path / "link.py"
        link.symlink_to(real)
        files, _ = walk_python_files(tmp_path, ())
        assert {f.relative_to(tmp_path).as_posix() for f in files} == {"real.py"}

    def test_symlinked_directory_not_followed(
        self, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        outside = tmp_path_factory.mktemp("outside_target")
        (outside / "secret.py").write_text("x = 1\n")
        (tmp_path / "linked_dir").symlink_to(outside)
        files, _ = walk_python_files(tmp_path, ())
        assert files == []

    def test_file_count_bound_truncates(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        mocker.patch("interbolt.scan.walk.SCAN_MAX_FILES", 2)
        for i in range(5):
            (tmp_path / f"f{i}.py").write_text("x = 1\n")
        files, truncated = walk_python_files(tmp_path, ())
        assert truncated is True
        assert len(files) == 2


class TestParsePythonFile:
    def test_parses_valid_source(self, tmp_path: Path) -> None:
        f = tmp_path / "a.py"
        f.write_text("x = 1\n")
        module = parse_python_file(f)
        assert module is not None

    def test_syntax_error_skipped_not_raised(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text("def broken(:\n")
        assert parse_python_file(f) is None

    def test_undecodable_bytes_skipped_not_raised(self, tmp_path: Path) -> None:
        f = tmp_path / "bad_encoding.py"
        f.write_bytes(b"\xff\xfe\x00\x01")
        assert parse_python_file(f) is None

    def test_oversized_file_skipped(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        mocker.patch("interbolt.scan.walk.SCAN_MAX_FILE_BYTES", 4)
        f = tmp_path / "big.py"
        f.write_text("x = 12345\n")
        assert parse_python_file(f) is None

    def test_missing_file_skipped_not_raised(self, tmp_path: Path) -> None:
        assert parse_python_file(tmp_path / "does_not_exist.py") is None
