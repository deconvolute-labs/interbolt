"""File discovery: scan root resolution, exclusion, and bounded parsing to AST."""

from __future__ import annotations

import ast
import fnmatch
import os
from collections.abc import Sequence
from pathlib import Path

from interbolt.constants import SCAN_MAX_FILE_BYTES, SCAN_MAX_FILES
from interbolt.utils import get_logger

_logger = get_logger("scan.walk")

DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        "build",
        "dist",
        "site-packages",
        "tests",
        "test",
    }
)


def resolve_scan_root(path: str | None) -> Path:
    """Resolve the scan root: an explicit `PATH`, else `src/`, else the cwd.

    Args:
        path: The `PATH` argument to `interbolt scan`, or `None`.

    Returns:
        The resolved (absolute) scan root.
    """
    if path is not None:
        return Path(path).resolve()
    candidate = Path.cwd() / "src"
    if candidate.is_dir():
        return candidate.resolve()
    return Path.cwd().resolve()


def walk_python_files(
    scan_root: Path, exclude: Sequence[str]
) -> tuple[list[Path], bool]:
    """Discover every `*.py` file under `scan_root`, bounded and exclusion-aware.

    Args:
        scan_root: The resolved scan root.
        exclude: User-supplied `--exclude` globs, additive to the defaults.

    Returns:
        `(files, truncated)`: the discovered files in a deterministic
        (sorted-per-directory) order, and whether the file-count bound
        stopped the walk before it finished.
    """
    return _walk_files(scan_root, exclude, suffix=".py")


def walk_json_files(scan_root: Path, exclude: Sequence[str]) -> tuple[list[Path], bool]:
    """Discover every `*.json` file under `scan_root`, bounded and exclusion-aware.

    Used to find MCP server configuration, which is JSON rather than Python.

    Args:
        scan_root: The resolved scan root.
        exclude: User-supplied `--exclude` globs, additive to the defaults.

    Returns:
        `(files, truncated)`: the discovered files in a deterministic
        (sorted-per-directory) order, and whether the file-count bound
        stopped the walk before it finished.
    """
    return _walk_files(scan_root, exclude, suffix=".json")


def _walk_files(
    scan_root: Path, exclude: Sequence[str], *, suffix: str
) -> tuple[list[Path], bool]:
    """Discover every file with `suffix` under `scan_root`, bounded and exclusion-aware.

    Symbolic links are never followed, for directories or for files.
    Directories named in `DEFAULT_EXCLUDED_DIRS`, plus every `--exclude`
    glob (matched against the scan-root-relative POSIX path), are skipped.
    The walk stops once `constants.SCAN_MAX_FILES` files have been found.
    """
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(scan_root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in DEFAULT_EXCLUDED_DIRS and not (current / name).is_symlink()
        )
        for filename in sorted(filenames):
            if not filename.endswith(suffix):
                continue
            file_path = current / filename
            if file_path.is_symlink():
                continue
            relative = file_path.relative_to(scan_root).as_posix()
            if any(fnmatch.fnmatch(relative, pattern) for pattern in exclude):
                continue
            if len(files) >= SCAN_MAX_FILES:
                return files, True
            files.append(file_path)
    return files, False


def parse_python_file(path: Path) -> ast.Module | None:
    """Read and parse one Python file with `ast.parse`. Never executes it.

    Every failure (too large, undecodable, unparseable, or a defensive catch
    for a pathological input) is logged at warning level and degrades to
    `None`, so the caller skips the file and the scan continues.

    Args:
        path: The file to read and parse.

    Returns:
        The parsed module, or `None` on any failure.
    """
    try:
        size = path.stat().st_size
        if size > SCAN_MAX_FILE_BYTES:
            _logger.warning(
                "skipping %s: %d bytes exceeds the %d-byte scan bound",
                path,
                size,
                SCAN_MAX_FILE_BYTES,
            )
            return None
        source = path.read_text(encoding="utf-8")
        return ast.parse(source, filename=str(path))
    except (
        SyntaxError,
        RecursionError,
        MemoryError,
        UnicodeDecodeError,
        ValueError,
        OSError,
    ) as exc:
        _logger.warning("skipping %s: %s", path, type(exc).__name__)
        return None
