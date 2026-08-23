"""Import-table resolution, shared by evidence collection and tool-list detection.

Maps a name bound by `import`/`from ... import ...` in one file to the
`module.symbol` (or bare module) form it resolves to, and maps a scanned
file's own dotted module path back to its file path. Both `evidence.py`
(resolving a call target) and `literal.py` (resolving a `tools=[...]`
reference) need the same resolution, so it lives here rather than in either.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import PurePosixPath


def module_dotted_path(path: str) -> str:
    """The dotted module path a scan-root-relative file path corresponds to."""
    parts = PurePosixPath(path)
    stem = (
        parts.parts[:-1]
        if parts.name == "__init__.py"
        else (*parts.parts[:-1], parts.stem)
    )
    return ".".join(stem)


def build_module_index(paths: Iterable[str]) -> dict[str, str]:
    """Map every scanned file's dotted module path to its own file path."""
    return {module_dotted_path(path): path for path in paths}


def package_of(path: str) -> str:
    """The dotted package path containing `path` (its parent directory)."""
    parent = PurePosixPath(path).parent
    return "" if str(parent) in (".", "") else str(parent).replace("/", ".")


def resolve_relative_module(
    current_path: str, level: int, module: str | None
) -> str | None:
    """Best-effort dotted module path for a `from .[...] import ...` statement."""
    package = package_of(current_path)
    parts = package.split(".") if package else []
    strip = level - 1
    if strip > len(parts):
        return None
    base_parts = parts[: len(parts) - strip] if strip else parts
    base = ".".join(base_parts)
    if module:
        return f"{base}.{module}" if base else module
    return base or None


def build_import_table(tree: ast.Module, current_path: str) -> dict[str, str]:
    """Map every locally-bound import name to its resolved `module.symbol` form."""
    table: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level = alias.name.split(".")[0]
                local = alias.asname or top_level
                table[local] = alias.name if alias.asname else top_level
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if node.module is None:
                    continue
                resolved_module = node.module
            else:
                resolved = resolve_relative_module(
                    current_path, node.level, node.module
                )
                if resolved is None:
                    continue
                resolved_module = resolved
            for alias in node.names:
                local = alias.asname or alias.name
                table[local] = f"{resolved_module}.{alias.name}"
    return table
