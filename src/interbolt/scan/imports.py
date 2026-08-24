"""Import-table resolution, shared by evidence collection and tool-list detection.

Maps a name bound by `import`/`from ... import ...` in one file to the
`module.symbol` (or bare module) form it resolves to, and maps a scanned
file's own dotted module path back to its file path. Both `evidence.py`
(resolving a call target) and `literal.py` (resolving a `tools=[...]`
reference) need the same resolution, so it lives here rather than in either.

A file's dotted module path is relative to the scan root by default. Given
`init_files` (the scanned paths that are `__init__.py`), it is instead
computed from the file's own source root: walking up from the file's
directory while each ancestor still contains an `__init__.py` among the
scanned files, and stopping at the first one that does not. This is the
same layout an `import` statement itself resolves against, so a scan
rooted above the actual package layout (a monorepo prefix, nested
packages) still produces module paths that match how the scanned code's
own imports spell them. `literal.py` opts into this; other callers keep
the scan-root-relative default.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import PurePosixPath


def build_init_files(paths: Iterable[str]) -> frozenset[str]:
    """Every scanned path that is a package's own `__init__.py`."""
    return frozenset(p for p in paths if PurePosixPath(p).name == "__init__.py")


def _source_root(path: str, init_files: frozenset[str] | None) -> str:
    """The nearest ancestor directory of `path` that is not itself a package.

    Walks upward from `path`'s own directory while `<dir>/__init__.py` is
    among `init_files`, stopping at the first ancestor without one, or at
    the scan root, whichever comes first. `init_files=None` skips the walk
    and always returns `""`, the scan-root-relative basis.
    """
    if init_files is None:
        return ""
    current = PurePosixPath(path).parent
    while str(current) not in (".", "") and f"{current}/__init__.py" in init_files:
        current = current.parent
    return "" if str(current) in (".", "") else str(current)


def module_dotted_path(path: str, init_files: frozenset[str] | None = None) -> str:
    """The dotted module path `path` resolves to.

    Relative to the scan root by default, or to `path`'s own source root
    when `init_files` is given; see `_source_root`.
    """
    root = _source_root(path, init_files)
    relative = PurePosixPath(path).relative_to(root) if root else PurePosixPath(path)
    stem = (
        relative.parts[:-1]
        if relative.name == "__init__.py"
        else (*relative.parts[:-1], relative.stem)
    )
    return ".".join(stem)


def build_module_index(
    paths: Iterable[str], init_files: frozenset[str] | None = None
) -> dict[str, str]:
    """Map every scanned file's dotted module path to its own file path."""
    return {module_dotted_path(path, init_files): path for path in paths}


def package_of(path: str, init_files: frozenset[str] | None = None) -> str:
    """The dotted package path containing `path` (its parent directory).

    Uses the same basis as `module_dotted_path`, so a relative import
    resolved through this stays consistent with a module index built
    alongside it.
    """
    root = _source_root(path, init_files)
    parent = PurePosixPath(path).parent
    relative = parent.relative_to(root) if root else parent
    return "" if str(relative) in (".", "") else str(relative).replace("/", ".")


def resolve_relative_module(
    current_path: str,
    level: int,
    module: str | None,
    init_files: frozenset[str] | None = None,
) -> str | None:
    """Best-effort dotted module path for a `from .[...] import ...` statement."""
    package = package_of(current_path, init_files)
    parts = package.split(".") if package else []
    strip = level - 1
    if strip > len(parts):
        return None
    base_parts = parts[: len(parts) - strip] if strip else parts
    base = ".".join(base_parts)
    if module:
        return f"{base}.{module}" if base else module
    return base or None


def build_import_table(
    tree: ast.Module, current_path: str, init_files: frozenset[str] | None = None
) -> dict[str, str]:
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
                    current_path, node.level, node.module, init_files
                )
                if resolved is None:
                    continue
                resolved_module = resolved
            for alias in node.names:
                local = alias.asname or alias.name
                table[local] = f"{resolved_module}.{alias.name}"
    return table
