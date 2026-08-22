"""Evidence collection: the external symbols a tool body reaches (§7).

Resolution uses each file's own import table. A call resolving to a
function defined elsewhere in the scanned tree is followed rather than
recorded, to a bounded depth; a call resolving to anything else (a stdlib
or third-party import, most commonly) is recorded as evidence. A call that
resolves to neither — a method call on a local variable, a dynamically
constructed target — is silently skipped: recording it would produce a
symbol with no library attached, which is noise.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import PurePosixPath

from interbolt.scan import security
from interbolt.scan.artifact import (
    ScanEvidence,
    ScanTool,
    ScanUndetected,
    UndetectedKind,
)

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def collect_all_evidence(
    tools: list[ScanTool], trees: dict[str, ast.Module], depth: int
) -> tuple[list[ScanTool], list[ScanUndetected]]:
    """Attach evidence to every tool with a resolved definition.

    Args:
        tools: The discovered tools (from `detect.detect_decorated_tools`).
        trees: Every scanned file's parsed module, keyed by its
            scan-root-relative POSIX path.
        depth: The maximum call-hop depth to follow (`--depth`).

    Returns:
        `(tools, undetected)`: `tools`, each with `evidence` populated (a
        tool whose definition could not be located in `trees` is returned
        unchanged; should not happen for a decorator-discovered tool, but
        degrades safely), and `traversal_truncated` entries from any
        function body whose expression nesting exceeded the scan's depth
        bound. This walk restarts its depth count at each function body, so
        it can truncate at a point `detect.py`'s whole-module walk did not.
    """
    by_location, by_name = _index_functions(trees)
    module_index = _build_module_index(trees.keys())
    result: list[ScanTool] = []
    undetected: list[ScanUndetected] = []
    for tool in tools:
        if tool.definition is None:
            result.append(tool)
            continue
        node = by_location.get((tool.definition.path, tool.definition.line))
        if node is None:
            result.append(tool)
            continue
        evidence, tool_undetected = _collect_evidence(
            tool.definition.path, node, trees, module_index, by_name, depth
        )
        result.append(tool.model_copy(update={"evidence": tuple(evidence)}))
        undetected.extend(tool_undetected)
    return result, undetected


def _index_functions(
    trees: dict[str, ast.Module],
) -> tuple[dict[tuple[str, int], _FunctionNode], dict[str, dict[str, _FunctionNode]]]:
    """Index every function def by `(path, lineno)`, and module-level ones by name.

    The location index locates a specific `ScanTool`'s own body (which may
    be a method, at any nesting level). The by-name index is module-level
    only, since a module's import table can only ever bind a module-level
    name, never a nested method.
    """
    by_location: dict[tuple[str, int], _FunctionNode] = {}
    by_name: dict[str, dict[str, _FunctionNode]] = {}
    for path, tree in trees.items():
        module_level: dict[str, _FunctionNode] = {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        by_name[path] = module_level
        for node, _depth, truncated in security.walk_ast_bounded(tree):
            if truncated or not isinstance(
                node, ast.FunctionDef | ast.AsyncFunctionDef
            ):
                continue
            by_location[(path, node.lineno)] = node
    return by_location, by_name


def _module_dotted_path(path: str) -> str:
    """The dotted module path a scan-root-relative file path corresponds to."""
    parts = PurePosixPath(path)
    stem = (
        parts.parts[:-1]
        if parts.name == "__init__.py"
        else (*parts.parts[:-1], parts.stem)
    )
    return ".".join(stem)


def _build_module_index(paths: Iterable[str]) -> dict[str, str]:
    """Map every scanned file's dotted module path to its own file path."""
    return {_module_dotted_path(path): path for path in paths}


def _package_of(path: str) -> str:
    """The dotted package path containing `path` (its parent directory)."""
    parent = PurePosixPath(path).parent
    return "" if str(parent) in (".", "") else str(parent).replace("/", ".")


def _resolve_relative_module(
    current_path: str, level: int, module: str | None
) -> str | None:
    """Best-effort dotted module path for a `from .[...] import ...` statement."""
    package = _package_of(current_path)
    parts = package.split(".") if package else []
    strip = level - 1
    if strip > len(parts):
        return None
    base_parts = parts[: len(parts) - strip] if strip else parts
    base = ".".join(base_parts)
    if module:
        return f"{base}.{module}" if base else module
    return base or None


def _build_import_table(tree: ast.Module, current_path: str) -> dict[str, str]:
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
                resolved = _resolve_relative_module(
                    current_path, node.level, node.module
                )
                if resolved is None:
                    continue
                resolved_module = resolved
            for alias in node.names:
                local = alias.asname or alias.name
                table[local] = f"{resolved_module}.{alias.name}"
    return table


def _resolve_call_symbol(call: ast.Call, import_table: dict[str, str]) -> str | None:
    """Resolve a call's target to `module.symbol`, one attribute level deep at most.

    `import a.b.c` then `a.b.c.d()` is not resolved: only a bare imported
    name, or one attribute access on a bare imported name, is. Deeper
    attribute chains are rare in practice and this mirrors the "a method
    call on a local variable is not recorded" scope limit already in §7.
    """
    func = call.func
    if isinstance(func, ast.Name):
        return import_table.get(func.id)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = import_table.get(func.value.id)
        return f"{base}.{func.attr}" if base is not None else None
    return None


def _collect_evidence(
    tool_path: str,
    tool_node: _FunctionNode,
    trees: dict[str, ast.Module],
    module_index: dict[str, str],
    by_name: dict[str, dict[str, _FunctionNode]],
    max_depth: int,
) -> tuple[list[ScanEvidence], list[ScanUndetected]]:
    """Walk `tool_node`'s body, following same-tree calls to `max_depth`."""
    seen: set[tuple[str, str, int]] = set()
    visited: set[tuple[str, str]] = set()
    evidence: list[ScanEvidence] = []
    undetected: list[ScanUndetected] = []

    def walk(path: str, node: _FunctionNode, depth: int) -> None:
        if (path, node.name) in visited:
            return
        visited.add((path, node.name))
        import_table = _build_import_table(trees[path], path)
        local_functions = by_name.get(path, {})
        for stmt in node.body:
            for sub, _depth2, truncated in security.walk_ast_bounded(stmt):
                if truncated:
                    undetected.append(
                        ScanUndetected(
                            kind=UndetectedKind.TRAVERSAL_TRUNCATED,
                            path=path,
                            line=getattr(sub, "lineno", node.lineno),
                            identifier=None,
                            detail=(
                                "expression nesting exceeded the scan's "
                                "traversal bound at this point"
                            ),
                        )
                    )
                    continue
                if not isinstance(sub, ast.Call):
                    continue
                func = sub.func
                if isinstance(func, ast.Name) and func.id in local_functions:
                    if depth < max_depth:
                        walk(path, local_functions[func.id], depth + 1)
                    continue
                symbol = _resolve_call_symbol(sub, import_table)
                if symbol is None:
                    continue
                module_part, _, attr_part = symbol.rpartition(".")
                target_path = module_index.get(module_part)
                if target_path is not None:
                    if depth < max_depth:
                        target_fn = by_name.get(target_path, {}).get(attr_part)
                        if target_fn is not None:
                            walk(target_path, target_fn, depth + 1)
                    continue
                # `symbol` is built from Python identifiers only (module
                # names, aliases, attribute names), which PEP 3131 already
                # excludes the forbidden Unicode categories from, unlike a
                # decorator's string-literal argument, so no rejection
                # check is needed here.
                key = (symbol, path, sub.lineno)
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(
                    ScanEvidence(symbol=symbol, path=path, line=sub.lineno, depth=depth)
                )

    walk(tool_path, tool_node, 0)
    evidence.sort(key=lambda e: (e.depth, e.path, e.line, e.symbol))
    return evidence, undetected
