"""Tool discovery from a literal `tools=[...]` schema.

Matches a `tools=` keyword argument whose value is a list of dictionary
literals, in either the OpenAI shape (`{"type": "function", "function":
{"name": ...}}`) or the Anthropic shape (`{"name": ..., "input_schema":
{...}}`). The implementation is resolved by searching every scanned file's
module-level functions for a unique name match, the same rule policy name
grounding reuses (`ground.py`).
"""

from __future__ import annotations

import ast

from interbolt.scan import security
from interbolt.scan.artifact import (
    Discovery,
    ScanDefinition,
    ScanUndetected,
    UndetectedKind,
)
from interbolt.scan.matches import Match
from interbolt.scan.signature import render_signature
from interbolt.utils.names import qualify_tool_name

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def index_module_functions(
    trees: dict[str, ast.Module],
) -> dict[str, list[tuple[str, _FunctionNode]]]:
    """Index every module-level function definition across all files, by bare name.

    Args:
        trees: Every scanned file's parsed module, keyed by its
            scan-root-relative POSIX path.

    Returns:
        Bare function name to every `(path, node)` it is defined at,
        module-level only. Two entries under one name, whether in the same
        file or different files, means the name is ambiguous.
    """
    by_name: dict[str, list[tuple[str, _FunctionNode]]] = {}
    for path, tree in trees.items():
        for node in tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                by_name.setdefault(node.name, []).append((path, node))
    return by_name


def collect_schema_literal_matches(
    trees: dict[str, ast.Module],
) -> tuple[dict[str, list[Match]], list[ScanUndetected]]:
    """Find every literal `tools=[...]` schema entry, without resolving collisions yet.

    Args:
        trees: Every scanned file's parsed module, keyed by its
            scan-root-relative POSIX path.

    Returns:
        `(matches_by_name, undetected)`, for merging against another
        detector's matches before a single, combined collision resolution.
        `undetected` carries `unresolved_tool_list` (a `tools=` value that
        is not a list of dict literals), `unresolved_implementation` and
        `ambiguous_implementation` (a resolved name with zero or multiple
        matching functions), `rejected_name`, and `traversal_truncated`.
    """
    functions_by_name = index_module_functions(trees)
    matches_by_name: dict[str, list[Match]] = {}
    undetected: list[ScanUndetected] = []

    for path, tree in trees.items():
        for node, _depth, truncated in security.walk_ast_bounded(tree):
            if truncated:
                undetected.append(
                    ScanUndetected(
                        kind=UndetectedKind.TRAVERSAL_TRUNCATED,
                        path=path,
                        line=getattr(node, "lineno", 0),
                        identifier=None,
                        detail=(
                            "expression nesting exceeded the scan's "
                            "traversal bound at this point"
                        ),
                    )
                )
                continue
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg == "tools":
                    _collect_tools_keyword(
                        path,
                        keyword.value,
                        functions_by_name,
                        matches_by_name,
                        undetected,
                    )

    return matches_by_name, undetected


def _collect_tools_keyword(
    path: str,
    value: ast.expr,
    functions_by_name: dict[str, list[tuple[str, _FunctionNode]]],
    matches_by_name: dict[str, list[Match]],
    undetected: list[ScanUndetected],
) -> None:
    """Handle one `tools=` keyword's value: a list of dict literals, or unreadable."""
    if not isinstance(value, ast.List):
        undetected.append(_unresolved_tool_list(path, value))
        return
    dict_items = [item for item in value.elts if isinstance(item, ast.Dict)]
    if len(dict_items) != len(value.elts):
        undetected.append(_unresolved_tool_list(path, value))
        return

    for item in dict_items:
        raw_name = _schema_dict_name(item)
        if raw_name is None:
            continue
        _resolve_schema_tool(
            path, item.lineno, raw_name, functions_by_name, matches_by_name, undetected
        )


def _unresolved_tool_list(path: str, value: ast.expr) -> ScanUndetected:
    """Build the `unresolved_tool_list` entry for an unreadable `tools=` value."""
    return ScanUndetected(
        kind=UndetectedKind.UNRESOLVED_TOOL_LIST,
        path=path,
        line=value.lineno,
        identifier=None,
        detail=(
            f"tools= is {_expression_kind(value)}; "
            "the tool names it produces are unknown"
        ),
    )


def _expression_kind(value: ast.expr) -> str:
    """A human-readable name for `value`'s expression kind, for `detector_detail`."""
    if isinstance(value, ast.List):
        return "a list containing something other than dict literals"
    if isinstance(value, ast.Name):
        return "a bare variable"
    if isinstance(value, ast.Call):
        return "a call expression"
    if isinstance(value, ast.BinOp):
        return "a concatenation expression"
    if isinstance(value, ast.ListComp):
        return "a comprehension"
    return f"a {type(value).__name__} expression"


def _dict_str_value(node: ast.Dict, key: str) -> str | None:
    """The string value of `key` in dict literal `node`, from `ast.Constant` only."""
    for k, v in zip(node.keys, node.values, strict=True):
        if (
            isinstance(k, ast.Constant)
            and k.value == key
            and isinstance(v, ast.Constant)
            and isinstance(v.value, str)
        ):
            return v.value
    return None


def _dict_value(node: ast.Dict, key: str) -> ast.expr | None:
    """The raw value node of `key` in dict literal `node`, or `None`."""
    for k, v in zip(node.keys, node.values, strict=True):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    return None


def _schema_dict_name(item: ast.Dict) -> str | None:
    """The tool name from one schema dict literal, OpenAI or Anthropic shape."""
    tool_type = _dict_str_value(item, "type")
    if tool_type == "function":
        function_value = _dict_value(item, "function")
        if isinstance(function_value, ast.Dict):
            return _dict_str_value(function_value, "name")
        return None
    return _dict_str_value(item, "name")


def _resolve_schema_tool(
    path: str,
    line: int,
    raw_name: str,
    functions_by_name: dict[str, list[tuple[str, _FunctionNode]]],
    matches_by_name: dict[str, list[Match]],
    undetected: list[ScanUndetected],
) -> None:
    """Qualify, sanitize, and resolve one schema-discovered tool name."""
    if security.is_forbidden_text(raw_name):
        undetected.append(
            ScanUndetected(
                kind=UndetectedKind.REJECTED_NAME,
                path=path,
                line=line,
                identifier=None,
                detail=(
                    "a discovered tool name contained a control or "
                    "bidirectional-format character and was rejected"
                ),
            )
        )
        return

    qualified_name = qualify_tool_name(raw_name)
    bare_name = qualified_name.rpartition(".")[2]
    candidates = functions_by_name.get(bare_name, [])

    if not candidates:
        undetected.append(
            ScanUndetected(
                kind=UndetectedKind.UNRESOLVED_IMPLEMENTATION,
                path=path,
                line=line,
                identifier=qualified_name,
                detail=(
                    f"tool name {qualified_name!r} has no matching function definition"
                ),
            )
        )
        return
    if len(candidates) > 1:
        undetected.append(
            ScanUndetected(
                kind=UndetectedKind.AMBIGUOUS_IMPLEMENTATION,
                path=path,
                line=line,
                identifier=qualified_name,
                detail=(
                    f"tool name {qualified_name!r} matches "
                    f"{len(candidates)} function definitions"
                ),
            )
        )
        return

    definition_path, definition_node = candidates[0]
    match = Match(
        qualified_name=qualified_name,
        definition=ScanDefinition(
            path=definition_path,
            line=definition_node.lineno,
            symbol=definition_node.name,
        ),
        signature=render_signature(definition_node),
        discovery=Discovery.SCHEMA_LITERAL,
        detector_detail=f"tools= list literal at {path}:{line}",
        guarded=False,
    )
    matches_by_name.setdefault(qualified_name, []).append(match)
