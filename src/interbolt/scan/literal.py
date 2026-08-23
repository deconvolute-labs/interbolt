"""Tool discovery from a `tools=` keyword argument's list value.

A `tools=` keyword is resolved element by element, in three shapes: a
reference to a function, resolved through the referencing file's import
table to any file in the scanned tree, or to its own module-level
definitions when the name is not imported, with a unique cross-tree name
match as a fallback when neither identifies a target; a dictionary literal
in the OpenAI or Anthropic tool schema shape, resolved by the same
cross-tree unique-name match (the rule policy name grounding reuses,
`ground.py`); or a bare name that itself resolves to a module-level list
constant, whose elements are then resolved the same way. An element that
resolves to neither shape is counted rather than voiding the whole list:
the site reports how many of its elements resolved, so a partially readable
list is never mistaken for a complete or an entirely unreadable one.
"""

from __future__ import annotations

import ast

from interbolt.scan import security
from interbolt.scan.artifact import (
    Discovery,
    ScanBindingSite,
    ScanDefinition,
    ScanUndetected,
    UndetectedKind,
)
from interbolt.scan.imports import build_import_table, build_module_index
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


def _index_module_functions_per_file(
    trees: dict[str, ast.Module],
) -> dict[str, dict[str, _FunctionNode]]:
    """Index each file's own module-level function definitions, by bare name.

    Unlike `index_module_functions`, this never merges names across files:
    a reference-list or module-constant element resolves against the
    module it actually appears in (its own definitions, or a name its own
    import table binds), never against an unrelated same-named function
    elsewhere in the scanned tree.
    """
    return {
        path: {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        for path, tree in trees.items()
    }


def collect_schema_literal_matches(
    trees: dict[str, ast.Module],
) -> tuple[dict[str, list[Match]], list[ScanUndetected]]:
    """Find every `tools=` list entry across a parsed file set, collisions unresolved.

    Args:
        trees: Every scanned file's parsed module, keyed by its
            scan-root-relative POSIX path.

    Returns:
        `(matches_by_name, undetected)`, for merging against another
        detector's matches before a single, combined collision resolution.
        `undetected` carries `unresolved_tool_list` (a `tools=` value that
        is not a list, not a resolvable module constant, or a list that
        resolved only partially), `unresolved_implementation` and
        `ambiguous_implementation` (a resolved schema name with zero or
        multiple matching functions), `rejected_name`, and
        `traversal_truncated`.
    """
    functions_by_name = index_module_functions(trees)
    module_functions = _index_module_functions_per_file(trees)
    import_tables = {
        path: build_import_table(tree, path) for path, tree in trees.items()
    }
    module_index = build_module_index(trees.keys())
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
                        trees,
                        functions_by_name,
                        module_functions,
                        import_tables,
                        module_index,
                        matches_by_name,
                        undetected,
                    )

    return matches_by_name, undetected


def _collect_tools_keyword(
    path: str,
    value: ast.expr,
    trees: dict[str, ast.Module],
    functions_by_name: dict[str, list[tuple[str, _FunctionNode]]],
    module_functions: dict[str, dict[str, _FunctionNode]],
    import_tables: dict[str, dict[str, str]],
    module_index: dict[str, str],
    matches_by_name: dict[str, list[Match]],
    undetected: list[ScanUndetected],
) -> None:
    """Handle one `tools=` value: a direct list, a named constant, or unreadable."""
    if isinstance(value, ast.List):
        binding_site = ScanBindingSite(path=path, line=value.lineno)
        _resolve_list_elements(
            path,
            value.elts,
            functions_by_name,
            module_functions,
            import_tables,
            module_index,
            Discovery.TOOL_LIST_REFERENCE,
            binding_site,
            value,
            matches_by_name,
            undetected,
        )
        return
    if isinstance(value, ast.Name):
        binding_site = ScanBindingSite(path=path, line=value.lineno)
        target_list = _resolve_module_constant_list(trees[path], value.id)
        if target_list is None:
            undetected.append(_unresolved_tool_list(path, value))
            return
        _resolve_list_elements(
            path,
            target_list.elts,
            functions_by_name,
            module_functions,
            import_tables,
            module_index,
            Discovery.TOOL_LIST_CONSTANT,
            binding_site,
            value,
            matches_by_name,
            undetected,
        )
        return
    undetected.append(_unresolved_tool_list(path, value))


def _resolve_module_constant_list(tree: ast.Module, name: str) -> ast.List | None:
    """The last module-level assignment of `name` to a list literal, or `None`.

    Same-file only, matching how Python itself would resolve a bare,
    unimported name at this scope. The last assignment wins, matching
    Python's own rebinding semantics for the common case of a single
    unconditional top-level assignment.
    """
    found: ast.List | None = None
    for node in tree.body:
        value: ast.expr | None
        if isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_names = [node.target.id]
            value = node.value
        else:
            continue
        if name in target_names and isinstance(value, ast.List):
            found = value
    return found


def _resolve_list_elements(
    path: str,
    elts: list[ast.expr],
    functions_by_name: dict[str, list[tuple[str, _FunctionNode]]],
    module_functions: dict[str, dict[str, _FunctionNode]],
    import_tables: dict[str, dict[str, str]],
    module_index: dict[str, str],
    discovery: Discovery,
    binding_site: ScanBindingSite,
    report_node: ast.expr,
    matches_by_name: dict[str, list[Match]],
    undetected: list[ScanUndetected],
) -> None:
    """Resolve every list element, then report the list as partial if any failed."""
    resolved_count = 0
    for item in elts:
        if isinstance(item, ast.Dict):
            if _resolve_schema_tool_element(
                path, item, functions_by_name, matches_by_name, undetected
            ):
                resolved_count += 1
            continue
        if isinstance(item, ast.Name | ast.Attribute):
            if _resolve_reference_element(
                path,
                item,
                functions_by_name,
                module_functions,
                import_tables,
                module_index,
                discovery,
                binding_site,
                matches_by_name,
                undetected,
            ):
                resolved_count += 1
            continue
        # A call, a constant, a comprehension element, or anything else:
        # counted as unresolved, no specific entry (the partial-list
        # message below names how many of the list's elements failed).

    _maybe_emit_partial(path, report_node, len(elts), resolved_count, undetected)


def _maybe_emit_partial(
    path: str,
    report_node: ast.expr,
    total: int,
    resolved: int,
    undetected: list[ScanUndetected],
) -> None:
    """Report a list as unresolved_tool_list when fewer than all elements resolved."""
    if total == 0 or resolved == total:
        return
    undetected.append(
        ScanUndetected(
            kind=UndetectedKind.UNRESOLVED_TOOL_LIST,
            path=path,
            line=report_node.lineno,
            identifier=None,
            detail=(
                f"tools= list has {total} elements; {resolved} resolved to "
                f"tools, {total - resolved} did not"
            ),
        )
    )


def _resolve_reference_element(
    path: str,
    item: ast.Name | ast.Attribute,
    functions_by_name: dict[str, list[tuple[str, _FunctionNode]]],
    module_functions: dict[str, dict[str, _FunctionNode]],
    import_tables: dict[str, dict[str, str]],
    module_index: dict[str, str],
    discovery: Discovery,
    binding_site: ScanBindingSite,
    matches_by_name: dict[str, list[Match]],
    undetected: list[ScanUndetected],
) -> bool:
    """Resolve one `ast.Name`/`ast.Attribute` list element to a tool, if it is one."""
    target_path, node = _resolve_reference_target(
        path, item, functions_by_name, module_functions, import_tables, module_index
    )
    if target_path is None or node is None:
        return False
    if security.is_forbidden_text(node.name):
        undetected.append(
            ScanUndetected(
                kind=UndetectedKind.REJECTED_NAME,
                path=target_path,
                line=node.lineno,
                identifier=None,
                detail=(
                    "a discovered tool name contained a control or "
                    "bidirectional-format character and was rejected"
                ),
            )
        )
        return False

    qualified_name = qualify_tool_name(node.name)
    shape = "reference" if discovery is Discovery.TOOL_LIST_REFERENCE else "constant"
    matches_by_name.setdefault(qualified_name, []).append(
        Match(
            qualified_name=qualified_name,
            definition=ScanDefinition(
                path=target_path, line=node.lineno, symbol=node.name
            ),
            signature=render_signature(node),
            discovery=discovery,
            detector_detail=(
                f"tools= list {shape} at {binding_site.path}:{binding_site.line}"
            ),
            guarded=False,
            binding_site=binding_site,
        )
    )
    return True


def _resolve_unique_cross_tree(
    name: str, functions_by_name: dict[str, list[tuple[str, _FunctionNode]]]
) -> tuple[str, _FunctionNode] | tuple[None, None]:
    """The single module-level function named `name` anywhere in the tree, if unique."""
    candidates = functions_by_name.get(name, [])
    if len(candidates) != 1:
        return None, None
    return candidates[0]


def _resolve_reference_target(
    path: str,
    item: ast.Name | ast.Attribute,
    functions_by_name: dict[str, list[tuple[str, _FunctionNode]]],
    module_functions: dict[str, dict[str, _FunctionNode]],
    import_tables: dict[str, dict[str, str]],
    module_index: dict[str, str],
) -> tuple[str, _FunctionNode] | tuple[None, None]:
    """Resolve a list element to `(path, node)` via imports, definitions, or a fallback.

    An `ast.Attribute` (`mod.func`) resolves one hop: `mod` must be a bare
    module import in the same file, resolved to a scanned file via the
    module index. An `ast.Name` resolves through the same file's import
    table when it is a `from X import name` binding (resolved the same
    way), or, when it is not imported at all, as a same-file module-level
    definition. When neither identifies a module, the bare name falls back
    to a unique module-level function of that name anywhere in the scanned
    tree; zero or more than one match leaves the reference unresolved.
    """
    import_table = import_tables.get(path, {})
    if isinstance(item, ast.Attribute):
        if not isinstance(item.value, ast.Name):
            return None, None
        base_module = import_table.get(item.value.id)
        if base_module is not None:
            target_path = module_index.get(base_module)
            if target_path is not None:
                node = module_functions.get(target_path, {}).get(item.attr)
                if node is not None:
                    return target_path, node
        return _resolve_unique_cross_tree(item.attr, functions_by_name)

    if item.id in import_table:
        resolved = import_table[item.id]
        if "." in resolved:
            module_part, _, attr_part = resolved.rpartition(".")
            target_path = module_index.get(module_part)
            if target_path is not None:
                node = module_functions.get(target_path, {}).get(attr_part)
                if node is not None:
                    return target_path, node
            return _resolve_unique_cross_tree(item.id, functions_by_name)
        # A bare `import mod` binding: a module, never a callable symbol.
        return None, None

    node = module_functions.get(path, {}).get(item.id)
    if node is not None:
        return path, node
    return _resolve_unique_cross_tree(item.id, functions_by_name)


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
    if isinstance(value, ast.Name):
        return "a bare variable that does not resolve to a module-level list"
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


def _resolve_schema_tool_element(
    path: str,
    item: ast.Dict,
    functions_by_name: dict[str, list[tuple[str, _FunctionNode]]],
    matches_by_name: dict[str, list[Match]],
    undetected: list[ScanUndetected],
) -> bool:
    """Resolve one dict-literal list element, OpenAI or Anthropic tool schema shape."""
    raw_name = _schema_dict_name(item)
    if raw_name is None:
        return False
    return _resolve_schema_tool(
        path, item.lineno, raw_name, functions_by_name, matches_by_name, undetected
    )


def _resolve_schema_tool(
    path: str,
    line: int,
    raw_name: str,
    functions_by_name: dict[str, list[tuple[str, _FunctionNode]]],
    matches_by_name: dict[str, list[Match]],
    undetected: list[ScanUndetected],
) -> bool:
    """Qualify, sanitize, and resolve one schema-discovered tool name.

    Returns whether the name resolved to exactly one tool. A rejection or a
    resolution failure emits its own specific `undetected` entry either
    way, since each is a diagnosis about one named tool rather than about
    the list's overall completeness.
    """
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
        return False

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
        return False
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
        return False

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
    return True
