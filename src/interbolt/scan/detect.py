"""Tool discovery by decorator (§6.2 of `dev/features/scanner.md`).

Schema-literal detection, registration/MCP detection, and policy-name
grounding are out of scope for PR1 (§12: PR2/PR3); this module matches only
the five decorator forms LangChain, the OpenAI Agents SDK, FastMCP, and
Interbolt's `@guard`/`@<handle>.guard` ship.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from interbolt.scan import security
from interbolt.scan.artifact import (
    Discovery,
    ScanCollision,
    ScanDefinition,
    ScanTool,
    ScanUndetected,
    UndetectedKind,
)
from interbolt.scan.signature import render_signature
from interbolt.utils.names import qualify_tool_name


@dataclass(frozen=True)
class _Match:
    """One decorator match on one function, before collision resolution."""

    qualified_name: str
    definition: ScanDefinition
    signature: str | None
    detector_detail: str
    guarded: bool


def detect_decorated_tools(
    trees: dict[str, ast.Module],
) -> tuple[list[ScanTool], list[ScanCollision], list[ScanUndetected]]:
    """Find every decorator-discovered tool across a parsed file set.

    Args:
        trees: Every scanned file's parsed module, keyed by its
            scan-root-relative POSIX path.

    Returns:
        `(tools, collisions, undetected)`. `tools` has no duplicate
        `qualified_name`: a colliding name is excluded from it and reported
        only in `collisions`. `undetected` carries `rejected_name` (an
        unsafe discovered name) and `traversal_truncated` (an AST branch
        past the depth bound) entries.
    """
    matches_by_name: dict[str, list[_Match]] = {}
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
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            _collect_function(path, node, matches_by_name, undetected)

    tools, collisions = _resolve_collisions(matches_by_name)
    return tools, collisions, undetected


def _collect_function(
    path: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    matches_by_name: dict[str, list[_Match]],
    undetected: list[ScanUndetected],
) -> None:
    """Match every decorator on one function def against the §6.2 table.

    When more than one decorator matches, an Interbolt match (`@guard` or
    `@<handle>.guard`) is authoritative for the name and detail, since
    `tool=` is the user's explicit assertion (§3.1); `guarded` is set
    whenever any matched decorator is Interbolt, independent of which one
    is authoritative.
    """
    resolved = [
        r
        for decorator in node.decorator_list
        if (r := _resolve_decorator(decorator, node.name)) is not None
    ]
    if not resolved:
        return
    guarded = any(is_interbolt for _, _, is_interbolt, _, _ in resolved)
    interbolt_matches = [r for r in resolved if r[2]]
    framework, display, _, raw_name, source = (interbolt_matches or resolved)[0]

    if security.is_forbidden_text(raw_name):
        undetected.append(
            ScanUndetected(
                kind=UndetectedKind.REJECTED_NAME,
                path=path,
                line=node.lineno,
                identifier=None,
                detail=(
                    "a discovered tool name contained a control or "
                    "bidirectional-format character and was rejected"
                ),
            )
        )
        return

    qualified_name = qualify_tool_name(raw_name)
    match = _Match(
        qualified_name=qualified_name,
        definition=ScanDefinition(path=path, line=node.lineno, symbol=node.name),
        signature=render_signature(node),
        detector_detail=_detector_detail(framework, display, source, qualified_name),
        guarded=guarded,
    )
    matches_by_name.setdefault(qualified_name, []).append(match)


def _resolve_collisions(
    matches_by_name: dict[str, list[_Match]],
) -> tuple[list[ScanTool], list[ScanCollision]]:
    """Split resolved matches into single-definition tools and collisions."""
    tools: list[ScanTool] = []
    collisions: list[ScanCollision] = []
    for qualified_name, matches in matches_by_name.items():
        if len(matches) > 1:
            collisions.append(
                ScanCollision(
                    qualified_name=qualified_name,
                    definitions=tuple(
                        sorted(
                            (m.definition for m in matches),
                            key=lambda d: (d.path, d.line),
                        )
                    ),
                )
            )
            continue
        match = matches[0]
        tools.append(
            ScanTool(
                qualified_name=match.qualified_name,
                definition=match.definition,
                signature=match.signature,
                discovery=Discovery.DECORATOR,
                detector_detail=match.detector_detail,
                declared=False,
                capabilities=(),
                guarded=match.guarded,
                policy_rules=(),
                evidence=(),
            )
        )
    tools.sort(key=lambda t: t.qualified_name)
    collisions.sort(key=lambda c: c.qualified_name)
    return tools, collisions


def _decorator_shape(decorator: ast.expr) -> tuple[ast.expr, ast.Call | None]:
    """Split a decorator expression into its target and an optional wrapping call."""
    if isinstance(decorator, ast.Call):
        return decorator.func, decorator
    return decorator, None


def _string_keyword(call: ast.Call | None, keyword: str) -> str | None:
    """The string value of `keyword=...` in `call`, or `None`."""
    if call is None:
        return None
    for kw in call.keywords:
        if (
            kw.arg == keyword
            and isinstance(kw.value, ast.Constant)
            and isinstance(kw.value.value, str)
        ):
            return kw.value.value
    return None


def _first_positional_string(call: ast.Call | None) -> str | None:
    """The first positional argument's string value in `call`, or `None`."""
    if call is None or not call.args:
        return None
    first = call.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return None


def _attribute_chain_text(node: ast.expr) -> str:
    """Reconstruct a dotted `a.b.c` attribute chain for display purposes only.

    Every character here comes from a Python identifier, which cannot
    contain a control, format, or separator character by Python's own
    grammar (PEP 3131), so this needs no `security.is_forbidden_text` check.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_attribute_chain_text(node.value)}.{node.attr}"
    return "..."


def _resolve_decorator(
    decorator: ast.expr, func_name: str
) -> tuple[str, str, bool, str, str | None] | None:
    """Match `decorator` against the §6.2 table and resolve its tool name.

    Returns `(framework, decorator_display, is_interbolt, raw_name,
    source)`, or `None` if `decorator` does not match any recognized form.
    `source` is the keyword or positional origin of `raw_name`, or `None`
    when it fell back to the function's own name.
    """
    target, call = _decorator_shape(decorator)
    if isinstance(target, ast.Name):
        segment, is_attribute, display = target.id, False, target.id
    elif isinstance(target, ast.Attribute):
        segment, is_attribute, display = (
            target.attr,
            True,
            _attribute_chain_text(target),
        )
    else:
        return None

    if segment == "tool" and not is_attribute:
        positional = _first_positional_string(call)
        if positional is not None:
            return "langchain", display, False, positional, "positional"
        name = _string_keyword(call, "name")
        if name is not None:
            return "langchain", display, False, name, "name"
        return "langchain", display, False, func_name, None
    if segment == "tool" and is_attribute:
        name = _string_keyword(call, "name")
        if name is not None:
            return "fastmcp", display, False, name, "name"
        return "fastmcp", display, False, func_name, None
    if segment == "function_tool" and not is_attribute:
        name = _string_keyword(call, "name_override")
        if name is not None:
            return "openai agents sdk", display, False, name, "name_override"
        return "openai agents sdk", display, False, func_name, None
    if segment == "guard":
        name = _string_keyword(call, "tool")
        if name is not None:
            return "interbolt", display, True, name, "tool"
        return "interbolt", display, True, func_name, None
    return None


def _detector_detail(
    framework: str, display: str, source: str | None, qualified_name: str
) -> str:
    """Render `detector_detail`, using the already-validated qualified name."""
    if source is None:
        return f"{framework} @{display}"
    if source == "positional":
        return f'{framework} @{display}("{qualified_name}")'
    return f'{framework} @{display}({source}="{qualified_name}")'
