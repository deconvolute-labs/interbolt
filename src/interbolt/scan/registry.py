"""Dynamic tool registration: calls and decorators the scanner cannot enumerate.

A call to `register_tool`, `add_tool`, `register`, `add_tools`, or a `.tool(`
call outside decorator position hands a tool to the runtime through a value
the scanner cannot resolve statically. So does a decorator whose final
segment names a registration pattern (`register_*`, `*_tool`, `action`,
`call_tool`, `list_tools`, and similar) but isn't one of `detect.py`'s
recognized tool decorators. Both are reported as blind spots.
"""

from __future__ import annotations

import ast

from interbolt.scan import security
from interbolt.scan.artifact import ScanUndetected, UndetectedKind

_REGISTRATION_NAMES = frozenset({"register_tool", "add_tool", "register", "add_tools"})

# Segments detect.py's core decorator allowlist already claims: a decorator
# matching one of these is a real tool declaration, never a registration
# blind spot, regardless of how broadly the patterns below would match it.
_CORE_ALLOWLIST_SEGMENTS = frozenset({"tool", "function_tool", "beta_tool", "guard"})
_BROAD_REGISTRATION_EXACT = frozenset({"action", "call_tool", "list_tools"})


def detect_registration(trees: dict[str, ast.Module]) -> list[ScanUndetected]:
    """Find every dynamic-registration call or decorator across a parsed file set.

    Args:
        trees: Every scanned file's parsed module, keyed by its
            scan-root-relative POSIX path.

    Returns:
        `dynamic_registration` and `traversal_truncated` entries.
    """
    undetected: list[ScanUndetected] = []
    for path, tree in trees.items():
        decorator_ids: set[int] = set()
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
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                decorator_ids.update(id(d) for d in node.decorator_list)
                for decorator in node.decorator_list:
                    _check_registration_decorator(
                        path, node.lineno, decorator, undetected
                    )
                continue
            if isinstance(node, ast.Call) and id(node) not in decorator_ids:
                _check_registration_call(path, node, undetected)
    return undetected


def _decorator_target(decorator: ast.expr) -> ast.expr:
    """The decorator's target expression, unwrapping a call form if present."""
    return decorator.func if isinstance(decorator, ast.Call) else decorator


def _decorator_final_segment(decorator: ast.expr) -> str | None:
    """The decorator's final attribute (or bare-name) segment, or `None`."""
    target = _decorator_target(decorator)
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _decorator_display(decorator: ast.expr) -> str:
    """Reconstruct the decorator's dotted display text, for `detail` only."""
    target = _decorator_target(decorator)
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return f"{_decorator_display(target.value)}.{target.attr}"
    return "..."


def _is_broad_registration_segment(segment: str) -> bool:
    """Whether `segment` matches a registration pattern and isn't a core decorator."""
    if segment in _CORE_ALLOWLIST_SEGMENTS:
        return False
    return (
        segment in _BROAD_REGISTRATION_EXACT
        or segment.startswith("register_")
        or segment.endswith("_tool")
    )


def _check_registration_decorator(
    path: str, lineno: int, decorator: ast.expr, undetected: list[ScanUndetected]
) -> None:
    """Report `decorator` as a registration blind spot if its segment matches."""
    segment = _decorator_final_segment(decorator)
    if segment is None or not _is_broad_registration_segment(segment):
        return
    undetected.append(
        ScanUndetected(
            kind=UndetectedKind.DYNAMIC_REGISTRATION,
            path=path,
            line=lineno,
            identifier=None,
            detail=(
                f"@{_decorator_display(decorator)} registers a tool at "
                "runtime; its name and implementation are unknown"
            ),
        )
    )


def _check_registration_call(
    path: str, node: ast.Call, undetected: list[ScanUndetected]
) -> None:
    """Report `node` as a registration blind spot if its shape matches one."""
    func = node.func
    if isinstance(func, ast.Name) and func.id in _REGISTRATION_NAMES:
        undetected.append(
            ScanUndetected(
                kind=UndetectedKind.DYNAMIC_REGISTRATION,
                path=path,
                line=node.lineno,
                identifier=None,
                detail=(
                    f"{func.id}(...) registers a tool at runtime; "
                    "its name and implementation are unknown"
                ),
            )
        )
        return
    if isinstance(func, ast.Attribute) and func.attr == "tool":
        undetected.append(
            ScanUndetected(
                kind=UndetectedKind.DYNAMIC_REGISTRATION,
                path=path,
                line=node.lineno,
                identifier=None,
                detail=(
                    ".tool(...) is called outside decorator position; "
                    "the registered tool is unknown"
                ),
            )
        )
