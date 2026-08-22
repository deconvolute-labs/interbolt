"""Dynamic tool registration: calls the scanner can see but cannot enumerate.

A call to `register_tool`, `add_tool`, `register`, `add_tools`, or a `.tool(`
call outside decorator position hands a tool to the runtime through a value
the scanner cannot resolve statically. These are reported as blind spots.
"""

from __future__ import annotations

import ast

from interbolt.scan import security
from interbolt.scan.artifact import ScanUndetected, UndetectedKind

_REGISTRATION_NAMES = frozenset({"register_tool", "add_tool", "register", "add_tools"})


def detect_registration(trees: dict[str, ast.Module]) -> list[ScanUndetected]:
    """Find every dynamic-registration call across a parsed file set.

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
                continue
            if isinstance(node, ast.Call) and id(node) not in decorator_ids:
                _check_registration_call(path, node, undetected)
    return undetected


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
