"""Source discovery: literal `taint(source=...)` call sites.

Finds every call site that passes a string-literal `source=` argument to
`taint`, matched by the call target's final attribute (or bare-name)
segment, the same convention `detect.py` uses for decorators. A `source=`
that is not a string literal is skipped.
"""

from __future__ import annotations

import ast

from interbolt.scan import security
from interbolt.scan.artifact import (
    ScanSource,
    ScanSourceSite,
    ScanUndetected,
    UndetectedKind,
)


def detect_taint_sources(
    trees: dict[str, ast.Module],
) -> tuple[tuple[ScanSource, ...], tuple[ScanUndetected, ...]]:
    """Find every literal `taint(source=...)` call site across a parsed file set.

    Args:
        trees: Every scanned file's parsed module, keyed by its
            scan-root-relative POSIX path.

    Returns:
        `(sources, undetected)`. `sources` is sorted by `name`, with each
        entry's `sites` sorted by `(path, line)` and `declared` always
        `False` (the caller joins against a policy separately). `undetected`
        carries `rejected_name` and `traversal_truncated` entries.
    """
    sites_by_name: dict[str, list[ScanSourceSite]] = {}
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
            if not isinstance(node, ast.Call) or not _is_taint_call(node.func):
                continue
            name = security.string_keyword(node, "source")
            if name is None:
                continue
            if security.is_forbidden_text(name):
                undetected.append(
                    ScanUndetected(
                        kind=UndetectedKind.REJECTED_NAME,
                        path=path,
                        line=node.lineno,
                        identifier=None,
                        detail=(
                            "a discovered source name contained a control or "
                            "bidirectional-format character and was rejected"
                        ),
                    )
                )
                continue
            sites_by_name.setdefault(name, []).append(
                ScanSourceSite(path=path, line=node.lineno)
            )

    sources = tuple(
        ScanSource(
            name=name,
            sites=tuple(sorted(dict.fromkeys(sites), key=lambda s: (s.path, s.line))),
            declared=False,
        )
        for name, sites in sorted(sites_by_name.items())
    )
    return sources, tuple(undetected)


def _is_taint_call(func: ast.expr) -> bool:
    """Whether `func` is a bare `taint` name or a `<chain>.taint` attribute access."""
    if isinstance(func, ast.Name):
        return func.id == "taint"
    return isinstance(func, ast.Attribute) and func.attr == "taint"
