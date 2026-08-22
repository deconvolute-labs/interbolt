"""Shared defenses against the code the scanner reads: never trust it.

`interbolt scan` reads a repository its user did not necessarily write.
Three primitives here are used across `walk.py`, `detect.py`, and
`evidence.py` so no module reimplements them: rejecting a string that could
display differently than it parses, confirming a path never escapes the
scan root, and walking an AST without recursing.
"""

from __future__ import annotations

import ast
import unicodedata
from collections.abc import Iterator
from pathlib import Path

from interbolt.constants import SCAN_MAX_AST_DEPTH

_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def is_forbidden_text(value: str) -> bool:
    """True if `value` contains a control, format, or line/paragraph separator.

    Categories `Cc` (control), `Cf` (format, including the bidirectional
    override characters), `Zl`, and `Zp`. Newlines, carriage returns, and
    NUL fall under `Cc`. Bidirectional overrides are the Trojan Source
    technique (CVE-2021-42574): they let a file's rendered text differ from
    what the parser sees, which in a scanner means a tool could parse as one
    name and display as another. Unicode letters are never rejected.

    Args:
        value: A candidate string that originated in the scanned repository.

    Returns:
        `True` if `value` should be rejected rather than entered into the
        artifact.
    """
    return any(unicodedata.category(ch) in _FORBIDDEN_CATEGORIES for ch in value)


def resolve_within_root(path: Path, root: Path) -> str | None:
    """Resolve `path` to a POSIX-relative form under `root`, or reject it.

    Rejects a path that is itself a symbolic link, and a path whose
    resolved form (following any symlinked ancestor directory) does not lie
    within `root`'s own resolved form. A rejected path is a way out of the
    scan root, so it is never written into the artifact.

    Args:
        path: The candidate path, typically already known to lie under
            `root` before symlink resolution.
        root: The scan root every artifact path must stay within.

    Returns:
        The POSIX-relative path from `root`, or `None` if `path` is a
        symlink or resolves outside `root`.
    """
    try:
        if path.is_symlink():
            return None
        resolved = path.resolve(strict=False)
        resolved_root = root.resolve(strict=False)
        relative = resolved.relative_to(resolved_root)
    except (OSError, ValueError):
        return None
    return relative.as_posix()


def walk_ast_bounded(
    node: ast.AST, max_depth: int = SCAN_MAX_AST_DEPTH
) -> Iterator[tuple[ast.AST, int, bool]]:
    """Walk every descendant of `node`, depth-tagged, without recursing.

    A branch deeper than `max_depth` is reported once, with the third
    element `True`, and not descended into further; every other node is
    reported with `False`.

    Args:
        node: The AST root to walk (a module, or a function body).
        max_depth: The deepest level to descend into. `node` itself is
            depth 0.

    Yields:
        `(descendant, depth, truncated)` for every visited node, in no
        guaranteed order.
    """
    stack: list[tuple[ast.AST, int]] = [(node, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            yield current, depth, True
            continue
        yield current, depth, False
        for child in ast.iter_child_nodes(current):
            stack.append((child, depth + 1))
