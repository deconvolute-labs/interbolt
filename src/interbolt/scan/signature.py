"""Render a tool's parameter list and return annotation, from the AST only (§6.2).

`ast.unparse` on the argument and annotation nodes, never source-text
slicing, so no comment can enter the artifact through this field. A
default value renders only when its node is a plain `ast.Constant`; any
other default (a call, a name reference, an f-string, ...) is dropped, and
the parameter still renders without it.
"""

from __future__ import annotations

import ast

from interbolt.scan import security


def render_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Render `node`'s signature as `"(a: int, b: str = 'x') -> bool"`.

    Args:
        node: The resolved tool definition.

    Returns:
        The rendered signature, or `None` if rendering fails, or if the
        result contains a control or Unicode-format character (§10.3) —
        the tool itself is still discovered; only this field is withheld.
    """
    try:
        rendered = _render(node)
    except (SyntaxError, ValueError, RecursionError):
        return None
    if security.is_forbidden_text(rendered):
        return None
    return rendered


def _render(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = node.args
    positional = [*args.posonlyargs, *args.args]
    defaults = args.defaults
    first_defaulted = len(positional) - len(defaults)

    parts: list[str] = []
    for i, arg in enumerate(positional):
        default = defaults[i - first_defaulted] if i >= first_defaulted else None
        parts.append(_render_arg(arg, default))
        if args.posonlyargs and i == len(args.posonlyargs) - 1:
            parts.append("/")

    if args.vararg is not None:
        parts.append(_render_arg(args.vararg, None, prefix="*"))
    elif args.kwonlyargs:
        parts.append("*")

    for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        parts.append(_render_arg(arg, default))

    if args.kwarg is not None:
        parts.append(_render_arg(args.kwarg, None, prefix="**"))

    rendered = "(" + ", ".join(parts) + ")"
    if node.returns is not None:
        rendered += f" -> {ast.unparse(node.returns)}"
    return rendered


def _render_arg(arg: ast.arg, default: ast.expr | None, *, prefix: str = "") -> str:
    text = prefix + arg.arg
    if arg.annotation is not None:
        text += f": {ast.unparse(arg.annotation)}"
    if isinstance(default, ast.Constant):
        text += f" = {ast.unparse(default)}"
    return text
