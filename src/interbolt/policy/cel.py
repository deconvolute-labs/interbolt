"""CEL compilation: policy DSL rewrite.

The policy DSL's `.any(` is retargeted to CEL's real `exists` macro via an
AST-level transform on celpy's parsed `lark.Tree` (`_rewrite_any_to_exists`).
The transform only mutates `member_dot_arg` nodes, celpy's own
method-call/macro-dispatch AST shape, so string, bytes, and triple-quoted
literal tokens are structurally unreachable by it and are never touched,
regardless of their contents.
"""

from __future__ import annotations

import celpy
import lark

_ENV = celpy.Environment()


def _rewrite_any_to_exists(tree: lark.Tree[lark.Token]) -> lark.Tree[lark.Token]:
    """Retarget every `.any(` method-call node to CEL's `exists` macro, in place.

    CEL has no `any` macro; its set is `{map, filter, all, exists,
    exists_one, reduce, min}`. `exists` ("at least one element satisfies the
    predicate") means the same thing as the policy DSL's `.any(`.

    Walks `tree`'s `member_dot_arg` nodes (the parse-tree shape celpy's own
    evaluator dispatches macros from) and renames the method token from
    `any` to `exists` wherever it appears.

    Args:
        tree: The parsed CEL AST from `Environment.compile()`.

    Returns:
        The same tree object, mutated in place.
    """
    # String, bytes, and triple-quoted literals live under a sibling `literal`
    # grammar node, so a `.any(` inside a CEL string is never touched here.
    for subtree in tree.iter_subtrees():
        if subtree.data != "member_dot_arg":
            continue
        method_token = subtree.children[1]
        if isinstance(method_token, lark.Token) and method_token.value == "any":
            subtree.children[1] = method_token.update(value="exists")
    return tree


def parse_normalized(source: str) -> lark.Tree[lark.Token]:
    """Parse one CEL expression and retarget `.any(` to `.exists(`.

    The shared first half of `compile_cel_expression`, exposed on its own for
    callers that need the parsed tree itself rather than a ready-to-evaluate
    `celpy.Runner`, for example a static analysis that inspects the boolean
    structure of a `when` expression.

    Args:
        source: The CEL expression text, as written in the policy YAML.

    Returns:
        The parsed, `.any`-normalized `lark.Tree`.

    Raises:
        celpy.CELParseError: If the expression is not valid CEL.
    """
    return _rewrite_any_to_exists(_ENV.compile(source))


def compile_cel_expression(source: str) -> celpy.Runner:
    """Compile one CEL `when` expression into a reusable, evaluate-many program.

    Args:
        source: The CEL expression text, as written in the policy YAML.

    Returns:
        A compiled celpy program, ready for repeated `evaluate()` calls.

    Raises:
        celpy.CELParseError: If the expression is not valid CEL.
    """
    return _ENV.program(parse_normalized(source))
