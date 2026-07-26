"""CEL compilation: policy conditions are plain CEL, nothing more.

`when` expressions use CEL's own macro set (`map`, `filter`, `all`,
`exists`, `exists_one`, `reduce`). `contains_any_macro` rejects `.any(` at
compile time: celpy accepts it at parse (there is no such macro) and only
fails once evaluated, so without this check a rule using it would compile
cleanly and then silently never match.
"""

from __future__ import annotations

import celpy
import lark

from interbolt.errors import InterboltConfigError

_ENV = celpy.Environment()

_ANY_MACRO_MESSAGE = (
    "uses '.any(...)', which is not a CEL macro. CEL's quantifier macro is "
    "'exists'. Change '.any(' to '.exists(' in this condition."
)


def contains_any_macro(tree: lark.Tree[lark.Token]) -> bool:
    """Whether `tree` calls a method named `any`, CEL's non-existent macro.

    Walks `member_dot_arg` nodes, the parse-tree shape celpy dispatches
    method calls and macros from. String, bytes, and triple-quoted literals
    live under a sibling `literal` node, so an `.any(` inside a CEL string is
    structurally unreachable here and is never reported.
    """
    for subtree in tree.iter_subtrees():
        if subtree.data != "member_dot_arg":
            continue
        method_token = subtree.children[1]
        if isinstance(method_token, lark.Token) and method_token.value == "any":
            return True
    return False


def parse_cel_expression(source: str) -> lark.Tree[lark.Token]:
    """Parse one CEL expression.

    The shared first half of `compile_cel_expression`, exposed on its own for
    callers that need the parsed tree itself rather than a ready-to-evaluate
    `celpy.Runner`, for example a static analysis that inspects the boolean
    structure of a `when` expression.

    Args:
        source: The CEL expression text, as written in the policy YAML.

    Returns:
        The parsed `lark.Tree`.

    Raises:
        celpy.CELParseError: If the expression is not valid CEL.
    """
    return _ENV.compile(source)


def compile_parsed(tree: lark.Tree[lark.Token]) -> celpy.Runner:
    """Finish compiling an already-parsed CEL tree into a runnable program.

    The shared second half of `compile_cel_expression`, exposed on its own
    for callers that already hold the parsed tree (for example a static
    analysis that also walks it) and would otherwise parse the same source
    twice.

    Args:
        tree: A tree from `parse_cel_expression`.

    Returns:
        A compiled celpy program, ready for repeated `evaluate()` calls.

    Raises:
        InterboltConfigError: If the expression calls `.any(`.
    """
    if contains_any_macro(tree):
        raise InterboltConfigError(_ANY_MACRO_MESSAGE)
    return _ENV.program(tree)


def compile_cel_expression(source: str) -> celpy.Runner:
    """Compile one CEL `when` expression into a reusable, evaluate-many program.

    Args:
        source: The CEL expression text, as written in the policy YAML.

    Returns:
        A compiled celpy program, ready for repeated `evaluate()` calls.

    Raises:
        celpy.CELParseError: If the expression is not valid CEL.
        InterboltConfigError: If the expression calls `.any(`.
    """
    return compile_parsed(parse_cel_expression(source))
