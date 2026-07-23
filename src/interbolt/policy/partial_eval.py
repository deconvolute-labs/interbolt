"""Generic partial evaluation of a CEL `when` expression against a partial binding.

Resolves only the `agent.id`/`agent.groups` predicates recognized by
`policy.shadowing`'s extractor; every other CEL construct (taint, args, run,
trifecta) is left as literal residual text, reconstructed as an exact
substring of the original expression from the parsed node's source span.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import lark

from interbolt.policy.shadowing import (
    _GroupMembership,
    _IdEquals,
    _IdNotEquals,
    _recognize_comparison,
    _recognize_groups_exists,
    _unwrap,
)

_Node = lark.Tree[lark.Token] | lark.Token
_Leaf = _IdEquals | _IdNotEquals | _GroupMembership
LeafResolver = Callable[[_Leaf], bool | None]


@dataclass(frozen=True)
class Residual:
    """A CEL subexpression left unresolved by partial evaluation.

    Attributes:
        text: The exact source substring of the residual, reconstructed from
            the parsed AST's span rather than reprinted from the tree, so it
            reads identically to how the policy author wrote it.
        member_dependent: True when every atom folded into this residual is a
            recognized identity shape left unresolved only because the
            binding is partial (an unbound `agent.id`, or a group other than
            the one bound); False when at least one atom is a genuine
            runtime condition (taint, args, run) or an unrecognized shape,
            meaning the residual would not fully resolve under any identity
            binding.
    """

    text: str
    member_dependent: bool


def span_text(node: _Node, when_text: str) -> str:
    """Reconstruct one AST node's exact source substring from its span.

    Args:
        node: A `lark.Tree` or `lark.Token` produced by `parse_normalized`.
        when_text: The original CEL source the node was parsed from.

    Returns:
        The substring of `when_text` covering `node`.
    """
    if isinstance(node, lark.Token):
        return when_text[node.start_pos : node.end_pos]
    return when_text[node.meta.start_pos : node.meta.end_pos]


def _combine_and(left: bool | Residual, right: bool | Residual) -> bool | Residual:
    if left is False or right is False:
        return False
    if isinstance(left, Residual) and isinstance(right, Residual):
        return Residual(
            f"{left.text} && {right.text}",
            left.member_dependent and right.member_dependent,
        )
    if isinstance(left, Residual):
        return left
    if isinstance(right, Residual):
        return right
    return True


def _combine_or(left: bool | Residual, right: bool | Residual) -> bool | Residual:
    if left is True or right is True:
        return True
    if isinstance(left, Residual) and isinstance(right, Residual):
        return Residual(
            f"{left.text} || {right.text}",
            left.member_dependent and right.member_dependent,
        )
    if isinstance(left, Residual):
        return left
    if isinstance(right, Residual):
        return right
    return False


def _negate(operand: bool | Residual) -> bool | Residual:
    if isinstance(operand, Residual):
        return Residual(f"!({operand.text})", operand.member_dependent)
    return not operand


def partial_eval(
    node: _Node, when_text: str, resolve_leaf: LeafResolver
) -> bool | Residual:
    """Partially evaluate one parsed CEL `when` against a partial identity binding.

    Recurses through `&&`/`||`/`!`, applying short-circuit simplification
    (`False && X` collapses to `False`, `True || X` collapses to `True`, and
    so on); a recognized `agent.id`/`agent.groups` leaf is resolved via
    `resolve_leaf` (`None` meaning "not determined by this binding"); anything
    else is an opaque atom, reported as a `Residual` that is never
    member-dependent.

    Args:
        node: The parsed CEL AST, or a subtree of it during recursion.
        when_text: The original CEL source, for reconstructing residual text.
        resolve_leaf: Resolves one recognized identity leaf to `True`/`False`,
            or `None` if the current binding does not determine it.

    Returns:
        `True`/`False` if the whole expression resolves under this binding,
        else a `Residual` describing what remains.
    """
    node = _unwrap(node)
    if (
        isinstance(node, lark.Tree)
        and node.data in ("conditionaland", "conditionalor")
        and len(node.children) == 2
    ):
        left = partial_eval(node.children[0], when_text, resolve_leaf)
        right = partial_eval(node.children[1], when_text, resolve_leaf)
        return (
            _combine_and(left, right)
            if node.data == "conditionaland"
            else _combine_or(left, right)
        )
    if isinstance(node, lark.Tree) and node.data == "unary" and len(node.children) == 2:
        return _negate(partial_eval(node.children[1], when_text, resolve_leaf))

    leaf: _Leaf | None = None
    if (
        isinstance(node, lark.Tree)
        and node.data == "relation"
        and len(node.children) == 2
    ):
        leaf = _recognize_comparison(node.children[0], node.children[1])
    elif isinstance(node, lark.Tree) and node.data == "member_dot_arg":
        leaf = _recognize_groups_exists(node)

    if leaf is not None:
        resolved = resolve_leaf(leaf)
        if resolved is not None:
            return resolved
        return Residual(span_text(node, when_text), member_dependent=True)
    return Residual(span_text(node, when_text), member_dependent=False)


def resolve_leaf_for_agent(agent_id: str, groups: frozenset[str]) -> LeafResolver:
    """Build a leaf resolver that fully binds both `agent.id` and `agent.groups`.

    Every recognized leaf resolves to a concrete `bool`; nothing is left
    unresolved, since under a full agent binding both fields are known.

    Args:
        agent_id: The bound agent's durable identity.
        groups: The bound agent's resolved groups (`resolve_agent_groups`).

    Returns:
        A resolver suitable for `partial_eval`.
    """

    def _resolve(leaf: _Leaf) -> bool:
        if isinstance(leaf, _IdEquals):
            return agent_id == leaf.literal
        if isinstance(leaf, _IdNotEquals):
            return agent_id != leaf.literal
        return leaf.group in groups

    return _resolve


def resolve_leaf_for_group(bound_group: str) -> LeafResolver:
    """Build a leaf resolver that binds only membership in one group.

    `agent.id` stays unbound (always `None`); `agent.groups.exists(...)`
    resolves to `True` only for the bound group itself, `None` for every
    other group, since membership in one group says nothing about another.

    Args:
        bound_group: The group name bound via `--group`.

    Returns:
        A resolver suitable for `partial_eval`.
    """

    def _resolve(leaf: _Leaf) -> bool | None:
        if isinstance(leaf, _GroupMembership):
            return True if leaf.group == bound_group else None
        return None

    return _resolve
