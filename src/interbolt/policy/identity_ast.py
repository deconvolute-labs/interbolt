"""CEL-AST recognizers for the six identity-predicate shapes built from
`agent.id`/`agent.groups`.

Each recognizer takes a parsed CEL node (or, for `recognize_identity_when`,
raw `when` text) and returns a small `IdentityPredicate` value if the node is
exactly one of the recognized shapes, `None` otherwise. Nothing here decides
reachability; that lives in `policy/shadowing.py`, built on these shapes.
"""

from __future__ import annotations

from dataclasses import dataclass

import lark
from celpy.evaluation import celstr

from interbolt.policy.cel import parse_normalized


@dataclass(frozen=True)
class IdEquals:
    literal: str


@dataclass(frozen=True)
class IdNotEquals:
    literal: str


@dataclass(frozen=True)
class GroupMembership:
    group: str


@dataclass(frozen=True)
class Negation:
    operand: IdentityPredicate


@dataclass(frozen=True)
class Conjunction:
    left: IdentityPredicate
    right: IdentityPredicate


@dataclass(frozen=True)
class Disjunction:
    left: IdentityPredicate
    right: IdentityPredicate


IdentityPredicate = (
    IdEquals | IdNotEquals | GroupMembership | Negation | Conjunction | Disjunction
)

# Grammar levels that wrap exactly one child when no operator is present at
# that precedence level; `unwrap_node` strips through them to reach the node
# that actually carries meaning. `ident` and `literal` are deliberately
# excluded: both terminate a walk, since their single child is the leaf value
# itself, not another node to recurse into.
_PASSTHROUGH_NODES = frozenset(
    {
        "expr",
        "conditionalor",
        "conditionaland",
        "relation",
        "addition",
        "multiplication",
        "unary",
        "member",
        "primary",
        "paren_expr",
    }
)

_Node = lark.Tree[lark.Token] | lark.Token


def unwrap_node(node: _Node) -> _Node:
    while (
        isinstance(node, lark.Tree)
        and node.data in _PASSTHROUGH_NODES
        and len(node.children) == 1
    ):
        node = node.children[0]
    return node


def _agent_field(node: _Node) -> str | None:
    """Return `"id"`/`"groups"` if `node` is exactly a bare `agent.<field>` access."""
    node = unwrap_node(node)
    if not (isinstance(node, lark.Tree) and node.data == "member_dot"):
        return None
    receiver, field_token = node.children
    receiver = unwrap_node(receiver)
    if not (isinstance(receiver, lark.Tree) and receiver.data == "ident"):
        return None
    ident_token = receiver.children[0]
    if not (isinstance(ident_token, lark.Token) and ident_token.value == "agent"):
        return None
    return field_token.value if isinstance(field_token, lark.Token) else None


def _string_literal(node: _Node) -> str | None:
    node = unwrap_node(node)
    if not (isinstance(node, lark.Tree) and node.data == "literal"):
        return None
    token = node.children[0]
    if not (
        isinstance(token, lark.Token) and token.type in ("STRING_LIT", "MLSTRING_LIT")
    ):
        return None
    return str(celstr(token))


def recognize_comparison(
    op_node: _Node, rhs_node: _Node
) -> IdEquals | IdNotEquals | None:
    if not (
        isinstance(op_node, lark.Tree)
        and op_node.data in ("relation_eq", "relation_ne")
    ):
        return None
    if _agent_field(op_node.children[0]) != "id":
        return None
    literal = _string_literal(rhs_node)
    if literal is None:
        return None
    return IdEquals(literal) if op_node.data == "relation_eq" else IdNotEquals(literal)


def recognize_groups_exists(
    node: lark.Tree[lark.Token],
) -> GroupMembership | None:
    if len(node.children) != 3:
        return None
    receiver, method_token, exprlist_node = node.children
    if not (isinstance(method_token, lark.Token) and method_token.value == "exists"):
        return None
    if _agent_field(receiver) != "groups":
        return None
    if not (
        isinstance(exprlist_node, lark.Tree)
        and exprlist_node.data == "exprlist"
        and len(exprlist_node.children) == 2
    ):
        return None
    bound_expr, predicate_expr = exprlist_node.children
    bound_ident = unwrap_node(bound_expr)
    if not (isinstance(bound_ident, lark.Tree) and bound_ident.data == "ident"):
        return None
    bound_token = bound_ident.children[0]
    if not isinstance(bound_token, lark.Token):
        return None
    predicate = unwrap_node(predicate_expr)
    if not (
        isinstance(predicate, lark.Tree)
        and predicate.data == "relation"
        and len(predicate.children) == 2
    ):
        return None
    op_node, rhs_node = predicate.children
    if not (isinstance(op_node, lark.Tree) and op_node.data == "relation_eq"):
        return None
    lhs = unwrap_node(op_node.children[0])
    if not (isinstance(lhs, lark.Tree) and lhs.data == "ident"):
        return None
    lhs_token = lhs.children[0]
    if not (isinstance(lhs_token, lark.Token) and lhs_token.value == bound_token.value):
        return None
    literal = _string_literal(rhs_node)
    return GroupMembership(literal) if literal is not None else None


def recognize_identity_expr(node: _Node) -> IdentityPredicate | None:
    node = unwrap_node(node)
    if not isinstance(node, lark.Tree):
        return None
    if node.data in ("conditionalor", "conditionaland") and len(node.children) == 2:
        left = recognize_identity_expr(node.children[0])
        right = recognize_identity_expr(node.children[1])
        if left is None or right is None:
            return None
        return (
            Disjunction(left, right)
            if node.data == "conditionalor"
            else Conjunction(left, right)
        )
    if node.data == "relation" and len(node.children) == 2:
        return recognize_comparison(node.children[0], node.children[1])
    if node.data == "unary" and len(node.children) == 2:
        operand = recognize_identity_expr(node.children[1])
        return Negation(operand) if operand is not None else None
    if node.data == "member_dot_arg":
        return recognize_groups_exists(node)
    return None


def recognize_identity_when(when: str) -> IdentityPredicate | None:
    try:
        tree = parse_normalized(when)
    except Exception:  # noqa: BLE001 -- any parse failure means "not identity-only"
        return None
    return recognize_identity_expr(tree)
