"""Identity-shadowing static analysis: a CEL-AST-based `validate_policy` check.

Every other lint in `policy/schema.py` is a regex or substring scan over a
`when` string. This one is not: whether an earlier rule's identity predicate
makes a later one unreachable depends on how `&&`/`||`/`!` combine
sub-predicates, which a text scan cannot decide. This module recognizes a
small, deliberately narrow set of CEL shapes built only from `agent.id`/
`agent.groups` predicates, resolves each recognized rule's predicate to the
concrete set of agent ids it matches, and reports a later rule as unreachable
when an earlier rule's matched set is a superset of it. A rule whose `when`
is not built purely from these shapes is skipped, never guessed at.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

import lark
from celpy.evaluation import celstr

if TYPE_CHECKING:
    from interbolt.policy.schema import SinkRule


class _UndeclaredAgent:
    """Sentinel standing for every agent id absent from the `agents` section."""

    __slots__ = ()


_UNDECLARED_AGENT = _UndeclaredAgent()
_AgentSetElement = str | _UndeclaredAgent
_UNDECLARED_AGENT_LABEL = "an undeclared agent"


@dataclass(frozen=True)
class _IdEquals:
    literal: str


@dataclass(frozen=True)
class _IdNotEquals:
    literal: str


@dataclass(frozen=True)
class _GroupMembership:
    group: str


@dataclass(frozen=True)
class _Negation:
    operand: _IdentityPredicate


@dataclass(frozen=True)
class _Conjunction:
    left: _IdentityPredicate
    right: _IdentityPredicate


@dataclass(frozen=True)
class _Disjunction:
    left: _IdentityPredicate
    right: _IdentityPredicate


_IdentityPredicate = (
    _IdEquals
    | _IdNotEquals
    | _GroupMembership
    | _Negation
    | _Conjunction
    | _Disjunction
)

# Grammar levels that wrap exactly one child when no operator is present at
# that precedence level; `_unwrap` strips through them to reach the node that
# actually carries meaning. `ident` and `literal` are deliberately excluded:
# both terminate a walk, since their single child is the leaf value itself,
# not another node to recurse into.
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


def _unwrap(node: _Node) -> _Node:
    while (
        isinstance(node, lark.Tree)
        and node.data in _PASSTHROUGH_NODES
        and len(node.children) == 1
    ):
        node = node.children[0]
    return node


def _agent_field(node: _Node) -> str | None:
    """Return `"id"`/`"groups"` if `node` is exactly a bare `agent.<field>` access."""
    node = _unwrap(node)
    if not (isinstance(node, lark.Tree) and node.data == "member_dot"):
        return None
    receiver, field_token = node.children
    receiver = _unwrap(receiver)
    if not (isinstance(receiver, lark.Tree) and receiver.data == "ident"):
        return None
    ident_token = receiver.children[0]
    if not (isinstance(ident_token, lark.Token) and ident_token.value == "agent"):
        return None
    return field_token.value if isinstance(field_token, lark.Token) else None


def _string_literal(node: _Node) -> str | None:
    node = _unwrap(node)
    if not (isinstance(node, lark.Tree) and node.data == "literal"):
        return None
    token = node.children[0]
    if not (
        isinstance(token, lark.Token) and token.type in ("STRING_LIT", "MLSTRING_LIT")
    ):
        return None
    return str(celstr(token))


def _recognize_comparison(
    op_node: _Node, rhs_node: _Node
) -> _IdEquals | _IdNotEquals | None:
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
    return (
        _IdEquals(literal) if op_node.data == "relation_eq" else _IdNotEquals(literal)
    )


def _recognize_groups_exists(
    node: lark.Tree[lark.Token],
) -> _GroupMembership | None:
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
    bound_ident = _unwrap(bound_expr)
    if not (isinstance(bound_ident, lark.Tree) and bound_ident.data == "ident"):
        return None
    bound_token = bound_ident.children[0]
    if not isinstance(bound_token, lark.Token):
        return None
    predicate = _unwrap(predicate_expr)
    if not (
        isinstance(predicate, lark.Tree)
        and predicate.data == "relation"
        and len(predicate.children) == 2
    ):
        return None
    op_node, rhs_node = predicate.children
    if not (isinstance(op_node, lark.Tree) and op_node.data == "relation_eq"):
        return None
    lhs = _unwrap(op_node.children[0])
    if not (isinstance(lhs, lark.Tree) and lhs.data == "ident"):
        return None
    lhs_token = lhs.children[0]
    if not (isinstance(lhs_token, lark.Token) and lhs_token.value == bound_token.value):
        return None
    literal = _string_literal(rhs_node)
    return _GroupMembership(literal) if literal is not None else None


def _recognize_identity_expr(node: _Node) -> _IdentityPredicate | None:
    node = _unwrap(node)
    if not isinstance(node, lark.Tree):
        return None
    if node.data in ("conditionalor", "conditionaland") and len(node.children) == 2:
        left = _recognize_identity_expr(node.children[0])
        right = _recognize_identity_expr(node.children[1])
        if left is None or right is None:
            return None
        return (
            _Disjunction(left, right)
            if node.data == "conditionalor"
            else _Conjunction(left, right)
        )
    if node.data == "relation" and len(node.children) == 2:
        return _recognize_comparison(node.children[0], node.children[1])
    if node.data == "unary" and len(node.children) == 2:
        operand = _recognize_identity_expr(node.children[1])
        return _Negation(operand) if operand is not None else None
    if node.data == "member_dot_arg":
        return _recognize_groups_exists(node)
    return None


def _recognize_identity_when(when: str) -> _IdentityPredicate | None:
    from interbolt.policy.compile import parse_normalized

    try:
        tree = parse_normalized(when)
    except Exception:  # noqa: BLE001 -- any parse failure means "not identity-only"
        return None
    return _recognize_identity_expr(tree)


def _literal_agent_ids(expr: _IdentityPredicate) -> frozenset[str]:
    if isinstance(expr, (_IdEquals, _IdNotEquals)):
        return frozenset({expr.literal})
    if isinstance(expr, _Negation):
        return _literal_agent_ids(expr.operand)
    if isinstance(expr, (_Conjunction, _Disjunction)):
        return _literal_agent_ids(expr.left) | _literal_agent_ids(expr.right)
    return frozenset()


def _resolve(
    expr: _IdentityPredicate,
    universe: frozenset[_AgentSetElement],
    id_to_groups: Mapping[str, frozenset[str]],
) -> frozenset[_AgentSetElement]:
    if isinstance(expr, _IdEquals):
        return frozenset({expr.literal})
    if isinstance(expr, _IdNotEquals):
        return universe - {expr.literal}
    if isinstance(expr, _GroupMembership):
        return frozenset(
            agent_id
            for agent_id in universe
            if isinstance(agent_id, str)
            and expr.group in id_to_groups.get(agent_id, frozenset())
        )
    if isinstance(expr, _Negation):
        return universe - _resolve(expr.operand, universe, id_to_groups)
    if isinstance(expr, _Conjunction):
        return _resolve(expr.left, universe, id_to_groups) & _resolve(
            expr.right, universe, id_to_groups
        )
    return _resolve(expr.left, universe, id_to_groups) | _resolve(
        expr.right, universe, id_to_groups
    )


def _pick_witness(resolved: frozenset[_AgentSetElement]) -> _AgentSetElement | None:
    concrete = sorted(w for w in resolved if isinstance(w, str))
    if concrete:
        return concrete[0]
    return _UNDECLARED_AGENT if _UNDECLARED_AGENT in resolved else None


def _witness_label(witness: _AgentSetElement) -> str:
    return (
        _UNDECLARED_AGENT_LABEL
        if isinstance(witness, _UndeclaredAgent)
        else repr(witness)
    )


def _explain_membership(
    expr: _IdentityPredicate,
    witness: _AgentSetElement,
    universe: frozenset[_AgentSetElement],
    id_to_groups: Mapping[str, frozenset[str]],
) -> str | None:
    if isinstance(expr, _GroupMembership):
        if isinstance(witness, str) and expr.group in id_to_groups.get(
            witness, frozenset()
        ):
            return f"{witness!r} is a member of group {expr.group!r}"
        return None
    if isinstance(expr, _IdEquals):
        return (
            f"{_witness_label(witness)} matches agent.id == {expr.literal!r}"
            if witness == expr.literal
            else None
        )
    if isinstance(expr, _IdNotEquals):
        if witness != expr.literal:
            return f"{_witness_label(witness)} is not {expr.literal!r}"
        return None
    if isinstance(expr, _Conjunction):
        return _explain_membership(
            expr.left, witness, universe, id_to_groups
        ) or _explain_membership(expr.right, witness, universe, id_to_groups)
    if isinstance(expr, _Disjunction):
        if witness in _resolve(expr.left, universe, id_to_groups):
            explanation = _explain_membership(
                expr.left, witness, universe, id_to_groups
            )
            if explanation is not None:
                return explanation
        if witness in _resolve(expr.right, universe, id_to_groups):
            return _explain_membership(expr.right, witness, universe, id_to_groups)
        return None
    return None  # _Negation: no single positive fact explains it cleanly


def _shadowing_message(
    sink_key: str,
    earlier: SinkRule,
    later: SinkRule,
    earlier_expr: _IdentityPredicate,
    universe: frozenset[_AgentSetElement],
    id_to_groups: Mapping[str, frozenset[str]],
    resolved_later: frozenset[_AgentSetElement],
) -> str:
    base = (
        f"sink {sink_key!r}: rule {later.name!r} is unreachable: every agent "
        f"matched by {later.name!r} is also matched by the earlier rule "
        f"{earlier.name!r}"
    )
    witness = _pick_witness(resolved_later)
    if witness is None:
        return base
    explanation = _explain_membership(earlier_expr, witness, universe, id_to_groups)
    if explanation is None:
        explanation = f"{_witness_label(witness)} satisfies rule {earlier.name!r}"
    return f"{base} ({explanation})"


def find_identity_shadowing(
    sink_key: str,
    rules: Sequence[SinkRule],
    whens: Sequence[str | None],
    *,
    declared_ids: frozenset[str],
    id_to_groups: Mapping[str, frozenset[str]],
) -> list[str]:
    """Scan one sink's ordered rules for identity-predicate shadowing.

    A later rule is reported when some earlier rule's identity predicate
    (built only from `agent.id`/`agent.groups` comparisons combined with
    `&&`/`||`/`!`) matches a superset of the agent ids the later rule's own
    identity predicate matches, since first-match-wins then makes the later
    rule unreachable. A rule whose `when` mixes in taint, args, run, or
    trifecta conditions is not purely identity-based and is skipped for both
    positions in a pair: this is a false-negative-by-design restriction, not
    an oversight, to keep every reported case provable rather than heuristic.

    Args:
        sink_key: The dotted sink name, for the problem message.
        rules: The sink's ordered rule list.
        whens: Each rule's effective `when` text (`_rule_when(rule)`), `None`
            for the catch-all; must be the same length as `rules`.
        declared_ids: Every agent id declared in the policy's `agents` section.
        id_to_groups: The declared agent-id-to-groups mapping.

    Returns:
        One problem string per rule proven unreachable this way.
    """
    recognized = [
        _recognize_identity_when(when) if when is not None else None for when in whens
    ]
    problems: list[str] = []
    for earlier_idx, expr_i in enumerate(recognized):
        if expr_i is None:
            continue
        for later_idx in range(earlier_idx + 1, len(rules)):
            expr_j = recognized[later_idx]
            if expr_j is None:
                continue
            universe: frozenset[_AgentSetElement] = frozenset(
                declared_ids | _literal_agent_ids(expr_i) | _literal_agent_ids(expr_j)
            ) | {_UNDECLARED_AGENT}
            resolved_j = _resolve(expr_j, universe, id_to_groups)
            if resolved_j <= _resolve(expr_i, universe, id_to_groups):
                problems.append(
                    _shadowing_message(
                        sink_key,
                        rules[earlier_idx],
                        rules[later_idx],
                        expr_i,
                        universe,
                        id_to_groups,
                        resolved_j,
                    )
                )
    return problems
