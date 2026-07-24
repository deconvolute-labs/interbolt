"""Identity-shadowing static analysis: a CEL-AST-based `validate_policy` check.

Resolves each recognized rule's identity predicate to the concrete set of
agent ids it matches, and reports a later rule as unreachable when an
earlier rule's matched set is a superset of it. Whether an earlier rule's
identity predicate makes a later one unreachable depends on how `&&`/`||`/
`!` combine sub-predicates, so this walks the parsed CEL AST rather than
scanning `when` text. A rule whose `when` is not built purely from these
shapes is skipped, never guessed at.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from interbolt.policy.identity_ast import (
    Conjunction,
    Disjunction,
    GroupMembership,
    IdentityPredicate,
    IdEquals,
    IdNotEquals,
    Negation,
    recognize_identity_when,
)

if TYPE_CHECKING:
    from interbolt.policy.schema import SinkRule


class _UndeclaredAgent:
    """Sentinel standing for every agent id absent from the `agents` section."""

    __slots__ = ()


_UNDECLARED_AGENT = _UndeclaredAgent()
_AgentSetElement = str | _UndeclaredAgent
_UNDECLARED_AGENT_LABEL = "an undeclared agent"


def _literal_agent_ids(expr: IdentityPredicate) -> frozenset[str]:
    if isinstance(expr, (IdEquals, IdNotEquals)):
        return frozenset({expr.literal})
    if isinstance(expr, Negation):
        return _literal_agent_ids(expr.operand)
    if isinstance(expr, (Conjunction, Disjunction)):
        return _literal_agent_ids(expr.left) | _literal_agent_ids(expr.right)
    return frozenset()


def _resolve(
    expr: IdentityPredicate,
    universe: frozenset[_AgentSetElement],
    id_to_groups: Mapping[str, frozenset[str]],
) -> frozenset[_AgentSetElement]:
    if isinstance(expr, IdEquals):
        return frozenset({expr.literal})
    if isinstance(expr, IdNotEquals):
        return universe - {expr.literal}
    if isinstance(expr, GroupMembership):
        return frozenset(
            agent_id
            for agent_id in universe
            if isinstance(agent_id, str)
            and expr.group in id_to_groups.get(agent_id, frozenset())
        )
    if isinstance(expr, Negation):
        return universe - _resolve(expr.operand, universe, id_to_groups)
    if isinstance(expr, Conjunction):
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


def explain_membership(
    expr: IdentityPredicate,
    witness: _AgentSetElement,
    universe: frozenset[_AgentSetElement],
    id_to_groups: Mapping[str, frozenset[str]],
) -> str | None:
    """Explain why `witness` matches `expr`, or `None` if no single fact explains it."""
    if isinstance(expr, GroupMembership):
        if isinstance(witness, str) and expr.group in id_to_groups.get(
            witness, frozenset()
        ):
            return f"{witness!r} is a member of group {expr.group!r}"
        return None
    if isinstance(expr, IdEquals):
        return (
            f"{_witness_label(witness)} matches agent.id == {expr.literal!r}"
            if witness == expr.literal
            else None
        )
    if isinstance(expr, IdNotEquals):
        if witness != expr.literal:
            return f"{_witness_label(witness)} is not {expr.literal!r}"
        return None
    if isinstance(expr, Conjunction):
        return explain_membership(
            expr.left, witness, universe, id_to_groups
        ) or explain_membership(expr.right, witness, universe, id_to_groups)
    if isinstance(expr, Disjunction):
        if witness in _resolve(expr.left, universe, id_to_groups):
            explanation = explain_membership(expr.left, witness, universe, id_to_groups)
            if explanation is not None:
                return explanation
        if witness in _resolve(expr.right, universe, id_to_groups):
            return explain_membership(expr.right, witness, universe, id_to_groups)
        return None
    return None  # Negation: no single positive fact explains it cleanly


def _shadowing_message(
    sink_key: str,
    earlier: SinkRule,
    later: SinkRule,
    earlier_expr: IdentityPredicate,
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
    explanation = explain_membership(earlier_expr, witness, universe, id_to_groups)
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
    positions in a pair, so every reported case stays provable rather than
    heuristic.

    Args:
        sink_key: The dotted sink name, for the problem message.
        rules: The sink's ordered rule list.
        whens: Each rule's effective `when` text (`rule_when(rule)`), `None`
            for the catch-all; must be the same length as `rules`.
        declared_ids: Every agent id declared in the policy's `agents` section.
        id_to_groups: The declared agent-id-to-groups mapping.

    Returns:
        One problem string per rule proven unreachable this way.
    """
    recognized = [
        recognize_identity_when(when) if when is not None else None for when in whens
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
