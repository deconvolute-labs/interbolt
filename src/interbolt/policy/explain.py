"""Static per-agent, per-group, and per-tool policy explanation.

Binds a concrete agent identity, a bare group, or neither (a per-tool scan)
and reports which sink rules can still fire, reusing `policy.identity_ast`'s
identity-predicate recognizer so an identity shape is never re-derived.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from interbolt.models.core import Action
from interbolt.policy.cel import parse_normalized
from interbolt.policy.evaluate import resolve_agent_groups
from interbolt.policy.identity_ast import (
    GroupMembership,
    IdEquals,
    IdNotEquals,
    recognize_comparison,
    recognize_groups_exists,
    recognize_identity_when,
)
from interbolt.policy.partial_eval import (
    partial_eval,
    resolve_leaf_for_agent,
    resolve_leaf_for_group,
)
from interbolt.policy.schema import SinkRule, rule_when
from interbolt.policy.shadowing import explain_membership

if TYPE_CHECKING:
    from interbolt.policy import Policy


class RuleOutcome(StrEnum):
    """One rule's reachability outcome for a queried agent, group, or tool."""

    ELIMINATED = "eliminated"
    UNCONDITIONAL = "unconditional"
    CONDITIONAL = "conditional"


@dataclass(frozen=True)
class RuleExplanation:
    """One sink rule's reachability outcome under one identity binding.

    Attributes:
        name: The rule's declared name.
        action: The rule's action.
        outcome: Whether the rule is eliminated, unconditional, or conditional.
        residual: The remaining CEL condition text, set only when `outcome`
            is `CONDITIONAL`.
        depends_on_member: True when `residual` is conditional only because
            the query left `agent.id` unbound (a `--group` query); always
            False under a full `--agent` binding.
        shadowed_by: The name of the earlier, unconditional rule in the same
            sink that makes this rule unreachable, set only when `outcome`
            is `ELIMINATED` for this reason.
        shadowed_by_reason: A human-readable membership fact explaining why
            the shadowing rule matches (for example, group membership), when
            one can be named cleanly; `None` when no single fact explains it.
    """

    name: str
    action: Action
    outcome: RuleOutcome
    residual: str | None = None
    depends_on_member: bool = False
    shadowed_by: str | None = None
    shadowed_by_reason: str | None = None


@dataclass(frozen=True)
class SinkExplanation:
    """One sink's rules, explained for one query, in declaration order."""

    sink_key: str
    rules: tuple[RuleExplanation, ...]
    default_action: Action


@dataclass(frozen=True)
class AgentExplanation:
    """The result of `explain_for_agent`: resolved groups plus every sink."""

    agent_id: str
    groups: frozenset[str]
    sinks: tuple[SinkExplanation, ...]


@dataclass(frozen=True)
class GroupExplanation:
    """The result of `explain_for_group`: every sink with `agent.id` unbound."""

    group: str
    sinks: tuple[SinkExplanation, ...]


@dataclass(frozen=True)
class ToolMention:
    """One rule's literal agent/group mentions, for `explain_for_tool`."""

    name: str
    action: Action
    agent_ids: frozenset[str]
    groups: frozenset[str]
    when: str | None


@dataclass(frozen=True)
class ToolExplanation:
    """The result of `explain_for_tool`: every rule's literal mentions."""

    sink_key: str
    mentions: tuple[ToolMention, ...]
    default_action: Action


_ShadowReason = Callable[[str], "str | None"]


def _no_shadow_reason(_when: str) -> str | None:
    return None


def _shadow_reason_for_agent(
    agent_id: str, id_to_groups: Mapping[str, frozenset[str]]
) -> _ShadowReason:
    def _reason(when_text: str) -> str | None:
        recognized = recognize_identity_when(when_text)
        if recognized is None:
            return None
        return explain_membership(
            recognized, agent_id, frozenset({agent_id}), id_to_groups
        )

    return _reason


def _explain_sink(
    sink_key: str,
    rules: Sequence[SinkRule],
    default_action: Action,
    resolve_leaf: Callable[[IdEquals | IdNotEquals | GroupMembership], bool | None],
    shadow_reason: _ShadowReason,
) -> SinkExplanation:
    explanations: list[RuleExplanation] = []
    shadowed_by: str | None = None
    shadowed_by_reason: str | None = None
    for rule in rules:
        if shadowed_by is not None:
            explanations.append(
                RuleExplanation(
                    name=rule.name,
                    action=rule.action,
                    outcome=RuleOutcome.ELIMINATED,
                    shadowed_by=shadowed_by,
                    shadowed_by_reason=shadowed_by_reason,
                )
            )
            continue

        when_text = rule_when(rule)
        if when_text is None:
            explanations.append(
                RuleExplanation(rule.name, rule.action, RuleOutcome.UNCONDITIONAL)
            )
            shadowed_by, shadowed_by_reason = rule.name, None
            continue

        tree = parse_normalized(when_text)
        result = partial_eval(tree, when_text, resolve_leaf)
        if result is False:
            explanations.append(
                RuleExplanation(rule.name, rule.action, RuleOutcome.ELIMINATED)
            )
        elif result is True:
            explanations.append(
                RuleExplanation(rule.name, rule.action, RuleOutcome.UNCONDITIONAL)
            )
            shadowed_by = rule.name
            shadowed_by_reason = shadow_reason(when_text)
        else:
            explanations.append(
                RuleExplanation(
                    rule.name,
                    rule.action,
                    RuleOutcome.CONDITIONAL,
                    residual=result.text,
                    depends_on_member=result.member_dependent,
                )
            )
    return SinkExplanation(
        sink_key=sink_key, rules=tuple(explanations), default_action=default_action
    )


def explain_for_agent(policy: Policy, agent_id: str) -> AgentExplanation:
    """Explain every sink's rules for one bound agent identity.

    Binds both `agent.id` (from `agent_id`) and `agent.groups` (resolved
    from the policy's declared membership table); an agent id absent from
    `agents:` resolves to the empty group set rather than erroring.

    Args:
        policy: The loaded, compiled policy.
        agent_id: The agent identity to bind.

    Returns:
        The agent's resolved groups and one `SinkExplanation` per declared
        sink, in policy document order.
    """
    groups = resolve_agent_groups(agent_id, policy.id_to_groups)
    resolve_leaf = resolve_leaf_for_agent(agent_id, groups)
    shadow_reason = _shadow_reason_for_agent(agent_id, policy.id_to_groups)
    sinks = tuple(
        _explain_sink(
            sink_key,
            rules,
            policy.document.defaults.sink_action,
            resolve_leaf,
            shadow_reason,
        )
        for sink_key, rules in policy.document.sinks.items()
    )
    return AgentExplanation(agent_id=agent_id, groups=groups, sinks=sinks)


def explain_for_group(policy: Policy, group: str) -> GroupExplanation:
    """Explain every sink's rules with `agent.groups` bound to one group.

    `agent.id` stays unbound: a rule keyed on a specific id is reported
    conditional with `depends_on_member=True` rather than resolved either
    way, since membership alone does not determine which member is acting.

    Args:
        policy: The loaded, compiled policy.
        group: The group to bind.

    Returns:
        One `SinkExplanation` per declared sink, in policy document order.
    """
    resolve_leaf = resolve_leaf_for_group(group)
    sinks = tuple(
        _explain_sink(
            sink_key,
            rules,
            policy.document.defaults.sink_action,
            resolve_leaf,
            _no_shadow_reason,
        )
        for sink_key, rules in policy.document.sinks.items()
    )
    return GroupExplanation(group=group, sinks=sinks)


def _mentions_in_when(when_text: str) -> tuple[frozenset[str], frozenset[str]]:
    tree = parse_normalized(when_text)
    agent_ids: set[str] = set()
    groups: set[str] = set()
    for subtree in tree.iter_subtrees():
        if subtree.data == "relation" and len(subtree.children) == 2:
            comparison = recognize_comparison(subtree.children[0], subtree.children[1])
            if isinstance(comparison, (IdEquals, IdNotEquals)):
                agent_ids.add(comparison.literal)
        elif subtree.data == "member_dot_arg":
            membership = recognize_groups_exists(subtree)
            if isinstance(membership, GroupMembership):
                groups.add(membership.group)
    return frozenset(agent_ids), frozenset(groups)


def explain_for_tool(policy: Policy, sink_key: str) -> ToolExplanation | None:
    """List every agent id and group literally mentioned in one sink's rules.

    A simpler scan than `explain_for_agent`/`explain_for_group`: it collects
    every recognized `agent.id`/`agent.groups` literal anywhere in each
    rule's `when`, regardless of how it combines with other conditions, and
    does not attempt reachability analysis.

    Args:
        policy: The loaded, compiled policy.
        sink_key: The dotted `namespace.tool` sink key to look up.

    Returns:
        The sink's mentions, or `None` if `sink_key` names no declared sink.
    """
    rules = policy.document.sinks.get(sink_key)
    if rules is None:
        return None
    mentions: list[ToolMention] = []
    for rule in rules:
        when_text = rule_when(rule)
        if when_text is None:
            mentions.append(
                ToolMention(rule.name, rule.action, frozenset(), frozenset(), None)
            )
            continue
        agent_ids, groups = _mentions_in_when(when_text)
        mentions.append(
            ToolMention(rule.name, rule.action, agent_ids, groups, when_text)
        )
    return ToolExplanation(
        sink_key=sink_key,
        mentions=tuple(mentions),
        default_action=policy.document.defaults.sink_action,
    )
