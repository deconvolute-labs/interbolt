from __future__ import annotations

from interbolt.models.core import Action
from interbolt.policy import Policy
from interbolt.policy.compile import compile_policy, parse_normalized
from interbolt.policy.explain import (
    RuleOutcome,
    explain_for_agent,
    explain_for_group,
    explain_for_tool,
)
from interbolt.policy.partial_eval import (
    Residual,
    partial_eval,
    resolve_leaf_for_agent,
    resolve_leaf_for_group,
)
from interbolt.policy.schema import AgentDeclaration, Defaults, PolicyDocument, SinkRule


def _simple_policy(
    sinks: dict[str, list[dict[str, str]]] | None = None,
    agents: dict[str, list[str]] | None = None,
    sink_action: Action = Action.BLOCK,
) -> Policy:
    raw_sinks: dict[str, tuple[SinkRule, ...]] = {}
    if sinks:
        for key, rules in sinks.items():
            raw_sinks[key] = tuple(
                SinkRule(name=r["name"], when=r.get("when"), action=Action(r["action"]))
                for r in rules
            )
    raw_agents: dict[str, AgentDeclaration] = {}
    if agents:
        raw_agents = {
            agent_id: AgentDeclaration(groups=tuple(groups))
            for agent_id, groups in agents.items()
        }
    document = PolicyDocument(
        version="1.0",
        defaults=Defaults(sink_action=sink_action),
        sources=(),
        agents=raw_agents,
        sinks=raw_sinks,
    )
    return Policy(document=document, compiled_sinks=compile_policy(document))


class TestPartialEval:
    def test_and_short_circuits_on_false(self) -> None:
        when = 'agent.id == "x" && taint.any(t, t.trust == "untrusted")'
        tree = parse_normalized(when)
        result = partial_eval(tree, when, resolve_leaf_for_agent("y", frozenset()))
        assert result is False

    def test_or_short_circuits_on_true(self) -> None:
        when = 'agent.id == "x" || taint.any(t, t.trust == "untrusted")'
        tree = parse_normalized(when)
        result = partial_eval(tree, when, resolve_leaf_for_agent("x", frozenset()))
        assert result is True

    def test_negation_of_resolved_leaf_flips(self) -> None:
        when = '!(agent.id == "x")'
        tree = parse_normalized(when)
        result = partial_eval(tree, when, resolve_leaf_for_agent("x", frozenset()))
        assert result is False

    def test_negation_of_residual_wraps_text(self) -> None:
        when = '!(taint.any(t, t.trust == "untrusted"))'
        tree = parse_normalized(when)
        result = partial_eval(tree, when, resolve_leaf_for_agent("x", frozenset()))
        assert isinstance(result, Residual)
        assert result.text == '!(taint.any(t, t.trust == "untrusted"))'
        assert result.member_dependent is False

    def test_residual_text_is_exact_source_substring(self) -> None:
        when = 'taint.any(t, t.trust == "untrusted")'
        tree = parse_normalized(when)
        result = partial_eval(tree, when, resolve_leaf_for_agent("x", frozenset()))
        assert isinstance(result, Residual)
        assert result.text == when

    def test_depends_on_member_always_false_under_agent_mode(self) -> None:
        when = (
            'agent.groups.exists(g, g == "payer") '
            '&& taint.any(t, t.trust == "untrusted")'
        )
        tree = parse_normalized(when)
        result = partial_eval(
            tree, when, resolve_leaf_for_agent("x", frozenset({"payer"}))
        )
        assert isinstance(result, Residual)
        assert result.member_dependent is False

    def test_group_mode_unbound_id_is_member_dependent(self) -> None:
        when = 'agent.id == "billing-agent"'
        tree = parse_normalized(when)
        result = partial_eval(tree, when, resolve_leaf_for_group("payer"))
        assert isinstance(result, Residual)
        assert result.member_dependent is True

    def test_group_mode_mixed_residual_not_member_dependent(self) -> None:
        when = 'agent.id == "billing-agent" && taint.any(t, t.trust == "untrusted")'
        tree = parse_normalized(when)
        result = partial_eval(tree, when, resolve_leaf_for_group("payer"))
        assert isinstance(result, Residual)
        assert result.member_dependent is False


class TestExplainForAgent:
    def test_rule_eliminated_when_identity_conjunct_false(self) -> None:
        policy = _simple_policy(
            sinks={
                "default.tool": [
                    {
                        "name": "other_agent_gate",
                        "when": (
                            'agent.id == "other-agent" '
                            '&& taint.any(t, t.trust == "untrusted")'
                        ),
                        "action": "block",
                    }
                ]
            }
        )
        explanation = explain_for_agent(policy, "billing-agent")
        rule = explanation.sinks[0].rules[0]
        assert rule.outcome is RuleOutcome.ELIMINATED

    def test_rule_with_no_identity_reference_reported_conditional_unchanged(
        self,
    ) -> None:
        when = 'taint.any(t, t.trust == "untrusted")'
        policy = _simple_policy(
            sinks={
                "default.tool": [
                    {"name": "taint_gate", "when": when, "action": "block"}
                ]
            }
        )
        rule = explain_for_agent(policy, "billing-agent").sinks[0].rules[0]
        assert rule.outcome is RuleOutcome.CONDITIONAL
        assert rule.residual == when
        assert rule.depends_on_member is False

    def test_identity_only_rule_unconditional_and_shadows_rest(self) -> None:
        policy = _simple_policy(
            sinks={
                "default.tool": [
                    {
                        "name": "id_rule",
                        "when": 'agent.id == "billing-agent"',
                        "action": "allow",
                    },
                    {
                        "name": "taint_gate",
                        "when": 'taint.any(t, t.trust == "untrusted")',
                        "action": "block",
                    },
                ]
            }
        )
        rules = explain_for_agent(policy, "billing-agent").sinks[0].rules
        assert rules[0].outcome is RuleOutcome.UNCONDITIONAL
        assert rules[1].outcome is RuleOutcome.ELIMINATED
        assert rules[1].shadowed_by == "id_rule"

    def test_identity_in_disjunction_reported_conditional_not_eliminated(self) -> None:
        when = 'agent.id == "other-agent" || taint.any(t, t.trust == "untrusted")'
        policy = _simple_policy(
            sinks={
                "default.tool": [
                    {"name": "mixed_rule", "when": when, "action": "block"}
                ]
            }
        )
        rule = explain_for_agent(policy, "billing-agent").sinks[0].rules[0]
        assert rule.outcome is RuleOutcome.CONDITIONAL
        assert rule.residual == 'taint.any(t, t.trust == "untrusted")'

    def test_empty_sink_reports_default_action(self) -> None:
        policy = _simple_policy(
            sinks={"default.tool": []}, sink_action=Action.REQUIRE_APPROVAL
        )
        sink = explain_for_agent(policy, "billing-agent").sinks[0]
        assert sink.rules == ()
        assert sink.default_action is Action.REQUIRE_APPROVAL

    def test_group_scoped_rule_resolved_for_member_eliminated_for_non_member(
        self,
    ) -> None:
        policy = _simple_policy(
            sinks={
                "default.tool": [
                    {
                        "name": "payer_rule",
                        "when": 'agent.groups.exists(g, g == "payer")',
                        "action": "allow",
                    }
                ]
            },
            agents={"billing-agent": ["payer"], "support-agent": ["internal"]},
        )
        member_rule = explain_for_agent(policy, "billing-agent").sinks[0].rules[0]
        non_member_rule = explain_for_agent(policy, "support-agent").sinks[0].rules[0]
        assert member_rule.outcome is RuleOutcome.UNCONDITIONAL
        assert non_member_rule.outcome is RuleOutcome.ELIMINATED

    def test_undeclared_agent_resolves_empty_groups_and_answers(self) -> None:
        policy = _simple_policy(
            sinks={
                "default.tool": [
                    {
                        "name": "payer_rule",
                        "when": 'agent.groups.exists(g, g == "payer")',
                        "action": "allow",
                    }
                ]
            }
        )
        explanation = explain_for_agent(policy, "some-typo-agent")
        assert explanation.groups == frozenset()
        assert explanation.sinks[0].rules[0].outcome is RuleOutcome.ELIMINATED

    def test_rule_shadowed_by_group_rule_names_rule_and_group(self) -> None:
        policy = _simple_policy(
            sinks={
                "default.tool": [
                    {
                        "name": "payers_need_approval",
                        "when": 'agent.groups.exists(g, g == "payer")',
                        "action": "require_approval",
                    },
                    {
                        "name": "billing_agent_blocked",
                        "when": 'agent.id == "billing-agent"',
                        "action": "block",
                    },
                ]
            },
            agents={"billing-agent": ["payer"]},
        )
        rules = explain_for_agent(policy, "billing-agent").sinks[0].rules
        assert rules[1].outcome is RuleOutcome.ELIMINATED
        assert rules[1].shadowed_by == "payers_need_approval"
        assert rules[1].shadowed_by_reason is not None
        assert "payer" in rules[1].shadowed_by_reason

    def test_partial_shadowing_dead_for_one_agent_live_for_another(self) -> None:
        policy = _simple_policy(
            sinks={
                "default.tool": [
                    {
                        "name": "payers_need_approval",
                        "when": 'agent.groups.exists(g, g == "payer")',
                        "action": "require_approval",
                    },
                    {
                        "name": "billing_agent_blocked",
                        "when": 'agent.id == "billing-agent"',
                        "action": "block",
                    },
                ]
            },
            agents={"billing-agent": ["payer"]},
        )
        member_result = explain_for_agent(policy, "billing-agent").sinks[0].rules[1]
        # a non-member agent named directly in the id rule still fires normally,
        # since the group rule does not match it and does not shadow it
        non_member_result = explain_for_agent(policy, "someone-else").sinks[0].rules[1]
        assert member_result.outcome is RuleOutcome.ELIMINATED
        assert (
            non_member_result.outcome is RuleOutcome.ELIMINATED
        )  # id != "someone-else"

        # the real partial-shadowing case: a *different* member of the same
        # group, not named by the id rule at all, still gets shadowed
        policy2 = _simple_policy(
            sinks={
                "default.tool": [
                    {
                        "name": "payers_need_approval",
                        "when": 'agent.groups.exists(g, g == "payer")',
                        "action": "require_approval",
                    },
                    {
                        "name": "generic_block",
                        "when": 'taint.any(t, t.trust == "untrusted")',
                        "action": "block",
                    },
                ]
            },
            agents={"billing-agent": ["payer"], "support-agent": ["internal"]},
        )
        member_rules = explain_for_agent(policy2, "billing-agent").sinks[0].rules
        non_member_rules = explain_for_agent(policy2, "support-agent").sinks[0].rules
        assert member_rules[1].outcome is RuleOutcome.ELIMINATED
        assert non_member_rules[1].outcome is RuleOutcome.CONDITIONAL


class TestExplainForGroup:
    def test_group_query_binds_membership_without_binding_id(self) -> None:
        policy = _simple_policy(
            sinks={
                "default.tool": [
                    {
                        "name": "id_rule",
                        "when": 'agent.id == "billing-agent"',
                        "action": "allow",
                    },
                    {
                        "name": "bound_group_rule",
                        "when": 'agent.groups.exists(g, g == "payer")',
                        "action": "allow",
                    },
                    {
                        "name": "other_group_rule",
                        "when": 'agent.groups.exists(g, g == "internal")',
                        "action": "block",
                    },
                ]
            }
        )
        rules = explain_for_group(policy, "payer").sinks[0].rules
        assert rules[0].outcome is RuleOutcome.CONDITIONAL
        assert rules[0].depends_on_member is True
        assert rules[1].outcome is RuleOutcome.UNCONDITIONAL
        # bound_group_rule shadows other_group_rule (first-match-wins), so it
        # never even gets a chance to be evaluated on its own terms
        assert rules[2].outcome is RuleOutcome.ELIMINATED
        assert rules[2].shadowed_by == "bound_group_rule"


class TestExplainForTool:
    def test_unknown_sink_returns_none(self) -> None:
        policy = _simple_policy()
        assert explain_for_tool(policy, "nope.nope") is None

    def test_catch_all_rule_mentions_nothing(self) -> None:
        policy = _simple_policy(
            sinks={"default.tool": [{"name": "catch_all", "action": "allow"}]}
        )
        mention = explain_for_tool(policy, "default.tool").mentions[0]  # type: ignore[union-attr]
        assert mention.agent_ids == frozenset()
        assert mention.groups == frozenset()
        assert mention.when is None

    def test_collects_ids_and_groups_across_disjunction_and_conjunction(self) -> None:
        when = (
            'agent.id == "billing-agent" || '
            '(agent.groups.exists(g, g == "payer") && agent.id != "support-agent")'
        )
        policy = _simple_policy(
            sinks={"default.tool": [{"name": "mixed", "when": when, "action": "block"}]}
        )
        mention = explain_for_tool(policy, "default.tool").mentions[0]  # type: ignore[union-attr]
        assert mention.agent_ids == {"billing-agent", "support-agent"}
        assert mention.groups == {"payer"}

    def test_zero_arg_dotted_call_does_not_crash(self) -> None:
        when = 'agent.groups.size() && agent.groups.exists(g, g == "payer")'
        policy = _simple_policy(
            sinks={"default.tool": [{"name": "mixed", "when": when, "action": "block"}]}
        )
        mention = explain_for_tool(policy, "default.tool").mentions[0]  # type: ignore[union-attr]
        assert mention.groups == {"payer"}
