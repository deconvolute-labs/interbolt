from __future__ import annotations

import lark
import pytest

from interbolt.models.core import Action, Label, TrustLevel
from interbolt.policy.compile import (
    _ENV,
    CompiledRule,
    CompiledSink,
    _rewrite_any_to_exists,
    compile_cel_expression,
    compile_policy,
)
from interbolt.policy.evaluate import (
    build_context,
    evaluate_sink,
    resolve_label_trust,
    resolve_labels,
)
from interbolt.policy.schema import (
    AgentDeclaration,
    Defaults,
    PolicyDocument,
    SinkRule,
)
from interbolt.taint import _fresh_label


def _label(source: str = "src", lineage: tuple[str, ...] | None = None) -> Label:
    lbl = _fresh_label(source)
    if lineage is not None:
        return Label(source=source, value_id=lbl.value_id, lineage=lineage)
    return lbl


def _simple_doc(
    sinks: dict[str, list[dict[str, str]]] | None = None,
    agents: dict[str, list[str]] | None = None,
) -> PolicyDocument:
    raw_sinks: dict[str, tuple[SinkRule, ...]] = {}
    if sinks:
        for key, rules in sinks.items():
            raw_sinks[key] = tuple(
                SinkRule(
                    name=r["name"],
                    when=r.get("when"),
                    action=Action(r["action"]),
                )
                for r in rules
            )
    raw_agents: dict[str, AgentDeclaration] = {}
    if agents:
        raw_agents = {
            agent_id: AgentDeclaration(groups=tuple(groups))
            for agent_id, groups in agents.items()
        }
    return PolicyDocument(
        version="1.0",
        defaults=Defaults(sink_action=Action.ALLOW),
        sources=(),
        agents=raw_agents,
        sinks=raw_sinks,
    )


class TestRewriteAnyToExists:
    def _method_tokens(self, tree: lark.Tree[lark.Token]) -> list[str]:
        tokens: list[str] = []
        for t in tree.iter_subtrees():
            if t.data != "member_dot_arg":
                continue
            method_token = t.children[1]
            assert isinstance(method_token, lark.Token)
            tokens.append(method_token.value)
        return tokens

    def test_replaces_any_with_exists(self) -> None:
        tree = _ENV.compile("taint.any(t, true)")
        _rewrite_any_to_exists(tree)
        assert self._method_tokens(tree) == ["exists"]

    def test_no_any_unchanged(self) -> None:
        tree = _ENV.compile('args.x == "y"')
        before = tree.pretty()
        _rewrite_any_to_exists(tree)
        assert tree.pretty() == before

    def test_multiple_occurrences_all_replaced(self) -> None:
        tree = _ENV.compile("taint.any(t, t.trust == 'x') && taint.any(t, true)")
        _rewrite_any_to_exists(tree)
        assert self._method_tokens(tree) == ["exists", "exists"]

    def test_any_inside_literal_only_is_untouched(self) -> None:
        tree = _ENV.compile('args.path.contains("backup.any(x)")')
        before = tree.pretty()
        _rewrite_any_to_exists(tree)
        assert tree.pretty() == before


class TestAnyRewriteLiteralPreservation:
    def _eval(
        self,
        expr: str,
        path: str,
        labels: tuple[Label, ...] = (),
        sources_table: dict[str, TrustLevel] | None = None,
    ) -> bool:
        runner = compile_cel_expression(expr)
        ctx = build_context(
            tool="t",
            args={"path": path},
            resolved_labels=resolve_labels(labels, sources_table or {}),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        return bool(runner.evaluate(ctx))

    def test_double_quoted_literal_preserved_and_real_call_rewritten(self) -> None:
        expr = (
            'args.path.contains("backup.any(x)") || '
            'taint.any(t, t.trust == "untrusted")'
        )
        assert self._eval(expr, "prefix backup.any(x) suffix") is True
        assert (
            self._eval(
                expr,
                "no match here",
                labels=(_label("web"),),
                sources_table={"web": TrustLevel.UNTRUSTED},
            )
            is True
        )
        assert self._eval(expr, "no match") is False

    def test_single_quoted_literal_with_any_preserved(self) -> None:
        expr = "args.path.contains('backup.any(x)')"
        assert self._eval(expr, "has backup.any(x) inside") is True
        assert self._eval(expr, "nothing here") is False

    def test_escaped_quote_inside_literal_preserved(self) -> None:
        expr = r'args.path.contains("backup.any(\"x\")")'
        assert self._eval(expr, 'has backup.any("x") inside') is True

    def test_raw_string_literal_with_any_preserved(self) -> None:
        expr = r'args.path.contains(r"backup.any(\d)")'
        assert self._eval(expr, "backup.any(\\d)") is True

    def test_end_to_end_policy_rule_matches_literal_substring(self) -> None:
        doc = _simple_doc(
            sinks={
                "default.tool": [
                    {
                        "name": "r",
                        "when": 'args.path.contains("backup.any(")',
                        "action": "block",
                    },
                    {"name": "default", "action": "allow"},
                ]
            }
        )
        compiled = compile_policy(doc)
        ctx_match = build_context(
            tool="default.tool",
            args={"path": "a backup.any( file"},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        _, action, _ = evaluate_sink(
            compiled["default.tool"], ctx_match, default_action=Action.ALLOW
        )
        assert action is Action.BLOCK

        ctx_no_match = build_context(
            tool="default.tool",
            args={"path": "clean"},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        _, action2, _ = evaluate_sink(
            compiled["default.tool"], ctx_no_match, default_action=Action.ALLOW
        )
        assert action2 is Action.ALLOW


class TestCompileCelExpression:
    def test_valid_expression_returns_runner(self) -> None:
        runner = compile_cel_expression("true")
        assert runner is not None

    def test_invalid_expression_raises(self) -> None:
        with pytest.raises(Exception):  # noqa: B017
            compile_cel_expression("%%% totally invalid")


class TestCompilePolicy:
    def test_produces_compiled_sinks(self) -> None:
        doc = _simple_doc(
            sinks={"default.tool": [{"name": "allow_all", "action": "allow"}]}
        )
        compiled = compile_policy(doc)
        assert "default.tool" in compiled
        assert isinstance(compiled["default.tool"], CompiledSink)

    def test_empty_sinks_produces_empty_dict(self) -> None:
        doc = _simple_doc()
        compiled = compile_policy(doc)
        assert compiled == {}

    def test_catch_all_rule_has_none_program(self) -> None:
        doc = _simple_doc(
            sinks={"default.tool": [{"name": "default", "action": "allow"}]}
        )
        compiled = compile_policy(doc)
        rule = compiled["default.tool"].rules[0]
        assert rule.program is None

    def test_conditional_rule_has_program(self) -> None:
        doc = _simple_doc(
            sinks={"default.tool": [{"name": "r", "when": "true", "action": "allow"}]}
        )
        compiled = compile_policy(doc)
        rule = compiled["default.tool"].rules[0]
        assert rule.program is not None

    def test_conditional_rule_retains_original_when_text(self) -> None:
        doc = _simple_doc(
            sinks={
                "default.tool": [
                    {"name": "r", "when": "args.x == 'y'", "action": "allow"}
                ]
            }
        )
        compiled = compile_policy(doc)
        rule = compiled["default.tool"].rules[0]
        assert rule.when == "args.x == 'y'"

    def test_catch_all_rule_has_none_when(self) -> None:
        doc = _simple_doc(
            sinks={"default.tool": [{"name": "default", "action": "allow"}]}
        )
        compiled = compile_policy(doc)
        rule = compiled["default.tool"].rules[0]
        assert rule.when is None


class TestResolveLabelTrust:
    def test_all_trusted_returns_trusted(self) -> None:
        lbl = _label("t1", lineage=("t1", "t2"))
        table = {"t1": TrustLevel.TRUSTED, "t2": TrustLevel.TRUSTED}
        assert resolve_label_trust(lbl, table) is TrustLevel.TRUSTED

    def test_any_untrusted_returns_untrusted(self) -> None:
        lbl = _label("t1", lineage=("trusted_src", "untrusted_src"))
        table = {
            "trusted_src": TrustLevel.TRUSTED,
            "untrusted_src": TrustLevel.UNTRUSTED,
        }
        assert resolve_label_trust(lbl, table) is TrustLevel.UNTRUSTED

    def test_unknown_source_defaults_to_untrusted(self) -> None:
        lbl = _label("unknown")
        assert resolve_label_trust(lbl, {}) is TrustLevel.UNTRUSTED

    def test_empty_lineage_returns_trusted(self) -> None:
        # No sources in lineage -> the loop never marks anything
        # untrusted -> returns TRUSTED.
        lbl = Label(source="s", value_id="x", lineage=())
        assert resolve_label_trust(lbl, {}) is TrustLevel.TRUSTED


class TestBuildContext:
    def _labels_for(self, sources: list[str]) -> tuple[Label, ...]:
        return tuple(_label(s) for s in sources)

    def test_returns_all_required_keys(self) -> None:
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        for key in (
            "tool",
            "args",
            "taint",
            "sources",
            "max_trust",
            "trifecta",
            "run",
            "agent",
        ):
            assert key in ctx

    def test_agent_map_contains_id(self) -> None:
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="billing-agent",
            groups=frozenset(),
        )
        assert str(ctx["agent"]["id"]) == "billing-agent"

    def test_agent_map_has_id_and_groups(self) -> None:
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        assert set(ctx["agent"].keys()) == {"id", "groups"}

    def test_agent_map_groups_renders_as_cel_list(self) -> None:
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="billing-agent",
            groups=frozenset({"payer", "internal"}),
        )
        groups = sorted(str(g) for g in ctx["agent"]["groups"])
        assert groups == ["internal", "payer"]

    def test_max_trust_untrusted_when_any_untrusted(self) -> None:
        labels = self._labels_for(["web"])
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=resolve_labels(labels, {"web": TrustLevel.UNTRUSTED}),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        assert str(ctx["max_trust"]) == "untrusted"

    def test_max_trust_trusted_when_all_trusted(self) -> None:
        labels = self._labels_for(["kb"])
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=resolve_labels(labels, {"kb": TrustLevel.TRUSTED}),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        assert str(ctx["max_trust"]) == "trusted"

    def test_max_trust_trusted_with_no_labels(self) -> None:
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        assert str(ctx["max_trust"]) == "trusted"

    def test_sources_list_deduplicates_shared_lineage(self) -> None:
        lbl1 = Label(source="a", value_id="x1", lineage=("a", "shared"))
        lbl2 = Label(source="b", value_id="x2", lineage=("b", "shared"))
        ctx = build_context(
            tool="t",
            args={},
            resolved_labels=resolve_labels((lbl1, lbl2), {}),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        sources = [str(s) for s in ctx["sources"]]
        assert sources.count("shared") == 1

    def test_per_label_map_contains_lineage(self) -> None:
        merged = Label(source="a", value_id="x1", lineage=("a", "b"))
        ctx = build_context(
            tool="t",
            args={},
            resolved_labels=resolve_labels((merged,), {}),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        taint_list = ctx["taint"]
        lineage = [str(s) for s in taint_list[0]["lineage"]]
        assert lineage == ["a", "b"]

    def test_per_label_map_contains_ingested_by(self) -> None:
        lbl = Label(
            source="a",
            value_id="x1",
            lineage=("a",),
            ingested_by=("agent_a", "agent_b"),
        )
        ctx = build_context(
            tool="t",
            args={},
            resolved_labels=resolve_labels((lbl,), {}),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        ingested_by = [str(s) for s in ctx["taint"][0]["ingested_by"]]
        assert ingested_by == ["agent_a", "agent_b"]

    def test_per_label_map_contains_endorsements(self) -> None:
        lbl = Label(
            source="a", value_id="x1", lineage=("a",), endorsements=("k1", "k2")
        )
        ctx = build_context(
            tool="t",
            args={},
            resolved_labels=resolve_labels((lbl,), {}),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        endorsements = [str(s) for s in ctx["taint"][0]["endorsements"]]
        assert endorsements == ["k1", "k2"]


class TestLineageVsSourceAfterMerge:
    """A merged label's `source` is only its first contributor; `t.lineage`
    is the honest way to check every contributing source after a merge."""

    def test_lineage_exists_fires_where_source_equality_would_not(self) -> None:
        # Simulates `kb_value + " " + web_value`: source is the first
        # contributor ("internal_kb"), but lineage carries both.
        merged = Label(
            source="internal_kb", value_id="m1", lineage=("internal_kb", "web_search")
        )
        sources_table = {
            "internal_kb": TrustLevel.TRUSTED,
            "web_search": TrustLevel.UNTRUSTED,
        }

        lineage_expr = compile_cel_expression(
            'taint.any(t, t.lineage.exists(s, s == "web_search"))'
        )
        source_expr = compile_cel_expression('taint.any(t, t.source == "web_search")')
        ctx = build_context(
            tool="t",
            args={},
            resolved_labels=resolve_labels((merged,), sources_table),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        assert bool(lineage_expr.evaluate(ctx)) is True
        assert bool(source_expr.evaluate(ctx)) is False


class TestRequireEndorsementSugar:
    def test_compiles_to_kind_matching_when_text(self) -> None:
        doc = PolicyDocument(
            version="1.0",
            defaults=Defaults(sink_action=Action.ALLOW),
            sources=(),
            sinks={
                "default.tool": (
                    SinkRule(
                        name="r",
                        require_endorsement="recipient_allowlisted",
                        action=Action.BLOCK,
                    ),
                )
            },
        )
        compiled = compile_policy(doc)
        rule = compiled["default.tool"].rules[0]
        assert rule.when is not None
        assert "recipient_allowlisted" in rule.when
        assert rule.program is not None

    def test_endorsed_with_required_kind_does_not_match(self) -> None:
        doc = PolicyDocument(
            version="1.0",
            defaults=Defaults(sink_action=Action.ALLOW),
            sources=(),
            sinks={
                "default.tool": (
                    SinkRule(
                        name="require_allowlist",
                        require_endorsement="recipient_allowlisted",
                        action=Action.BLOCK,
                    ),
                    SinkRule(name="default", action=Action.ALLOW),
                )
            },
        )
        compiled = compile_policy(doc)
        lbl = Label(
            source="web_search",
            value_id="v1",
            lineage=("web_search",),
            endorsements=("recipient_allowlisted",),
        )
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=resolve_labels((lbl,), {}),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        _, action, _ = evaluate_sink(
            compiled["default.tool"], ctx, default_action=Action.ALLOW
        )
        assert action is Action.ALLOW

    def test_endorsed_with_wrong_kind_still_matches(self) -> None:
        # Sanitizer-mismatch: endorsed for a different kind than the sink
        # requires must still be gated.
        doc = PolicyDocument(
            version="1.0",
            defaults=Defaults(sink_action=Action.ALLOW),
            sources=(),
            sinks={
                "default.tool": (
                    SinkRule(
                        name="require_allowlist",
                        require_endorsement="recipient_allowlisted",
                        action=Action.BLOCK,
                    ),
                    SinkRule(name="default", action=Action.ALLOW),
                )
            },
        )
        compiled = compile_policy(doc)
        lbl = Label(
            source="web_search",
            value_id="v1",
            lineage=("web_search",),
            endorsements=("url_sanitized",),
        )
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=resolve_labels((lbl,), {}),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )
        _, action, _ = evaluate_sink(
            compiled["default.tool"], ctx, default_action=Action.ALLOW
        )
        assert action is Action.BLOCK


class TestAgentIdInCel:
    """`agent.id` is a top-level CEL map field, mirroring `run.tainted`."""

    def test_agent_id_matches_in_rule(self) -> None:
        doc = _simple_doc(
            sinks={
                "default.tool": [
                    {
                        "name": "r",
                        "when": 'agent.id == "billing-agent"',
                        "action": "block",
                    },
                    {"name": "default", "action": "allow"},
                ]
            }
        )
        compiled = compile_policy(doc)
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="billing-agent",
            groups=frozenset(),
        )
        _, action, _ = evaluate_sink(
            compiled["default.tool"], ctx, default_action=Action.ALLOW
        )
        assert action is Action.BLOCK

    def test_agent_id_does_not_match_different_agent(self) -> None:
        doc = _simple_doc(
            sinks={
                "default.tool": [
                    {
                        "name": "r",
                        "when": 'agent.id == "billing-agent"',
                        "action": "block",
                    },
                    {"name": "default", "action": "allow"},
                ]
            }
        )
        compiled = compile_policy(doc)
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="support-agent",
            groups=frozenset(),
        )
        _, action, _ = evaluate_sink(
            compiled["default.tool"], ctx, default_action=Action.ALLOW
        )
        assert action is Action.ALLOW

    def test_vacuous_taint_all_true_on_zero_labels(self) -> None:
        # Documents CEL's empty-list fold explicitly: `taint.all` folds to
        # `true` on an empty list, so pairing it with an identity check in an
        # allow rule is vacuously satisfied by any unlabeled/laundered call.
        # This is the exact hazard `validate_policy`'s new warning lint flags.
        expr = compile_cel_expression(
            'taint.all(t, t.trust == "trusted") && agent.id == "x"'
        )
        ctx = build_context(
            tool="t",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="x",
            groups=frozenset(),
        )
        assert bool(expr.evaluate(ctx)) is True


class TestIngestedByInCel:
    """`t.ingested_by` answers "which agent's ingress is upstream of this
    call," independent of `agent.id`, which answers "who is calling now."
    """

    def _doc(self) -> PolicyDocument:
        return _simple_doc(
            sinks={
                "default.tool": [
                    {
                        "name": "r",
                        "when": (
                            'taint.any(t, t.ingested_by.exists(a, a == "researcher"))'
                        ),
                        "action": "block",
                    },
                    {"name": "default", "action": "allow"},
                ]
            }
        )

    def test_matches_value_ingested_by_named_agent_regardless_of_caller(self) -> None:
        # Headline scenario: agent A (researcher) ingests the data, agent B
        # (support-agent) is the one calling the sink. The rule fires on
        # ingested_by, not on agent.id.
        compiled = compile_policy(self._doc())
        lbl = Label(
            source="web_search",
            value_id="v1",
            lineage=("web_search",),
            ingested_by=("researcher",),
        )
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=resolve_labels((lbl,), {}),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="support-agent",
            groups=frozenset(),
        )
        _, action, _ = evaluate_sink(
            compiled["default.tool"], ctx, default_action=Action.ALLOW
        )
        assert action is Action.BLOCK

    def test_does_not_match_value_ingested_elsewhere(self) -> None:
        compiled = compile_policy(self._doc())
        lbl = Label(
            source="web_search",
            value_id="v1",
            lineage=("web_search",),
            ingested_by=("planner",),
        )
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=resolve_labels((lbl,), {}),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="support-agent",
            groups=frozenset(),
        )
        _, action, _ = evaluate_sink(
            compiled["default.tool"], ctx, default_action=Action.ALLOW
        )
        assert action is Action.ALLOW


class TestAgentGroupsInCel:
    """`agent.groups` is a CEL list nested inside the `agent` map, resolved
    from the policy's optional `agents` section via `Policy.id_to_groups`.
    """

    def _group_gated_doc(self) -> PolicyDocument:
        return _simple_doc(
            sinks={
                "default.tool": [
                    {
                        "name": "r",
                        "when": 'agent.groups.exists(g, g == "payer")',
                        "action": "block",
                    },
                    {"name": "default", "action": "allow"},
                ]
            },
            agents={"billing-agent": ["payer", "internal"]},
        )

    def test_declared_group_matches_in_rule(self) -> None:
        compiled = compile_policy(self._group_gated_doc())
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="billing-agent",
            groups=frozenset({"payer", "internal"}),
        )
        _, action, _ = evaluate_sink(
            compiled["default.tool"], ctx, default_action=Action.ALLOW
        )
        assert action is Action.BLOCK

    def test_undeclared_agent_resolves_empty_and_does_not_match(self) -> None:
        compiled = compile_policy(self._group_gated_doc())
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="unknown-agent",
            groups=frozenset(),
        )
        _, action, _ = evaluate_sink(
            compiled["default.tool"], ctx, default_action=Action.ALLOW
        )
        assert action is Action.ALLOW

    def test_no_agents_section_behaves_like_today(self) -> None:
        doc = _simple_doc(
            sinks={
                "default.tool": [
                    {
                        "name": "r",
                        "when": 'agent.groups.exists(g, g == "payer")',
                        "action": "block",
                    },
                    {"name": "default", "action": "allow"},
                ]
            }
        )
        compiled = compile_policy(doc)
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="billing-agent",
            groups=frozenset(),
        )
        _, action, _ = evaluate_sink(
            compiled["default.tool"], ctx, default_action=Action.ALLOW
        )
        assert action is Action.ALLOW

    def test_all_on_empty_groups_is_vacuously_true(self) -> None:
        # Documents the same empty-list-fold hazard as
        # test_vacuous_taint_all_true_on_zero_labels, one level up: an
        # undeclared or group-less agent still satisfies `agent.groups.all`.
        expr = compile_cel_expression('agent.groups.all(g, g == "payer")')
        ctx = build_context(
            tool="t",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="researcher",
            groups=frozenset(),
        )
        assert bool(expr.evaluate(ctx)) is True

    def test_multi_group_agent_matches_first_rule_in_order(self) -> None:
        doc = _simple_doc(
            sinks={
                "default.tool": [
                    {
                        "name": "payer_rule",
                        "when": 'agent.groups.exists(g, g == "payer")',
                        "action": "block",
                    },
                    {
                        "name": "internal_rule",
                        "when": 'agent.groups.exists(g, g == "internal")',
                        "action": "require_approval",
                    },
                    {"name": "default", "action": "allow"},
                ]
            },
            agents={"billing-agent": ["payer", "internal"]},
        )
        compiled = compile_policy(doc)
        ctx = build_context(
            tool="default.tool",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="billing-agent",
            groups=frozenset({"payer", "internal"}),
        )
        name, action, _ = evaluate_sink(
            compiled["default.tool"], ctx, default_action=Action.ALLOW
        )
        assert name == "payer_rule"
        assert action is Action.BLOCK


class TestEvaluateSink:
    def _catch_all_sink(self, action: Action = Action.ALLOW) -> CompiledSink:
        return CompiledSink(
            rules=(CompiledRule(name="default", action=action, program=None),)
        )

    def _conditional_sink(self, expr: str, action: Action) -> CompiledSink:
        return CompiledSink(
            rules=(
                CompiledRule(
                    name="cond",
                    action=action,
                    program=compile_cel_expression(expr),
                ),
            )
        )

    def _empty_context(self) -> dict[str, object]:
        return build_context(
            tool="t",
            args={},
            resolved_labels=(),
            trifecta=frozenset(),
            run_tainted=False,
            agent_id="agent-1",
            groups=frozenset(),
        )

    def test_catch_all_fires_immediately(self) -> None:
        sink = self._catch_all_sink(Action.ALLOW)
        name, action, condition = evaluate_sink(
            sink, self._empty_context(), default_action=Action.BLOCK
        )
        assert name == "default"
        assert action is Action.ALLOW
        assert condition is None

    def test_first_conditional_match_wins(self) -> None:
        sink = CompiledSink(
            rules=(
                CompiledRule(
                    name="first",
                    action=Action.BLOCK,
                    program=compile_cel_expression("true"),
                    when="true",
                ),
                CompiledRule(
                    name="second",
                    action=Action.ALLOW,
                    program=compile_cel_expression("true"),
                    when="true",
                ),
            )
        )
        name, action, condition = evaluate_sink(
            sink, self._empty_context(), default_action=Action.ALLOW
        )
        assert name == "first"
        assert action is Action.BLOCK
        assert condition == "true"

    def test_no_match_returns_default_action(self) -> None:
        sink = CompiledSink(
            rules=(
                CompiledRule(
                    name="never",
                    action=Action.BLOCK,
                    program=compile_cel_expression("false"),
                    when="false",
                ),
            )
        )
        name, action, condition = evaluate_sink(
            sink, self._empty_context(), default_action=Action.ALLOW
        )
        assert name is None
        assert action is Action.ALLOW
        assert condition is None
