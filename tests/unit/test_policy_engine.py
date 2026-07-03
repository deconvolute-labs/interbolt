from __future__ import annotations

import pytest

from interbolt.models.core import Action, Label, TrustLevel
from interbolt.policy.engine import (
    CompiledRule,
    CompiledSink,
    _rewrite_any_to_exists,
    build_context,
    compile_cel_expression,
    compile_policy,
    evaluate_sink,
    resolve_label_trust,
)
from interbolt.policy.schema import (
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
    return PolicyDocument(
        version="1.0",
        defaults=Defaults(sink_action=Action.ALLOW),
        sources=(),
        sinks=raw_sinks,
    )


class TestRewriteAnyToExists:
    def test_replaces_any_with_exists(self) -> None:
        result = _rewrite_any_to_exists("taint.any(t, true)")
        assert result == "taint.exists(t, true)"

    def test_no_any_unchanged(self) -> None:
        expr = 'args.x == "y"'
        assert _rewrite_any_to_exists(expr) == expr

    def test_multiple_occurrences_all_replaced(self) -> None:
        expr = "taint.any(t, t.trust == 'x') && taint.any(t, true)"
        result = _rewrite_any_to_exists(expr)
        assert ".any(" not in result
        assert result.count(".exists(") == 2


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
        # Vacuous truth: no sources in lineage → the loop never marks anything
        # untrusted → returns TRUSTED.
        lbl = Label(source="s", value_id="x", lineage=())
        assert resolve_label_trust(lbl, {}) is TrustLevel.TRUSTED


class TestBuildContext:
    def _labels_for(self, sources: list[str]) -> tuple[Label, ...]:
        return tuple(_label(s) for s in sources)

    def test_returns_all_required_keys(self) -> None:
        ctx = build_context(
            tool="default.tool",
            args={},
            labels=(),
            trifecta=frozenset(),
            sources_table={},
            run_tainted=False,
        )
        for key in ("tool", "args", "taint", "sources", "max_trust", "trifecta"):
            assert key in ctx

    def test_max_trust_untrusted_when_any_untrusted(self) -> None:
        labels = self._labels_for(["web"])
        ctx = build_context(
            tool="default.tool",
            args={},
            labels=labels,
            trifecta=frozenset(),
            sources_table={"web": TrustLevel.UNTRUSTED},
            run_tainted=False,
        )
        assert str(ctx["max_trust"]) == "untrusted"

    def test_max_trust_trusted_when_all_trusted(self) -> None:
        labels = self._labels_for(["kb"])
        ctx = build_context(
            tool="default.tool",
            args={},
            labels=labels,
            trifecta=frozenset(),
            sources_table={"kb": TrustLevel.TRUSTED},
            run_tainted=False,
        )
        assert str(ctx["max_trust"]) == "trusted"

    def test_max_trust_trusted_with_no_labels(self) -> None:
        ctx = build_context(
            tool="default.tool",
            args={},
            labels=(),
            trifecta=frozenset(),
            sources_table={},
            run_tainted=False,
        )
        assert str(ctx["max_trust"]) == "trusted"

    def test_sources_list_deduplicates_shared_lineage(self) -> None:
        lbl1 = Label(source="a", value_id="x1", lineage=("a", "shared"))
        lbl2 = Label(source="b", value_id="x2", lineage=("b", "shared"))
        ctx = build_context(
            tool="t",
            args={},
            labels=(lbl1, lbl2),
            trifecta=frozenset(),
            sources_table={},
            run_tainted=False,
        )
        sources = [str(s) for s in ctx["sources"]]
        assert sources.count("shared") == 1


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
            labels=(),
            trifecta=frozenset(),
            sources_table={},
            run_tainted=False,
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
