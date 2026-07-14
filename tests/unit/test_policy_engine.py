from __future__ import annotations

import lark
import pytest

from interbolt.models.core import Action, Label, TrustLevel
from interbolt.policy.engine import (
    _ENV,
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
            labels=labels,
            trifecta=frozenset(),
            sources_table=sources_table or {},
            run_tainted=False,
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
            labels=(),
            trifecta=frozenset(),
            sources_table={},
            run_tainted=False,
        )
        _, action, _ = evaluate_sink(
            compiled["default.tool"], ctx_match, default_action=Action.ALLOW
        )
        assert action is Action.BLOCK

        ctx_no_match = build_context(
            tool="default.tool",
            args={"path": "clean"},
            labels=(),
            trifecta=frozenset(),
            sources_table={},
            run_tainted=False,
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
