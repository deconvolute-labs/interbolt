from __future__ import annotations

import asyncio
from collections import UserDict

import pytest
from pytest_mock import MockerFixture

from interbolt.errors import InterboltUsageError
from interbolt.models.core import Label
from interbolt.taint import (
    LabeledValue,
    Tainted,
    TaintedBytes,
    _fresh_label,
    _merge_labels,
    collect_labels,
    taint,
    track_model_call,
    unwrap,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _label(source: str = "src") -> Label:
    return _fresh_label(source)


# ---------------------------------------------------------------------------
# _fresh_label / _merge_labels
# ---------------------------------------------------------------------------


class TestFreshLabelAndMerge:
    def test_fresh_label_structure(self) -> None:
        lbl = _fresh_label("my_source")
        assert lbl.source == "my_source"
        assert lbl.lineage == ("my_source",)
        assert len(lbl.value_id) == 36  # UUID4

    def test_merge_labels_single_mints_new_value_id(self) -> None:
        lbl = _label("s")
        merged = _merge_labels(lbl)
        assert merged.source == lbl.source
        assert merged.lineage == lbl.lineage
        assert merged.value_id != lbl.value_id

    def test_merge_labels_two_unions_lineage(self) -> None:
        a = _label("src_a")
        b = _label("src_b")
        merged = _merge_labels(a, b)
        assert "src_a" in merged.lineage
        assert "src_b" in merged.lineage

    def test_merge_labels_overlapping_lineage_deduplicates(self) -> None:
        a = _fresh_label("shared")
        b = _fresh_label("shared")
        merged = _merge_labels(a, b)
        assert merged.lineage.count("shared") == 1

    def test_merge_labels_zero_args_raises(self) -> None:
        with pytest.raises(InterboltUsageError):
            _merge_labels()


# ---------------------------------------------------------------------------
# Tainted
# ---------------------------------------------------------------------------


class TestTainted:
    def test_tainted_is_str_subclass(self) -> None:
        t = Tainted("hello", label=_label())
        assert isinstance(t, str)

    def test_tainted_carries_label(self) -> None:
        lbl = _label("s")
        t = Tainted("hello", label=lbl)
        assert t.label is lbl

    def test_add_two_tainted_merges_lineage(self) -> None:
        t1 = Tainted("hello", label=_label("a"))
        t2 = Tainted(" world", label=_label("b"))
        result = t1 + t2
        assert isinstance(result, Tainted)
        assert "a" in result.label.lineage
        assert "b" in result.label.lineage

    def test_add_tainted_and_plain_str_keeps_self_label(self) -> None:
        t1 = Tainted("hello", label=_label("a"))
        result = t1 + " world"
        assert isinstance(result, Tainted)
        assert result.label.lineage == ("a",)

    def test_radd_plain_str_plus_tainted_keeps_self_label_only(self) -> None:
        # When doing plain_str + tainted, Python calls tainted.__radd__(plain_str).
        # __radd__ only carries self.label; the plain string has no label to merge.
        t = Tainted("world", label=_label("a"))
        result = "hello " + t
        assert isinstance(result, Tainted)
        assert result.label.lineage == ("a",)

    def test_mod_propagates_label(self) -> None:
        t = Tainted("Hello %s", label=_label("a"))
        result = t % "world"
        assert isinstance(result, Tainted)
        assert "a" in result.label.lineage

    def test_rmod_plain_format_string(self) -> None:
        t = Tainted("world", label=_label("a"))
        result = "Hello %s" % t  # noqa: UP031
        assert isinstance(result, Tainted)
        assert "a" in result.label.lineage

    def test_mul_propagates_label(self) -> None:
        t = Tainted("ab", label=_label("a"))
        result = t * 3
        assert isinstance(result, Tainted)
        assert "a" in result.label.lineage

    def test_rmul_propagates_label(self) -> None:
        t = Tainted("ab", label=_label("a"))
        result = 3 * t
        assert isinstance(result, Tainted)
        assert "a" in result.label.lineage

    def test_getitem_slice_returns_tainted(self) -> None:
        t = Tainted("hello", label=_label("a"))
        result = t[1:3]
        assert isinstance(result, Tainted)
        assert "a" in result.label.lineage

    def test_format_spec_empty_returns_self(self) -> None:
        t = Tainted("hello", label=_label("a"))
        result = format(t, "")
        # Empty format_spec: __format__ returns self unchanged (still Tainted)
        assert isinstance(result, Tainted)
        assert result is t

    def test_format_spec_nonempty_loses_taint(self) -> None:
        # Non-empty format_spec falls back to str.__format__, which produces a
        # plain str — the propagation contract documents this gap.
        t = Tainted("hello", label=_label("a"))
        result = format(t, ">10")
        assert type(result) is str
        assert not isinstance(result, Tainted)

    def test_upper_propagates_label(self) -> None:
        t = Tainted("hello", label=_label("a"))
        assert isinstance(t.upper(), Tainted)

    def test_lower_propagates_label(self) -> None:
        t = Tainted("HELLO", label=_label("a"))
        assert isinstance(t.lower(), Tainted)

    def test_strip_propagates_label(self) -> None:
        t = Tainted("  hi  ", label=_label("a"))
        assert isinstance(t.strip(), Tainted)

    def test_lstrip_propagates_label(self) -> None:
        t = Tainted("  hi", label=_label("a"))
        assert isinstance(t.lstrip(), Tainted)

    def test_rstrip_propagates_label(self) -> None:
        t = Tainted("hi  ", label=_label("a"))
        assert isinstance(t.rstrip(), Tainted)

    def test_replace_with_plain_arg_keeps_self_label(self) -> None:
        t = Tainted("hello world", label=_label("a"))
        result = t.replace("world", "there")
        assert isinstance(result, Tainted)
        assert result.label.lineage == ("a",)

    def test_replace_with_tainted_arg_merges_lineage(self) -> None:
        t1 = Tainted("hello world", label=_label("a"))
        t2 = Tainted("there", label=_label("b"))
        result = t1.replace("world", t2)
        assert isinstance(result, Tainted)
        assert "a" in result.label.lineage
        assert "b" in result.label.lineage

    def test_format_method_merges_arg_labels(self) -> None:
        template = Tainted("Hello {name}", label=_label("a"))
        name = Tainted("world", label=_label("b"))
        result = template.format(name=name)
        assert isinstance(result, Tainted)
        assert "a" in result.label.lineage
        assert "b" in result.label.lineage

    def test_split_returns_list_of_tainted(self) -> None:
        t = Tainted("a b c", label=_label("a"))
        parts = t.split(" ")
        assert all(isinstance(p, Tainted) for p in parts)

    def test_rsplit_returns_list_of_tainted(self) -> None:
        t = Tainted("a b c", label=_label("a"))
        parts = t.rsplit(" ")
        assert all(isinstance(p, Tainted) for p in parts)

    def test_splitlines_returns_list_of_tainted(self) -> None:
        t = Tainted("a\nb\nc", label=_label("a"))
        parts = t.splitlines()
        assert all(isinstance(p, Tainted) for p in parts)

    def test_partition_all_parts_tainted(self) -> None:
        t = Tainted("hello world", label=_label("a"))
        head, sep, tail = t.partition(" ")
        assert isinstance(head, Tainted)
        assert isinstance(sep, Tainted)
        assert isinstance(tail, Tainted)

    def test_rpartition_all_parts_tainted(self) -> None:
        t = Tainted("a.b.c", label=_label("a"))
        head, sep, tail = t.rpartition(".")
        assert isinstance(head, Tainted)
        assert isinstance(sep, Tainted)
        assert isinstance(tail, Tainted)

    def test_join_with_tainted_items_merges_lineage(self) -> None:
        sep = Tainted(", ", label=_label("sep_src"))
        t1 = Tainted("a", label=_label("item_src"))
        result = sep.join([t1])
        assert isinstance(result, Tainted)
        assert "sep_src" in result.label.lineage
        assert "item_src" in result.label.lineage

    def test_join_with_plain_items_keeps_sep_label(self) -> None:
        sep = Tainted(", ", label=_label("sep_src"))
        result = sep.join(["a", "b"])
        assert isinstance(result, Tainted)
        assert result.label.lineage == ("sep_src",)


# ---------------------------------------------------------------------------
# TaintedBytes
# ---------------------------------------------------------------------------


class TestTaintedBytes:
    def test_tainted_bytes_is_bytes_subclass(self) -> None:
        tb = TaintedBytes(b"hello", label=_label())
        assert isinstance(tb, bytes)

    def test_add_propagates_label(self) -> None:
        tb1 = TaintedBytes(b"hello", label=_label("a"))
        tb2 = TaintedBytes(b" world", label=_label("b"))
        result = tb1 + tb2
        assert isinstance(result, TaintedBytes)
        assert "a" in result.label.lineage
        assert "b" in result.label.lineage

    def test_radd_keeps_self_label(self) -> None:
        tb = TaintedBytes(b"world", label=_label("a"))
        result = b"hello " + tb
        assert isinstance(result, TaintedBytes)
        assert result.label.lineage == ("a",)

    def test_getitem_int_returns_int_not_tainted_bytes(self) -> None:
        # bytes[int] yields an int in Python — TaintedBytes preserves this.
        tb = TaintedBytes(b"hello", label=_label())
        item = tb[0]
        assert type(item) is int

    def test_getitem_slice_returns_tainted_bytes(self) -> None:
        tb = TaintedBytes(b"hello", label=_label("a"))
        result = tb[1:3]
        assert isinstance(result, TaintedBytes)
        assert "a" in result.label.lineage

    def test_upper_propagates_label(self) -> None:
        tb = TaintedBytes(b"hello", label=_label())
        assert isinstance(tb.upper(), TaintedBytes)

    def test_lower_propagates_label(self) -> None:
        tb = TaintedBytes(b"HELLO", label=_label())
        assert isinstance(tb.lower(), TaintedBytes)

    def test_strip_propagates_label(self) -> None:
        tb = TaintedBytes(b"  hi  ", label=_label())
        assert isinstance(tb.strip(), TaintedBytes)

    def test_replace_propagates_label(self) -> None:
        tb = TaintedBytes(b"hello world", label=_label())
        result = tb.replace(b"world", b"there")
        assert isinstance(result, TaintedBytes)

    def test_mod_propagates_label(self) -> None:
        tb = TaintedBytes(b"hello %s", label=_label("a"))
        result = tb % (b"world",)
        assert isinstance(result, TaintedBytes)
        assert result.label.lineage == ("a",)

    def test_mod_merges_tainted_argument_label(self) -> None:
        tb = TaintedBytes(b"hello %s", label=_label("a"))
        arg = TaintedBytes(b"world", label=_label("b"))
        result = tb % (arg,)
        assert "a" in result.label.lineage
        assert "b" in result.label.lineage

    def test_rmod_plain_template_keeps_self_label(self) -> None:
        tb = TaintedBytes(b"world", label=_label("a"))
        result = b"hello %s" % tb
        assert isinstance(result, TaintedBytes)
        assert result.label.lineage == ("a",)

    def test_mul_propagates_label(self) -> None:
        tb = TaintedBytes(b"ab", label=_label("a"))
        result = tb * 3
        assert isinstance(result, TaintedBytes)
        assert result == b"ababab"
        assert result.label.lineage == ("a",)

    def test_rmul_propagates_label(self) -> None:
        tb = TaintedBytes(b"ab", label=_label("a"))
        result = 3 * tb
        assert isinstance(result, TaintedBytes)
        assert result == b"ababab"

    def test_lstrip_propagates_label(self) -> None:
        tb = TaintedBytes(b"  hi", label=_label())
        result = tb.lstrip()
        assert isinstance(result, TaintedBytes)
        assert result == b"hi"

    def test_rstrip_propagates_label(self) -> None:
        tb = TaintedBytes(b"hi  ", label=_label())
        result = tb.rstrip()
        assert isinstance(result, TaintedBytes)
        assert result == b"hi"

    def test_split_returns_list_of_tainted_bytes(self) -> None:
        tb = TaintedBytes(b"a,b,c", label=_label("a"))
        parts = tb.split(b",")
        assert all(isinstance(p, TaintedBytes) for p in parts)
        assert [bytes(p) for p in parts] == [b"a", b"b", b"c"]

    def test_rsplit_returns_list_of_tainted_bytes(self) -> None:
        tb = TaintedBytes(b"a,b,c", label=_label("a"))
        parts = tb.rsplit(b",", 1)
        assert all(isinstance(p, TaintedBytes) for p in parts)
        assert [bytes(p) for p in parts] == [b"a,b", b"c"]

    def test_splitlines_returns_list_of_tainted_bytes(self) -> None:
        tb = TaintedBytes(b"a\nb", label=_label("a"))
        parts = tb.splitlines()
        assert all(isinstance(p, TaintedBytes) for p in parts)
        assert [bytes(p) for p in parts] == [b"a", b"b"]

    def test_partition_all_parts_tainted_bytes(self) -> None:
        tb = TaintedBytes(b"a=b", label=_label("a"))
        head, sep, tail = tb.partition(b"=")
        assert isinstance(head, TaintedBytes)
        assert isinstance(sep, TaintedBytes)
        assert isinstance(tail, TaintedBytes)
        assert (bytes(head), bytes(sep), bytes(tail)) == (b"a", b"=", b"b")

    def test_rpartition_all_parts_tainted_bytes(self) -> None:
        tb = TaintedBytes(b"a=b=c", label=_label("a"))
        head, sep, tail = tb.rpartition(b"=")
        assert isinstance(head, TaintedBytes)
        assert isinstance(sep, TaintedBytes)
        assert isinstance(tail, TaintedBytes)
        assert (bytes(head), bytes(sep), bytes(tail)) == (b"a=b", b"=", b"c")

    def test_join_with_tainted_items_merges_lineage(self) -> None:
        sep = TaintedBytes(b",", label=_label("sep"))
        items = [
            TaintedBytes(b"a", label=_label("x")),
            TaintedBytes(b"b", label=_label("y")),
        ]
        result = sep.join(items)
        assert isinstance(result, TaintedBytes)
        assert result == b"a,b"
        assert set(result.label.lineage) == {"sep", "x", "y"}

    def test_join_with_plain_items_keeps_sep_label(self) -> None:
        sep = TaintedBytes(b",", label=_label("sep"))
        result = sep.join([b"a", b"b"])
        assert isinstance(result, TaintedBytes)
        assert result.label.lineage == ("sep",)


# ---------------------------------------------------------------------------
# LabeledValue
# ---------------------------------------------------------------------------


class TestLabeledValue:
    def test_eq_with_another_labeled_value_same_underlying(self) -> None:
        lbl = _label()
        lv1 = LabeledValue(value=42, label=lbl)
        lv2 = LabeledValue(value=42, label=_label("other"))
        assert lv1 == lv2

    def test_eq_with_plain_value(self) -> None:
        lv = LabeledValue(value=42, label=_label())
        assert lv == 42

    def test_ne_with_different_plain_value(self) -> None:
        lv = LabeledValue(value=42, label=_label())
        assert lv != 43

    def test_hash_equals_plain_value_hash(self) -> None:
        lv = LabeledValue(value=42, label=_label())
        assert hash(lv) == hash(42)

    def test_bool_true_for_truthy(self) -> None:
        assert bool(LabeledValue(value=1, label=_label()))

    def test_bool_false_for_falsy(self) -> None:
        assert not bool(LabeledValue(value=0, label=_label()))

    def test_bool_false_for_none(self) -> None:
        assert not bool(LabeledValue(value=None, label=_label()))


# ---------------------------------------------------------------------------
# taint()
# ---------------------------------------------------------------------------


class TestTaintFunction:
    def test_str_returns_tainted(self) -> None:
        result = taint("hello", source="s")
        assert isinstance(result, Tainted)
        assert result.label.source == "s"

    def test_bytes_returns_tainted_bytes(self) -> None:
        result = taint(b"hello", source="s")
        assert isinstance(result, TaintedBytes)

    def test_list_recurses_str_elements(self) -> None:
        result = taint(["a", "b"], source="s")
        assert isinstance(result, list)
        assert all(isinstance(x, Tainted) for x in result)

    def test_tuple_recurses(self) -> None:
        result = taint(("a", "b"), source="s")
        assert isinstance(result, tuple)
        assert all(isinstance(x, Tainted) for x in result)

    def test_set_recurses(self) -> None:
        result = taint({"a", "b"}, source="s")
        assert isinstance(result, set)
        assert all(isinstance(x, Tainted) for x in result)

    def test_frozenset_recurses(self) -> None:
        result = taint(frozenset({"a"}), source="s")
        assert isinstance(result, frozenset)
        assert all(isinstance(x, Tainted) for x in result)

    def test_dict_recurses_keys_and_values(self) -> None:
        result = taint({"key": "val"}, source="s")
        assert isinstance(result, dict)
        for k, v in result.items():
            assert isinstance(k, Tainted)
            assert isinstance(v, Tainted)

    def test_userdict_mapping_recurses_like_dict(self) -> None:
        # A non-dict Mapping must be recursed into just like a plain dict,
        # not collapsed into one opaque LabeledValue for the whole mapping.
        result = taint(UserDict({"key": "val"}), source="s")
        assert isinstance(result, dict)
        for k, v in result.items():
            assert isinstance(k, Tainted)
            assert isinstance(v, Tainted)

    def test_int_returns_labeled_value(self) -> None:
        result = taint(42, source="s")
        assert isinstance(result, LabeledValue)
        assert result.value == 42

    def test_none_returns_labeled_value(self) -> None:
        result = taint(None, source="s")
        assert isinstance(result, LabeledValue)
        assert result.value is None

    def test_source_recorded_on_label(self) -> None:
        result = taint("x", source="my_source")
        assert isinstance(result, Tainted)
        assert result.label.source == "my_source"
        assert result.label.lineage == ("my_source",)


# ---------------------------------------------------------------------------
# taint(derived_from=...) — "model as a new source"
# ---------------------------------------------------------------------------


class TestTaintDerivedFrom:
    def test_none_behaves_like_plain_taint(self, mocker: MockerFixture) -> None:
        spy = mocker.patch("interbolt.taint._record_ingress")
        result = taint("out", source="model", derived_from=None)
        assert isinstance(result, Tainted)
        assert result.label.lineage == ("model",)
        spy.assert_called_once_with("model")

    def test_empty_list_behaves_like_plain_taint(self, mocker: MockerFixture) -> None:
        spy = mocker.patch("interbolt.taint._record_ingress")
        result = taint("out", source="model", derived_from=[])
        assert isinstance(result, Tainted)
        assert result.label.lineage == ("model",)
        spy.assert_called_once_with("model")

    def test_all_plain_inputs_returns_value_unwrapped(
        self, mocker: MockerFixture
    ) -> None:
        spy = mocker.patch("interbolt.taint._record_ingress")
        value = "out"
        result = taint(value, source="model", derived_from=["plain prompt", 42])
        assert result is value
        assert not isinstance(result, Tainted)
        spy.assert_not_called()

    def test_single_labeled_input_propagates_its_lineage(self) -> None:
        prompt = taint("attacker text", source="web_search")
        result = taint("summary", source="model", derived_from=[prompt])
        assert isinstance(result, Tainted)
        assert result.label.source == "model"
        assert result.label.lineage == ("web_search",)

    def test_mixed_trust_inputs_union_lineage(self) -> None:
        untrusted = taint("attacker text", source="web_search")
        trusted = taint("kb text", source="internal_kb")
        result = taint("summary", source="model", derived_from=[untrusted, trusted])
        assert set(result.label.lineage) == {"web_search", "internal_kb"}

    def test_does_not_record_ingress_for_derivation_hop(
        self, mocker: MockerFixture
    ) -> None:
        spy = mocker.patch("interbolt.taint._record_ingress")
        untrusted = taint("attacker text", source="web_search")
        spy.reset_mock()  # drop the call recorded by the taint() call above
        taint("summary", source="model", derived_from=[untrusted])
        spy.assert_not_called()

    def test_container_value_mints_distinct_value_id_per_leaf(self) -> None:
        untrusted = taint("attacker text", source="web_search")
        result = taint(["a", "b"], source="model", derived_from=[untrusted])
        assert isinstance(result, list)
        assert result[0].label.value_id != result[1].label.value_id
        assert result[0].label.lineage == ("web_search",) == result[1].label.lineage

    def test_derived_from_container_input_collects_nested_labels(self) -> None:
        untrusted = taint("attacker text", source="web_search")
        result = taint("summary", source="model", derived_from=[{"nested": untrusted}])
        assert result.label.lineage == ("web_search",)


# ---------------------------------------------------------------------------
# track_model_call
# ---------------------------------------------------------------------------


class TestTrackModelCall:
    def test_bare_decorator_taints_return_value(self) -> None:
        @track_model_call
        def call_model(prompt: str) -> str:
            return "summary"

        untrusted = taint("attacker text", source="web_search")
        result = call_model(untrusted)
        assert isinstance(result, Tainted)
        assert result.label.source == "model"
        assert result.label.lineage == ("web_search",)

    def test_parameterized_decorator_uses_custom_source(self) -> None:
        @track_model_call(source="gpt-4")  # type: ignore[untyped-decorator]
        def call_model(prompt: str) -> str:
            return "summary"

        untrusted = taint("attacker text", source="web_search")
        result = call_model(untrusted)
        assert result.label.source == "gpt-4"

    def test_all_plain_arguments_returns_untainted_result(self) -> None:
        @track_model_call
        def call_model(prompt: str) -> str:
            return "summary"

        result = call_model("plain prompt")
        assert not isinstance(result, Tainted)
        assert result == "summary"

    def test_mixed_trust_arguments_union_lineage(self) -> None:
        @track_model_call
        def call_model(prompt: str, context: str) -> str:
            return "summary"

        untrusted = taint("attacker text", source="web_search")
        trusted = taint("kb text", source="internal_kb")
        result = call_model(untrusted, context=trusted)
        assert set(result.label.lineage) == {"web_search", "internal_kb"}

    def test_async_function_is_wrapped_and_tainted(self) -> None:
        @track_model_call
        async def call_model(prompt: str) -> str:
            return "summary"

        untrusted = taint("attacker text", source="web_search")
        result = asyncio.run(call_model(untrusted))
        assert isinstance(result, Tainted)
        assert result.label.lineage == ("web_search",)

    def test_preserves_function_name(self) -> None:
        @track_model_call
        def call_model(prompt: str) -> str:
            return "summary"

        assert call_model.__name__ == "call_model"


# ---------------------------------------------------------------------------
# collect_labels()
# ---------------------------------------------------------------------------


class TestCollectLabels:
    def test_from_tainted_str(self) -> None:
        t = taint("hello", source="s")
        labels = collect_labels(t, max_depth=2)
        assert len(labels) == 1
        assert labels[0].source == "s"

    def test_from_tainted_bytes(self) -> None:
        t = taint(b"hello", source="s")
        labels = collect_labels(t, max_depth=2)
        assert len(labels) == 1

    def test_from_labeled_value(self) -> None:
        lv = LabeledValue(value=42, label=_label("s"))
        labels = collect_labels(lv, max_depth=0)
        assert len(labels) == 1
        assert labels[0].source == "s"

    def test_from_plain_str_returns_empty(self) -> None:
        labels = collect_labels("plain", max_depth=2)
        assert labels == ()

    def test_deduplicates_by_value_id_not_source(self) -> None:
        # Same object referenced twice → 1 label (same value_id)
        t = taint("hello", source="s")
        labels = collect_labels({"a": t, "b": t}, max_depth=2)
        assert len(labels) == 1

        # Two separate taint() calls with same source → 2 distinct labels
        t1 = taint("hello", source="s")
        t2 = taint("world", source="s")
        labels2 = collect_labels([t1, t2], max_depth=2)
        assert len(labels2) == 2

    def test_max_depth_limits_discovery(self) -> None:
        # Tainted at depth 3 — not found with max_depth=2
        t = taint("deep", source="s")
        nested = [[t]]  # depth 1: outer list, depth 2: inner list, depth 3: t
        labels = collect_labels([nested], max_depth=2)
        # With max_depth=2 we recurse into the outer list (depth 1)
        # and the inner list (depth 2), but t is at depth 3 — not found.
        # Actually: collect_labels([nested], max_depth=2)
        # depth=2: iterate outer list → nested at depth=1
        # depth=1: iterate inner list [[t]] → [t] at depth=0
        # depth=0: stop → t not found
        assert len(labels) == 0

    def test_nested_mapping_walks_keys_and_values(self) -> None:
        tk = taint("key", source="k_src")
        tv = taint("val", source="v_src")
        labels = collect_labels({tk: tv}, max_depth=2)
        sources = {lbl.source for lbl in labels}
        assert "k_src" in sources
        assert "v_src" in sources

    def test_list_container(self) -> None:
        t1 = taint("a", source="s1")
        t2 = taint("b", source="s2")
        labels = collect_labels([t1, t2], max_depth=2)
        assert len(labels) == 2


# ---------------------------------------------------------------------------
# unwrap()
# ---------------------------------------------------------------------------


class TestUnwrap:
    def test_tainted_str_passthrough(self) -> None:
        # Tainted IS a str subclass, so unwrap returns it as-is (still Tainted)
        lbl = _label("s")
        t = Tainted("hello", label=lbl)
        result = unwrap(t)
        assert isinstance(result, Tainted)

    def test_labeled_value_returns_inner_value(self) -> None:
        lv = LabeledValue(value=42, label=_label())
        assert unwrap(lv) == 42

    def test_nested_labeled_value_recurses(self) -> None:
        inner = LabeledValue(value=1, label=_label())
        outer = LabeledValue(value=inner, label=_label())
        assert unwrap(outer) == 1

    def test_dict_rebuilds_with_plain_values(self) -> None:
        tk = taint("key", source="s")
        tv = LabeledValue(value=99, label=_label())
        result = unwrap({tk: tv})
        assert isinstance(result, dict)
        key = next(iter(result))
        assert type(key) is str or isinstance(key, Tainted)  # Tainted IS str
        assert result[key] == 99

    def test_list_rebuilds(self) -> None:
        lv = LabeledValue(value=7, label=_label())
        result = unwrap([lv, lv])
        assert result == [7, 7]

    def test_plain_value_passthrough(self) -> None:
        assert unwrap("plain") == "plain"
        assert unwrap(42) == 42
        assert unwrap(None) is None
