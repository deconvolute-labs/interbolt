from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import celpy
from celpy import celtypes
from celpy.adapter import json_to_cel

from interlock.models.core import Action, Label, TrustLevel
from interlock.policy.schema import PolicyDocument

_ANY_MACRO_PATTERN = re.compile(r"\.any\(")
_ENV = celpy.Environment()


def _rewrite_any_to_exists(source: str) -> str:
    """Rewrite the policy DSL's `.any(` to CEL's real `exists` macro.

    CEL's macro set is exactly `{map, filter, all, exists, exists_one, reduce,
    min}`; there is no `any`. `exists` ("at least one element satisfies the
    predicate") is semantically identical to Python's `any`, so this is a safe
    textual rewrite, done once at compile time, never per evaluation.
    """
    return _ANY_MACRO_PATTERN.sub(".exists(", source)


def compile_cel_expression(source: str) -> celpy.Runner:
    """Compile one CEL `when` expression into a reusable, evaluate-many program.

    Args:
        source: The CEL expression text, as written in the policy YAML.

    Returns:
        A compiled celpy program, ready for repeated `evaluate()` calls.

    Raises:
        celpy.CELParseError: If the expression is not valid CEL.
    """
    return _ENV.program(_ENV.compile(_rewrite_any_to_exists(source)))


@dataclass(frozen=True)
class CompiledRule:
    """One compiled rule. `program is None` marks the unconditional catch-all."""

    name: str
    action: Action
    program: celpy.Runner | None


@dataclass(frozen=True)
class CompiledSink:
    """A sink's ordered, compiled rule list."""

    rules: tuple[CompiledRule, ...]


def compile_policy(document: PolicyDocument) -> dict[str, CompiledSink]:
    """Compile every sink's rule list once, at policy load time.

    Args:
        document: The validated policy document.

    Returns:
        A mapping of dotted sink key to its compiled rule list.
    """
    compiled: dict[str, CompiledSink] = {}
    for sink_key, rules in document.sinks.items():
        compiled_rules = tuple(
            CompiledRule(
                name=rule.name,
                action=rule.action,
                program=compile_cel_expression(rule.when)
                if rule.when is not None
                else None,
            )
            for rule in rules
        )
        compiled[sink_key] = CompiledSink(rules=compiled_rules)
    return compiled


def resolve_label_trust(
    label: Label, sources_table: Mapping[str, TrustLevel]
) -> TrustLevel:
    """Resolve a label's trust from every name in its lineage, untrusted-wins.

    Trust is never stored on a `Label`; this is the one place it is computed,
    at the sink, from the policy's `sources` table. A name not in the table
    defaults to untrusted (default-deny).
    """
    for name in label.lineage:
        if sources_table.get(name, TrustLevel.UNTRUSTED) is TrustLevel.UNTRUSTED:
            return TrustLevel.UNTRUSTED
    return TrustLevel.TRUSTED


def _convert_args(args: Mapping[str, Any]) -> celtypes.MapType:
    converted: dict[celtypes.StringType, Any] = {}
    for key, value in args.items():
        try:
            converted[celtypes.StringType(key)] = json_to_cel(value)
        except (ValueError, TypeError):
            # Not representable in CEL (e.g. an arbitrary object); simply
            # unavailable to `when` predicates, same as a missing key.
            continue
    return celtypes.MapType(converted)


def build_context(
    *,
    tool: str,
    args: Mapping[str, Any],
    labels: tuple[Label, ...],
    trifecta: frozenset[str],
    sources_table: Mapping[str, TrustLevel],
) -> dict[str, Any]:
    """Build the CEL evaluation context for one `check()` call.

    `args` must already be stripped of taint carriers (plain `str`/`bytes`/
    containers) by the caller; this function has no knowledge of `Tainted`,
    `TaintedBytes`, or `LabeledValue` (`policy/` never imports `taint/`).

    `taint` stays a plain CEL list so `taint.any(...)`/`taint.all(...)` keep
    working as macros over it. The two aggregate convenience values move to
    top-level siblings, `sources` and `max_trust`, rather than `taint.sources`/
    `taint.max_trust`: CEL cannot make one context variable both a list (for
    the macros) and a map (for dotted field access) at once.

    Args:
        tool: The dotted qualified tool name.
        args: The call's bound arguments, taint carriers already stripped.
        labels: Every label collected from the call's original arguments.
        trifecta: The trifecta legs satisfied by this call.
        sources_table: The policy's declared source-to-trust mapping.

    Returns:
        A context mapping ready for `celpy.Runner.evaluate(...)`.
    """
    taint_list = celtypes.ListType(
        [
            celtypes.MapType(
                {
                    celtypes.StringType("source"): celtypes.StringType(label.source),
                    celtypes.StringType("trust"): celtypes.StringType(
                        resolve_label_trust(label, sources_table).value
                    ),
                }
            )
            for label in labels
        ]
    )

    all_sources: dict[str, None] = {}
    for label in labels:
        for name in label.lineage:
            all_sources.setdefault(name, None)

    max_trust = (
        TrustLevel.UNTRUSTED
        if any(
            resolve_label_trust(label, sources_table) is TrustLevel.UNTRUSTED
            for label in labels
        )
        else TrustLevel.TRUSTED
    )

    return {
        "tool": celtypes.StringType(tool),
        "args": _convert_args(args),
        "taint": taint_list,
        "sources": celtypes.ListType(
            [celtypes.StringType(name) for name in all_sources]
        ),
        "max_trust": celtypes.StringType(max_trust.value),
        "trifecta": celtypes.ListType([celtypes.StringType(leg) for leg in trifecta]),
    }


def evaluate_sink(
    compiled_sink: CompiledSink, context: Mapping[str, Any], *, default_action: Action
) -> tuple[str | None, Action]:
    """Evaluate a sink's compiled rules, first match wins.

    Args:
        compiled_sink: The sink's compiled rule list.
        context: The CEL context built by `build_context`.
        default_action: The action to fall through to if no rule matches.

    Returns:
        The matched rule's name (or `None` for the default) and its action.

    Raises:
        celpy.evaluation.CELEvalError: If a rule's `when` references a missing
            argument, a `None` value, or otherwise fails to evaluate.
    """
    for rule in compiled_sink.rules:
        if rule.program is None:
            return rule.name, rule.action
        if bool(rule.program.evaluate(context)):
            return rule.name, rule.action
    return None, default_action
