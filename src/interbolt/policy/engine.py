"""CEL compilation: policy DSL rewrite, context building, and rule evaluation.

The policy DSL's `.any(` is retargeted to CEL's real `exists` macro via an
AST-level transform on celpy's parsed `lark.Tree` (`_rewrite_any_to_exists`),
not a text-level rewrite. A text substitution would also rewrite `.any(`
occurrences that appear inside a CEL string literal, silently corrupting a
security predicate's intended meaning. The transform only mutates
`member_dot_arg` nodes, celpy's own method-call/macro-dispatch AST shape
(see `celpy/evaluation.py:member_dot_arg`), so string, bytes, and
triple-quoted literal tokens are structurally unreachable by it and are
never touched, regardless of their contents.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import celpy
import lark
from celpy import celtypes
from celpy.adapter import json_to_cel

from interbolt.models.core import Action, Label, TrustLevel
from interbolt.policy.schema import PolicyDocument, SinkRule

_ENV = celpy.Environment()


def _rewrite_any_to_exists(tree: lark.Tree[lark.Token]) -> lark.Tree[lark.Token]:
    """Retarget every `.any(` method-call node to CEL's `exists` macro, in place.

    CEL has no `any` macro; its set is `{map, filter, all, exists,
    exists_one, reduce, min}`. `exists` ("at least one element satisfies the
    predicate") means the same thing as the policy DSL's `.any(`.

    Walks `tree`'s `member_dot_arg` nodes (the parse-tree shape celpy's own
    evaluator dispatches macros from) and renames the method token from
    `any` to `exists` wherever it appears. String, bytes, and triple-quoted
    literal tokens live under a sibling `literal` grammar node and are never
    visited by this walk, so a `.any(` occurring inside any CEL string form
    is never touched.

    Args:
        tree: The parsed CEL AST from `Environment.compile()`.

    Returns:
        The same tree object, mutated in place.
    """
    for subtree in tree.iter_subtrees():
        if subtree.data != "member_dot_arg":
            continue
        method_token = subtree.children[1]
        if isinstance(method_token, lark.Token) and method_token.value == "any":
            subtree.children[1] = method_token.update(value="exists")
    return tree


def compile_cel_expression(source: str) -> celpy.Runner:
    """Compile one CEL `when` expression into a reusable, evaluate-many program.

    Args:
        source: The CEL expression text, as written in the policy YAML.

    Returns:
        A compiled celpy program, ready for repeated `evaluate()` calls.

    Raises:
        celpy.CELParseError: If the expression is not valid CEL.
    """
    tree = _rewrite_any_to_exists(_ENV.compile(source))
    return _ENV.program(tree)


@dataclass(frozen=True)
class CompiledRule:
    """One compiled rule. `program is None` marks the unconditional catch-all."""

    name: str
    action: Action
    program: celpy.Runner | None
    when: str | None = None


@dataclass(frozen=True)
class CompiledSink:
    """A sink's ordered, compiled rule list."""

    rules: tuple[CompiledRule, ...]


def _require_endorsement_when(kind: str) -> str:
    """Synthesize the `when:` text for a `require_endorsement: <kind>` rule.

    Compiles to exactly the kind-matching idiom: gate untrusted data that
    lacks the endorsement this sink requires, matching a source endorsed for
    one kind but not this one (the sanitizer-mismatch case).
    """
    return (
        'taint.any(t, t.trust == "untrusted" && '
        f'!t.endorsements.exists(k, k == "{kind}"))'
    )


def _rule_when(rule: SinkRule) -> str | None:
    if rule.require_endorsement is not None:
        return _require_endorsement_when(rule.require_endorsement)
    return rule.when


def compile_policy(document: PolicyDocument) -> dict[str, CompiledSink]:
    """Compile every sink's rule list once, at policy load time.

    A rule's `require_endorsement: <kind>` field (mutually exclusive with
    `when`, enforced at schema validation) is sugar that compiles to the
    equivalent `when:` CEL text, so `CompiledRule.when`/`matched_condition`
    always show real, human-readable CEL regardless of which field the
    policy author wrote.

    Args:
        document: The validated policy document.

    Returns:
        A mapping of dotted sink key to its compiled rule list.
    """
    compiled: dict[str, CompiledSink] = {}
    for sink_key, rules in document.sinks.items():
        compiled_rules = []
        for rule in rules:
            when = _rule_when(rule)
            compiled_rules.append(
                CompiledRule(
                    name=rule.name,
                    action=rule.action,
                    program=compile_cel_expression(when) if when is not None else None,
                    when=when,
                )
            )
        compiled[sink_key] = CompiledSink(rules=tuple(compiled_rules))
    return compiled


def resolve_source_trust(
    name: str, sources_table: Mapping[str, TrustLevel]
) -> TrustLevel:
    """Resolve one bare source name against the policy's `sources` table.

    A name not in the table defaults to untrusted (default-deny). This is
    the single trust-resolution primitive; `resolve_label_trust` (per-label
    lineage) and the run-level gating computation in `enforcement` (per-run
    ingress sources) both reduce to repeated calls of this.
    """
    return sources_table.get(name, TrustLevel.UNTRUSTED)


def resolve_label_trust(
    label: Label, sources_table: Mapping[str, TrustLevel]
) -> TrustLevel:
    """Resolve a label's trust from every name in its lineage, untrusted-wins.

    Computed here, at the sink, from the policy's `sources` table; see
    `Label` for why trust isn't stored on the label itself.
    """
    for name in label.lineage:
        if resolve_source_trust(name, sources_table) is TrustLevel.UNTRUSTED:
            return TrustLevel.UNTRUSTED
    return TrustLevel.TRUSTED


@dataclass(frozen=True)
class ResolvedLabel:
    """A label's trust, resolved once against the policy's `sources` table.

    The single-resolution structure `check()` derives its four label-trust-
    dependent values from (the per-label CEL entry, `max_trust`, `trifecta`,
    `untrusted_sources`), instead of resolving the same labels repeatedly.
    """

    label: Label
    trust: TrustLevel
    untrusted_lineage: frozenset[str]


def resolve_labels(
    labels: tuple[Label, ...], sources_table: Mapping[str, TrustLevel]
) -> tuple[ResolvedLabel, ...]:
    """Resolve every label's trust against `sources_table`, exactly once each.

    Args:
        labels: Every label collected from a call's arguments.
        sources_table: The policy's declared source-to-trust mapping.

    Returns:
        One `ResolvedLabel` per input label, in the same order.
    """
    resolved = []
    for label in labels:
        untrusted_lineage = frozenset(
            name
            for name in label.lineage
            if resolve_source_trust(name, sources_table) is TrustLevel.UNTRUSTED
        )
        trust = TrustLevel.UNTRUSTED if untrusted_lineage else TrustLevel.TRUSTED
        resolved.append(
            ResolvedLabel(label=label, trust=trust, untrusted_lineage=untrusted_lineage)
        )
    return tuple(resolved)


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
    resolved_labels: tuple[ResolvedLabel, ...],
    trifecta: frozenset[str],
    run_tainted: bool,
) -> dict[str, Any]:
    """Build the CEL evaluation context for one `check()` call.

    `args` must already be plain values with taint carriers stripped;
    `policy/` has no dependency on `taint/`, so this function only handles
    `str`/`bytes`/containers. Trust is read from `resolved_labels`
    (`resolve_labels`, resolved once in `enforcement.check()`) rather than
    re-resolved here against a sources table, so this function never walks
    a label's lineage itself.

    `taint` stays a plain CEL list so `taint.any(...)`/`taint.all(...)` work
    as macros. `sources` and `max_trust` are top-level siblings, not
    `taint.sources`/`taint.max_trust`, because CEL can't make one variable
    both a list and a map. `run` is a map since `run.tainted` only needs
    dotted access.

    Args:
        tool: The dotted qualified tool name.
        args: The call's bound arguments, taint carriers already stripped.
        resolved_labels: Every label collected from the call's original
            arguments, with trust already resolved.
        trifecta: The trifecta legs satisfied by this call.
        run_tainted: Whether the active run has ingested untrusted data via
            `taint()` at any point, resolved by `enforcement` from the
            per-run ingress registry (run-level gating).

    Returns:
        A context mapping ready for `celpy.Runner.evaluate(...)`.
    """
    taint_list = celtypes.ListType(
        [
            celtypes.MapType(
                {
                    celtypes.StringType("source"): celtypes.StringType(
                        resolved.label.source
                    ),
                    celtypes.StringType("trust"): celtypes.StringType(
                        resolved.trust.value
                    ),
                    celtypes.StringType("lineage"): celtypes.ListType(
                        [celtypes.StringType(name) for name in resolved.label.lineage]
                    ),
                    celtypes.StringType("endorsements"): celtypes.ListType(
                        [
                            celtypes.StringType(kind)
                            for kind in resolved.label.endorsements
                        ]
                    ),
                }
            )
            for resolved in resolved_labels
        ]
    )

    all_sources: dict[str, None] = {}
    for resolved in resolved_labels:
        for name in resolved.label.lineage:
            all_sources.setdefault(name, None)

    max_trust = (
        TrustLevel.UNTRUSTED
        if any(resolved.trust is TrustLevel.UNTRUSTED for resolved in resolved_labels)
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
        "run": celtypes.MapType(
            {celtypes.StringType("tainted"): celtypes.BoolType(run_tainted)}
        ),
    }


def evaluate_sink(
    compiled_sink: CompiledSink, context: Mapping[str, Any], *, default_action: Action
) -> tuple[str | None, Action, str | None]:
    """Evaluate a sink's compiled rules, first match wins.

    Args:
        compiled_sink: The sink's compiled rule list.
        context: The CEL context built by `build_context`.
        default_action: The action to fall through to if no rule matches.

    Returns:
        The matched rule's name (or `None` for the default), its action, and
        the matched rule's original CEL condition text (`None` for the
        catch-all rule or when nothing matched).

    Raises:
        celpy.evaluation.CELEvalError: If a rule's `when` references a missing
            argument, a `None` value, or otherwise fails to evaluate.
        celpy.evaluation.CELUnsupportedError: If a rule's `when` uses a CEL
            feature the runtime does not fully implement.
    """
    for rule in compiled_sink.rules:
        if rule.program is None:
            return rule.name, rule.action, rule.when
        if bool(rule.program.evaluate(context)):
            return rule.name, rule.action, rule.when
    return None, default_action, None
