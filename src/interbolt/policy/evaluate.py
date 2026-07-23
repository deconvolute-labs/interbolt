"""Per-call policy evaluation: trust resolution, CEL context, sink evaluation.

Everything here runs on every guarded call.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from celpy import celtypes
from celpy.adapter import json_to_cel

from interbolt.models.core import Action, Label, TrustLevel
from interbolt.policy.compile import CompiledSink


def resolve_source_trust(
    name: str, sources_table: Mapping[str, TrustLevel]
) -> TrustLevel:
    """Resolve one bare source name against the policy's `sources` table.

    A name not in the table defaults to untrusted (default-deny); this
    fallback is fixed and not configurable. This is the single
    trust-resolution primitive; `resolve_label_trust` (per-label lineage)
    and the run-level gating computation in `enforcement` (per-run ingress
    sources) both reduce to repeated calls of this.
    """
    return sources_table.get(name, TrustLevel.UNTRUSTED)


def resolve_agent_groups(
    agent_id: str, id_to_groups: Mapping[str, frozenset[str]]
) -> frozenset[str]:
    """Resolve one agent id's declared groups against the policy's `agents` table.

    An agent id absent from the table (not declared in the policy's
    optional `agents:` section) resolves to the empty set rather than
    raising: an undeclared agent still evaluates normally, just with no
    groups. A typo or a newly deployed agent belongs in `validate`-time
    output, not a runtime exception, and absence of a group is not itself a
    trust signal, unlike `resolve_source_trust`'s untrusted-by-default
    fallback.

    Args:
        agent_id: The acting agent's durable identity.
        id_to_groups: The policy's declared agent-id-to-groups mapping
            (`Policy.id_to_groups`).

    Returns:
        The agent's declared groups, or the empty frozenset if undeclared.
    """
    return id_to_groups.get(agent_id, frozenset())


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
    agent_id: str,
    groups: frozenset[str],
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
    both a list and a map. `run` and `agent` are maps since `run.tainted`
    and `agent.id` only ever need dotted access, never quantification.
    `agent.groups` is a list-typed value nested inside the `agent` map, the
    same shape `t.lineage`/`t.ingested_by`/`t.endorsements` already use
    inside each `taint` entry: a CEL map can hold a list value, so
    `agent.groups.exists(...)` quantifies over that nested list without
    `agent` itself needing to be a list.

    Args:
        tool: The dotted qualified tool name.
        args: The call's bound arguments, taint carriers already stripped.
        resolved_labels: Every label collected from the call's original
            arguments, with trust already resolved.
        trifecta: The trifecta legs satisfied by this call.
        run_tainted: Whether the active run has ingested untrusted data via
            `taint()` at any point, resolved by `enforcement` from the
            per-run ingress registry (run-level gating).
        agent_id: The acting agent's durable identity, the same value
            resolved once in `Runtime.check` and stamped on `Decision`, so
            the CEL context and the audit record never disagree.
        groups: The acting agent's declared groups, already resolved once
            via `resolve_agent_groups`/`Policy.id_to_groups` by the caller,
            never re-resolved here, the same shape as `resolved_labels`.

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
                    celtypes.StringType("ingested_by"): celtypes.ListType(
                        [
                            celtypes.StringType(agent)
                            for agent in resolved.label.ingested_by
                        ]
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
        "agent": celtypes.MapType(
            {
                celtypes.StringType("id"): celtypes.StringType(agent_id),
                celtypes.StringType("groups"): celtypes.ListType(
                    [celtypes.StringType(group) for group in sorted(groups)]
                ),
            }
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
