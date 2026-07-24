"""One-time policy compilation: `CompiledRule`, `CompiledSink`, `compile_policy`."""

from __future__ import annotations

from dataclasses import dataclass

import celpy

from interbolt.models.core import Action
from interbolt.policy.cel import compile_cel_expression
from interbolt.policy.schema import PolicyDocument, rule_when


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
            when = rule_when(rule)
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
