"""One-time policy compilation: `CompiledRule`, `CompiledSink`, `compile_policy`."""

from __future__ import annotations

from dataclasses import dataclass

import celpy
from celpy.celparser import CELParseError

from interbolt.errors import InterboltConfigError
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

    Raises:
        celpy.CELParseError: If a rule's CEL expression fails to parse, with
            the sink and rule name prefixed onto the message.
        InterboltConfigError: If a rule's CEL expression uses a disallowed
            construct, such as `.any(`, with the same prefix.
    """
    compiled: dict[str, CompiledSink] = {}
    for sink_key, declaration in document.sinks.items():
        compiled_rules = []
        for rule in declaration.rules:
            when = rule_when(rule)
            program = None
            if when is not None:
                try:
                    program = compile_cel_expression(when)
                except InterboltConfigError as exc:
                    raise InterboltConfigError(
                        f"sink {sink_key!r}: rule {rule.name!r} {exc}"
                    ) from exc
                except CELParseError as exc:
                    raise CELParseError(
                        f"sink {sink_key!r}: rule {rule.name!r}: {exc}"
                    ) from exc
            compiled_rules.append(
                CompiledRule(
                    name=rule.name,
                    action=rule.action,
                    program=program,
                    when=when,
                )
            )
        compiled[sink_key] = CompiledSink(rules=tuple(compiled_rules))
    return compiled
