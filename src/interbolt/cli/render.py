"""Rendering: the console factory, action colors, and record/explanation printers."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Sequence

from rich.console import Console
from rich.tree import Tree

from interbolt import (
    Action,
    Capability,
    Diagnostic,
    Endorsement,
    Event,
    Finding,
    RuleExplanation,
    RuleOutcome,
    SinkExplanation,
    ToolMention,
    describe_diagnostic,
    describe_endorsement,
    describe_event,
    describe_finding,
)

_ACTION_COLOR: dict[Action, str] = {
    Action.ALLOW: "green",
    Action.BLOCK: "red",
    Action.REQUIRE_APPROVAL: "yellow",
}


def build_console(*, quiet: bool = False, no_color: bool = False) -> Console:
    """Build the console for one CLI invocation.

    Args:
        quiet: Reserved for the caller's own suppression decisions; the
            console itself is unchanged, since a quiet run still prints
            problems.
        no_color: Disable ANSI color regardless of terminal detection.

    Returns:
        A `rich.console.Console` for this invocation.
    """
    return Console(no_color=no_color)


def emit_json(console: Console, payload: dict[str, object]) -> None:
    """Print a JSON payload verbatim, with no markup, highlighting, or wrapping."""
    console.print(
        json.dumps(payload, indent=2, sort_keys=False),
        markup=False,
        highlight=False,
        soft_wrap=True,
    )


def _run_id_of(record: Event | Finding | Endorsement | Diagnostic) -> str:
    """The record's run id: an `Event` carries it on `decision`, the others directly."""
    return record.decision.run_id if isinstance(record, Event) else record.run_id


def _agent_id_of(record: Event | Finding | Endorsement | Diagnostic) -> str:
    """The record's agent id: an `Event` carries it on `decision`, others directly."""
    return record.decision.agent_id if isinstance(record, Event) else record.agent_id


def _build_tree(records: Sequence[Event | Finding | Endorsement | Diagnostic]) -> Tree:
    """Render records as a console tree grouped by run, then by agent.

    Args:
        records: The records to render, typically from `_load_records`.

    Returns:
        A `rich.tree.Tree` ready to print with a `rich.console.Console`.
    """
    by_run: dict[str, dict[str, list[Event | Finding | Endorsement | Diagnostic]]] = (
        defaultdict(lambda: defaultdict(list))
    )
    for record in records:
        by_run[_run_id_of(record)][_agent_id_of(record)].append(record)

    root = Tree("provenance log")
    for run_id, by_agent in by_run.items():
        run_records = [r for agent_records in by_agent.values() for r in agent_records]
        n_events = sum(1 for r in run_records if isinstance(r, Event))
        n_findings = sum(1 for r in run_records if isinstance(r, Finding))
        n_endorsements = sum(1 for r in run_records if isinstance(r, Endorsement))
        n_diagnostics = sum(1 for r in run_records if isinstance(r, Diagnostic))
        run_node = root.add(
            f"run {run_id} ({n_events} events, {n_findings} findings, "
            f"{n_endorsements} endorsements, {n_diagnostics} diagnostics)"
        )
        for agent_id, agent_records in by_agent.items():
            agent_node = run_node.add(f"agent {agent_id}")
            for record in sorted(agent_records, key=lambda r: r.timestamp):
                if isinstance(record, Event):
                    agent_node.add(describe_event(record))
                elif isinstance(record, Finding):
                    agent_node.add(describe_finding(record))
                elif isinstance(record, Endorsement):
                    agent_node.add(describe_endorsement(record))
                else:
                    agent_node.add(describe_diagnostic(record))
    return root


def _print_rule(console: Console, rule: RuleExplanation) -> None:
    """Print one rule's reachability outcome, colored by its action."""
    color = _ACTION_COLOR[rule.action]
    if rule.outcome is RuleOutcome.UNCONDITIONAL:
        console.print(f"  [{color}]{rule.action}[/{color}] {rule.name} (unconditional)")
        return
    if rule.outcome is RuleOutcome.CONDITIONAL:
        label = "depends on which member" if rule.depends_on_member else "conditional"
        console.print(
            f"  [{color}]{rule.action}[/{color}] {rule.name} ({label}: {rule.residual})"
        )
        return
    detail = "eliminated"
    if rule.shadowed_by is not None:
        detail = f"eliminated, shadowed by {rule.shadowed_by!r}"
        if rule.shadowed_by_reason is not None:
            detail += f" ({rule.shadowed_by_reason})"
    console.print(f"  [dim]{rule.name} ({detail})[/dim]")


def _print_sink(console: Console, sink: SinkExplanation, show_eliminated: bool) -> None:
    """Print one sink's rules (eliminated ones only when `show_eliminated`)."""
    console.print(f"[bold]{sink.sink_key}[/bold]")
    for rule in sink.rules:
        if rule.outcome is RuleOutcome.ELIMINATED and not show_eliminated:
            continue
        _print_rule(console, rule)
    default_color = _ACTION_COLOR[sink.default_action]
    console.print(
        f"  default: [{default_color}]{sink.default_action}[/{default_color}]"
    )


def _print_tool_capabilities(
    console: Console, capabilities: frozenset[Capability]
) -> None:
    """Print one tool's declared capabilities for `--tool`, or that none exist."""
    if capabilities:
        console.print("  capabilities: " + ", ".join(sorted(capabilities)))
    else:
        console.print("  capabilities: none declared")


def _print_tool_mention(console: Console, mention: ToolMention) -> None:
    """Print one rule's literal agent/group mentions for `--tool`."""
    color = _ACTION_COLOR[mention.action]
    if mention.when is None:
        console.print(
            f"  [{color}]{mention.action}[/{color}] {mention.name} "
            "(catch-all, no identity reference)"
        )
        return
    refs = []
    if mention.agent_ids:
        refs.append("agent ids: " + ", ".join(sorted(mention.agent_ids)))
    if mention.groups:
        refs.append("groups: " + ", ".join(sorted(mention.groups)))
    ref_text = "; ".join(refs) if refs else "no identity reference"
    console.print(f"  [{color}]{mention.action}[/{color}] {mention.name} ({ref_text})")
