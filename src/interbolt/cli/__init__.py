from __future__ import annotations

import argparse
import importlib.resources
import json
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError
from rich.console import Console
from rich.tree import Tree

from interbolt import (
    RECORD_TYPE_ENDORSEMENT,
    RECORD_TYPE_EVENT,
    RECORD_TYPE_FINDING,
    Action,
    AgentExplanation,
    Endorsement,
    Event,
    Finding,
    GroupExplanation,
    Policy,
    PolicyEvaluationError,
    RuleExplanation,
    RuleOutcome,
    SinkExplanation,
    ToolMention,
    describe_endorsement,
    describe_event,
    describe_finding,
    explain_for_agent,
    explain_for_group,
    explain_for_tool,
)

_console = Console()

_ACTION_COLOR: dict[Action, str] = {
    Action.ALLOW: "green",
    Action.BLOCK: "red",
    Action.REQUIRE_APPROVAL: "yellow",
}


def main(argv: list[str] | None = None) -> int:
    """The `interbolt` console script entrypoint.

    Args:
        argv: Command-line arguments, or `None` to use `sys.argv[1:]`.

    Returns:
        The process exit code: 0 on success, 1 on failure.
    """
    parser = argparse.ArgumentParser(prog="interbolt")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate", help="Static schema and CEL checks only."
    )
    validate_parser.add_argument("policy_path")

    init_parser = subparsers.add_parser(
        "init", help="Write the starter policy file to disk."
    )
    init_parser.add_argument(
        "policy_path",
        nargs="?",
        default="policy.example.yaml",
        help="Target path (default: policy.example.yaml in the current directory)",
    )

    inspect_parser = subparsers.add_parser(
        "inspect", help="Render a JsonlReporter provenance log as a console tree."
    )
    inspect_parser.add_argument("path", help="JSONL file written by JsonlReporter")
    inspect_parser.add_argument(
        "--run-id", default=None, help="Only render this run_id"
    )

    explain_parser = subparsers.add_parser(
        "explain",
        help="Show which sink rules can fire for one agent, group, or tool.",
    )
    explain_parser.add_argument("policy_path")
    explain_target = explain_parser.add_mutually_exclusive_group(required=True)
    explain_target.add_argument(
        "--agent", default=None, help="Bind agent.id and agent.groups"
    )
    explain_target.add_argument("--group", default=None, help="Bind agent.groups only")
    explain_target.add_argument(
        "--tool", default=None, help="List every agent/group mentioned in one sink"
    )
    explain_parser.add_argument(
        "--show-eliminated",
        action="store_true",
        help="Also print dead rules, dimmed",
    )

    args = parser.parse_args(argv)

    if args.command == "validate":
        return _validate(args.policy_path)
    if args.command == "init":
        return _init(args.policy_path)
    if args.command == "inspect":
        return _inspect(args.path, args.run_id)
    if args.command == "explain":
        return _explain(
            args.policy_path, args.agent, args.group, args.tool, args.show_eliminated
        )
    return 1


def _validate(policy_path: str) -> int:
    problems = Policy.validate(policy_path)
    warnings = [p for p in problems if p.startswith("warning:")]
    errors = [p for p in problems if not p.startswith("warning:")]
    for warning in warnings:
        _console.print(f"[yellow]![/yellow] {warning}")
    for error in errors:
        _console.print(f"[red]✗[/red] {error}")
    if errors:
        return 1
    if warnings:
        _console.print(f"[green]✓[/green] {policy_path} is valid (with warnings)")
        return 0
    _console.print(f"[green]✓[/green] {policy_path} is valid")
    return 0


def _init(policy_path: str) -> int:
    target = Path(policy_path)
    if target.exists():
        _console.print(f"[red]✗[/red] {policy_path!r} already exists; remove it first")
        return 1
    source = importlib.resources.files("interbolt").joinpath("policy.example.yaml")
    try:
        content = source.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:
        _console.print(f"[red]✗[/red] could not read packaged starter policy: {exc}")
        return 1
    try:
        target.write_text(content, encoding="utf-8")
    except OSError as exc:
        _console.print(f"[red]✗[/red] could not write {policy_path!r}: {exc}")
        return 1
    _console.print(f"[green]✓[/green] wrote {policy_path}")
    return 0


def _load_records(path: Path) -> list[Event | Finding | Endorsement]:
    """Parse a JSONL file written by `JsonlReporter`.

    Args:
        path: The JSONL file to read.

    Returns:
        Every successfully parsed `Event`/`Finding`/`Endorsement`, in file
        order. A line that fails to parse as JSON, carries an unrecognized
        or missing `record_type`, or fails model validation is skipped, with
        a warning printed to the console, and reading continues.
    """
    records: list[Event | Finding | Endorsement] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_number, raw_line in enumerate(fh, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
                record_type = raw.pop("record_type", None)
                if record_type == RECORD_TYPE_EVENT:
                    records.append(Event.model_validate(raw))
                elif record_type == RECORD_TYPE_FINDING:
                    records.append(Finding.model_validate(raw))
                elif record_type == RECORD_TYPE_ENDORSEMENT:
                    records.append(Endorsement.model_validate(raw))
                else:
                    raise ValueError(f"unrecognized record_type: {record_type!r}")
            except (json.JSONDecodeError, ValidationError, ValueError) as exc:
                _console.print(f"[yellow]![/yellow] line {line_number}: {exc}")
    return records


def _run_id_of(record: Event | Finding | Endorsement) -> str:
    """The record's run id: an `Event` carries it on `decision`, the others directly."""
    return record.decision.run_id if isinstance(record, Event) else record.run_id


def _agent_id_of(record: Event | Finding | Endorsement) -> str:
    """The record's agent id: an `Event` carries it on `decision`, others directly."""
    return record.decision.agent_id if isinstance(record, Event) else record.agent_id


def _build_tree(records: Sequence[Event | Finding | Endorsement]) -> Tree:
    """Render records as a console tree grouped by run, then by agent.

    Args:
        records: The records to render, typically from `_load_records`.

    Returns:
        A `rich.tree.Tree` ready to print with a `rich.console.Console`.
    """
    by_run: dict[str, dict[str, list[Event | Finding | Endorsement]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for record in records:
        by_run[_run_id_of(record)][_agent_id_of(record)].append(record)

    root = Tree("provenance log")
    for run_id, by_agent in by_run.items():
        run_records = [r for agent_records in by_agent.values() for r in agent_records]
        n_events = sum(1 for r in run_records if isinstance(r, Event))
        n_findings = sum(1 for r in run_records if isinstance(r, Finding))
        n_endorsements = sum(1 for r in run_records if isinstance(r, Endorsement))
        run_node = root.add(
            f"run {run_id} ({n_events} events, {n_findings} findings, "
            f"{n_endorsements} endorsements)"
        )
        for agent_id, agent_records in by_agent.items():
            agent_node = run_node.add(f"agent {agent_id}")
            for record in sorted(agent_records, key=lambda r: r.timestamp):
                if isinstance(record, Event):
                    agent_node.add(describe_event(record))
                elif isinstance(record, Finding):
                    agent_node.add(describe_finding(record))
                else:
                    agent_node.add(describe_endorsement(record))
    return root


def _inspect(path_str: str, run_id: str | None) -> int:
    path = Path(path_str)
    if not path.exists():
        _console.print(f"[red]✗[/red] {path} not found")
        return 1

    records = _load_records(path)
    if run_id is not None:
        records = [r for r in records if _run_id_of(r) == run_id]
    if not records:
        _console.print(f"[red]✗[/red] no records found in {path}")
        return 1

    _console.print(_build_tree(records))
    _console.print(f"[green]✓[/green] rendered {len(records)} record(s) from {path}")
    return 0


def _print_rule(rule: RuleExplanation) -> None:
    """Print one rule's reachability outcome, colored by its action."""
    color = _ACTION_COLOR[rule.action]
    if rule.outcome is RuleOutcome.UNCONDITIONAL:
        _console.print(
            f"  [{color}]{rule.action}[/{color}] {rule.name} (unconditional)"
        )
        return
    if rule.outcome is RuleOutcome.CONDITIONAL:
        label = "depends on which member" if rule.depends_on_member else "conditional"
        _console.print(
            f"  [{color}]{rule.action}[/{color}] {rule.name} ({label}: {rule.residual})"
        )
        return
    detail = "eliminated"
    if rule.shadowed_by is not None:
        detail = f"eliminated, shadowed by {rule.shadowed_by!r}"
        if rule.shadowed_by_reason is not None:
            detail += f" ({rule.shadowed_by_reason})"
    _console.print(f"  [dim]{rule.name} ({detail})[/dim]")


def _print_sink(sink: SinkExplanation, show_eliminated: bool) -> None:
    """Print one sink's rules (eliminated ones only when `show_eliminated`)."""
    _console.print(f"[bold]{sink.sink_key}[/bold]")
    for rule in sink.rules:
        if rule.outcome is RuleOutcome.ELIMINATED and not show_eliminated:
            continue
        _print_rule(rule)
    default_color = _ACTION_COLOR[sink.default_action]
    _console.print(
        f"  default: [{default_color}]{sink.default_action}[/{default_color}]"
    )


def _print_tool_mention(mention: ToolMention) -> None:
    """Print one rule's literal agent/group mentions for `--tool`."""
    color = _ACTION_COLOR[mention.action]
    if mention.when is None:
        _console.print(
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
    _console.print(f"  [{color}]{mention.action}[/{color}] {mention.name} ({ref_text})")


def _explain(
    policy_path: str,
    agent: str | None,
    group: str | None,
    tool: str | None,
    show_eliminated: bool,
) -> int:
    try:
        policy = Policy.from_file(policy_path)
    except PolicyEvaluationError as exc:
        _console.print(f"[red]✗[/red] {exc}")
        return 1

    if tool is not None:
        tool_explanation = explain_for_tool(policy, tool)
        if tool_explanation is None:
            _console.print(f"[red]✗[/red] no sink named {tool!r} in {policy_path}")
            return 1
        _console.print(f"[bold]{tool_explanation.sink_key}[/bold]")
        for mention in tool_explanation.mentions:
            _print_tool_mention(mention)
        default_color = _ACTION_COLOR[tool_explanation.default_action]
        _console.print(
            f"  default: [{default_color}]{tool_explanation.default_action}"
            f"[/{default_color}] (undeclared agents fall through to this)"
        )
        return 0

    if agent is not None:
        agent_explanation: AgentExplanation = explain_for_agent(policy, agent)
        groups_text = ", ".join(sorted(agent_explanation.groups)) or "none"
        _console.print(f"{agent_explanation.agent_id} (groups: {groups_text})")
        for sink in agent_explanation.sinks:
            _print_sink(sink, show_eliminated)
        return 0

    if group is not None:
        group_explanation: GroupExplanation = explain_for_group(policy, group)
        _console.print(f"group {group_explanation.group}")
        for sink in group_explanation.sinks:
            _print_sink(sink, show_eliminated)
        return 0

    _console.print("[red]✗[/red] one of --agent, --group, or --tool is required")
    return 1
