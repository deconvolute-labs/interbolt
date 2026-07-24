"""Subcommand bodies: `validate`, `init`, `inspect`, `explain`."""

from __future__ import annotations

import importlib.resources
import json
from pathlib import Path

from pydantic import ValidationError

from interbolt import (
    RECORD_TYPE_ENDORSEMENT,
    RECORD_TYPE_EVENT,
    RECORD_TYPE_FINDING,
    AgentExplanation,
    Endorsement,
    Event,
    Finding,
    GroupExplanation,
    Policy,
    PolicyEvaluationError,
    explain_for_agent,
    explain_for_group,
    explain_for_tool,
)
from interbolt.cli.render import (
    _ACTION_COLOR,
    _build_tree,
    _console,
    _print_sink,
    _print_tool_mention,
    _run_id_of,
)


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
