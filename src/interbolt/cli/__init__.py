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
    RECORD_TYPE_EVENT,
    RECORD_TYPE_FINDING,
    Action,
    Event,
    Finding,
    Policy,
)

_console = Console()

_ACTION_COLOR = {
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
        "validate", help="Static policy analysis only. Never executes an agent."
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

    args = parser.parse_args(argv)

    if args.command == "validate":
        return _validate(args.policy_path)
    if args.command == "init":
        return _init(args.policy_path)
    if args.command == "inspect":
        return _inspect(args.path, args.run_id)
    return 1


def _validate(policy_path: str) -> int:
    problems = Policy.validate(policy_path)
    if problems:
        for problem in problems:
            _console.print(f"[red]✗[/red] {problem}")
        return 1
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


def _load_records(path: Path) -> list[Event | Finding]:
    """Parse a JSONL file written by `JsonlReporter`.

    Args:
        path: The JSONL file to read.

    Returns:
        Every successfully parsed `Event`/`Finding`, in file order. A line
        that fails to parse as JSON, carries an unrecognized or missing
        `record_type`, or fails model validation is skipped with a warning
        printed to the console; it does not abort the read.
    """
    records: list[Event | Finding] = []
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
                else:
                    raise ValueError(f"unrecognized record_type: {record_type!r}")
            except (json.JSONDecodeError, ValidationError, ValueError) as exc:
                _console.print(f"[yellow]![/yellow] line {line_number}: {exc}")
    return records


def _describe_event(event: Event) -> str:
    """Build the display label for one `Event` leaf node.

    Args:
        event: The event to describe.

    Returns:
        A rich-markup string summarizing the decision.
    """
    color = _ACTION_COLOR.get(event.decision.action, "white")
    rule = event.matched_rule or "default"
    trust = "untrusted" if "from_untrusted" in event.trifecta else "trusted"
    sources = ", ".join(sorted(event.sources)) or "-"
    lineage = ", ".join(event.lineage) or "-"
    run_tainted = "[red bold]True[/red bold]" if event.run_tainted else "False"
    return (
        f"{event.decision.tool}  "
        f"[{color}]{event.decision.action.value}[/{color}]  "
        f"rule={rule}  mode={event.mode.value}  trust={trust}  "
        f"run_tainted={run_tainted}  sources={{{sources}}}  lineage=({lineage})"
    )


def _describe_finding(finding: Finding) -> str:
    """Build the display label for one `Finding` leaf node.

    Args:
        finding: The finding to describe.

    Returns:
        A rich-markup string summarizing the laundering-audit hit.
    """
    return (
        f"[yellow]finding[/yellow]  source={finding.source}  "
        f"tool={finding.tool}  argument={finding.argument}"
    )


def _build_tree(records: Sequence[Event | Finding]) -> Tree:
    """Render records as a console tree grouped by run, then by agent.

    Args:
        records: The records to render, typically from `_load_records`.

    Returns:
        A `rich.tree.Tree` ready to print with a `rich.console.Console`.
    """
    by_run: dict[str, dict[str, list[Event | Finding]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for record in records:
        by_run[record.run_id][record.agent_id].append(record)

    root = Tree("provenance log")
    for run_id, by_agent in by_run.items():
        run_records = [r for agent_records in by_agent.values() for r in agent_records]
        n_events = sum(1 for r in run_records if isinstance(r, Event))
        n_findings = sum(1 for r in run_records if isinstance(r, Finding))
        run_node = root.add(f"run {run_id} ({n_events} events, {n_findings} findings)")
        for agent_id, agent_records in by_agent.items():
            agent_node = run_node.add(f"agent {agent_id}")
            for record in sorted(agent_records, key=lambda r: r.timestamp):
                if isinstance(record, Event):
                    agent_node.add(_describe_event(record))
                else:
                    agent_node.add(_describe_finding(record))
    return root


def _inspect(path_str: str, run_id: str | None) -> int:
    path = Path(path_str)
    if not path.exists():
        _console.print(f"[red]✗[/red] {path} not found")
        return 1

    records = _load_records(path)
    if run_id is not None:
        records = [r for r in records if r.run_id == run_id]
    if not records:
        _console.print(f"[red]✗[/red] no records found in {path}")
        return 1

    _console.print(_build_tree(records))
    _console.print(f"[green]✓[/green] rendered {len(records)} record(s) from {path}")
    return 0
