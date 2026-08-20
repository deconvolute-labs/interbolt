"""`policy` subcommand bodies: `init`, `validate`, `explain`."""

from __future__ import annotations

import argparse
import importlib.resources
from pathlib import Path

from rich.console import Console

from interbolt import (
    AgentExplanation,
    GroupExplanation,
    Policy,
    PolicyEvaluationError,
    SinkExplanation,
    explain_for_agent,
    explain_for_group,
    explain_for_tool,
)
from interbolt.cli.exit_codes import EXIT_FINDINGS, EXIT_INTERNAL, EXIT_OK, EXIT_USAGE
from interbolt.cli.render import (
    _ACTION_COLOR,
    _print_sink,
    _print_tool_capabilities,
    _print_tool_mention,
    emit_json,
)


def _validate(args: argparse.Namespace, console: Console) -> int:
    problems = Policy.validate(args.policy_path)
    warnings = [p for p in problems if p.startswith("warning:")]
    errors = [p for p in problems if not p.startswith("warning:")]

    if args.format == "json":
        emit_json(
            console,
            {
                "command": "policy validate",
                "policy_path": args.policy_path,
                "ok": not errors,
                "errors": errors,
                "warnings": [w.removeprefix("warning: ") for w in warnings],
            },
        )
        return EXIT_FINDINGS if errors else EXIT_OK

    for warning in warnings:
        console.print(f"[yellow]![/yellow] {warning}")
    for error in errors:
        console.print(f"[red]✗[/red] {error}")
    if errors:
        return EXIT_FINDINGS
    if warnings:
        if not args.quiet:
            console.print(
                f"[green]✓[/green] {args.policy_path} is valid (with warnings)"
            )
        return EXIT_OK
    if not args.quiet:
        console.print(f"[green]✓[/green] {args.policy_path} is valid")
    return EXIT_OK


def _init(args: argparse.Namespace, console: Console) -> int:
    target = Path(args.policy_path)
    if target.exists():
        message = f"{args.policy_path!r} already exists; remove it first"
        if args.format == "json":
            emit_json(
                console,
                {
                    "command": "policy init",
                    "policy_path": args.policy_path,
                    "written": False,
                    "error": message,
                },
            )
        else:
            console.print(f"[red]✗[/red] {message}")
        return EXIT_USAGE

    source = importlib.resources.files("interbolt").joinpath("policy.example.yaml")
    try:
        content = source.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:
        message = f"could not read packaged starter policy: {exc}"
        if args.format == "json":
            emit_json(
                console,
                {
                    "command": "policy init",
                    "policy_path": args.policy_path,
                    "written": False,
                    "error": message,
                },
            )
        else:
            console.print(f"[red]✗[/red] {message}")
        return EXIT_INTERNAL

    try:
        target.write_text(content, encoding="utf-8")
    except OSError as exc:
        message = f"could not write {args.policy_path!r}: {exc}"
        if args.format == "json":
            emit_json(
                console,
                {
                    "command": "policy init",
                    "policy_path": args.policy_path,
                    "written": False,
                    "error": message,
                },
            )
        else:
            console.print(f"[red]✗[/red] {message}")
        return EXIT_USAGE

    if args.format == "json":
        emit_json(
            console,
            {
                "command": "policy init",
                "policy_path": args.policy_path,
                "written": True,
            },
        )
        return EXIT_OK
    if not args.quiet:
        console.print(f"[green]✓[/green] wrote {args.policy_path}")
    return EXIT_OK


def _sink_json(sink: SinkExplanation) -> dict[str, object]:
    return {
        "sink_key": sink.sink_key,
        "default_action": sink.default_action,
        "rules": [
            {
                "name": rule.name,
                "action": rule.action,
                "outcome": rule.outcome,
                "residual": rule.residual,
                "depends_on_member": rule.depends_on_member,
                "shadowed_by": rule.shadowed_by,
                "shadowed_by_reason": rule.shadowed_by_reason,
            }
            for rule in sink.rules
        ],
    }


def _explain_agent_json(
    policy_path: str, explanation: AgentExplanation
) -> dict[str, object]:
    return {
        "command": "policy explain",
        "policy_path": policy_path,
        "target": {"kind": "agent", "value": explanation.agent_id},
        "groups": sorted(explanation.groups),
        "sinks": [_sink_json(sink) for sink in explanation.sinks],
    }


def _explain_group_json(
    policy_path: str, explanation: GroupExplanation
) -> dict[str, object]:
    return {
        "command": "policy explain",
        "policy_path": policy_path,
        "target": {"kind": "group", "value": explanation.group},
        "sinks": [_sink_json(sink) for sink in explanation.sinks],
    }


def _explain(args: argparse.Namespace, console: Console) -> int:
    try:
        policy = Policy.from_file(args.policy_path)
    except PolicyEvaluationError as exc:
        message = str(exc)
        if args.format == "json":
            emit_json(
                console,
                {
                    "command": "policy explain",
                    "policy_path": args.policy_path,
                    "error": message,
                },
            )
        else:
            console.print(f"[red]✗[/red] {message}")
        return EXIT_USAGE

    if args.tool is not None:
        tool_explanation = explain_for_tool(policy, args.tool)
        if tool_explanation is None:
            message = f"no sink named {args.tool!r} in {args.policy_path}"
            if args.format == "json":
                emit_json(
                    console,
                    {
                        "command": "policy explain",
                        "policy_path": args.policy_path,
                        "target": {"kind": "tool", "value": args.tool},
                        "error": message,
                    },
                )
            else:
                console.print(f"[red]✗[/red] {message}")
            return EXIT_USAGE

        if args.format == "json":
            emit_json(
                console,
                {
                    "command": "policy explain",
                    "policy_path": args.policy_path,
                    "target": {"kind": "tool", "value": args.tool},
                    "sink_key": tool_explanation.sink_key,
                    "capabilities": sorted(tool_explanation.capabilities),
                    "default_action": tool_explanation.default_action,
                    "mentions": [
                        {
                            "name": mention.name,
                            "action": mention.action,
                            "when": mention.when,
                            "agent_ids": sorted(mention.agent_ids),
                            "groups": sorted(mention.groups),
                        }
                        for mention in tool_explanation.mentions
                    ],
                },
            )
            return EXIT_OK

        console.print(f"[bold]{tool_explanation.sink_key}[/bold]")
        _print_tool_capabilities(console, tool_explanation.capabilities)
        for mention in tool_explanation.mentions:
            _print_tool_mention(console, mention)
        default_color = _ACTION_COLOR[tool_explanation.default_action]
        console.print(
            f"  default: [{default_color}]{tool_explanation.default_action}"
            f"[/{default_color}] (undeclared agents fall through to this)"
        )
        return EXIT_OK

    if args.agent is not None:
        agent_explanation: AgentExplanation = explain_for_agent(policy, args.agent)
        if args.format == "json":
            emit_json(console, _explain_agent_json(args.policy_path, agent_explanation))
            return EXIT_OK
        groups_text = ", ".join(sorted(agent_explanation.groups)) or "none"
        console.print(f"{agent_explanation.agent_id} (groups: {groups_text})")
        for sink in agent_explanation.sinks:
            _print_sink(console, sink, args.show_eliminated)
        return EXIT_OK

    if args.group is not None:
        group_explanation: GroupExplanation = explain_for_group(policy, args.group)
        if args.format == "json":
            emit_json(console, _explain_group_json(args.policy_path, group_explanation))
            return EXIT_OK
        console.print(f"group {group_explanation.group}")
        for sink in group_explanation.sinks:
            _print_sink(console, sink, args.show_eliminated)
        return EXIT_OK

    message = "one of --agent, --group, or --tool is required"
    if args.format == "json":
        emit_json(
            console,
            {
                "command": "policy explain",
                "policy_path": args.policy_path,
                "error": message,
            },
        )
    else:
        console.print(f"[red]✗[/red] {message}")
    return EXIT_USAGE
