"""`scan` command body: `_scan`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from interbolt import (
    InterboltConfigError,
    Policy,
    PolicyEvaluationError,
    ScanArtifact,
    ScanTool,
    ScanUndetected,
    scan_repository,
)
from interbolt.cli.exit_codes import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE
from interbolt.cli.render import emit_json
from interbolt.constants import ENV_API_KEY


def _scan(args: argparse.Namespace, console: Console) -> int:
    usage_error = _usage_error(args)
    if usage_error is not None:
        return _print_error(console, args, usage_error)

    policy_path: str | None = args.policy
    policy = None
    if policy_path is not None:
        try:
            policy = Policy.from_file(policy_path)
        except (PolicyEvaluationError, InterboltConfigError) as exc:
            return _print_error(console, args, str(exc))

    try:
        artifact = scan_repository(
            args.path, exclude=tuple(args.exclude), depth=args.depth, policy=policy
        )
    except InterboltConfigError as exc:
        return _print_error(console, args, str(exc))

    if policy_path is not None and not _policy_within_scan_root(args.path, policy_path):
        console.print(
            f"[yellow]![/yellow] --policy {escape(policy_path)} resolves "
            "outside the scan root"
        )

    payload = artifact.model_dump(mode="json")
    artifact_text = (
        json.dumps(payload, indent=2, sort_keys=False, ensure_ascii=True) + "\n"
    )
    stdout_is_artifact = args.out == "-"

    if stdout_is_artifact:
        sys.stdout.write(artifact_text)
    else:
        out_path = Path(args.out)
        if out_path.parent != Path():
            out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(artifact_text, encoding="utf-8")

    # Under `--out -`, stdout carries only the raw artifact written above;
    # everything this command would otherwise print goes to stderr instead.
    target = (
        Console(file=sys.stderr, no_color=args.no_color)
        if stdout_is_artifact
        else console
    )

    exit_code = EXIT_OK
    if args.fail_on == "undeclared" and artifact.agents[0].undeclared_tool_count > 0:
        exit_code = EXIT_FINDINGS

    if args.format == "json":
        if not stdout_is_artifact:
            emit_json(target, payload)
        return exit_code

    wrote_to = None if stdout_is_artifact else args.out
    _print_text_summary(
        target, artifact, quiet=args.quiet, out_path=wrote_to, out_arg=args.out
    )
    return exit_code


def _usage_error(args: argparse.Namespace) -> str | None:
    """A usage error to report before scanning, or `None` if the arguments are valid."""
    if args.fail_on == "undeclared" and args.policy is None:
        return "--fail-on undeclared requires --policy"
    if args.policy is not None and os.environ.get(ENV_API_KEY):
        return (
            f"--policy is not accepted while {ENV_API_KEY} is set; "
            "the remote policy is authoritative"
        )
    return None


def _print_error(console: Console, args: argparse.Namespace, message: str) -> int:
    if args.format == "json":
        emit_json(console, {"command": "scan", "error": message})
    else:
        console.print(f"[red]x[/red] {escape(message)}")
    return EXIT_USAGE


def _policy_within_scan_root(path: str | None, policy_path: str) -> bool:
    """Whether `policy_path` resolves inside the scan root `--path` would resolve to.

    Mirrors the scan-root default in `scan/walk.py:resolve_scan_root` (`PATH`
    if given, else `src/` if it exists, else the current directory), so the
    warning this backs matches what the scan itself actually walked.
    """
    if path is not None:
        scan_root = Path(path).resolve()
    else:
        candidate = Path.cwd() / "src"
        scan_root = candidate.resolve() if candidate.is_dir() else Path.cwd().resolve()
    return scan_root in Path(policy_path).resolve().parents or (
        Path(policy_path).resolve() == scan_root
    )


def _print_text_summary(
    console: Console,
    artifact: ScanArtifact,
    *,
    quiet: bool,
    out_path: str | None,
    out_arg: str,
) -> None:
    """The three-block text report: tools, unreadable surface, verdict."""
    console.print(_header(artifact))
    console.print()
    _print_tools(console, artifact.tools)
    _print_undetected(console, artifact.undetected)
    _print_undeclared_worklist(console, artifact, out_arg)
    console.print()
    console.print(f"repo scope: verdict {_verdict_line(artifact)}")
    if not quiet and out_path is not None:
        console.print()
        console.print(f"wrote {escape(out_path)}")


def _verdict_line(artifact: ScanArtifact) -> str:
    agent = artifact.agents[0]
    if agent.verdict == "incomplete":
        plural = "" if agent.undeclared_tool_count == 1 else "s"
        count = agent.undeclared_tool_count
        return f"{agent.verdict} ({count} tool{plural} undeclared)"
    return str(agent.verdict)


def _header(artifact: ScanArtifact) -> str:
    name = escape(artifact.repository.root_name)
    suffix = f", {escape(artifact.policy.ref)}" if artifact.policy.ref else ""
    if artifact.repository.revision:
        short_revision = escape(artifact.repository.revision[:7])
        return f"Scanned {name} at {short_revision}{suffix}"
    return f"Scanned {name}{suffix}"


def _print_tools(console: Console, tools: Sequence[ScanTool]) -> None:
    if not tools:
        console.print("no tools found")
        return
    plural = "" if len(tools) == 1 else "s"
    console.print(f"{len(tools)} tool{plural} found")
    for tool in tools:
        name = f"{escape(tool.qualified_name):<26}"
        if tool.declared:
            capabilities = ", ".join(tool.capabilities) or "no capabilities"
            console.print(f"  {name}{capabilities:<20}declared")
            continue
        line = f"  {name}undeclared"
        if tool.evidence:
            top = tool.evidence[0]  # sorted by (depth, path, line, symbol)
            line += f"    {escape(top.symbol)} at {escape(top.path)}:{top.line}"
        console.print(line)


def _print_undetected(console: Console, undetected: Sequence[ScanUndetected]) -> None:
    if not undetected:
        return
    console.print()
    plural = "" if len(undetected) == 1 else "s"
    console.print(f"{len(undetected)} surface{plural} not readable")
    for item in undetected:
        location = f"{escape(item.path)}:{item.line}"
        console.print(f"  {location:<24}{escape(item.detail)}")


def _print_undeclared_worklist(
    console: Console, artifact: ScanArtifact, out_arg: str
) -> None:
    agent = artifact.agents[0]
    if artifact.policy.source == "none" or agent.undeclared_tool_count == 0:
        return
    console.print()
    plural = "" if agent.undeclared_tool_count == 1 else "s"
    console.print(f"{agent.undeclared_tool_count} tool{plural} undeclared")
    console.print(f"  interbolt policy init --from-scan {escape(out_arg)}")
