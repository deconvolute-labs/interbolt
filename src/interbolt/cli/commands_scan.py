"""`scan` command body: `_scan`."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from interbolt import ScanArtifact, ScanTool, ScanUndetected, scan_repository
from interbolt.cli.exit_codes import EXIT_OK, EXIT_USAGE
from interbolt.cli.render import emit_json
from interbolt.errors import InterboltConfigError


def _scan(args: argparse.Namespace, console: Console) -> int:
    try:
        artifact = scan_repository(
            args.path, exclude=tuple(args.exclude), depth=args.depth
        )
    except InterboltConfigError as exc:
        message = str(exc)
        if args.format == "json":
            emit_json(console, {"command": "scan", "error": message})
        else:
            console.print(f"[red]x[/red] {escape(message)}")
        return EXIT_USAGE

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

    if args.format == "json":
        if not stdout_is_artifact:
            emit_json(target, payload)
        return EXIT_OK

    wrote_to = None if stdout_is_artifact else args.out
    _print_text_summary(target, artifact, quiet=args.quiet, out_path=wrote_to)
    return EXIT_OK


def _print_text_summary(
    console: Console, artifact: ScanArtifact, *, quiet: bool, out_path: str | None
) -> None:
    """The three-block text report: tools, unreadable surface, verdict."""
    console.print(_header(artifact))
    console.print()
    _print_tools(console, artifact.tools)
    _print_undetected(console, artifact.undetected)
    console.print()
    console.print(f"repo scope: verdict {artifact.agents[0].verdict}")
    if not quiet and out_path is not None:
        console.print()
        console.print(f"wrote {escape(out_path)}")


def _header(artifact: ScanArtifact) -> str:
    name = escape(artifact.repository.root_name)
    if artifact.repository.revision:
        short_revision = escape(artifact.repository.revision[:7])
        return f"Scanned {name} at {short_revision}"
    return f"Scanned {name}"


def _print_tools(console: Console, tools: Sequence[ScanTool]) -> None:
    if not tools:
        console.print("no tools found")
        return
    plural = "" if len(tools) == 1 else "s"
    console.print(f"{len(tools)} tool{plural} found")
    for tool in tools:
        line = f"  {escape(tool.qualified_name):<26}undeclared"
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
