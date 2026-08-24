"""`scan` command body: `_scan`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from rich.console import Console
from rich.markup import escape

from interbolt import (
    InterboltConfigError,
    Policy,
    PolicyEvaluationError,
    ScanArtifact,
    ScanTool,
    ScanUndetected,
    UndetectedKind,
    scan_repository,
)
from interbolt.cli.exit_codes import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE
from interbolt.cli.render import emit_json
from interbolt.constants import (
    ENV_API_KEY,
    SCAN_TEXT_COLUMN_MAX_WIDTH,
    SCAN_UNDETECTED_LOCATIONS_SHOWN,
)


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
    collision_counts = {
        c.qualified_name: len(c.definitions) for c in artifact.collisions
    }
    _print_tools(console, artifact.tools, collision_counts)
    _print_undetected(console, artifact.undetected, out_arg)
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


def _truncate_middle(text: str, width: int) -> str:
    """Truncate `text` to `width`, keeping both ends via a middle ellipsis."""
    if len(text) <= width:
        return text
    if width < 5:
        return text[:width]
    keep = width - 1
    left = (keep + 1) // 2
    right = keep - left
    return f"{text[:left]}…{text[-right:]}"


_COLUMN_GAP = "    "  # visual separation between computed-width columns


def _fit(text: str, width: int) -> str:
    r"""Fit repository-derived `text` to a computed column, then escape it.

    Truncates before escaping, never after: `rich.markup.escape()` can
    lengthen a string (`[` becomes `\[`), and truncating an already-escaped
    string could split that sequence and leave a stray backslash for rich
    to reinterpret.
    """
    capped = min(width, SCAN_TEXT_COLUMN_MAX_WIDTH)
    return escape(_truncate_middle(text, capped)).ljust(capped)


def _print_tools(
    console: Console, tools: Sequence[ScanTool], collision_counts: dict[str, int]
) -> None:
    if not tools:
        console.print("no tools found")
        return
    plural = "" if len(tools) == 1 else "s"
    console.print(f"{len(tools)} tool{plural} found")

    rows: list[tuple[str, str, str]] = []
    for tool in tools:
        status = "declared" if tool.declared else "undeclared"
        if tool.collision:
            count = collision_counts.get(tool.qualified_name, 0)
            detail = f"{count} definitions, see collisions"
        elif tool.declared:
            detail = ", ".join(tool.capabilities) or "no capabilities"
        elif tool.evidence:
            top = tool.evidence[0]  # sorted by (depth, path, line, symbol)
            detail = f"{top.symbol} at {top.path}:{top.line}"
        else:
            detail = ""
        rows.append((tool.qualified_name, status, detail))

    name_width = max(len(row[0]) for row in rows)
    status_width = max(len(row[1]) for row in rows)
    for name, status, detail in rows:
        line = f"  {_fit(name, name_width)}{_COLUMN_GAP}{_fit(status, status_width)}"
        if detail:
            line += f"{_COLUMN_GAP}{escape(detail)}"
        console.print(line.rstrip())


_KIND_LABELS: dict[UndetectedKind, str] = {
    UndetectedKind.MCP_SERVER: "MCP server",
    UndetectedKind.DYNAMIC_REGISTRATION: "dynamic registration",
    UndetectedKind.UNRESOLVED_TOOL_LIST: "unresolved tool list",
    UndetectedKind.UNRESOLVED_IMPLEMENTATION: "unresolved impl",
    UndetectedKind.AMBIGUOUS_IMPLEMENTATION: "ambiguous impl",
    UndetectedKind.REJECTED_NAME: "rejected name",
    UndetectedKind.FILES_TRUNCATED: "files truncated",
    UndetectedKind.TRAVERSAL_TRUNCATED: "traversal truncated",
    UndetectedKind.UNDETECTED_TOOL_SURFACE: "undetected tool surface",
}


def _format_locations(items: Sequence[ScanUndetected]) -> str:
    """Format up to `SCAN_UNDETECTED_LOCATIONS_SHOWN` locations for one group.

    The first location always shows its full path. A later location in the
    same file as the one just shown drops the directory, since repeating it
    adds nothing; a location in a different file keeps its full path. An
    identifier, when the entry has one, follows the location.
    """
    parts: list[str] = []
    previous_path: str | None = None
    for item in items:
        shown = (
            item.path if item.path != previous_path else PurePosixPath(item.path).name
        )
        location = f"{shown}:{item.line}"
        if item.identifier:
            location += f"  {item.identifier!r}"
        parts.append(location)
        previous_path = item.path
    return ", ".join(parts)


def _print_undetected(
    console: Console, undetected: Sequence[ScanUndetected], out_arg: str
) -> None:
    if not undetected:
        return
    console.print()
    plural = "" if len(undetected) == 1 else "s"
    console.print(f"{len(undetected)} surface{plural} not readable")

    groups: dict[UndetectedKind, list[ScanUndetected]] = {}
    for item in undetected:
        groups.setdefault(item.kind, []).append(item)
    ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0].value))

    count_width = max(len(str(len(items))) for _, items in ordered)
    label_width = max(len(_KIND_LABELS[kind]) for kind, _ in ordered)
    for kind, items in ordered:
        count_text = f"{len(items):>{count_width}}"
        shown = items[:SCAN_UNDETECTED_LOCATIONS_SHOWN]
        locations = _format_locations(shown)
        remaining = len(items) - len(shown)
        if remaining > 0:
            locations += f", +{remaining} more"
        label = _KIND_LABELS[kind].ljust(label_width)
        console.print(f"  {count_text}  {label}  {escape(locations)}")
    console.print(f"  full detail in {escape(out_arg)}")


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
