from __future__ import annotations

import argparse
import importlib.resources
from pathlib import Path

from rich.console import Console

from interbolt import Policy

_console = Console()


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

    args = parser.parse_args(argv)

    if args.command == "validate":
        return _validate(args.policy_path)
    if args.command == "init":
        return _init(args.policy_path)
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
