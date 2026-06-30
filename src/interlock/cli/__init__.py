from __future__ import annotations

import argparse

from rich.console import Console

from interlock import Policy

_console = Console()


def main(argv: list[str] | None = None) -> int:
    """The `interlock` console script entrypoint.

    Args:
        argv: Command-line arguments, or `None` to use `sys.argv[1:]`.

    Returns:
        The process exit code: 0 on success, 1 on failure.
    """
    parser = argparse.ArgumentParser(prog="interlock")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate", help="Static policy analysis only. Never executes an agent."
    )
    validate_parser.add_argument("policy_path")

    args = parser.parse_args(argv)

    if args.command == "validate":
        return _validate(args.policy_path)
    return 1


def _validate(policy_path: str) -> int:
    problems = Policy.validate(policy_path)
    if problems:
        for problem in problems:
            _console.print(f"[red]✗[/red] {problem}")
        return 1
    _console.print(f"[green]✓[/green] {policy_path} is valid")
    return 0
