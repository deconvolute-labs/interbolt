"""The `interbolt` console script entry point and its argparse wiring."""

from __future__ import annotations

import argparse

from interbolt.cli.commands import _explain, _init, _inspect, _validate


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
