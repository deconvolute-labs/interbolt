"""The `interbolt` console script entry point and its argparse wiring."""

from __future__ import annotations

import argparse

from rich.console import Console

from interbolt import __version__
from interbolt.cli.commands_policy import _explain, _init, _validate
from interbolt.cli.commands_run import _inspect
from interbolt.cli.exit_codes import EXIT_INTERNAL
from interbolt.cli.render import build_console

# Part one: argument builders. Each adds one command's own arguments to a
# parser it is given, called once for the noun-nested parser and once for
# the deprecated top-level alias.


def _add_init_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "policy_path",
        nargs="?",
        default="policy.yaml",
        help="Target path (default: policy.yaml in the current directory)",
    )


def _add_validate_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "policy_path",
        nargs="?",
        default="policy.yaml",
        help="Policy file to validate (default: policy.yaml)",
    )


def _add_explain_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "policy_path",
        nargs="?",
        default="policy.yaml",
        help="Policy file to explain (default: policy.yaml)",
    )
    explain_target = parser.add_mutually_exclusive_group(required=True)
    explain_target.add_argument(
        "--agent", default=None, help="Bind agent.id and agent.groups"
    )
    explain_target.add_argument("--group", default=None, help="Bind agent.groups only")
    explain_target.add_argument(
        "--tool", default=None, help="List every agent/group mentioned in one sink"
    )
    parser.add_argument(
        "--show-eliminated",
        action="store_true",
        help="Also print dead rules, dimmed",
    )


def _add_inspect_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", help="JSONL file written by JsonlReporter")
    parser.add_argument("--run-id", default=None, help="Only render this run_id")


# Part two: the shared parent every leaf subparser inherits.


def _global_parser() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--format", choices=("text", "json"), default="text")
    parent.add_argument("--quiet", "-q", action="store_true")
    parent.add_argument("--no-color", action="store_true")
    return parent


# Part three: the tree.


def _hide_alias(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser], name: str
) -> None:
    """Drop a deprecated alias's help-listing entry.

    `help=argparse.SUPPRESS` on `add_parser` only blanks the alias's help
    text; it still renders an empty line in `--help` and still appears in
    the usage synopsis. Removing its pseudo-action is the standard
    workaround for full suppression.
    """
    subparsers._choices_actions = [
        action for action in subparsers._choices_actions if action.dest != name
    ]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="interbolt")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(
        dest="command", required=True, metavar="{policy,run}"
    )
    parent = _global_parser()

    policy_parser = subparsers.add_parser(
        "policy", help="Author, check, and explain a policy file."
    )
    policy_sub = policy_parser.add_subparsers(dest="policy_command", required=True)

    p = policy_sub.add_parser(
        "init", parents=[parent], help="Write the starter policy file to disk."
    )
    _add_init_args(p)
    p.set_defaults(handler=_init, deprecated_alias=None)

    p = policy_sub.add_parser(
        "validate", parents=[parent], help="Static schema and CEL checks only."
    )
    _add_validate_args(p)
    p.set_defaults(handler=_validate, deprecated_alias=None)

    p = policy_sub.add_parser(
        "explain",
        parents=[parent],
        help="Show which sink rules can fire for one agent, group, or tool.",
    )
    _add_explain_args(p)
    p.set_defaults(handler=_explain, deprecated_alias=None)

    run_parser = subparsers.add_parser("run", help="Read the output of a run.")
    run_sub = run_parser.add_subparsers(dest="run_command", required=True)

    p = run_sub.add_parser(
        "inspect",
        parents=[parent],
        help="Render a JsonlReporter provenance log as a console tree.",
    )
    _add_inspect_args(p)
    p.set_defaults(handler=_inspect, deprecated_alias=None)

    # Deprecated, hidden aliases: same argument builders, dispatch to the
    # same handlers, removed in 0.5.0.
    p = subparsers.add_parser("init", parents=[parent], help=argparse.SUPPRESS)
    _add_init_args(p)
    p.set_defaults(handler=_init, deprecated_alias="interbolt policy init")
    _hide_alias(subparsers, "init")

    p = subparsers.add_parser("validate", parents=[parent], help=argparse.SUPPRESS)
    _add_validate_args(p)
    p.set_defaults(handler=_validate, deprecated_alias="interbolt policy validate")
    _hide_alias(subparsers, "validate")

    p = subparsers.add_parser("inspect", parents=[parent], help=argparse.SUPPRESS)
    _add_inspect_args(p)
    p.set_defaults(handler=_inspect, deprecated_alias="interbolt run inspect")
    _hide_alias(subparsers, "inspect")

    p = subparsers.add_parser("explain", parents=[parent], help=argparse.SUPPRESS)
    _add_explain_args(p)
    p.set_defaults(handler=_explain, deprecated_alias="interbolt policy explain")
    _hide_alias(subparsers, "explain")

    return parser


def _warn_deprecated(alias: str) -> None:
    """Print the deprecation notice for a flat alias to stderr, never stdout."""
    stderr_console = Console(stderr=True)
    stderr_console.print(
        "interbolt: this command name is deprecated and will be removed in "
        f"0.5.0; use `{alias}`"
    )


# Part four: dispatch.


def main(argv: list[str] | None = None) -> int:
    """The `interbolt` console script entrypoint.

    Args:
        argv: Command-line arguments, or `None` to use `sys.argv[1:]`.

    Returns:
        The process exit code; see `interbolt.cli.exit_codes`.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    console = build_console(quiet=args.quiet, no_color=args.no_color)
    if args.deprecated_alias is not None:
        _warn_deprecated(args.deprecated_alias)
    try:
        return int(args.handler(args, console))
    except Exception as exc:  # noqa: BLE001
        # The last line of defense for the console script: an unexpected
        # exception is reported as EXIT_INTERNAL. Command bodies still catch
        # and map their own expected failures.
        console.print(f"[red]x[/red] internal error: {exc}")
        return EXIT_INTERNAL
