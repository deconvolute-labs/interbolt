"""The command tree itself: noun grouping and shared arguments.

Guards against the surface drifting. Every addition or rename to the tree must fail
`TestCommandTree` until updated deliberately.
"""

from __future__ import annotations

import argparse

import pytest

from interbolt import __version__
from interbolt.cli import main
from interbolt.cli.commands_policy import _explain, _init, _validate
from interbolt.cli.commands_run import _inspect
from interbolt.cli.main import _build_parser


def _leaf_choices(
    parser: argparse.ArgumentParser, dest: str
) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction) and action.dest == dest:
            return dict(action.choices)
    raise AssertionError(f"no subparsers action with dest={dest!r}")


class TestCommandTree:
    def test_exact_tree_structure(self) -> None:
        parser = _build_parser()
        top_level = _leaf_choices(parser, "command")
        assert set(top_level) == {"policy", "run"}

        policy_commands = _leaf_choices(top_level["policy"], "policy_command")
        assert set(policy_commands) == {"init", "validate", "explain"}

        run_commands = _leaf_choices(top_level["run"], "run_command")
        assert set(run_commands) == {"inspect"}

    def test_policy_alone_exits_nonzero(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["policy"])
        assert exc_info.value.code != 0

    def test_run_alone_exits_nonzero(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["run"])
        assert exc_info.value.code != 0

    def test_version_prints_and_exits_zero(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
        assert capsys.readouterr().out.strip() == __version__

    @pytest.mark.parametrize(
        "argv",
        [
            ["validate", "policy.yaml"],
            ["init"],
            ["explain", "policy.yaml", "--agent", "a"],
            ["inspect", "path.jsonl"],
        ],
    )
    def test_flat_command_no_longer_recognized(self, argv: list[str]) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(argv)
        assert exc_info.value.code != 0


class TestEveryCommandParsesAndDispatches:
    @pytest.mark.parametrize(
        ("argv", "handler"),
        [
            (["policy", "init"], _init),
            (["policy", "validate"], _validate),
            (["policy", "explain", "--agent", "a"], _explain),
            (["run", "inspect", "path.jsonl"], _inspect),
        ],
    )
    def test_dispatches_to_expected_handler(
        self, argv: list[str], handler: object
    ) -> None:
        parser = _build_parser()
        args = parser.parse_args(argv)
        assert args.handler is handler

    @pytest.mark.parametrize(
        "leaf",
        [
            ["policy", "init"],
            ["policy", "validate"],
            ["policy", "explain", "--agent", "a"],
            ["run", "inspect", "path.jsonl"],
        ],
    )
    def test_shared_arguments_accepted(self, leaf: list[str]) -> None:
        parser = _build_parser()
        args = parser.parse_args([*leaf, "--format", "json", "--quiet", "--no-color"])
        assert args.format == "json"
        assert args.quiet is True
        assert args.no_color is True
