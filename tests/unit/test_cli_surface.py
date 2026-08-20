"""The command tree itself: noun grouping, shared arguments, and deprecated aliases.

Guards against the surface drifting once `scan` starts adding flags: every
addition or rename to the tree must fail `TestCommandTree` until updated
deliberately.
"""

from __future__ import annotations

import argparse
import json

import pytest
from pytest_mock import MockerFixture

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
        assert set(top_level) == {
            "policy",
            "run",
            "init",
            "validate",
            "inspect",
            "explain",
        }

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


class TestDeprecatedAliases:
    @pytest.mark.parametrize(
        ("alias_argv", "noun_argv", "handler"),
        [
            (["init"], ["policy", "init"], _init),
            (["validate"], ["policy", "validate"], _validate),
            (
                ["explain", "--agent", "a"],
                ["policy", "explain", "--agent", "a"],
                _explain,
            ),
            (["inspect", "path.jsonl"], ["run", "inspect", "path.jsonl"], _inspect),
        ],
    )
    def test_alias_dispatches_to_same_handler_as_noun_form(
        self,
        alias_argv: list[str],
        noun_argv: list[str],
        handler: object,
    ) -> None:
        parser = _build_parser()
        alias_args = parser.parse_args(alias_argv)
        noun_args = parser.parse_args(noun_argv)
        assert alias_args.handler is handler
        assert noun_args.handler is handler
        assert noun_args.deprecated_alias is None
        assert alias_args.deprecated_alias is not None

    @pytest.mark.parametrize(
        ("alias_argv", "expected_replacement", "patch_target"),
        [
            (["init"], "interbolt policy init", "interbolt.cli.main._init"),
            (["validate"], "interbolt policy validate", "interbolt.cli.main._validate"),
            (
                ["explain", "--agent", "a"],
                "interbolt policy explain",
                "interbolt.cli.main._explain",
            ),
            (
                ["inspect", "path.jsonl"],
                "interbolt run inspect",
                "interbolt.cli.main._inspect",
            ),
        ],
    )
    def test_alias_emits_deprecation_notice_to_stderr(
        self,
        alias_argv: list[str],
        expected_replacement: str,
        patch_target: str,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        mocker.patch(patch_target, return_value=0)
        result = main(alias_argv)
        assert result == 0
        captured = capsys.readouterr()
        assert "deprecated" in captured.err
        assert expected_replacement in captured.err
        assert captured.out == ""

    def test_json_format_stays_clean_on_stdout_for_alias(
        self, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mocker.patch("interbolt.cli.commands_policy.Policy.validate", return_value=[])
        result = main(["validate", "policy.yaml", "--format", "json"])
        assert result == 0
        captured = capsys.readouterr()
        assert "deprecated" not in captured.out
        assert "deprecated" in captured.err
        payload = json.loads(captured.out)
        assert payload["command"] == "policy validate"
