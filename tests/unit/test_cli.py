from __future__ import annotations

import pytest
from pytest_mock import MockerFixture

from interbolt.cli import main


class TestValidateSubcommand:
    def test_valid_policy_exits_zero(self, mocker: MockerFixture) -> None:
        mocker.patch("interbolt.cli.Policy.validate", return_value=[])
        result = main(["validate", "policy.yaml"])
        assert result == 0

    def test_invalid_policy_exits_one(self, mocker: MockerFixture) -> None:
        mocker.patch("interbolt.cli.Policy.validate", return_value=["problem A"])
        result = main(["validate", "policy.yaml"])
        assert result == 1

    def test_path_passed_to_policy_validate(self, mocker: MockerFixture) -> None:
        mock_validate = mocker.patch("interbolt.cli.Policy.validate", return_value=[])
        main(["validate", "/some/path/policy.yaml"])
        mock_validate.assert_called_once_with("/some/path/policy.yaml")

    def test_multiple_problems_all_printed(self, mocker: MockerFixture) -> None:
        problems = ["issue one", "issue two"]
        mocker.patch("interbolt.cli.Policy.validate", return_value=problems)
        mock_print = mocker.patch("interbolt.cli._console.print")
        result = main(["validate", "policy.yaml"])
        assert result == 1
        assert mock_print.call_count == len(problems)

    def test_valid_policy_prints_success_message(self, mocker: MockerFixture) -> None:
        mocker.patch("interbolt.cli.Policy.validate", return_value=[])
        mock_print = mocker.patch("interbolt.cli._console.print")
        main(["validate", "policy.yaml"])
        mock_print.assert_called_once()
        printed_text = str(mock_print.call_args)
        assert "policy.yaml" in printed_text


class TestNoSubcommand:
    def test_no_subcommand_exits_nonzero(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code != 0

    def test_unknown_subcommand_exits_nonzero(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["notacommand", "arg"])
        assert exc_info.value.code != 0
