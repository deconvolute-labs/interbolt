from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from interbolt.cli import _build_tree, _load_records, main
from interbolt.constants import (
    EVENT_SCHEMA_VERSION,
    RECORD_TYPE_EVENT,
    RECORD_TYPE_FINDING,
)
from interbolt.models.core import Action, Decision, Event, Finding, Mode


def _decision(action: Action = Action.ALLOW, tool: str = "default.tool") -> Decision:
    return Decision(
        action=action,
        matched_rule=None,
        matched_condition=None,
        tool=tool,
        contributing_labels=(),
        trifecta=frozenset(),
        untrusted_sources=frozenset(),
        run_tainted=False,
        mode=Mode.ENFORCE,
        decision_id=str(uuid.uuid4()),
        agent_id="agent-a",
        run_id="run-1",
        session_id=None,
    )


def _event(*, run_id: str = "run-1", agent_id: str = "agent-a") -> Event:
    decision = _decision()
    return Event(
        schema_version=EVENT_SCHEMA_VERSION,
        decision=decision,
        agent_id=agent_id,
        run_id=run_id,
        session_id=None,
        sources=frozenset(),
        lineage=(),
        matched_rule=None,
        trifecta=frozenset(),
        untrusted_sources=frozenset(),
        run_tainted=False,
        mode=Mode.ENFORCE,
        outcome="allow",
        timestamp=datetime.now(UTC),
    )


def _event_line(*, run_id: str = "run-1", agent_id: str = "agent-a") -> str:
    event = _event(run_id=run_id, agent_id=agent_id)
    payload = {"record_type": RECORD_TYPE_EVENT, **event.model_dump(mode="json")}
    return json.dumps(payload)


def _finding_line(*, run_id: str = "run-1", agent_id: str = "agent-a") -> str:
    finding = Finding(
        schema_version=EVENT_SCHEMA_VERSION,
        source="web",
        tool="default.tool",
        argument="cmd",
        agent_id=agent_id,
        run_id=run_id,
        session_id=None,
        timestamp=datetime.now(UTC),
    )
    payload = {"record_type": RECORD_TYPE_FINDING, **finding.model_dump(mode="json")}
    return json.dumps(payload)


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

    def test_warnings_only_exits_zero(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "interbolt.cli.Policy.validate",
            return_value=["warning: rule 'r' compares t.source directly"],
        )
        result = main(["validate", "policy.yaml"])
        assert result == 0

    def test_warnings_only_still_prints_the_warning(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "interbolt.cli.Policy.validate",
            return_value=["warning: rule 'r' compares t.source directly"],
        )
        mock_print = mocker.patch("interbolt.cli._console.print")
        main(["validate", "policy.yaml"])
        printed_text = str(mock_print.call_args_list)
        assert "t.source" in printed_text

    def test_warning_and_error_together_exits_one(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "interbolt.cli.Policy.validate",
            return_value=["warning: t.source used", "real error"],
        )
        result = main(["validate", "policy.yaml"])
        assert result == 1


class TestNoSubcommand:
    def test_no_subcommand_exits_nonzero(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code != 0

    def test_unknown_subcommand_exits_nonzero(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["notacommand", "arg"])
        assert exc_info.value.code != 0


class TestInitSubcommand:
    def test_writes_starter_policy_to_explicit_path(self, tmp_path: Path) -> None:
        target = tmp_path / "my_policy.yaml"
        result = main(["init", str(target)])
        assert result == 0
        assert target.exists()
        assert "version" in target.read_text(encoding="utf-8")

    def test_refuses_to_overwrite_existing_file(self, tmp_path: Path) -> None:
        target = tmp_path / "my_policy.yaml"
        target.write_text("existing content", encoding="utf-8")
        result = main(["init", str(target)])
        assert result == 1
        assert target.read_text(encoding="utf-8") == "existing content"

    def test_default_path_resolves_relative_to_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = main(["init"])
        assert result == 0
        assert (tmp_path / "policy.example.yaml").exists()

    def test_packaged_resource_read_failure_exits_one(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        mock_files = mocker.patch("interbolt.cli.importlib.resources.files")
        mock_files.return_value.joinpath.return_value.read_text.side_effect = OSError(
            "no package data"
        )
        result = main(["init", str(tmp_path / "policy.yaml")])
        assert result == 1

    def test_target_write_failure_exits_one(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        mocker.patch("pathlib.Path.write_text", side_effect=OSError("disk full"))
        result = main(["init", str(tmp_path / "policy.yaml")])
        assert result == 1

    def test_success_prints_wrote_message(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        mock_print = mocker.patch("interbolt.cli._console.print")
        target = tmp_path / "policy.yaml"
        main(["init", str(target)])
        printed_text = str(mock_print.call_args)
        assert str(target) in printed_text


class TestInspectSubcommand:
    def test_missing_file_exits_one(self, tmp_path: Path) -> None:
        result = main(["inspect", str(tmp_path / "missing.jsonl")])
        assert result == 1

    def test_valid_jsonl_renders_and_exits_zero(self, tmp_path: Path) -> None:
        log = tmp_path / "log.jsonl"
        log.write_text(_event_line() + "\n" + _finding_line() + "\n", encoding="utf-8")
        result = main(["inspect", str(log)])
        assert result == 0

    def test_malformed_line_skipped_valid_line_still_renders(
        self, tmp_path: Path
    ) -> None:
        log = tmp_path / "log.jsonl"
        log.write_text("{not valid json\n" + _event_line() + "\n", encoding="utf-8")
        result = main(["inspect", str(log)])
        assert result == 0

    def test_malformed_line_prints_warning(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        mock_print = mocker.patch("interbolt.cli._console.print")
        log = tmp_path / "log.jsonl"
        log.write_text("{not valid json\n" + _event_line() + "\n", encoding="utf-8")
        main(["inspect", str(log)])
        printed_text = " ".join(str(c) for c in mock_print.call_args_list)
        assert "line 1" in printed_text

    def test_unrecognized_record_type_skipped(self, tmp_path: Path) -> None:
        log = tmp_path / "log.jsonl"
        log.write_text(json.dumps({"record_type": "mystery"}) + "\n", encoding="utf-8")
        result = main(["inspect", str(log)])
        assert result == 1  # no records survived

    def test_blank_lines_skipped_silently(self, tmp_path: Path) -> None:
        log = tmp_path / "log.jsonl"
        log.write_text("\n   \n" + _event_line() + "\n\n", encoding="utf-8")
        result = main(["inspect", str(log)])
        assert result == 0

    def test_run_id_filter_renders_only_matching_run(self, tmp_path: Path) -> None:
        log = tmp_path / "log.jsonl"
        log.write_text(
            _event_line(run_id="run-1") + "\n" + _event_line(run_id="run-2") + "\n",
            encoding="utf-8",
        )
        result = main(["inspect", str(log), "--run-id", "run-1"])
        assert result == 0

    def test_run_id_filter_no_match_exits_one(self, tmp_path: Path) -> None:
        log = tmp_path / "log.jsonl"
        log.write_text(_event_line(run_id="run-1") + "\n", encoding="utf-8")
        result = main(["inspect", str(log), "--run-id", "no-such-run"])
        assert result == 1


class TestLoadRecords:
    def test_loads_event_and_finding(self, tmp_path: Path) -> None:
        log = tmp_path / "log.jsonl"
        log.write_text(_event_line() + "\n" + _finding_line() + "\n", encoding="utf-8")
        records = _load_records(log)
        assert len(records) == 2
        assert isinstance(records[0], Event)
        assert isinstance(records[1], Finding)

    def test_skips_malformed_json_line(self, tmp_path: Path) -> None:
        log = tmp_path / "log.jsonl"
        log.write_text("not json at all\n" + _event_line() + "\n", encoding="utf-8")
        records = _load_records(log)
        assert len(records) == 1

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        log = tmp_path / "log.jsonl"
        log.write_text("\n" + _event_line() + "\n\n", encoding="utf-8")
        records = _load_records(log)
        assert len(records) == 1

    def test_loads_schema_version_5_shaped_event_missing_trace_fields(
        self, tmp_path: Path
    ) -> None:
        """A record written before trace_id/span_id existed (schema_version 5)
        has no trace_id/span_id keys at all; it must still parse, with both
        fields defaulting to None."""
        payload = json.loads(_event_line())
        payload["schema_version"] = 5
        del payload["trace_id"]
        del payload["span_id"]
        log = tmp_path / "log.jsonl"
        log.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        records = _load_records(log)
        assert len(records) == 1
        event = records[0]
        assert isinstance(event, Event)
        assert event.trace_id is None
        assert event.span_id is None


class TestBuildTree:
    def test_groups_by_run_then_agent(self) -> None:
        events = [_event(run_id="run-1", agent_id="agent-a")]
        tree = _build_tree(events)
        assert "provenance log" in str(tree.label)
        run_node = tree.children[0]
        assert "run-1" in str(run_node.label)
        agent_node = run_node.children[0]
        assert "agent-a" in str(agent_node.label)

    def test_empty_records_produces_root_only(self) -> None:
        tree = _build_tree([])
        assert "provenance log" in str(tree.label)
        assert tree.children == []
