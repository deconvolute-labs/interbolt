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
from interbolt.errors import PolicyEvaluationError
from interbolt.models.core import Action, Decision, Event, Finding, Mode, Outcome
from interbolt.policy.explain import (
    AgentExplanation,
    GroupExplanation,
    RuleExplanation,
    RuleOutcome,
    SinkExplanation,
    ToolExplanation,
    ToolMention,
)


def _decision(
    action: Action = Action.ALLOW,
    tool: str = "default.tool",
    run_id: str = "run-1",
    agent_id: str = "agent-a",
) -> Decision:
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
        agent_id=agent_id,
        run_id=run_id,
        session_id=None,
    )


def _event(*, run_id: str = "run-1", agent_id: str = "agent-a") -> Event:
    decision = _decision(run_id=run_id, agent_id=agent_id)
    return Event(
        schema_version=EVENT_SCHEMA_VERSION,
        decision=decision,
        sources=frozenset(),
        outcome=Outcome.ALLOW,
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


def _rule(
    name: str = "r",
    action: Action = Action.ALLOW,
    outcome: RuleOutcome = RuleOutcome.UNCONDITIONAL,
    residual: str | None = None,
    depends_on_member: bool = False,
    shadowed_by: str | None = None,
    shadowed_by_reason: str | None = None,
) -> RuleExplanation:
    return RuleExplanation(
        name=name,
        action=action,
        outcome=outcome,
        residual=residual,
        depends_on_member=depends_on_member,
        shadowed_by=shadowed_by,
        shadowed_by_reason=shadowed_by_reason,
    )


class TestExplainSubcommand:
    def test_agent_and_group_mutually_exclusive(self) -> None:
        with pytest.raises(SystemExit):
            main(["explain", "policy.yaml", "--agent", "a", "--group", "g"])

    def test_agent_and_tool_mutually_exclusive(self) -> None:
        with pytest.raises(SystemExit):
            main(["explain", "policy.yaml", "--agent", "a", "--tool", "ns.tool"])

    def test_missing_target_flag_exits_nonzero(self) -> None:
        with pytest.raises(SystemExit):
            main(["explain", "policy.yaml"])

    def test_policy_load_failure_exits_one(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "interbolt.cli.Policy.from_file",
            side_effect=PolicyEvaluationError("bad policy"),
        )
        result = main(["explain", "policy.yaml", "--agent", "a"])
        assert result == 1

    def test_policy_load_failure_prints_error(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "interbolt.cli.Policy.from_file",
            side_effect=PolicyEvaluationError("bad policy"),
        )
        mock_print = mocker.patch("interbolt.cli._console.print")
        main(["explain", "policy.yaml", "--agent", "a"])
        printed_text = str(mock_print.call_args)
        assert "bad policy" in printed_text

    def test_unknown_tool_sink_exits_one(self, mocker: MockerFixture) -> None:
        mocker.patch("interbolt.cli.Policy.from_file")
        mocker.patch("interbolt.cli.explain_for_tool", return_value=None)
        result = main(["explain", "policy.yaml", "--tool", "ns.tool"])
        assert result == 1

    def test_agent_query_exits_zero_even_with_all_rules_eliminated(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("interbolt.cli.Policy.from_file")
        explanation = AgentExplanation(
            agent_id="a",
            groups=frozenset(),
            sinks=(
                SinkExplanation(
                    sink_key="default.tool",
                    rules=(_rule(outcome=RuleOutcome.ELIMINATED),),
                    default_action=Action.BLOCK,
                ),
            ),
        )
        mocker.patch("interbolt.cli.explain_for_agent", return_value=explanation)
        result = main(["explain", "policy.yaml", "--agent", "a"])
        assert result == 0

    def test_header_prints_agent_id_and_sorted_groups(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("interbolt.cli.Policy.from_file")
        explanation = AgentExplanation(
            agent_id="billing-agent", groups=frozenset({"internal", "payer"}), sinks=()
        )
        mocker.patch("interbolt.cli.explain_for_agent", return_value=explanation)
        mock_print = mocker.patch("interbolt.cli._console.print")
        main(["explain", "policy.yaml", "--agent", "billing-agent"])
        printed_text = str(mock_print.call_args_list[0])
        assert "billing-agent" in printed_text
        assert "internal, payer" in printed_text

    def test_header_prints_none_for_empty_groups(self, mocker: MockerFixture) -> None:
        mocker.patch("interbolt.cli.Policy.from_file")
        explanation = AgentExplanation(agent_id="a", groups=frozenset(), sinks=())
        mocker.patch("interbolt.cli.explain_for_agent", return_value=explanation)
        mock_print = mocker.patch("interbolt.cli._console.print")
        main(["explain", "policy.yaml", "--agent", "a"])
        printed_text = str(mock_print.call_args_list[0])
        assert "none" in printed_text

    def test_group_header_prints_group_name(self, mocker: MockerFixture) -> None:
        mocker.patch("interbolt.cli.Policy.from_file")
        explanation = GroupExplanation(group="payer", sinks=())
        mocker.patch("interbolt.cli.explain_for_group", return_value=explanation)
        mock_print = mocker.patch("interbolt.cli._console.print")
        main(["explain", "policy.yaml", "--group", "payer"])
        printed_text = str(mock_print.call_args_list[0])
        assert "payer" in printed_text

    def test_eliminated_rules_hidden_by_default(self, mocker: MockerFixture) -> None:
        mocker.patch("interbolt.cli.Policy.from_file")
        explanation = AgentExplanation(
            agent_id="a",
            groups=frozenset(),
            sinks=(
                SinkExplanation(
                    sink_key="default.tool",
                    rules=(_rule(name="dead", outcome=RuleOutcome.ELIMINATED),),
                    default_action=Action.BLOCK,
                ),
            ),
        )
        mocker.patch("interbolt.cli.explain_for_agent", return_value=explanation)
        mock_print = mocker.patch("interbolt.cli._console.print")
        main(["explain", "policy.yaml", "--agent", "a"])
        printed_text = " ".join(str(c) for c in mock_print.call_args_list)
        assert "dead" not in printed_text

    def test_show_eliminated_flag_prints_dimmed_rules_with_shadow_annotation(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("interbolt.cli.Policy.from_file")
        explanation = AgentExplanation(
            agent_id="a",
            groups=frozenset(),
            sinks=(
                SinkExplanation(
                    sink_key="default.tool",
                    rules=(
                        _rule(
                            name="dead",
                            outcome=RuleOutcome.ELIMINATED,
                            shadowed_by="winner",
                            shadowed_by_reason="'a' is a member of group 'g'",
                        ),
                    ),
                    default_action=Action.BLOCK,
                ),
            ),
        )
        mocker.patch("interbolt.cli.explain_for_agent", return_value=explanation)
        mock_print = mocker.patch("interbolt.cli._console.print")
        main(["explain", "policy.yaml", "--agent", "a", "--show-eliminated"])
        printed_text = " ".join(str(c) for c in mock_print.call_args_list)
        assert "dead" in printed_text
        assert "winner" in printed_text
        assert "member of group" in printed_text

    def test_conditional_rule_depends_on_member_label(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("interbolt.cli.Policy.from_file")
        explanation = GroupExplanation(
            group="payer",
            sinks=(
                SinkExplanation(
                    sink_key="default.tool",
                    rules=(
                        _rule(
                            name="id_rule",
                            outcome=RuleOutcome.CONDITIONAL,
                            residual='agent.id == "billing-agent"',
                            depends_on_member=True,
                        ),
                    ),
                    default_action=Action.BLOCK,
                ),
            ),
        )
        mocker.patch("interbolt.cli.explain_for_group", return_value=explanation)
        mock_print = mocker.patch("interbolt.cli._console.print")
        main(["explain", "policy.yaml", "--group", "payer"])
        printed_text = " ".join(str(c) for c in mock_print.call_args_list)
        assert "depends on which member" in printed_text

    def test_plain_conditional_rule_does_not_say_depends_on_member(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("interbolt.cli.Policy.from_file")
        explanation = AgentExplanation(
            agent_id="a",
            groups=frozenset(),
            sinks=(
                SinkExplanation(
                    sink_key="default.tool",
                    rules=(
                        _rule(
                            name="taint_rule",
                            outcome=RuleOutcome.CONDITIONAL,
                            residual='taint.any(t, t.trust == "untrusted")',
                            depends_on_member=False,
                        ),
                    ),
                    default_action=Action.BLOCK,
                ),
            ),
        )
        mocker.patch("interbolt.cli.explain_for_agent", return_value=explanation)
        mock_print = mocker.patch("interbolt.cli._console.print")
        main(["explain", "policy.yaml", "--agent", "a"])
        printed_text = " ".join(str(c) for c in mock_print.call_args_list)
        assert "depends on which member" not in printed_text
        assert "conditional" in printed_text

    def test_tool_query_prints_mentions_and_default_action(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("interbolt.cli.Policy.from_file")
        explanation = ToolExplanation(
            sink_key="payments.send_payment",
            mentions=(
                ToolMention(
                    name="payer_rule",
                    action=Action.ALLOW,
                    agent_ids=frozenset(),
                    groups=frozenset({"payer"}),
                    when='agent.groups.exists(g, g == "payer")',
                ),
            ),
            default_action=Action.BLOCK,
        )
        mocker.patch("interbolt.cli.explain_for_tool", return_value=explanation)
        mock_print = mocker.patch("interbolt.cli._console.print")
        result = main(["explain", "policy.yaml", "--tool", "payments.send_payment"])
        assert result == 0
        printed_text = " ".join(str(c) for c in mock_print.call_args_list)
        assert "payments.send_payment" in printed_text
        assert "payer" in printed_text
