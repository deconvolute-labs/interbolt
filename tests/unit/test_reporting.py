from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from pytest_mock import MockerFixture

from interbolt.constants import EVENT_SCHEMA_VERSION, RECORD_TYPE_EVENT
from interbolt.models.core import (
    Action,
    Decision,
    Endorsement,
    Event,
    Finding,
    Mode,
    Outcome,
)
from interbolt.reporting import (
    CompositeReporter,
    InMemoryReporter,
    JsonlReporter,
    LoggingReporter,
    NullReporter,
    describe_decision,
    describe_endorsement,
    describe_event,
    describe_finding,
)


def _decision(
    action: Action = Action.ALLOW,
    matched_rule: str | None = None,
    matched_condition: str | None = None,
    untrusted_sources: frozenset[str] = frozenset(),
) -> Decision:
    return Decision(
        action=action,
        matched_rule=matched_rule,
        matched_condition=matched_condition,
        tool="default.tool",
        contributing_labels=(),
        trifecta=frozenset(),
        untrusted_sources=untrusted_sources,
        run_tainted=False,
        mode=Mode.ENFORCE,
        decision_id=str(uuid.uuid4()),
        agent_id="agent",
        run_id="run",
        session_id=None,
    )


def _event() -> Event:
    return Event(
        schema_version=EVENT_SCHEMA_VERSION,
        decision=_decision(),
        sources=frozenset(),
        outcome=Outcome.ALLOW,
        timestamp=datetime.now(UTC),
    )


def _finding() -> Finding:
    return Finding(
        schema_version=EVENT_SCHEMA_VERSION,
        source="web",
        tool="default.tool",
        argument="cmd",
        agent_id="agent",
        run_id="run",
        session_id=None,
        timestamp=datetime.now(UTC),
    )


def _endorsement(
    *, kind: str = "recipient_allowlisted", note: str | None = None
) -> Endorsement:
    return Endorsement(
        schema_version=EVENT_SCHEMA_VERSION,
        kind=kind,
        note=note,
        lineage=("web_search",),
        value_id=str(uuid.uuid4()),
        agent_id="agent",
        run_id="run",
        session_id=None,
        timestamp=datetime.now(UTC),
    )


class TestNullReporter:
    def test_export_does_not_raise_on_event(self) -> None:
        NullReporter().export(_event())

    def test_export_does_not_raise_on_finding(self) -> None:
        NullReporter().export(_finding())

    def test_export_does_not_raise_on_endorsement(self) -> None:
        NullReporter().export(_endorsement())


class TestInMemoryReporter:
    def test_captures_event(self) -> None:
        reporter = InMemoryReporter()
        ev = _event()
        reporter.export(ev)
        assert len(reporter.events) == 1
        assert reporter.events[0] is ev

    def test_captures_decision_from_event(self) -> None:
        reporter = InMemoryReporter()
        ev = _event()
        reporter.export(ev)
        assert len(reporter.decisions) == 1
        assert reporter.decisions[0] is ev.decision

    def test_captures_finding(self) -> None:
        reporter = InMemoryReporter()
        f = _finding()
        reporter.export(f)
        assert len(reporter.findings) == 1
        assert reporter.findings[0] is f

    def test_finding_not_in_events(self) -> None:
        reporter = InMemoryReporter()
        reporter.export(_finding())
        assert len(reporter.events) == 0
        assert len(reporter.decisions) == 0

    def test_captures_endorsement(self) -> None:
        reporter = InMemoryReporter()
        e = _endorsement()
        reporter.export(e)
        assert len(reporter.endorsements) == 1
        assert reporter.endorsements[0] is e

    def test_endorsement_not_in_events_or_findings(self) -> None:
        reporter = InMemoryReporter()
        reporter.export(_endorsement())
        assert reporter.events == []
        assert reporter.findings == []

    def test_clear_empties_all_lists(self) -> None:
        reporter = InMemoryReporter()
        reporter.export(_event())
        reporter.export(_finding())
        reporter.export(_endorsement())
        reporter.clear()
        assert reporter.events == []
        assert reporter.decisions == []
        assert reporter.findings == []
        assert reporter.endorsements == []

    def test_multiple_events_accumulate(self) -> None:
        reporter = InMemoryReporter()
        reporter.export(_event())
        reporter.export(_event())
        reporter.export(_event())
        assert len(reporter.events) == 3
        assert len(reporter.decisions) == 3


class TestLoggingReporter:
    def test_calls_logger_debug(self, mocker: MockerFixture) -> None:
        mock_debug = mocker.patch("interbolt.reporting._logger.debug")
        ev = _event()
        LoggingReporter().export(ev)
        mock_debug.assert_called_once()
        call_args = mock_debug.call_args
        assert ev in call_args.args or ev in call_args.kwargs.values()


class TestJsonlReporter:
    def test_round_trips_trace_id_and_span_id(self, tmp_path: Path) -> None:
        path = tmp_path / "log.jsonl"
        ev = Event(
            schema_version=EVENT_SCHEMA_VERSION,
            decision=_decision(),
            sources=frozenset(),
            outcome=Outcome.ALLOW,
            trace_id="a" * 32,
            span_id="b" * 16,
            timestamp=datetime.now(UTC),
        )
        JsonlReporter(path).export(ev)
        line = path.read_text(encoding="utf-8").strip()
        payload = json.loads(line)
        assert payload["record_type"] == RECORD_TYPE_EVENT
        assert payload["trace_id"] == "a" * 32
        assert payload["span_id"] == "b" * 16
        payload.pop("record_type")
        round_tripped = Event.model_validate(payload)
        assert round_tripped.trace_id == "a" * 32
        assert round_tripped.span_id == "b" * 16

    def test_trace_id_and_span_id_absent_when_none(self, tmp_path: Path) -> None:
        path = tmp_path / "log.jsonl"
        JsonlReporter(path).export(_event())
        line = path.read_text(encoding="utf-8").strip()
        payload = json.loads(line)
        assert payload["trace_id"] is None
        assert payload["span_id"] is None


class TestCompositeReporter:
    def test_export_fans_out_to_all_wrapped_reporters(self) -> None:
        a, b = InMemoryReporter(), InMemoryReporter()
        composite = CompositeReporter([a, b])
        ev = _event()
        composite.export(ev)
        assert a.events == [ev]
        assert b.events == [ev]

    def test_add_appends_and_is_visible_via_reporters(self) -> None:
        a = InMemoryReporter()
        composite = CompositeReporter([a])
        b = InMemoryReporter()
        composite.add(b)
        assert composite.reporters == (a, b)

    def test_export_reaches_a_reporter_added_after_construction(self) -> None:
        a = InMemoryReporter()
        composite = CompositeReporter([a])
        b = InMemoryReporter()
        composite.add(b)
        ev = _event()
        composite.export(ev)
        assert a.events == [ev]
        assert b.events == [ev]

    def test_one_reporter_raising_does_not_block_another(
        self, mocker: MockerFixture
    ) -> None:
        broken = mocker.Mock()
        broken.export.side_effect = RuntimeError("boom")
        ok = InMemoryReporter()
        composite = CompositeReporter([broken, ok])
        ev = _event()
        composite.export(ev)  # must not raise
        assert ok.events == [ev]

    def test_added_reporter_raising_does_not_block_another(
        self, mocker: MockerFixture
    ) -> None:
        ok = InMemoryReporter()
        composite = CompositeReporter([ok])
        broken = mocker.Mock()
        broken.export.side_effect = RuntimeError("boom")
        composite.add(broken)
        ev = _event()
        composite.export(ev)  # must not raise
        assert ok.events == [ev]

    def test_add_from_another_thread_while_exporting_does_not_raise(self) -> None:
        composite = CompositeReporter([InMemoryReporter()])
        errors: list[BaseException] = []

        def add_loop() -> None:
            try:
                for _ in range(200):
                    composite.add(InMemoryReporter())
            except BaseException as exc:  # noqa: BLE001 -- captured for the main thread
                errors.append(exc)

        thread = threading.Thread(target=add_loop)
        thread.start()
        try:
            for _ in range(200):
                composite.export(_event())
        finally:
            thread.join()

        assert errors == []


class TestDescribeEvent:
    def test_includes_tool_and_action(self) -> None:
        text = describe_event(_event())
        assert "default.tool" in text
        assert "allow" in text

    def test_includes_matched_rule_or_default(self) -> None:
        assert "default" in describe_event(_event())


class TestDescribeFinding:
    def test_includes_source_tool_and_argument(self) -> None:
        text = describe_finding(_finding())
        assert "web" in text
        assert "default.tool" in text
        assert "cmd" in text


class TestDescribeEndorsement:
    def test_includes_kind_and_lineage(self) -> None:
        text = describe_endorsement(_endorsement(kind="recipient_allowlisted"))
        assert "recipient_allowlisted" in text
        assert "web_search" in text

    def test_includes_note_when_present(self) -> None:
        text = describe_endorsement(_endorsement(note="verified by hand"))
        assert "verified by hand" in text

    def test_omits_note_field_when_absent(self) -> None:
        text = describe_endorsement(_endorsement(note=None))
        assert "note=" not in text


class TestDescribeDecision:
    def test_includes_tool_and_action(self) -> None:
        text = describe_decision(_decision(action=Action.BLOCK))
        assert "default.tool" in text
        assert "block" in text

    def test_matched_rule_name_shown_when_present(self) -> None:
        text = describe_decision(_decision(matched_rule="block_exfil"))
        assert "block_exfil" in text

    def test_no_matched_rule_shows_default_sink_action_note(self) -> None:
        text = describe_decision(_decision(matched_rule=None))
        assert "no match" in text

    def test_untrusted_sources_shown(self) -> None:
        text = describe_decision(_decision(untrusted_sources=frozenset({"web_search"})))
        assert "web_search" in text

    def test_matched_condition_shown_when_present(self) -> None:
        text = describe_decision(
            _decision(
                matched_rule="block_exfil",
                matched_condition="taint.any(t, t.trust == 'untrusted')",
            )
        )
        assert "taint.any(t, t.trust == 'untrusted')" in text

    def test_matched_condition_absent_when_none(self) -> None:
        text = describe_decision(_decision(matched_condition=None))
        assert "when=" not in text
