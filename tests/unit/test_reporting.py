from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime

from pytest_mock import MockerFixture

from interbolt.constants import EVENT_SCHEMA_VERSION
from interbolt.models.core import Action, Decision, Event, Finding, Mode
from interbolt.reporting import (
    CompositeReporter,
    InMemoryReporter,
    LoggingReporter,
    NullReporter,
    describe_decision,
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
        agent_id="agent",
        run_id="run",
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


class TestNullReporter:
    def test_export_does_not_raise_on_event(self) -> None:
        NullReporter().export(_event())

    def test_export_does_not_raise_on_finding(self) -> None:
        NullReporter().export(_finding())


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

    def test_clear_empties_all_lists(self) -> None:
        reporter = InMemoryReporter()
        reporter.export(_event())
        reporter.export(_finding())
        reporter.clear()
        assert reporter.events == []
        assert reporter.decisions == []
        assert reporter.findings == []

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
