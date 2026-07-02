from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pytest_mock import MockerFixture

from interbolt.constants import EVENT_SCHEMA_VERSION
from interbolt.models.core import Action, Decision, Event, Finding, Mode
from interbolt.reporting import InMemoryReporter, LoggingReporter, NullReporter


def _decision() -> Decision:
    return Decision(
        action=Action.ALLOW,
        matched_rule=None,
        tool="default.tool",
        contributing_labels=(),
        trifecta=frozenset(),
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
