from __future__ import annotations

import importlib
import sys
import uuid
from collections.abc import Generator
from datetime import UTC, datetime

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from pytest_mock import MockerFixture

from interbolt.constants import EVENT_SCHEMA_VERSION
from interbolt.enforcement.check import _emit
from interbolt.errors import InterboltConfigError
from interbolt.models.core import Action, Decision, Endorsement, Event, Finding, Mode
from interbolt.reporting.otel import OTelReporter

_exporter = InMemorySpanExporter()
_provider = TracerProvider()
_provider.add_span_processor(SimpleSpanProcessor(_exporter))
trace.set_tracer_provider(_provider)
_tracer = _provider.get_tracer("test")


@pytest.fixture(autouse=True)
def _clear_exporter() -> Generator[None, None, None]:
    _exporter.clear()
    yield
    _exporter.clear()


def _make_decision(**overrides: object) -> Decision:
    defaults: dict[str, object] = dict(
        action=Action.BLOCK,
        matched_rule="block_untrusted_exfil",
        matched_condition='taint.any(t, t.trust == "untrusted")',
        tool="default.send_email",
        contributing_labels=(),
        trifecta=frozenset({"from_untrusted"}),
        untrusted_sources=frozenset({"web_search"}),
        run_tainted=False,
        mode=Mode.ENFORCE,
        decision_id=str(uuid.uuid4()),
        agent_id="test-agent",
        run_id="test-run",
        session_id=None,
    )
    defaults.update(overrides)
    return Decision(**defaults)  # type: ignore[arg-type]


def _make_event(*, decision: Decision | None = None, **overrides: object) -> Event:
    decision = decision or _make_decision()
    defaults: dict[str, object] = dict(
        schema_version=EVENT_SCHEMA_VERSION,
        decision=decision,
        sources=frozenset({"web_search"}),
        outcome=decision.action.value,
        timestamp=datetime.now(UTC),
    )
    defaults.update(overrides)
    return Event(**defaults)  # type: ignore[arg-type]


def _make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = dict(
        schema_version=EVENT_SCHEMA_VERSION,
        source="web_search",
        tool="default.send_email",
        argument="body",
        agent_id="test-agent",
        run_id="test-run",
        session_id=None,
        timestamp=datetime.now(UTC),
    )
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def _make_endorsement(**overrides: object) -> Endorsement:
    defaults: dict[str, object] = dict(
        schema_version=EVENT_SCHEMA_VERSION,
        kind="recipient_allowlisted",
        note=None,
        lineage=("web_search",),
        value_id=str(uuid.uuid4()),
        agent_id="test-agent",
        run_id="test-run",
        session_id=None,
        timestamp=datetime.now(UTC),
    )
    defaults.update(overrides)
    return Endorsement(**defaults)  # type: ignore[arg-type]


class TestActiveSpan:
    def test_event_attaches_span_event_with_expected_attributes(self) -> None:
        reporter = OTelReporter()
        event = _make_event()
        with _tracer.start_as_current_span("host-span"):
            reporter.export(event)
        finished = [s for s in _exporter.get_finished_spans() if s.name == "host-span"]
        assert len(finished) == 1
        span_events = finished[0].events
        assert len(span_events) == 1
        assert span_events[0].name == "interbolt.decision"
        attrs = span_events[0].attributes
        assert attrs is not None
        assert attrs["gen_ai.tool.name"] == "default.send_email"
        assert attrs["interbolt.outcome"] == "block"
        assert attrs["interbolt.decision.action"] == "block"
        assert attrs["interbolt.decision.id"] == event.decision.decision_id
        assert attrs["interbolt.matched_rule"] == "block_untrusted_exfil"
        assert attrs["interbolt.mode"] == "enforce"
        assert attrs["interbolt.agent_id"] == "test-agent"
        assert attrs["interbolt.run_id"] == "test-run"
        assert attrs["interbolt.run_tainted"] is False
        assert tuple(attrs["interbolt.sources"]) == ("web_search",)
        assert tuple(attrs["interbolt.untrusted_sources"]) == ("web_search",)
        assert tuple(attrs["interbolt.trifecta"]) == ("from_untrusted",)

    def test_finding_attaches_span_event(self) -> None:
        reporter = OTelReporter()
        finding = _make_finding()
        with _tracer.start_as_current_span("host-span"):
            reporter.export(finding)
        finished = [s for s in _exporter.get_finished_spans() if s.name == "host-span"]
        events = finished[0].events
        assert len(events) == 1
        assert events[0].name == "interbolt.finding"
        attrs = events[0].attributes
        assert attrs is not None
        assert attrs["interbolt.finding.source"] == "web_search"
        assert attrs["interbolt.finding.argument"] == "body"
        assert attrs["gen_ai.tool.name"] == "default.send_email"

    def test_endorsement_attaches_span_event(self) -> None:
        reporter = OTelReporter()
        endorsement = _make_endorsement(note="checked against allowlist")
        with _tracer.start_as_current_span("host-span"):
            reporter.export(endorsement)
        finished = [s for s in _exporter.get_finished_spans() if s.name == "host-span"]
        events = finished[0].events
        assert len(events) == 1
        assert events[0].name == "interbolt.endorsement"
        attrs = events[0].attributes
        assert attrs is not None
        assert attrs["interbolt.endorsement.kind"] == "recipient_allowlisted"
        assert attrs["interbolt.endorsement.note"] == "checked against allowlist"


class TestNoActiveSpan:
    def test_event_creates_fallback_span(self) -> None:
        reporter = OTelReporter()
        event = _make_event()
        reporter.export(event)
        finished = _exporter.get_finished_spans()
        assert len(finished) == 1
        assert finished[0].name == "interbolt.decision"
        assert finished[0].attributes is not None
        assert finished[0].attributes["gen_ai.tool.name"] == "default.send_email"
        assert len(finished[0].events) == 0

    def test_finding_creates_fallback_span(self) -> None:
        reporter = OTelReporter()
        reporter.export(_make_finding())
        finished = _exporter.get_finished_spans()
        assert len(finished) == 1
        assert finished[0].name == "interbolt.finding"


class TestNoneFieldsOmitted:
    def test_event_session_id_none_is_absent(self) -> None:
        reporter = OTelReporter()
        decision = _make_decision(session_id=None)
        reporter.export(_make_event(decision=decision))
        attrs = _exporter.get_finished_spans()[0].attributes
        assert attrs is not None
        assert "interbolt.session_id" not in attrs

    def test_event_matched_rule_none_is_absent(self) -> None:
        reporter = OTelReporter()
        decision = _make_decision(matched_rule=None, matched_condition=None)
        reporter.export(_make_event(decision=decision))
        attrs = _exporter.get_finished_spans()[0].attributes
        assert attrs is not None
        assert "interbolt.matched_rule" not in attrs

    def test_endorsement_note_none_is_absent(self) -> None:
        reporter = OTelReporter()
        reporter.export(_make_endorsement(note=None))
        attrs = _exporter.get_finished_spans()[0].attributes
        assert attrs is not None
        assert "interbolt.endorsement.note" not in attrs


class TestNoSensitiveFieldsLeak:
    def test_event_attributes_exclude_labels_and_condition(self) -> None:
        reporter = OTelReporter()
        reporter.export(_make_event())
        attrs = _exporter.get_finished_spans()[0].attributes
        assert attrs is not None
        assert not any("contributing_labels" in key for key in attrs)
        assert not any("matched_condition" in key for key in attrs)


class TestImportGuard:
    def test_import_without_opentelemetry_raises_config_error(self) -> None:
        sys.modules.pop("interbolt.reporting.otel", None)
        real_opentelemetry_modules = {
            name: mod
            for name, mod in sys.modules.items()
            if name.startswith("opentelemetry")
        }
        for name in real_opentelemetry_modules:
            sys.modules.pop(name, None)
        sys.modules["opentelemetry"] = None  # type: ignore[assignment]
        try:
            with pytest.raises(InterboltConfigError, match=r"interbolt\[otel\]"):
                importlib.import_module("interbolt.reporting.otel")
        finally:
            sys.modules.pop("opentelemetry", None)
            sys.modules.pop("interbolt.reporting.otel", None)
            sys.modules.update(real_opentelemetry_modules)
            importlib.import_module("interbolt.reporting.otel")

    def test_bare_import_interbolt_succeeds_without_extra(self) -> None:
        import interbolt

        assert interbolt.__version__


class TestReporterExceptionIsolation:
    def test_broken_export_is_swallowed_by_emit(self, mocker: MockerFixture) -> None:
        reporter = OTelReporter()
        mocker.patch(
            "interbolt.reporting.otel.trace.get_current_span",
            side_effect=RuntimeError("boom"),
        )
        _emit(reporter, _make_event())  # must not raise
