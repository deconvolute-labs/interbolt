"""`OTelReporter`: maps decision records onto OpenTelemetry spans at the edge.

Requires the `interbolt[otel]` extra (`opentelemetry-api`). This module is
never imported by the rest of the library; `interbolt/__init__.py` exposes
`OTelReporter` lazily via `__getattr__` so importing bare `interbolt` never
requires OpenTelemetry to be installed.
"""

from __future__ import annotations

from collections.abc import Sequence

from interbolt import __version__ as _version
from interbolt.errors import InterboltConfigError
from interbolt.models.core import Endorsement, Event, Finding
from interbolt.utils import get_logger

try:
    from opentelemetry import trace
except ImportError as exc:
    raise InterboltConfigError(
        "OTelReporter requires the opentelemetry-api package; install it "
        'with `pip install "interbolt[otel]"`'
    ) from exc

_logger = get_logger("reporting.otel")

_EVENT_DECISION = "interbolt.decision"
_EVENT_FINDING = "interbolt.finding"
_EVENT_ENDORSEMENT = "interbolt.endorsement"

_AttributeValue = str | int | bool | Sequence[str]


def _event_attributes(event: Event) -> dict[str, _AttributeValue]:
    """Flatten an `Event` to primitive OTel span-event attributes.

    Excludes `contributing_labels` (unbounded after fan-out) and
    `matched_condition` (may embed sensitive literal text from the policy).
    The full record remains available through the native reporters.
    """
    decision = event.decision
    attrs: dict[str, _AttributeValue] = {
        "interbolt.schema_version": event.schema_version,
        "gen_ai.tool.name": decision.tool,
        "interbolt.outcome": event.outcome,
        "interbolt.decision.action": decision.action.value,
        "interbolt.decision.id": decision.decision_id,
        "interbolt.mode": event.mode.value,
        "interbolt.agent_id": event.agent_id,
        "interbolt.run_id": event.run_id,
        "interbolt.run_tainted": event.run_tainted,
        "interbolt.sources": sorted(event.sources),
        "interbolt.untrusted_sources": sorted(event.untrusted_sources),
        "interbolt.trifecta": sorted(event.trifecta),
    }
    if event.matched_rule is not None:
        attrs["interbolt.matched_rule"] = event.matched_rule
    if event.session_id is not None:
        attrs["interbolt.session_id"] = event.session_id
    return attrs


def _finding_attributes(finding: Finding) -> dict[str, _AttributeValue]:
    """Flatten a `Finding` (laundering-audit hit) to OTel span-event attributes."""
    attrs: dict[str, _AttributeValue] = {
        "interbolt.schema_version": finding.schema_version,
        "gen_ai.tool.name": finding.tool,
        "interbolt.agent_id": finding.agent_id,
        "interbolt.run_id": finding.run_id,
        "interbolt.finding.source": finding.source,
        "interbolt.finding.argument": finding.argument,
    }
    if finding.session_id is not None:
        attrs["interbolt.session_id"] = finding.session_id
    return attrs


def _endorsement_attributes(endorsement: Endorsement) -> dict[str, _AttributeValue]:
    """Flatten an `Endorsement` to OTel span-event attributes."""
    attrs: dict[str, _AttributeValue] = {
        "interbolt.schema_version": endorsement.schema_version,
        "interbolt.agent_id": endorsement.agent_id,
        "interbolt.run_id": endorsement.run_id,
        "interbolt.endorsement.kind": endorsement.kind,
    }
    if endorsement.session_id is not None:
        attrs["interbolt.session_id"] = endorsement.session_id
    if endorsement.note is not None:
        attrs["interbolt.endorsement.note"] = endorsement.note
    return attrs


class OTelReporter:
    """Maps `Event`/`Finding`/`Endorsement` records onto OpenTelemetry spans.

    Never the native record format: Interbolt's own versioned schema
    (`Event`/`Finding`/`Endorsement`) is the source of truth, and this
    reporter is a mapping at the edge for interop with existing OTel
    instrumentation.

    Two emission paths. When the current span is recording (the common case:
    the host application already wraps the tool call in its own span), the
    record is added as a span event (`interbolt.decision`,
    `interbolt.finding`, or `interbolt.endorsement`) on that span. Otherwise,
    a zero-work span named the same way is created and immediately closed
    via a tracer named `"interbolt"`. With no `TracerProvider` configured,
    this fallback is a no-op by OTel design: nothing is exported.

    Adding a span event or opening a no-work span is an in-memory operation
    on the host's tracing SDK; there is no I/O in this reporter, so it is
    non-blocking by construction.
    """

    def __init__(self) -> None:
        self._tracer = trace.get_tracer("interbolt", _version)

    def export(self, event: Event | Finding | Endorsement) -> None:
        """Emit `event` as a span event or a zero-work fallback span.

        Args:
            event: The record to emit.
        """
        if isinstance(event, Event):
            name, attributes = _EVENT_DECISION, _event_attributes(event)
        elif isinstance(event, Finding):
            name, attributes = _EVENT_FINDING, _finding_attributes(event)
        else:
            name, attributes = _EVENT_ENDORSEMENT, _endorsement_attributes(event)

        span = trace.get_current_span()
        if span.is_recording():
            span.add_event(name, attributes=attributes)
            return
        with self._tracer.start_as_current_span(name, attributes=attributes):
            pass
