from __future__ import annotations

from interlock.models.core import Decision, Event, Finding
from interlock.utils import get_logger

_logger = get_logger("reporting")


class NullReporter:
    """The default reporter: a no-op. Keeps the library fully local by default."""

    def export(self, event: Event | Finding) -> None:
        """Discard the record.

        Args:
            event: The record to discard.
        """
        return None


class InMemoryReporter:
    """Captures every exported record in memory; the testing/audit assertion surface."""

    def __init__(self) -> None:
        self.events: list[Event] = []
        self.decisions: list[Decision] = []
        self.findings: list[Finding] = []

    def export(self, event: Event | Finding) -> None:
        """Capture the record.

        Args:
            event: The record to capture.
        """
        if isinstance(event, Event):
            self.events.append(event)
            self.decisions.append(event.decision)
        else:
            self.findings.append(event)

    def clear(self) -> None:
        """Discard every captured record."""
        self.events.clear()
        self.decisions.clear()
        self.findings.clear()


class LoggingReporter:
    """Emits every record via the library logger, at DEBUG."""

    def export(self, event: Event | Finding) -> None:
        """Log the record.

        Args:
            event: The record to log.
        """
        _logger.debug("export: %r", event)
