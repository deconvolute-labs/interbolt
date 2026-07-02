from __future__ import annotations

import json
import os
from pathlib import Path

from interbolt.constants import RECORD_TYPE_EVENT, RECORD_TYPE_FINDING
from interbolt.errors import InterboltConfigError
from interbolt.models.core import Decision, Event, Finding
from interbolt.utils import get_logger

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


class JsonlReporter:
    """Appends every exported record as one JSON line to a file.

    Opens the destination file fresh on every `export()` call (append mode,
    flush, and `fsync`), so a record is durable on disk before `export()`
    returns. Each line carries a `"record_type"` key (`"event"` or
    `"finding"`) alongside the record's own fields, so a reader can recover
    the concrete type without guessing from field shape.

    Logs one WARNING-level line after the first successful write, naming the
    destination path, so the library is not silent by default about where
    its output landed even without a `LoggingReporter` configured.

    Attributes:
        path: The destination file.
    """

    def __init__(self, path: str | Path) -> None:
        """Prepare the destination file for appending.

        Args:
            path: The destination JSONL file. Appended to, never truncated;
                created (along with parent directories) on first write if it
                does not already exist.

        Raises:
            InterboltConfigError: If `path` is an existing directory, or its
                parent directories cannot be created.
        """
        self.path = Path(path)
        if self.path.is_dir():
            raise InterboltConfigError(f"{self.path} is a directory, not a file")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise InterboltConfigError(
                f"cannot create parent directory for {self.path}: {exc}"
            ) from exc
        self._announced: bool = False

    def export(self, event: Event | Finding) -> None:
        """Append one JSON line for this record.

        Args:
            event: The record to persist.
        """
        record_type = (
            RECORD_TYPE_EVENT if isinstance(event, Event) else RECORD_TYPE_FINDING
        )
        payload = {"record_type": record_type, **event.model_dump(mode="json")}
        line = json.dumps(payload, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        if not self._announced:
            self._announced = True
            _logger.warning(
                "interbolt: wrote provenance log to %s (inspect with "
                "'interbolt inspect %s')",
                self.path,
                self.path,
            )
