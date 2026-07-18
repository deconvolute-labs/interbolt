from __future__ import annotations

import json
import os
import threading
from collections.abc import Sequence
from pathlib import Path

from interbolt.constants import (
    RECORD_TYPE_ENDORSEMENT,
    RECORD_TYPE_EVENT,
    RECORD_TYPE_FINDING,
)
from interbolt.errors import InterboltConfigError
from interbolt.models.core import Action, Decision, Endorsement, Event, Finding
from interbolt.models.protocols import Reporter
from interbolt.utils import get_logger

_logger = get_logger("reporting")

_ACTION_COLOR = {
    Action.ALLOW: "green",
    Action.BLOCK: "red",
    Action.REQUIRE_APPROVAL: "yellow",
}


class NullReporter:
    """The default reporter: a no-op. Keeps the library fully local by default."""

    def export(self, event: Event | Finding | Endorsement) -> None:
        """Discard the record."""
        return None


class InMemoryReporter:
    """Captures every exported record in memory; the testing/audit assertion surface."""

    def __init__(self) -> None:
        self.events: list[Event] = []
        self.decisions: list[Decision] = []
        self.findings: list[Finding] = []
        self.endorsements: list[Endorsement] = []

    def export(self, event: Event | Finding | Endorsement) -> None:
        """Capture the record."""
        if isinstance(event, Event):
            self.events.append(event)
            self.decisions.append(event.decision)
        elif isinstance(event, Finding):
            self.findings.append(event)
        elif isinstance(event, Endorsement):
            self.endorsements.append(event)
        else:
            raise TypeError(f"Unexpected event type: {type(event)}")

    def clear(self) -> None:
        """Discard every captured record."""
        self.events.clear()
        self.decisions.clear()
        self.findings.clear()
        self.endorsements.clear()


class LoggingReporter:
    """Emits every record via the library logger, at DEBUG."""

    def export(self, event: Event | Finding | Endorsement) -> None:
        """Log the record."""
        _logger.debug("export: %r", event)


class JsonlReporter:
    """Appends every exported record as one JSON line to a file.

    Opens the destination file fresh on every `export()` call (append mode,
    flush, and `fsync`), so a record is durable on disk before `export()`
    returns. Each line carries a `"record_type"` key (`"event"` or
    `"finding"`) alongside the record's own fields, so a reader can recover
    the concrete type without guessing from field shape.

    Logs one WARNING-level line after the first successful write, naming the
    destination path, so where the output landed is visible even without a
    `LoggingReporter` configured.

    Attributes:
        path: The destination file.
    """

    def __init__(self, path: str | Path) -> None:
        """Prepare the destination file for appending.

        Args:
            path: The destination JSONL file, appended to; created (with
                parent directories) on first write if it doesn't exist.

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

    def export(self, event: Event | Finding | Endorsement) -> None:
        """Append one JSON line for this record."""
        if isinstance(event, Event):
            record_type = RECORD_TYPE_EVENT
        elif isinstance(event, Finding):
            record_type = RECORD_TYPE_FINDING
        else:
            record_type = RECORD_TYPE_ENDORSEMENT
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


class CompositeReporter:
    """Fans a record out to multiple reporters, isolating each one's failures.

    One broken sub-reporter never prevents the record from reaching the
    others, mirroring the fire-and-forget contract `enforcement` already
    applies to a single reporter. The sequence is appendable at any time via
    `add()`, thread-safe under a lock; `export()` fans out to a snapshot of
    the list taken at call time, so an `add()` racing an `export()` is safe.
    """

    def __init__(self, reporters: Sequence[Reporter]) -> None:
        """Wrap an initial sequence of reporters."""
        self._lock = threading.Lock()
        self._reporters: list[Reporter] = list(reporters)

    @property
    def reporters(self) -> tuple[Reporter, ...]:
        """A snapshot of the wrapped reporters, in call order."""
        with self._lock:
            return tuple(self._reporters)

    def add(self, reporter: Reporter) -> None:
        """Append a reporter to the fan-out sequence.

        Args:
            reporter: The reporter to add.
        """
        with self._lock:
            self._reporters.append(reporter)

    def export(self, event: Event | Finding | Endorsement) -> None:
        """Export the record to a snapshot of every wrapped reporter, in order."""
        with self._lock:
            snapshot = list(self._reporters)
        for reporter in snapshot:
            try:
                reporter.export(event)
            except Exception:  # noqa: BLE001 -- one reporter's failure must not block another
                _logger.warning(
                    "reporter %r failed to export %r", reporter, type(event).__name__
                )


def describe_event(event: Event) -> str:
    """Build a one-line, rich-markup-tagged human summary of an `Event`.

    The building block for a custom console/CLI reporter: pass the result
    to a `rich.console.Console.print` (or strip the `[tag]...[/tag]` markup
    for a plain-text sink). Used by `interbolt inspect` internally.

    Args:
        event: The event to describe.

    Returns:
        A rich-markup string summarizing the decision.
    """
    color = _ACTION_COLOR.get(event.decision.action, "white")
    rule = event.decision.matched_rule or "default"
    untrusted = ", ".join(sorted(event.decision.untrusted_sources)) or "-"
    sources = ", ".join(sorted(event.sources)) or "-"
    lineage = ", ".join(sorted(event.sources)) or "-"
    run_tainted = "[red bold]True[/red bold]" if event.decision.run_tainted else "False"
    return (
        f"{event.decision.tool}  "
        f"[{color}]{event.decision.action.value}[/{color}]  "
        f"rule={rule}  mode={event.decision.mode.value}  "
        f"untrusted_sources={{{untrusted}}}  "
        f"run_tainted={run_tainted}  sources={{{sources}}}  lineage=({lineage})"
    )


def describe_decision(decision: Decision) -> str:
    """Build a one-line, rich-markup-tagged human summary of a `Decision`.

    For a caller catching `PolicyViolation`/`ApprovalDenied` (both carry
    `.decision`) or holding a `Decision` returned from `check()` directly:
    a ready-made explanation of what happened and why, without assembling
    one from `matched_rule`/`untrusted_sources`/`matched_condition` by hand.

    Args:
        decision: The decision to describe.

    Returns:
        A rich-markup string summarizing the decision, including the
        matched rule's CEL condition text when one is available.
    """
    color = _ACTION_COLOR.get(decision.action, "white")
    rule = decision.matched_rule or "no match (default sink action)"
    condition = (
        f"  when={decision.matched_condition!r}" if decision.matched_condition else ""
    )
    untrusted = ", ".join(sorted(decision.untrusted_sources)) or "-"
    return (
        f"{decision.tool}  [{color}]{decision.action.value}[/{color}]  "
        f"rule={rule}{condition}  mode={decision.mode.value}  "
        f"untrusted_sources={{{untrusted}}}"
    )


def describe_finding(finding: Finding) -> str:
    """Build a one-line, rich-markup-tagged human summary of a `Finding`.

    Args:
        finding: The finding to describe.

    Returns:
        A rich-markup string summarizing the laundering-audit hit.
    """
    return (
        f"[yellow]finding[/yellow]  source={finding.source}  "
        f"tool={finding.tool}  argument={finding.argument}"
    )


def describe_endorsement(endorsement: Endorsement) -> str:
    """Build a one-line, rich-markup-tagged human summary of an `Endorsement`.

    Args:
        endorsement: The endorsement to describe.

    Returns:
        A rich-markup string summarizing the endorsement.
    """
    lineage = ", ".join(endorsement.lineage) or "-"
    note = f"  note={endorsement.note!r}" if endorsement.note else ""
    return (
        f"[cyan]endorsement[/cyan]  kind={endorsement.kind}  lineage=({lineage}){note}"
    )
