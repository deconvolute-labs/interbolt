"""The run-tainted-without-attribution diagnostic, checked at agent_context exit."""

from __future__ import annotations

from datetime import UTC, datetime

from interbolt.constants import EVENT_SCHEMA_VERSION
from interbolt.models.core import Diagnostic
from interbolt.models.protocols import Reporter
from interbolt.taint import clear_run_diagnostics, run_diagnostic_state
from interbolt.utils import current_trace_context, get_logger

_logger = get_logger("enforcement")


def emit_run_diagnostic(
    *,
    run_id: str,
    agent_id: str,
    reporter: Reporter,
    policy_fingerprint: str,
) -> None:
    """Warn and export a `Diagnostic` if the run went tainted with no attribution.

    Reads and clears the diagnostic bookkeeping `check()` accumulated for
    `run_id` (a no-op if nothing was ever recorded, including when
    `configure(diagnostics=False)`). Fires only when the run reached
    `run_tainted=True` and at least one call happened after that point, but
    none of those calls ever produced a non-empty `contributing_labels`:
    value-level attribution silently failed somewhere between `taint()` and
    the guarded call.

    Args:
        run_id: The run that just exited its `agent_context`.
        agent_id: The agent the run's `agent_context` was opened with.
        reporter: Where the resulting `Diagnostic` goes.
        policy_fingerprint: The producing policy's fingerprint.
    """
    any_contributing_labels_seen, calls_since_taint, untrusted_sources = (
        run_diagnostic_state(run_id)
    )
    clear_run_diagnostics(run_id)
    if calls_since_taint == 0 or any_contributing_labels_seen:
        return

    _logger.warning(
        "run %s reached run_tainted=True via %s, but 0 of %d calls after "
        "that point carried any contributing_labels; value-level attribution "
        "may be getting stripped between taint() and your guarded calls "
        "(common causes: str(), f-string embedding, .join() on a plain separator)",
        run_id,
        ", ".join(untrusted_sources) or "<unknown>",
        calls_since_taint,
    )

    trace_id, span_id = current_trace_context() or (None, None)
    diagnostic = Diagnostic(
        schema_version=EVENT_SCHEMA_VERSION,
        trace_id=trace_id,
        span_id=span_id,
        policy_fingerprint=policy_fingerprint,
        timestamp=datetime.now(UTC),
        agent_id=agent_id,
        run_id=run_id,
        session_id=None,
        ingress_sources=untrusted_sources,
        calls_since_taint=calls_since_taint,
    )
    try:
        reporter.export(diagnostic)
    except Exception:  # noqa: BLE001 - a reporter failure must never affect a run
        _logger.warning("reporter %r failed to export %r", reporter, "Diagnostic")
