"""The taint package's process-global state.

Holds the run-ingress registry, the run-capability registry, the
run-diagnostic registry, and the two extension hooks `runtime.configure()`
installs: the `taint()`-time audit observer and the `endorse()`-time emitter.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping

from interbolt.constants import (
    RUN_CAPABILITY_EVICTION_MARKER_MAX_TRACKED,
    RUN_CAPABILITY_MAX_TRACKED_RUNS,
)
from interbolt.models.core import Endorsement
from interbolt.utils import current_run_id, get_logger

_logger = get_logger("taint.runstate")

_run_ingress: dict[str, dict[str, dict[str, None]]] = {}
_ingress_lock = threading.Lock()


def record_ingress(entries: Mapping[str, Iterable[str]]) -> None:
    """Record that each source in `entries` tainted data during the active run.

    `entries` maps a source name to the agent ids to credit with ingesting
    it. Keyed by the ambient `current_run_id`, for `enforcement.check()` to
    resolve later against run-level gating. Trust itself is resolved at the
    sink, from the policy's `sources` table.
    """
    if not entries:
        return
    run_id = current_run_id.get()
    if run_id is None:
        _logger.debug(
            "taint(source in %r) called with no active agent_context; this "
            "ingress cannot be attributed to a run, so run.tainted will not "
            "reflect it for any policy that references it",
            tuple(entries),
        )
        return
    with _ingress_lock:
        run_sources = _run_ingress.setdefault(run_id, {})
        for source, agent_ids in entries.items():
            run_sources.setdefault(source, {}).update(dict.fromkeys(agent_ids))


def run_ingress(run_id: str) -> dict[str, tuple[str, ...]]:
    """Every source passed to `taint()` while `run_id` was active, with its agents.

    Ordered by first-seen source name, each source's agent ids ordered by
    first-seen agent.
    """
    with _ingress_lock:
        return {
            source: tuple(agent_ids)
            for source, agent_ids in _run_ingress.get(run_id, {}).items()
        }


def clear_run_ingress(run_id: str) -> None:
    """Drop the recorded ingress sources for a finished run."""
    with _ingress_lock:
        _run_ingress.pop(run_id, None)


_run_capabilities: OrderedDict[str, set[str]] = OrderedDict()
_evicted_run_capabilities: OrderedDict[str, None] = OrderedDict()
_capability_lock = threading.Lock()


def record_capabilities(run_id: str, capabilities: frozenset[str]) -> frozenset[str]:
    """Union `capabilities` into `run_id`'s accumulated set; return the result.

    Returns the run's full accumulated set after recording, in one lock
    acquisition, so a caller never records and then reads across a race.
    Recording an empty `capabilities` still touches the run's entry and
    returns its accumulated set, so a call to a capability-less tool sees
    the legs the run already carries.

    Bounded to `constants.RUN_CAPABILITY_MAX_TRACKED_RUNS` runs, evicting the
    least-recently-touched entry past that cap. An evicted run's accumulated
    legs are gone; a later call under that run id starts a fresh empty set
    rather than raising. Eviction is logged at WARNING and recorded so
    `capability_registry_evicted` can report it.
    """
    with _capability_lock:
        entry = _run_capabilities.setdefault(run_id, set())
        entry.update(capabilities)
        _run_capabilities.move_to_end(run_id)
        while len(_run_capabilities) > RUN_CAPABILITY_MAX_TRACKED_RUNS:
            evicted_run_id, _ = _run_capabilities.popitem(last=False)
            _evicted_run_capabilities[evicted_run_id] = None
            _evicted_run_capabilities.move_to_end(evicted_run_id)
            while (
                len(_evicted_run_capabilities)
                > RUN_CAPABILITY_EVICTION_MARKER_MAX_TRACKED
            ):
                _evicted_run_capabilities.popitem(last=False)
            _logger.warning(
                "record_capabilities(): evicted run %s past %d tracked runs; "
                "its accumulated capability legs were dropped",
                evicted_run_id,
                RUN_CAPABILITY_MAX_TRACKED_RUNS,
            )
        return frozenset(entry)


def run_capabilities(run_id: str) -> frozenset[str]:
    """The trifecta capability legs recorded for `run_id` so far."""
    with _capability_lock:
        return frozenset(_run_capabilities.get(run_id, set()))


def capability_registry_evicted(run_id: str) -> bool:
    """Whether `run_id`'s accumulated capability legs were dropped by eviction."""
    with _capability_lock:
        return run_id in _evicted_run_capabilities


def clear_run_capabilities(run_id: str) -> None:
    """Drop the recorded capability legs for a finished run."""
    with _capability_lock:
        _run_capabilities.pop(run_id, None)
        _evicted_run_capabilities.pop(run_id, None)


class _RunDiagnosticState:
    """One run's bookkeeping for the run-tainted-without-attribution diagnostic."""

    __slots__ = (
        "any_contributing_labels_seen",
        "calls_since_taint",
        "untrusted_sources",
    )

    def __init__(self) -> None:
        self.any_contributing_labels_seen = False
        self.calls_since_taint = 0
        self.untrusted_sources: tuple[str, ...] = ()


_run_diagnostics: dict[str, _RunDiagnosticState] = {}
_diagnostics_lock = threading.Lock()


def record_diagnostic_call(
    run_id: str,
    *,
    run_tainted: bool,
    has_contributing_labels: bool,
    untrusted_sources: tuple[str, ...],
) -> None:
    """Update `run_id`'s diagnostic bookkeeping with one `check()` call's outcome.

    Called from `enforcement.check()` on every call, when diagnostics are
    enabled. Tracks whether any call in the run has ever produced non-empty
    `contributing_labels`, and counts calls made while the run was already
    tainted, plus the run's current untrusted source names, for
    `enforcement.diagnostics.emit_run_diagnostic` to read at run end.
    """
    with _diagnostics_lock:
        state = _run_diagnostics.setdefault(run_id, _RunDiagnosticState())
        if has_contributing_labels:
            state.any_contributing_labels_seen = True
        if run_tainted:
            state.calls_since_taint += 1
            state.untrusted_sources = untrusted_sources


def run_diagnostic_state(run_id: str) -> tuple[bool, int, tuple[str, ...]]:
    """`run_id`'s diagnostic bookkeeping, as recorded by `record_diagnostic_call`.

    Returns all-empty defaults if nothing was ever recorded for this run,
    including when diagnostics are disabled.
    """
    with _diagnostics_lock:
        state = _run_diagnostics.get(run_id)
        if state is None:
            return False, 0, ()
        return (
            state.any_contributing_labels_seen,
            state.calls_since_taint,
            state.untrusted_sources,
        )


def clear_run_diagnostics(run_id: str) -> None:
    """Drop the recorded diagnostic bookkeeping for a finished run."""
    with _diagnostics_lock:
        _run_diagnostics.pop(run_id, None)


_taint_observer: Callable[[str, str, str], None] | None = None
"""The taint()-time content observer, installed by runtime.configure(audit=True).

A plain module-level hook: taint/ owns and exposes this extension point so
runtime/ (the composition root) can wire an AuditRegistry observer without
taint/ importing enforcement/ or runtime/, the same dependency-inversion
shape as `current_run_id`. Internal, not part of the public surface.
"""


def install_taint_observer(cb: Callable[[str, str, str], None] | None) -> None:
    """Install, or clear with `None`, the taint()-time content observer.

    Called only from `runtime.configure()`. `configure(audit=True)` installs
    a closure that resolves the source name against the policy's sources
    table and registers untrusted content with the `AuditRegistry`;
    `configure(audit=False)` installs `None`, so re-`configure()` cleanly
    disables it.
    """
    global _taint_observer
    _taint_observer = cb


def get_taint_observer() -> Callable[[str, str, str], None] | None:
    """The currently installed taint()-time content observer, or `None`."""
    return _taint_observer


_endorsement_emitter: Callable[[Endorsement], None] | None = None
"""The endorse()-time emitter hook, installed by runtime.configure().

Unlike the taint()-time audit observer (`install_taint_observer`, gated
behind `audit=True`), this hook is installed unconditionally on every
`configure()` call: endorsement auditing is not optional whenever a
runtime (and therefore a reporter, even the default `NullReporter`) exists.
Internal, not part of the public surface.
"""


def install_endorsement_emitter(cb: Callable[[Endorsement], None] | None) -> None:
    """Install, or clear with `None`, the endorse()-time emitter hook.

    Called only from `runtime.configure()`, every call, regardless of the
    `audit` flag.
    """
    global _endorsement_emitter
    _endorsement_emitter = cb


def get_endorsement_emitter() -> Callable[[Endorsement], None] | None:
    """The currently installed endorse()-time emitter hook, or `None`."""
    return _endorsement_emitter
