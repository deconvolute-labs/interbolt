"""The taint package's process-global state.

Holds the run-ingress registry and the two extension hooks `runtime.configure()`
installs: the `taint()`-time audit observer and the `endorse()`-time emitter.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from interbolt.models.core import Endorsement
from interbolt.utils import current_run_id, get_logger

_logger = get_logger("taint.runstate")

_run_ingress_sources: dict[str, set[str]] = {}
_ingress_lock = threading.Lock()


def _record_ingress(source: str) -> None:
    """Record that `source` tainted data during the active run, if any.

    Records the bare source name, keyed by the ambient `current_run_id`, for
    `enforcement.check()` to resolve later against run-level gating
    (`run.tainted`). Trust itself is resolved at the sink, from the policy's
    `sources` table.
    """
    run_id = current_run_id.get()
    if run_id is None:
        _logger.debug(
            "taint(source=%r) called with no active agent_context; this "
            "ingress cannot be attributed to a run, so run.tainted will not "
            "reflect it for any policy that references it",
            source,
        )
        return
    with _ingress_lock:
        _run_ingress_sources.setdefault(run_id, set()).add(source)


def run_ingress_sources(run_id: str) -> frozenset[str]:
    """Every source name passed to `taint()` while `run_id` was active."""
    with _ingress_lock:
        return frozenset(_run_ingress_sources.get(run_id, ()))


def clear_run_ingress(run_id: str) -> None:
    """Drop the recorded ingress sources for a finished run."""
    with _ingress_lock:
        _run_ingress_sources.pop(run_id, None)


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
