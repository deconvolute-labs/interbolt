from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from contextvars import ContextVar
from functools import lru_cache
from typing import Any

logger = logging.getLogger("interbolt")

current_run_id: ContextVar[str | None] = ContextVar("interbolt_run_id", default=None)
"""The active run's identity, bound by `Runtime.agent_context` for its duration.

A leaf-level primitive shared by `taint/` and `runtime/` without either
importing the other: `taint()` reads it to attribute run-scoped ingress;
`runtime/` sets it in `agent_context` and reads it in the guard wrappers.
"""

current_agent_id: ContextVar[str | None] = ContextVar(
    "interbolt_agent_id", default=None
)
"""The active agent's identity, bound by `Runtime.agent_context`/guard wrappers.

A leaf-level primitive, the same shape as `current_run_id` above and for the
same reason: `taint/endorse.py` reads it to attribute an `Endorsement`
record's `agent_id` without importing `runtime/`; `runtime/guard.py`
re-exports this same `ContextVar` rather than defining its own.
"""


def get_logger(name: str | None = None) -> logging.Logger:
    """Return the library logger, or a child of it.

    Args:
        name: Optional dotted suffix appended to the "interbolt" logger name.

    Returns:
        The "interbolt" logger, or "interbolt.<name>" if `name` is given.
    """
    if name is None:
        return logger
    return logger.getChild(name)


@lru_cache(maxsize=1)
def _trace_reader() -> Callable[[], tuple[str, str] | None] | None:
    """Resolve, once, the OpenTelemetry trace-context reader, or `None`.

    Soft-imports `opentelemetry.trace`; when the package is absent, this
    resolves to `None` forever (the `lru_cache` makes the ImportError check
    happen exactly once per process, not on every `current_trace_context()`
    call).
    """
    try:
        from opentelemetry import trace
    except ImportError:
        return None

    def _read() -> tuple[str, str] | None:
        span = trace.get_current_span()
        ctx = span.get_span_context()
        if not ctx.is_valid or not (ctx.trace_flags.sampled or span.is_recording()):
            return None
        return format(ctx.trace_id, "032x"), format(ctx.span_id, "016x")

    return _read


def current_trace_context() -> tuple[str, str] | None:
    """Return the active span's `(trace_id, span_id)` as W3C hex strings.

    `None` when OpenTelemetry is absent, no span is active, or the active
    context is neither sampled nor recording. `enforcement.check()` and the
    `endorse()` emitter call this to stamp `trace_id`/`span_id` on emitted
    records without `taint/`, `policy/`, or `enforcement/` ever importing
    OpenTelemetry directly.
    """
    reader = _trace_reader()
    return None if reader is None else reader()


def bind_arguments(
    sig: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Bind a call's positional/keyword arguments to `sig`, defaults applied.

    A leaf-level primitive shared by `runtime/guard.py` (the `guard`
    decorator's argument collection) and `taint/` (`track_model_call`'s
    argument collection), without either importing the other.
    """
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)
