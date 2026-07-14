from __future__ import annotations

import inspect
import logging
from contextvars import ContextVar
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
