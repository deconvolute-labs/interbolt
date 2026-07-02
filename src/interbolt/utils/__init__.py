from __future__ import annotations

import logging
from contextvars import ContextVar

logger = logging.getLogger("interbolt")

current_run_id: ContextVar[str | None] = ContextVar("interbolt_run_id", default=None)
"""The active run's identity, bound by `Runtime.agent_context` for its duration.

A leaf-level primitive shared by `taint/` and `runtime/` without either
importing the other: `taint()` reads it to attribute run-scoped ingress
(spec §15.8); `runtime/` sets it in `agent_context` and reads it in the
guard wrappers.
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
