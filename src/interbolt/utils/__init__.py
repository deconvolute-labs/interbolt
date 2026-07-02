from __future__ import annotations

import logging
import os
from contextvars import ContextVar
from pathlib import Path

import platformdirs

logger = logging.getLogger("interbolt")

current_run_id: ContextVar[str | None] = ContextVar("interbolt_run_id", default=None)
"""The active run's identity, bound by `Runtime.agent_context` for its duration.

A leaf-level primitive (stdlib `contextvars` only) so both `taint/` and
`runtime/` can read/set it without either importing the other: `taint()`
reads it to attribute run-scoped ingress (§15.8 run-level gating); `runtime/`
sets it in `agent_context` and reads it in the guard wrappers.
"""

# TODO: Add this format for the logger
LOG_FORMAT: str = "[%(levelname)s] %(asctime)s %(message)s"
DATE_FORMAT: str = "%H:%M:%S"


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


def cache_dir() -> Path:
    """Return the per-user cache directory interbolt should use.

    Honors the `INTERBOLT_CACHE_DIR` environment variable; otherwise resolves the
    OS-conventional per-user cache directory via `platformdirs`.

    Returns:
        The cache directory path. Not created by this function.
    """
    env_dir = os.environ.get("INTERBOLT_CACHE_DIR")
    if env_dir:
        return Path(env_dir)
    return Path(platformdirs.user_cache_dir(appname="interbolt"))
