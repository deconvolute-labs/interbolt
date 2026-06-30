from __future__ import annotations

import logging
import os
from pathlib import Path

import platformdirs

logger = logging.getLogger("interlock")
logger.addHandler(logging.NullHandler())

# TODO: Add this format for the logger
LOG_FORMAT: str = "[%(levelname)s] %(asctime)s %(message)s"
DATE_FORMAT: str = "%H:%M:%S"


def get_logger(name: str | None = None) -> logging.Logger:
    """Return the library logger, or a child of it.

    Args:
        name: Optional dotted suffix appended to the "interlock" logger name.

    Returns:
        The "interlock" logger, or "interlock.<name>" if `name` is given.
    """
    if name is None:
        return logger
    return logger.getChild(name)


def cache_dir() -> Path:
    """Return the per-user cache directory interlock should use.

    Honors the `INTERLOCK_CACHE_DIR` environment variable; otherwise resolves the
    OS-conventional per-user cache directory via `platformdirs`.

    Returns:
        The cache directory path. Not created by this function.
    """
    env_dir = os.environ.get("INTERLOCK_CACHE_DIR")
    if env_dir:
        return Path(env_dir)
    return Path(platformdirs.user_cache_dir(appname="interlock"))
