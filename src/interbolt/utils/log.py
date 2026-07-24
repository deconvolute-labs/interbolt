"""The library logger and its accessor."""

from __future__ import annotations

import logging

logger = logging.getLogger("interbolt")


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
