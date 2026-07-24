"""Leaf-level shared primitives: logging, identity contextvars, argument binding."""

from __future__ import annotations

from interbolt.utils.context import (
    current_agent_id,
    current_run_id,
    current_trace_context,
)
from interbolt.utils.log import get_logger, logger
from interbolt.utils.signatures import bind_arguments

__all__ = [
    "logger",
    "get_logger",
    "current_run_id",
    "current_agent_id",
    "current_trace_context",
    "bind_arguments",
]
