"""The process-current runtime: the global, the lock, and its read/write pair.

`configure()` is the only writer (`_set_current`); the module-level
dispatch surface (`guard`/`check`/`agent`) and `get_runtime()` are the readers.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from interbolt.errors import InterboltUsageError

if TYPE_CHECKING:
    from interbolt.runtime.runtime import Runtime

_current_runtime: Runtime | None = None
_runtime_lock = threading.Lock()


def _set_current(runtime: Runtime) -> None:
    """Install `runtime` as process-current. Called only by `configure()`."""
    global _current_runtime
    with _runtime_lock:
        _current_runtime = runtime


def _current() -> Runtime:
    """Return the process-current runtime, or raise if configure() hasn't run.

    Reads the module-global reference without the lock: in CPython a plain
    attribute read is atomic, and `_runtime_lock` only needs to serialize
    concurrent writers (`configure()`). Guarding this read would put lock
    contention on every guarded call's hot path for no
    correctness benefit. Do not add a lock here.
    """
    runtime = _current_runtime
    if runtime is None:
        raise InterboltUsageError(
            "interbolt.configure() must be called before using the bare guard/check API"
        )
    return runtime


def get_runtime() -> Runtime:
    """Return the process-current runtime.

    The `get_tracer_provider()` analog. Use this to reach the live runtime
    later, for example to call `Runtime.add_reporter`.

    Returns:
        The process-current `Runtime`.

    Raises:
        InterboltUsageError: If `configure()` has not been called yet.
    """
    return _current()
