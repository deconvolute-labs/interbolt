from __future__ import annotations

import os

from interlock.errors import InterlockConfigError

DEFAULT_NAMESPACE: str = "default"
DEFAULT_AGENT_ID: str = "default"

ENV_MODE: str = "INTERLOCK_MODE"
ENV_AUDIT: str = "INTERLOCK_AUDIT"
ENV_RECURSION_DEPTH: str = "INTERLOCK_RECURSION_DEPTH"
ENV_CACHE_DIR: str = "INTERLOCK_CACHE_DIR"

DEFAULT_RECURSION_DEPTH: int = 4
RECURSION_DEPTH_MAX: int = 10
EVENT_SCHEMA_VERSION: int = 1
AUDIT_MIN_MATCH_LENGTH: int = 12

TRIFECTA_FROM_UNTRUSTED: str = "from_untrusted"
TRIFECTA_COMPUTABLE_LEGS: frozenset[str] = frozenset({TRIFECTA_FROM_UNTRUSTED})


def _resolve_recursion_depth() -> int:
    """Resolve the container-recursion depth once, at import time.

    Reads `INTERLOCK_RECURSION_DEPTH`, falling back to `DEFAULT_RECURSION_DEPTH`.
    Both `taint()` and `check()`/`guard` read the resulting constant, so
    ingress labeling and sink collection are bounded identically (§6.6).

    Raises:
        InterlockConfigError: If the env var is set but is not an integer in
            `[1, RECURSION_DEPTH_MAX]`.
    """
    raw = os.environ.get(ENV_RECURSION_DEPTH)
    if raw is None:
        return DEFAULT_RECURSION_DEPTH
    try:
        depth = int(raw)
    except ValueError as exc:
        raise InterlockConfigError(
            f"{ENV_RECURSION_DEPTH}={raw!r} is not an integer"
        ) from exc
    if not (1 <= depth <= RECURSION_DEPTH_MAX):
        raise InterlockConfigError(
            f"{ENV_RECURSION_DEPTH}={raw!r} must be in [1, {RECURSION_DEPTH_MAX}]"
        )
    return depth


RECURSION_DEPTH: int = _resolve_recursion_depth()
