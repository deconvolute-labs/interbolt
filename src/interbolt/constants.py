from __future__ import annotations

import os

from interbolt.errors import InterboltConfigError

DEFAULT_NAMESPACE: str = "default"
DEFAULT_AGENT_ID: str = "default"

ENV_MODE: str = "INTERBOLT_MODE"
ENV_AUDIT: str = "INTERBOLT_AUDIT"
ENV_RECURSION_DEPTH: str = "INTERBOLT_RECURSION_DEPTH"
ENV_CACHE_DIR: str = "INTERBOLT_CACHE_DIR"

DEFAULT_RECURSION_DEPTH: int = 4
RECURSION_DEPTH_MAX: int = 10
EVENT_SCHEMA_VERSION: int = 3
AUDIT_MIN_MATCH_LENGTH: int = 12

RECORD_TYPE_EVENT: str = "event"
RECORD_TYPE_FINDING: str = "finding"

TRIFECTA_FROM_UNTRUSTED: str = "from_untrusted"
TRIFECTA_COMPUTABLE_LEGS: frozenset[str] = frozenset({TRIFECTA_FROM_UNTRUSTED})

RUN_COMPUTABLE_FIELDS: frozenset[str] = frozenset({"tainted"})


def _resolve_recursion_depth() -> int:
    """Resolve the container-recursion depth once, at import time.

    Reads `INTERBOLT_RECURSION_DEPTH`, falling back to `DEFAULT_RECURSION_DEPTH`.
    Both `taint()` and `check()`/`guard` read the resulting constant, so
    ingress labeling and sink collection are bounded identically (§6.6).

    Raises:
        InterboltConfigError: If the env var is set but is not an integer in
            `[1, RECURSION_DEPTH_MAX]`.
    """
    raw = os.environ.get(ENV_RECURSION_DEPTH)
    if raw is None:
        return DEFAULT_RECURSION_DEPTH
    try:
        depth = int(raw)
    except ValueError as exc:
        raise InterboltConfigError(
            f"{ENV_RECURSION_DEPTH}={raw!r} is not an integer"
        ) from exc
    if not (1 <= depth <= RECURSION_DEPTH_MAX):
        raise InterboltConfigError(
            f"{ENV_RECURSION_DEPTH}={raw!r} must be in [1, {RECURSION_DEPTH_MAX}]"
        )
    return depth


RECURSION_DEPTH: int = _resolve_recursion_depth()
