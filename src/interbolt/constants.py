from __future__ import annotations

import os

from interbolt.errors import InterboltConfigError

DEFAULT_NAMESPACE: str = "default"
DEFAULT_AGENT_ID: str = "default"

ENV_MODE: str = "INTERBOLT_MODE"
ENV_AUDIT: str = "INTERBOLT_AUDIT"
ENV_RECURSION_DEPTH: str = "INTERBOLT_RECURSION_DEPTH"

DEFAULT_RECURSION_DEPTH: int = 4
RECURSION_DEPTH_MAX: int = 10
EVENT_SCHEMA_VERSION: int = 8
AUDIT_MIN_MATCH_LENGTH: int = 12
AUDIT_FINDINGS_MAX: int = 10_000
AUDIT_MAX_TRACKED_RUNS: int = 1_000

RECORD_TYPE_EVENT: str = "event"
RECORD_TYPE_FINDING: str = "finding"
RECORD_TYPE_ENDORSEMENT: str = "endorsement"

# The builtin container types `taint()`, `collect_labels()`, and the audit
# walk all recurse into identically; a single shared definition keeps the
# three traversals from silently drifting apart. `dict`/`Mapping` are
# handled separately since a `Mapping` needs key-and-value recursion, not
# plain iteration.
# Deliberately not given an explicit `tuple[type, ...]` annotation: that
# would widen the type and break `isinstance(value, CONTAINER_TYPES)`
# narrowing at every call site. Left for mypy to infer as the precise
# heterogeneous tuple type instead.
CONTAINER_TYPES = (list, tuple, set, frozenset)

TRIFECTA_FROM_UNTRUSTED: str = "from_untrusted"
TRIFECTA_COMPUTABLE_LEGS: frozenset[str] = frozenset({TRIFECTA_FROM_UNTRUSTED})

RUN_COMPUTABLE_FIELDS: frozenset[str] = frozenset({"tainted"})
AGENT_COMPUTABLE_FIELDS: frozenset[str] = frozenset({"id", "groups"})


def _resolve_recursion_depth() -> int:
    """Resolve the container-recursion depth once, at import time.

    Reads `INTERBOLT_RECURSION_DEPTH`, falling back to `DEFAULT_RECURSION_DEPTH`.
    `taint()` and `check()`/`guard` both use the result to bound how deep
    they recurse into containers.

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
