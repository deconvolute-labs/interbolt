from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from interbolt.models.core import Decision


class InterboltError(Exception):
    """Base class for every exception interbolt raises as part of a policy decision."""


class PolicyViolation(InterboltError):
    """Raised when a guarded call is blocked by policy.

    Attributes:
        decision: The `Decision` that produced the block.
    """

    def __init__(self, message: str, *, decision: Decision) -> None:
        super().__init__(message)
        self.decision = decision


class PolicyEvaluationError(InterboltError):
    """Raised when policy evaluation itself fails.

    Covers a malformed policy file at load time, and a CEL evaluation error
    (missing argument, `None` value, non-marshalable value) under `enforce` mode
    at call time.

    Attributes:
        decision: The partial `Decision`, if one was assembled before the error.
            `None` for load-time failures, where no call context exists yet.
    """

    def __init__(self, message: str, *, decision: Decision | None = None) -> None:
        super().__init__(message)
        self.decision = decision


class ApprovalDenied(InterboltError):
    """Raised when a `require_approval` decision is denied by the approval resolver.

    Attributes:
        decision: The `Decision` that required approval.
    """

    def __init__(self, message: str, *, decision: Decision) -> None:
        super().__init__(message)
        self.decision = decision


class InterboltConfigError(InterboltError, ValueError):
    """Raised for an invalid configuration value.

    Examples: an unrecognized `mode`, an out-of-range
    `INTERBOLT_RECURSION_DEPTH`, a tool or namespace name containing a dot.
    Subclasses `ValueError` as well as `InterboltError`, so callers can catch it
    either as interbolt's own type or by its builtin semantics.
    """


class InterboltUsageError(InterboltError, RuntimeError):
    """Raised when the public API is used out of sequence.

    Example: calling `check()`/`guard` before `configure()` has run.
    Subclasses `RuntimeError` as well as `InterboltError`, so callers can catch
    it either as interbolt's own type or by its builtin semantics.
    """
