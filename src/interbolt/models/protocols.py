from __future__ import annotations

from collections.abc import Awaitable
from typing import Protocol, runtime_checkable

from interbolt.models.core import Decision, Event, Finding


@runtime_checkable
class Reporter(Protocol):
    """The reporting seam. `enforcement` emits through this, never a concrete type."""

    def export(self, event: Event | Finding) -> None:
        """Emit a decision event or audit finding.

        Args:
            event: The record to emit.

        A reporter's `export` must never block or delay a decision; that is the
        reporter author's responsibility, not a guarantee the engine provides.
        """
        ...


@runtime_checkable
class ApprovalResolver(Protocol):
    """Resolves a `require_approval` decision to allow or deny.

    Invoked synchronously at a sync call site and asynchronously (awaited) at an
    async call site; a sync call site cannot use a resolver that only returns an
    awaitable.
    """

    def __call__(self, decision: Decision) -> bool | Awaitable[bool]:
        """Decide whether to allow the call that produced `decision`.

        Args:
            decision: The decision that requires approval.

        Returns:
            `True` to allow the call, `False` to deny it. May return an
            awaitable when called from an async call site.
        """
        ...


def auto_deny(decision: Decision) -> bool:
    """The default `ApprovalResolver`: deny every approval request.

    Args:
        decision: The decision that requires approval.

    Returns:
        Always `False`.
    """
    return False
