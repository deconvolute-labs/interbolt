from __future__ import annotations

from collections.abc import Awaitable
from typing import Protocol

from interbolt.models.core import Decision, Endorsement, Event, Finding


class Reporter(Protocol):
    """The interface `enforcement` emits decision events and audit findings through."""

    def export(self, event: Event | Finding | Endorsement) -> None:
        """Emit a decision event, audit finding, or endorsement record.

        Args:
            event: The record to emit.

        Implementations must return immediately; blocking here delays the
        decision that triggered it.
        """
        ...


class ApprovalResolver(Protocol):
    """Resolves a `require_approval` decision to allow or deny.

    Called synchronously at a sync call site and awaited at an async call
    site. A sync call site needs a resolver that returns a plain `bool`.
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
