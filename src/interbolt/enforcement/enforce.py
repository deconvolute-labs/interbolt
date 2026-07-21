"""enforce_decision(): turn a computed Decision into control flow."""

from __future__ import annotations

import inspect

from interbolt.errors import ApprovalDenied, InterboltUsageError, PolicyViolation
from interbolt.models.core import Action, Decision
from interbolt.models.protocols import ApprovalResolver


def _violation_message(decision: Decision) -> str:
    if decision.matched_rule:
        return (
            f"blocked by policy rule {decision.matched_rule!r} "
            f"for tool {decision.tool!r}"
        )
    return f"blocked by default sink action for tool {decision.tool!r}"


def _approval_message(decision: Decision) -> str:
    return f"approval denied for tool {decision.tool!r}"


async def enforce_decision(
    decision: Decision, *, approval_resolver: ApprovalResolver
) -> None:
    """Enforce `decision` at an asynchronous call site.

    A no-op on `allow`. Raises `PolicyViolation` on `block`. On
    `require_approval`, calls `approval_resolver` and raises `ApprovalDenied`
    if it denies. An awaitable result from `approval_resolver` is awaited.

    For a synchronous call site, use `enforce_decision_sync` instead: same
    contract, no `await` required.

    Args:
        decision: The decision to enforce, as returned by `check()`.
        approval_resolver: Resolves a `require_approval` decision to allow
            or deny.

    Raises:
        PolicyViolation: If `decision.action` is `block`.
        ApprovalDenied: If `decision.action` is `require_approval` and
            `approval_resolver` denies it.
    """
    if decision.action is Action.ALLOW:
        return
    if decision.action is Action.BLOCK:
        raise PolicyViolation(_violation_message(decision), decision=decision)
    result = approval_resolver(decision)
    if inspect.isawaitable(result):
        result = await result
    if not result:
        raise ApprovalDenied(_approval_message(decision), decision=decision)
    # TODO: emit a reporter record for the approval resolution outcome itself,
    # not just the require_approval Event already emitted by check().


def enforce_decision_sync(
    decision: Decision, *, approval_resolver: ApprovalResolver
) -> None:
    """Synchronous counterpart to `enforce_decision`.

    Same contract as `enforce_decision`; use this when the call site cannot
    `await`. Raises `InterboltUsageError` if `approval_resolver` returns an
    awaitable, since a sync call site has no way to await it.

    Args:
        decision: The decision to enforce, as returned by `check()`.
        approval_resolver: Resolves a `require_approval` decision to allow
            or deny.

    Raises:
        PolicyViolation: If `decision.action` is `block`.
        ApprovalDenied: If `decision.action` is `require_approval` and
            `approval_resolver` denies it.
        InterboltUsageError: If `approval_resolver` returns an awaitable at
            this synchronous call site.
    """
    if decision.action is Action.ALLOW:
        return
    if decision.action is Action.BLOCK:
        raise PolicyViolation(_violation_message(decision), decision=decision)
    result = approval_resolver(decision)
    if inspect.isawaitable(result):
        if inspect.iscoroutine(result):
            result.close()
        raise InterboltUsageError(
            "a sync call site cannot use an ApprovalResolver that returns an awaitable"
        )
    if not result:
        raise ApprovalDenied(_approval_message(decision), decision=decision)
    # TODO: emit a reporter record for the approval resolution outcome itself,
    # not just the require_approval Event already emitted by check().
