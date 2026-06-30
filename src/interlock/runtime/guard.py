from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, TypeVar, overload

from interlock.constants import DEFAULT_NAMESPACE
from interlock.errors import ApprovalDenied, InterlockUsageError, PolicyViolation
from interlock.models.core import Action, Decision, validate_qualified_name_part

if TYPE_CHECKING:
    from interlock.runtime import Runtime

_F = TypeVar("_F", bound=Callable[..., Any])

current_agent_id: ContextVar[str | None] = ContextVar(
    "interlock_agent_id", default=None
)
current_run_id: ContextVar[str | None] = ContextVar("interlock_run_id", default=None)


def _qualify_tool_name(tool: str) -> str:
    """Resolve a bare or explicitly-qualified tool name to its dotted form.

    A name with no dot gets `constants.DEFAULT_NAMESPACE` prepended. A name
    with one dot is treated as already-qualified `namespace.tool`, per §8.2:
    "@agent.guard(tool='fs.write')  # explicit qualified or bare tool name".
    Neither half may itself contain a dot.
    """
    if "." in tool:
        namespace, _, bare_tool = tool.rpartition(".")
        validate_qualified_name_part(namespace, part="namespace")
        validate_qualified_name_part(bare_tool, part="tool")
        return tool
    validate_qualified_name_part(tool, part="tool")
    return f"{DEFAULT_NAMESPACE}.{tool}"


class AgentHandle:
    """A per-agent decorator handle.

    Captures `agent_id` eagerly (a string, safe at import time); resolves the
    current runtime lazily, at call time, via `runtime_resolver`.
    """

    def __init__(
        self, agent_id: str, *, runtime_resolver: Callable[[], Runtime]
    ) -> None:
        self._agent_id = agent_id
        self._runtime_resolver = runtime_resolver

    @overload
    def guard(self, func: _F) -> _F: ...
    @overload
    def guard(self, *, tool: str | None = None) -> Callable[[_F], _F]: ...
    def guard(self, func: _F | None = None, *, tool: str | None = None) -> Any:  # noqa: ANN401
        """Guard a function with this agent's identity.

        Args:
            func: The function to guard, when used as a bare `@handle.guard`.
            tool: The tool name, when used as `@handle.guard(tool=...)`. The
                bare tool name defaults to the function's name; the namespace
                defaults to `constants.DEFAULT_NAMESPACE`.

        Returns:
            The guarded function, or a decorator if called with arguments.
        """

        def decorator(fn: _F) -> _F:
            return _build_wrapper(
                fn,
                agent_id_source=lambda: self._agent_id,
                tool=tool or fn.__name__,
                runtime_resolver=self._runtime_resolver,
            )

        if func is not None:
            return decorator(func)
        return decorator


def _violation_message(decision: Decision) -> str:
    if decision.matched_rule:
        return (
            f"blocked by policy rule {decision.matched_rule!r} "
            f"for tool {decision.tool!r}"
        )
    return f"blocked by default sink action for tool {decision.tool!r}"


def _approval_message(decision: Decision) -> str:
    return f"approval denied for tool {decision.tool!r}"


def _enforce_decision_sync(rt: Runtime, decision: Decision) -> None:
    if decision.action is Action.ALLOW:
        return
    if decision.action is Action.BLOCK:
        raise PolicyViolation(_violation_message(decision), decision=decision)
    result = rt.approval_resolver(decision)
    if inspect.isawaitable(result):
        raise InterlockUsageError(
            "a sync call site cannot use an ApprovalResolver that returns an awaitable"
        )
    if not result:
        raise ApprovalDenied(_approval_message(decision), decision=decision)


async def _enforce_decision_async(rt: Runtime, decision: Decision) -> None:
    if decision.action is Action.ALLOW:
        return
    if decision.action is Action.BLOCK:
        raise PolicyViolation(_violation_message(decision), decision=decision)
    result = rt.approval_resolver(decision)
    if inspect.isawaitable(result):
        result = await result
    if not result:
        raise ApprovalDenied(_approval_message(decision), decision=decision)


def _bind_args(
    sig: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)


def _build_wrapper[F: Callable[..., Any]](
    fn: F,
    *,
    agent_id_source: Callable[[], str],
    tool: str,
    runtime_resolver: Callable[[], Runtime],
) -> F:
    """Build the sync or async guard wrapper for `fn`, sharing one decision path.

    Detects `inspect.iscoroutinefunction(fn)` once, at decoration time, and
    returns the matching wrapper. Both wrappers extract bound arguments and
    call `rt.check(...)` identically; only the resolver-await and call-through
    differ, per the "one implementation, two surfaces" rule.
    """
    qualified_tool = _qualify_tool_name(tool)
    sig = inspect.signature(fn)

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            rt = runtime_resolver()
            decision = rt.check(
                tool=qualified_tool,
                args=_bind_args(sig, args, kwargs),
                agent_id=agent_id_source(),
                run_id=current_run_id.get(),
            )
            await _enforce_decision_async(rt, decision)
            return await fn(*args, **kwargs)

        return async_wrapper  # type: ignore[return-value]

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        rt = runtime_resolver()
        decision = rt.check(
            tool=qualified_tool,
            args=_bind_args(sig, args, kwargs),
            agent_id=agent_id_source(),
            run_id=current_run_id.get(),
        )
        _enforce_decision_sync(rt, decision)
        return fn(*args, **kwargs)

    return sync_wrapper  # type: ignore[return-value]
