from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, TypeVar, overload

from interbolt.constants import DEFAULT_AGENT_ID, DEFAULT_NAMESPACE
from interbolt.errors import ApprovalDenied, InterboltUsageError, PolicyViolation
from interbolt.models.core import Action, Decision
from interbolt.runtime.current import _current
from interbolt.taint import track_model_call as _track_model_call
from interbolt.utils import bind_arguments
from interbolt.utils import current_agent_id as current_agent_id
from interbolt.utils import current_run_id as current_run_id
from interbolt.utils.names import split_qualified_name, validate_qualified_name_part

if TYPE_CHECKING:
    from interbolt.runtime.runtime import Runtime

_F = TypeVar("_F", bound=Callable[..., Any])


def _qualify_tool_name(tool: str) -> str:
    """Resolve a bare or explicitly-qualified tool name to its dotted form.

    A bare name (no dot) gets `constants.DEFAULT_NAMESPACE` prepended. A
    dotted name is treated as already-qualified `namespace.tool`.
    """
    if split_qualified_name(tool) is not None:
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

    @overload
    def track_model_call(self, fn: _F) -> _F: ...
    @overload
    def track_model_call(self, *, source: str = "model") -> Callable[[_F], _F]: ...
    def track_model_call(self, fn: _F | None = None, *, source: str = "model") -> Any:  # noqa: ANN401
        """Equivalent to the module-level `interbolt.taint.track_model_call`.

        Delegates directly to it; this handle's agent identity plays no role,
        since taint derivation is identity-free. Provided so one handle
        offers the whole decorator vocabulary (`@support.guard`,
        `@support.track_model_call`), for discoverability.

        Args:
            fn: The function to wrap, when used as a bare
                `@handle.track_model_call`.
            source: The name recorded as the derivation hop on the tainted
                return value.

        Returns:
            The wrapped function, or a decorator if called with arguments.
        """
        return _track_model_call(fn, source=source)


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
        raise InterboltUsageError(
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
                args=bind_arguments(sig, args, kwargs),
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
            args=bind_arguments(sig, args, kwargs),
            agent_id=agent_id_source(),
            run_id=current_run_id.get(),
        )
        _enforce_decision_sync(rt, decision)
        return fn(*args, **kwargs)

    return sync_wrapper  # type: ignore[return-value]


def agent(agent_id: str) -> AgentHandle:
    """Return a durable per-agent handle, a secondary pattern to bare `guard`.

    Prefer `agent_context`/`agent_context_sync` and the bare `guard`/`check`
    for most cases. Use this handle when a function needs a fixed `agent_id`
    captured once at decoration time, or when guarded calls run on a thread
    pool: `agent_id` here is a plain string carried explicitly, so it works
    across threads where `agent_context`'s `ContextVar` would not.

    Captures `agent_id` eagerly (a plain string, safe to call at import time,
    before `configure()` has run) and resolves the current runtime lazily,
    at call time, exactly like bare `guard` does: a module defining
    `support = agent("support-agent")` at import time works regardless of
    whether `configure()` has run yet, and rebinds automatically if
    `configure()` is called again later (for example, between tests).

    Args:
        agent_id: The durable, integrator-supplied agent identity.

    Returns:
        An `AgentHandle` whose `.guard` decorates with this agent_id.
    """
    return AgentHandle(agent_id, runtime_resolver=_current)


def guard[F: Callable[..., Any]](
    func: F | None = None, *, tool: str | None = None
) -> Any:  # noqa: ANN401
    """Guard a function with the ambient agent identity. The primary pattern.

    The recommended way to guard a tool call: decorate the function with a
    bare `@guard` where it is defined, with no agent reference at decoration
    time, and bind the acting agent's identity for the duration of a run
    with `Runtime.agent_context` at the call site. Agent identity is read
    from the `agent_context` contextvar, falling back to
    `constants.DEFAULT_AGENT_ID` when no `agent_context` is active.

    Resolves the current runtime lazily, at call time, so a module using
    `@guard` can be imported before `configure()` has run.

    Offloaded to a thread pool? Use `agent(...)` instead (see its docstring).

    Args:
        func: The function to guard, when used as a bare `@guard`.
        tool: The tool name, when used as `@guard(tool=...)`.

    Returns:
        The guarded function, or a decorator if called with arguments.
    """

    def decorator(fn: F) -> F:
        return _build_wrapper(
            fn,
            agent_id_source=lambda: current_agent_id.get() or DEFAULT_AGENT_ID,
            tool=tool or fn.__name__,
            runtime_resolver=_current,
        )

    if func is not None:
        return decorator(func)
    return decorator


def check(
    *,
    tool: str,
    args: Mapping[str, Any],
    agent_id: str,
    run_id: str | None = None,
    session_id: str | None = None,
) -> Decision:
    """Evaluate policy for one call, against the current runtime.

    The explicit, framework-agnostic counterpart to `guard`: `agent_id` is
    always a required argument here, rather than read from the
    `agent_context` contextvar. Use this directly for a custom dispatch
    loop, an MCP router, or an existing tool registry; use `guard` to pick
    up the ambient agent identity from `Runtime.agent_context` automatically.

    Args:
        tool: The dotted qualified tool name.
        args: The call's bound arguments.
        agent_id: The durable agent identity.
        run_id: The per-run identity, or `None` to mint a fresh one.
        session_id: The optional session identity.

    Returns:
        The computed `Decision`.
    """
    return _current().check(
        tool=tool, args=args, agent_id=agent_id, run_id=run_id, session_id=session_id
    )
