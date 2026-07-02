from __future__ import annotations

import inspect
import os
import uuid
from collections.abc import AsyncGenerator, Callable, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from interbolt.constants import DEFAULT_AGENT_ID, ENV_AUDIT, ENV_MODE
from interbolt.enforcement import AuditRegistry
from interbolt.enforcement import check as _enforcement_check
from interbolt.errors import InterboltConfigError, InterboltUsageError
from interbolt.models.core import Decision, Finding, Mode
from interbolt.models.protocols import ApprovalResolver, Reporter, auto_deny
from interbolt.policy import Policy
from interbolt.policy import default_policy as _default_policy
from interbolt.reporting import NullReporter
from interbolt.runtime.guard import (
    AgentHandle,
    _build_wrapper,
    current_agent_id,
    current_run_id,
)
from interbolt.taint import clear_run_ingress
from interbolt.utils import get_logger

_logger = get_logger("runtime")

_current_runtime: Runtime | None = None


class Runtime:
    """The composition root: one runtime per process, holding the live configuration."""

    def __init__(
        self,
        *,
        policy: Policy,
        reporter: Reporter,
        approval_resolver: ApprovalResolver,
        mode: Mode,
        audit: bool,
    ) -> None:
        self.policy = policy
        self.reporter = reporter
        self.approval_resolver = approval_resolver
        self.mode = mode
        self._audit_registry = AuditRegistry() if audit else None

    def agent(self, agent_id: str) -> AgentHandle:
        """Return a durable per-agent handle, a secondary pattern to bare `guard`.

        Prefer `agent_context` and the bare `guard`/`check` for most cases.
        Reach for this handle when a function needs a fixed `agent_id`
        captured once at decoration time rather than read from the ambient
        `agent_context`, and in particular when guarded calls are offloaded
        to a thread pool: `agent_context`'s `contextvars.ContextVar` does not
        cross that boundary, but this handle's `agent_id` is a plain string
        carried explicitly and is immune to that limit.

        Args:
            agent_id: The durable, integrator-supplied agent identity.

        Returns:
            An `AgentHandle` whose `.guard` decorates with this agent_id.
        """
        return AgentHandle(agent_id, runtime_resolver=lambda: self)

    @asynccontextmanager
    async def agent_context(self, agent_id: str) -> AsyncGenerator[None]:
        """Bind the current agent and mint a run_id for the duration of the block.

        This is the primary way to inject agent identity: it pairs with the
        bare `guard`/`check`, which read `agent_id` from the
        `contextvars.ContextVar` this sets rather than from a durable handle.
        Guarded calls made inside this block share one `run_id`. Calls made
        outside any `agent_context` fall back to `constants.DEFAULT_AGENT_ID`
        and get a fresh `run_id` each. Any `taint()` call made inside this
        block is also attributed to this run for run-level gating
        (`run.tainted`, `dev/spec.md` §15.8); that attribution is cleared,
        alongside the audit registry, when the block exits.

        A `ContextVar` does not cross into a thread pool. If guarded calls
        are offloaded to threads, use the durable `agent(...)` handle
        instead, which carries `agent_id` explicitly. Note that `taint()`
        calls made inside such an offloaded thread are, for the same reason,
        invisible to this run's `run.tainted` gating.

        Args:
            agent_id: The agent identity to bind for this run.
        """
        run_id = str(uuid.uuid4())
        agent_token = current_agent_id.set(agent_id)
        run_token = current_run_id.set(run_id)
        try:
            yield
        finally:
            current_agent_id.reset(agent_token)
            current_run_id.reset(run_token)
            clear_run_ingress(run_id)
            if self._audit_registry is not None:
                self._audit_registry.clear_run(run_id)

    def check(
        self,
        *,
        tool: str,
        args: Mapping[str, Any],
        agent_id: str,
        run_id: str | None = None,
        session_id: str | None = None,
    ) -> Decision:
        """Evaluate policy for one guarded call. See `enforcement.check`.

        Args:
            tool: The dotted qualified tool name.
            args: The call's bound arguments.
            agent_id: The durable agent identity.
            run_id: The per-run identity, or `None` to mint a fresh one.
            session_id: The optional session identity.

        Returns:
            The computed `Decision`.
        """
        return _enforcement_check(
            tool=tool,
            args=args,
            agent_id=agent_id,
            run_id=run_id,
            session_id=session_id,
            policy=self.policy,
            reporter=self.reporter,
            mode=self.mode,
            audit_registry=self._audit_registry,
        )

    def audit_findings(self) -> list[Finding]:
        """Every laundering-audit finding recorded so far.

        Returns:
            The findings, or an empty list if the audit instrument is disabled.
        """
        if self._audit_registry is None:
            return []
        return self._audit_registry.findings


def _parse_mode(value: Mode | str, *, source: str) -> Mode:
    try:
        return Mode(value)
    except ValueError as exc:
        raise InterboltConfigError(f"{source}={value!r} is not a valid mode") from exc


def configure(
    *,
    policy: Policy | None = None,
    reporter: Reporter | None = None,
    approval_resolver: ApprovalResolver = auto_deny,
    mode: Mode | str = Mode.ENFORCE,
    audit: bool = False,
) -> Runtime:
    """Set up the process-wide runtime and install it as the process-current runtime.

    No import-time side effects: only calling `configure()` compiles policy
    and applies environment overrides. The effective mode is resolved from
    three sources, highest precedence first: the `INTERBOLT_MODE` environment
    variable, the policy file's `defaults.fail_mode`, and the `mode=`
    argument (the in-code default, lowest precedence). A `INTERBOLT_MODE`
    override that actually changes the effective mode logs a warning, so a
    non-enforcing mode cannot silently ship. `INTERBOLT_AUDIT` overrides
    `audit`. Every call also logs one WARNING-level summary line (effective
    mode, policy source, source/sink counts, and the caller's file:line),
    independent of any configured `Reporter`, so the library is not silent
    by default even without a `LoggingReporter`.

    Args:
        policy: The compiled policy to enforce. When ``None``, the built-in
            default policy is used: no sources, no sinks, every guarded call
            falls through to ``require_approval``. This is reflected in the
            `configure()` summary warning, pointing to ``interbolt init``.
        reporter: Where decisions and findings are emitted. Defaults to
            `NullReporter()`.
        approval_resolver: Resolves `require_approval` decisions. Defaults to
            `auto_deny`.
        mode: The lowest-precedence default enforcement mode.
        audit: Whether to enable the laundering-audit instrument.

    Returns:
        The newly configured `Runtime`, also installed as process-current.

    Raises:
        InterboltConfigError: If the effective mode (after the precedence
            chain above) is not one of the valid modes.
    """
    global _current_runtime

    if policy is None:
        policy = _default_policy()

    resolved_mode = _parse_mode(mode, source="mode")
    if policy.document.defaults.fail_mode is not None:
        resolved_mode = policy.document.defaults.fail_mode

    env_mode = os.environ.get(ENV_MODE)
    if env_mode is not None:
        parsed_env_mode = _parse_mode(env_mode, source=ENV_MODE)
        if parsed_env_mode != resolved_mode:
            _logger.warning(
                "%s=%r overrides effective mode=%r",
                ENV_MODE,
                env_mode,
                resolved_mode,
            )
        resolved_mode = parsed_env_mode

    env_audit = os.environ.get(ENV_AUDIT)
    if env_audit is not None:
        audit = env_audit.strip().lower() in {"1", "true", "yes", "on"}

    frame = inspect.currentframe()
    caller = frame.f_back if frame is not None else None
    caller_location = (
        f"{Path(caller.f_code.co_filename).name}:{caller.f_lineno}"
        if caller is not None
        else "unknown"
    )

    policy_source = policy.source or "built-in default (run `interbolt init`)"
    _logger.warning(
        "interbolt active: mode=%s policy=%s sources=%d sinks=%d (configured at %s)",
        resolved_mode,
        policy_source,
        len(policy.document.sources),
        len(policy.document.sinks),
        caller_location,
    )

    runtime = Runtime(
        policy=policy,
        reporter=reporter or NullReporter(),
        approval_resolver=approval_resolver,
        mode=resolved_mode,
        audit=audit,
    )
    _current_runtime = runtime
    return runtime


def _current() -> Runtime:
    if _current_runtime is None:
        raise InterboltUsageError(
            "interbolt.configure() must be called before using the bare guard/check API"
        )
    return _current_runtime


def guard[F: Callable[..., Any]](
    func: F | None = None, *, tool: str | None = None
) -> Any:  # noqa: ANN401
    """Guard a function with the ambient agent identity. The primary pattern.

    This is the recommended way to guard a tool call: decorate the function
    with a bare `@guard` where it is defined, with no agent reference at
    decoration time, and bind the acting agent's identity for the duration
    of a run with `Runtime.agent_context` at the call site. Agent identity
    is read from the `agent_context` contextvar, falling back to
    `constants.DEFAULT_AGENT_ID` when no `agent_context` is active.

    Resolves the current runtime lazily, at call time, so decorating a
    module never requires `configure()` to have run.

    For guarded calls offloaded to a thread pool, where a
    `contextvars.ContextVar` does not cross the thread boundary, use the
    durable `Runtime.agent` handle instead.

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

    The explicit, framework-agnostic counterpart to `guard`: it never reads
    the `agent_context` contextvar, so `agent_id` is always a required
    argument here. Use this directly for a custom dispatch loop, an MCP
    router, or an existing tool registry; use `guard` when the ambient
    agent identity from `Runtime.agent_context` should be picked up
    automatically instead.

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
