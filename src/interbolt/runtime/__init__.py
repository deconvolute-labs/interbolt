from __future__ import annotations

import os
import uuid
from collections.abc import AsyncGenerator, Callable, Mapping
from contextlib import asynccontextmanager
from typing import Any

from interbolt.constants import DEFAULT_AGENT_ID, ENV_AUDIT, ENV_MODE
from interbolt.enforcement import AuditRegistry
from interbolt.enforcement import check as _enforcement_check
from interbolt.errors import InterboltConfigError, InterboltUsageError
from interbolt.models.core import Decision, Finding, Mode
from interbolt.models.protocols import ApprovalResolver, Reporter, auto_deny
from interbolt.policy import Policy
from interbolt.reporting import NullReporter
from interbolt.runtime.guard import (
    AgentHandle,
    _build_wrapper,
    current_agent_id,
    current_run_id,
)
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
        """Return a handle bound to a durable agent identity.

        Args:
            agent_id: The durable, integrator-supplied agent identity.

        Returns:
            An `AgentHandle` whose `.guard` decorates with this agent_id.
        """
        return AgentHandle(agent_id, runtime_resolver=lambda: self)

    @asynccontextmanager
    async def agent_context(self, agent_id: str) -> AsyncGenerator[None]:
        """Bind the current agent and mint a run_id for the duration of the block.

        Guarded calls made inside this block (via the bare `guard`/`check`)
        pick up `agent_id` and share one `run_id`. Calls made outside any
        `agent_context` get a fresh `run_id` each.

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
    policy: Policy,
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
    `audit`.

    Args:
        policy: The compiled policy to enforce.
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

    _parse_mode(mode, source="mode")  # validates the lowest-precedence source
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
    """Guard a function with the ambient agent identity.

    Resolves the current runtime lazily, at call time, so decorating a
    module never requires `configure()` to have run. Agent identity comes
    from the `agent_context` contextvar, or `constants.DEFAULT_AGENT_ID`.

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
