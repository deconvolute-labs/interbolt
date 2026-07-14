from __future__ import annotations

import os
import sys
import threading
import uuid
from collections.abc import AsyncGenerator, Callable, Generator, Mapping
from contextlib import asynccontextmanager, contextmanager
from contextvars import Token
from typing import Any

from interbolt.constants import DEFAULT_AGENT_ID, ENV_AUDIT, ENV_MODE
from interbolt.enforcement import AuditRegistry
from interbolt.enforcement import check as _enforcement_check
from interbolt.errors import InterboltConfigError, InterboltUsageError
from interbolt.models.core import Decision, Finding, Mode
from interbolt.models.protocols import ApprovalResolver, Reporter, auto_deny
from interbolt.policy import Policy
from interbolt.policy import default_policy as _default_policy
from interbolt.reporting import CompositeReporter, NullReporter
from interbolt.runtime.guard import (
    AgentHandle,
    _build_wrapper,
    current_agent_id,
    current_run_id,
)
from interbolt.runtime.observers import make_audit_observer, make_endorsement_emitter
from interbolt.taint import (
    clear_run_ingress,
    install_endorsement_emitter,
    install_taint_observer,
)
from interbolt.utils import get_logger

_logger = get_logger("runtime")

_current_runtime: Runtime | None = None
_runtime_lock = threading.Lock()


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
        self._reporter = (
            reporter
            if isinstance(reporter, CompositeReporter)
            else CompositeReporter([reporter])
        )
        self.approval_resolver = approval_resolver
        self.mode = mode
        self._audit_registry = AuditRegistry() if audit else None

    @property
    def reporter(self) -> Reporter:
        """The composite reporter every decision and finding is emitted through."""
        return self._reporter

    def add_reporter(self, reporter: Reporter) -> None:
        """Attach an additional reporter to this live runtime.

        The `add_span_processor` analog: every `Runtime` holds a
        `CompositeReporter` internally, seeded from `configure(reporter=...)`,
        and this appends to it without reconfiguring. The non-blocking
        contract applies to an added reporter exactly as it does
        to the one passed to `configure()`: a reporter that blocks in
        `export` blocks the decision that triggered it, and owning that is
        the reporter author's responsibility. There is no `remove_reporter`;
        call `configure()` again to reset the reporter set.

        Args:
            reporter: The reporter to attach.
        """
        self._reporter.add(reporter)

    def agent(self, agent_id: str) -> AgentHandle:
        """Equivalent to the module-level `agent()`.

        Kept as a method for discoverability (`runtime.agent(...)`);
        delegates to the same lazy-resolving implementation rather than
        pinning to this `Runtime` instance, so it rebinds after a later
        `configure()` call exactly like bare `guard` does.

        Args:
            agent_id: The durable, integrator-supplied agent identity.

        Returns:
            An `AgentHandle` whose `.guard` decorates with this agent_id.
        """
        return agent(agent_id)

    def _enter_agent_context(
        self, agent_id: str
    ) -> tuple[str, Token[str | None], Token[str | None]]:
        run_id = str(uuid.uuid4())
        agent_token = current_agent_id.set(agent_id)
        run_token = current_run_id.set(run_id)
        return run_id, agent_token, run_token

    def _exit_agent_context(
        self,
        run_id: str,
        agent_token: Token[str | None],
        run_token: Token[str | None],
    ) -> None:
        current_agent_id.reset(agent_token)
        current_run_id.reset(run_token)
        clear_run_ingress(run_id)
        if self._audit_registry is not None:
            self._audit_registry.clear_run(run_id)

    @asynccontextmanager
    async def agent_context(self, agent_id: str) -> AsyncGenerator[None]:
        """Bind the current agent and mint a run_id for the duration of the block.

        The primary way to inject agent identity: `guard`/`check` read
        `agent_id` from the `ContextVar` this sets. Guarded calls inside
        this block share one `run_id`; calls outside any `agent_context`
        fall back to `constants.DEFAULT_AGENT_ID` with a fresh `run_id`
        each. Any `taint()` call inside this block is attributed to this
        run for run-level gating (`run.tainted`); that
        attribution clears, along with the audit registry, when the block
        exits.

        For a synchronous call site, use `agent_context_sync` instead: same
        binding and cleanup, no `async with` required.

        Offloading guarded calls to a thread pool? Use `agent(...)` instead
        (see its docstring): a `ContextVar` doesn't cross that boundary,
        and for the same reason, `taint()` calls made in an offloaded
        thread are invisible to this run's `run.tainted` gating.

        Args:
            agent_id: The agent identity to bind for this run.
        """
        run_id, agent_token, run_token = self._enter_agent_context(agent_id)
        try:
            yield
        finally:
            self._exit_agent_context(run_id, agent_token, run_token)

    @contextmanager
    def agent_context_sync(self, agent_id: str) -> Generator[None]:
        """Synchronous counterpart to `agent_context`.

        Same identity/run binding and cleanup as `agent_context`; use this
        when the call site cannot use `async with`.

        Args:
            agent_id: The agent identity to bind for this run.
        """
        run_id, agent_token, run_token = self._enter_agent_context(agent_id)
        try:
            yield
        finally:
            self._exit_agent_context(run_id, agent_token, run_token)

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
            reporter=self._reporter,
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


def _caller_location() -> tuple[str, int]:
    """Return the (filename, lineno) of configure()'s caller.

    Uses `sys._getframe` (CPython-specific, guarded with a fallback) rather
    than `inspect.stack()`, which walks and resolves the entire call stack,
    including reading source context lines, just to extract one frame.
    """
    try:
        frame = sys._getframe(2)
        return frame.f_code.co_filename, frame.f_lineno
    except AttributeError:
        return "unknown", 0


def configure(
    *,
    policy: Policy | None = None,
    reporter: Reporter | None = None,
    approval_resolver: ApprovalResolver = auto_deny,
    mode: Mode | str = Mode.ENFORCE,
    audit: bool = False,
) -> Runtime:
    """Set up the process-wide runtime and install it as the process-current runtime.

    Calling `configure()` is what compiles policy and applies environment
    overrides; nothing happens at import time. The effective mode is
    resolved from three sources, highest precedence first: the
    `INTERBOLT_MODE` environment variable, the policy file's
    `defaults.fail_mode`, and the `mode=` argument (the in-code default,
    lowest precedence). If `INTERBOLT_MODE` changes the effective mode,
    `configure()` logs a WARNING so the change is visible. `INTERBOLT_AUDIT`
    overrides `audit`. Every call also logs one INFO-level summary line
    (effective mode, policy source, source/sink counts, and the caller's
    file:line), independent of any configured `Reporter`, so this is
    visible even without a `LoggingReporter`. Passing no `policy` logs a
    separate WARNING pointing to `interbolt init`. Every call also installs
    the `endorse()`-time emitter that routes `Endorsement` records to this
    runtime's reporter, unconditionally: unlike the audit instrument below,
    endorsement auditing is not opt-in.

    Args:
        policy: The compiled policy to enforce. When ``None``, the built-in
            default policy is used: no sources, no sinks, every guarded call
            falls through to ``require_approval``. This is reflected in a
            dedicated `configure()` warning, pointing to ``interbolt init``.
        reporter: Where decisions and findings are emitted. Defaults to
            `NullReporter()`.
        approval_resolver: Resolves `require_approval` decisions. Defaults to
            `auto_deny`.
        mode: The lowest-precedence default enforcement mode.
        audit: Whether to enable the laundering-audit instrument. When
            `True`, also installs a `taint/`-level observer hook (see
            `taint.install_taint_observer`) so laundering-audit content is
            registered at `taint()` time, attributed to the ambient run;
            `False` (including via a later `configure()` call) uninstalls it.

    Returns:
        The newly configured `Runtime`, also installed as process-current.

    Raises:
        InterboltConfigError: If the effective mode (after the precedence
            chain above) is not one of the valid modes.
    """
    global _current_runtime

    policy_was_given = policy is not None
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

    runtime = Runtime(
        policy=policy,
        reporter=reporter or NullReporter(),
        approval_resolver=approval_resolver,
        mode=resolved_mode,
        audit=audit,
    )
    with _runtime_lock:
        _current_runtime = runtime

    if audit and runtime._audit_registry is not None:
        install_taint_observer(make_audit_observer(policy, runtime._audit_registry))
    else:
        install_taint_observer(None)

    install_endorsement_emitter(make_endorsement_emitter(runtime))

    if not policy_was_given:
        _logger.warning(
            "configure(): no policy given; using the built-in default policy "
            "(no sources, no sinks, every guarded call falls through to "
            "require_approval); run `interbolt init` to generate a policy file"
        )

    caller_file, caller_line = _caller_location()

    _logger.info(
        "configure(): mode=%s policy_source=%s sources=%d sinks=%d audit=%s "
        "caller=%s:%d",
        resolved_mode.value,
        policy.source or "programmatic (no file; interbolt init to generate one)",
        len(policy.document.sources),
        len(policy.document.sinks),
        audit,
        caller_file,
        caller_line,
    )
    return runtime


def _current() -> Runtime:
    """Return the process-current runtime, or raise if configure() hasn't run.

    Reads the module-global reference without the lock: in CPython a plain
    attribute read is atomic, and `_runtime_lock` only needs to serialize
    concurrent writers (`configure()`). Guarding this read would put lock
    contention on every guarded call's hot path for no
    correctness benefit. Do not add the lock back here.
    """
    runtime = _current_runtime
    if runtime is None:
        raise InterboltUsageError(
            "interbolt.configure() must be called before using the bare guard/check API"
        )
    return runtime


def get_runtime() -> Runtime:
    """Return the process-current runtime.

    The `get_tracer_provider()` analog.Use this to reach the live runtime
    later, for example to call `Runtime.add_reporter`.

    Returns:
        The process-current `Runtime`.

    Raises:
        InterboltUsageError: If `configure()` has not been called yet.
    """
    return _current()


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
