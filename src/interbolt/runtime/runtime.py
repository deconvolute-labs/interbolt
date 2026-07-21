"""The Runtime class: the composition root, one per process."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Generator, Mapping
from contextlib import asynccontextmanager, contextmanager
from contextvars import Token
from typing import Any

from interbolt.enforcement import AuditRegistry
from interbolt.enforcement import check as _enforcement_check
from interbolt.enforcement import enforce_decision as _enforcement_enforce_decision
from interbolt.enforcement import (
    enforce_decision_sync as _enforcement_enforce_decision_sync,
)
from interbolt.models.core import Decision, Finding, Mode
from interbolt.models.protocols import ApprovalResolver, Reporter
from interbolt.policy import Policy
from interbolt.reporting import CompositeReporter
from interbolt.runtime.guard import AgentHandle, agent
from interbolt.taint import clear_run_ingress
from interbolt.utils import current_agent_id, current_run_id


class Runtime:
    """The composition root: one runtime per process, holding the live configuration."""

    def __init__(
        self,
        *,
        policy: Policy,
        reporter: Reporter,
        approval_resolver: ApprovalResolver,
        mode: Mode,
        audit_registry: AuditRegistry | None,
    ) -> None:
        self.policy = policy
        self._reporter = (
            reporter
            if isinstance(reporter, CompositeReporter)
            else CompositeReporter([reporter])
        )
        self.approval_resolver = approval_resolver
        self.mode = mode
        self._audit_registry = audit_registry

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
            run_id: The per-run identity. `None` resolves the ambient
                `agent_context` run id when one is active, minting a fresh
                id only when no run is active.
            session_id: The optional session identity.

        Returns:
            The computed `Decision`.
        """
        if run_id is None:
            run_id = current_run_id.get()
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

    async def enforce_decision(self, decision: Decision) -> None:
        """Enforce `decision`, asynchronously. See `enforcement.enforce_decision`.

        Args:
            decision: The decision to enforce, as returned by `check()`.
        """
        await _enforcement_enforce_decision(
            decision, approval_resolver=self.approval_resolver
        )

    def enforce_decision_sync(self, decision: Decision) -> None:
        """Enforce `decision`, synchronously. See `enforcement.enforce_decision_sync`.

        Args:
            decision: The decision to enforce, as returned by `check()`.
        """
        _enforcement_enforce_decision_sync(
            decision, approval_resolver=self.approval_resolver
        )

    def audit_findings(self) -> list[Finding]:
        """Every laundering-audit finding recorded so far.

        Returns:
            The findings, or an empty list if the audit instrument is disabled.
        """
        if self._audit_registry is None:
            return []
        return self._audit_registry.findings
