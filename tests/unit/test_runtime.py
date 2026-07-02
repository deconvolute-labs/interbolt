from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING

import pytest

import interbolt.runtime as _rt_module
from interbolt.constants import DEFAULT_AGENT_ID, ENV_AUDIT, ENV_MODE
from interbolt.errors import InterboltConfigError, InterboltUsageError
from interbolt.models.core import Mode
from interbolt.policy import Policy
from interbolt.reporting import InMemoryReporter, NullReporter
from interbolt.runtime import Runtime, _current, configure
from interbolt.runtime.guard import AgentHandle, current_agent_id, current_run_id

if TYPE_CHECKING:
    pass


class TestConfigure:
    def test_returns_runtime_instance(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())
        assert isinstance(rt, Runtime)

    def test_sets_current_runtime(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())
        assert _rt_module._current_runtime is rt

    def test_mode_arg_used_when_policy_omits_fail_mode(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        # After Bug 2 fix: policy with fail_mode=None means configure()'s
        # mode= arg is used as the effective mode.
        policy = make_policy(fail_mode=None)
        rt = configure(policy=policy, mode=Mode.MONITOR)
        assert rt.mode is Mode.MONITOR

    def test_policy_fail_mode_overrides_mode_arg(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        from interbolt.models.core import Mode

        # Policy explicitly sets fail_mode=enforce; configure(mode=MONITOR) → ENFORCE
        policy = make_policy(fail_mode=Mode.ENFORCE)
        rt = configure(policy=policy, mode=Mode.MONITOR)
        assert rt.mode is Mode.ENFORCE

    def test_env_var_interbolt_mode_overrides_policy_fail_mode(
        self,
        make_policy: Callable[..., Policy],
        monkeypatch: pytest.MonkeyPatch,
        reset_runtime: None,
    ) -> None:
        monkeypatch.setenv(ENV_MODE, "dry_run")
        policy = make_policy(fail_mode=Mode.ENFORCE)
        rt = configure(policy=policy)
        assert rt.mode is Mode.DRY_RUN

    def test_invalid_mode_arg_raises_config_error(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        with pytest.raises(InterboltConfigError):
            configure(policy=make_policy(), mode="bad_mode")

    def test_invalid_env_mode_raises(
        self,
        make_policy: Callable[..., Policy],
        monkeypatch: pytest.MonkeyPatch,
        reset_runtime: None,
    ) -> None:
        monkeypatch.setenv(ENV_MODE, "not_a_mode")
        with pytest.raises(InterboltConfigError):
            configure(policy=make_policy())

    def test_env_audit_true_overrides_false(
        self,
        make_policy: Callable[..., Policy],
        monkeypatch: pytest.MonkeyPatch,
        reset_runtime: None,
    ) -> None:
        monkeypatch.setenv(ENV_AUDIT, "1")
        rt = configure(policy=make_policy(), audit=False)
        assert rt._audit_registry is not None

    def test_env_audit_false_overrides_true(
        self,
        make_policy: Callable[..., Policy],
        monkeypatch: pytest.MonkeyPatch,
        reset_runtime: None,
    ) -> None:
        monkeypatch.setenv(ENV_AUDIT, "0")
        rt = configure(policy=make_policy(), audit=True)
        assert rt._audit_registry is None

    def test_env_audit_accepts_true_yes_on(
        self,
        make_policy: Callable[..., Policy],
        monkeypatch: pytest.MonkeyPatch,
        reset_runtime: None,
    ) -> None:
        for value in ("true", "yes", "on", "1"):
            monkeypatch.setenv(ENV_AUDIT, value)
            rt = configure(policy=make_policy(), audit=False)
            assert rt._audit_registry is not None, f"Expected audit for {value!r}"

    def test_reporter_defaults_to_null_reporter(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())
        assert isinstance(rt.reporter, NullReporter)

    def test_custom_reporter_is_used(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        reporter = InMemoryReporter()
        rt = configure(policy=make_policy(), reporter=reporter)
        assert rt.reporter is reporter


class TestCurrent:
    def test_current_without_configure_raises_interbolt_usage_error(
        self, reset_runtime: None
    ) -> None:
        with pytest.raises(InterboltUsageError):
            _current()

    def test_current_after_configure_returns_runtime(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())
        assert _current() is rt


class TestRuntime:
    def test_agent_returns_agent_handle(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())
        handle = rt.agent("my-agent")
        assert isinstance(handle, AgentHandle)

    def test_agent_handle_via_runtime_agent_uses_its_agent_id(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        reporter = InMemoryReporter()
        rt = configure(policy=make_policy(), reporter=reporter)
        handle = rt.agent("x")

        @handle.guard
        def send_email(to: str) -> None:
            return None

        send_email(to="a@example.com")
        assert reporter.decisions[0].agent_id == "x"

    def test_check_delegates_to_enforcement_check(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        from interbolt.models.core import Decision

        rt = configure(policy=make_policy(), reporter=InMemoryReporter())
        decision = rt.check(
            tool="default.tool", args={}, agent_id="agent", run_id="run"
        )
        assert isinstance(decision, Decision)

    def test_audit_findings_empty_when_disabled(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy(), audit=False)
        assert rt.audit_findings() == []

    def test_audit_findings_returns_findings_when_enabled(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        # Returns an empty list when nothing found; just verify it's a list.
        rt = configure(policy=make_policy(), audit=True)
        assert isinstance(rt.audit_findings(), list)

    async def test_agent_context_sets_context_vars(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())
        async with rt.agent_context("agent-xyz"):
            assert current_agent_id.get() == "agent-xyz"
            assert current_run_id.get() is not None

    async def test_agent_context_resets_context_vars_on_exit(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())
        async with rt.agent_context("agent-xyz"):
            pass
        assert current_agent_id.get() is None
        assert current_run_id.get() is None

    async def test_agent_context_clears_audit_registry_on_exit(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        from interbolt.constants import AUDIT_MIN_MATCH_LENGTH
        from interbolt.models.core import TrustLevel
        from interbolt.taint import taint

        rt = configure(policy=make_policy(), audit=True)
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        tainted = taint(secret, source="web")

        async with rt.agent_context("agent-xyz") as _:
            run_id = current_run_id.get()
            assert run_id is not None
            registry = rt._audit_registry
            assert registry is not None
            # Manually register something for this run
            registry.register_from_args(
                {"x": tainted},
                sources_table={"web": TrustLevel.UNTRUSTED},
                run_id=run_id,
                depth=4,
            )
            assert run_id in registry._by_run

        # After context exits, the run_id's entries are cleared
        assert registry is not None
        assert run_id not in registry._by_run

    async def test_agent_context_isolates_concurrent_agents(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        from interbolt.runtime import guard

        reporter = InMemoryReporter()
        rt = configure(policy=make_policy(), reporter=reporter)

        @guard
        async def my_tool(x: str) -> str:
            return x

        async def run_as(agent_id: str, delay: float) -> None:
            async with rt.agent_context(agent_id):
                await asyncio.sleep(delay)
                await my_tool(agent_id)

        await asyncio.gather(
            run_as("agent-a", 0.02),
            run_as("agent-b", 0.0),
        )

        assert len(reporter.decisions) == 2
        by_agent = {d.agent_id: d for d in reporter.decisions}
        assert set(by_agent) == {"agent-a", "agent-b"}
        # Each agent_context block mints its own run_id; no bleed means
        # the two decisions never share one.
        assert by_agent["agent-a"].run_id != by_agent["agent-b"].run_id


class TestModuleLevelGuard:
    def test_guard_as_bare_decorator_succeeds_without_configure(
        self, reset_runtime: None
    ) -> None:
        from interbolt.runtime import guard

        # Decoration must not require configure() to have been called.
        @guard
        def my_func(x: str) -> str:
            return x

        assert callable(my_func)

    def test_guard_decorated_fn_raises_usage_error_before_configure(
        self, reset_runtime: None
    ) -> None:
        from interbolt.runtime import guard

        @guard
        def my_func(x: str) -> str:
            return x

        with pytest.raises(InterboltUsageError):
            my_func("value")

    def test_guard_decorated_fn_works_after_configure(
        self,
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        from interbolt.runtime import guard

        configure(policy=make_policy())

        @guard
        def my_func(x: str) -> str:
            return x

        result = my_func("hello")
        assert result == "hello"

    async def test_guard_picks_up_agent_context_identity(
        self,
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        from interbolt.runtime import guard

        reporter = InMemoryReporter()
        rt = configure(policy=make_policy(), reporter=reporter)

        @guard
        async def my_func(x: str) -> str:
            return x

        async with rt.agent_context("agent-a"):
            await my_func("hello")

        assert reporter.decisions[0].agent_id == "agent-a"

    def test_guard_falls_back_to_default_agent_id_outside_agent_context(
        self,
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        from interbolt.runtime import guard

        reporter = InMemoryReporter()
        configure(policy=make_policy(), reporter=reporter)

        @guard
        def my_func(x: str) -> str:
            return x

        my_func("hello")
        assert reporter.decisions[0].agent_id == DEFAULT_AGENT_ID

    def test_guard_with_tool_arg_uses_qualified_name(
        self,
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        from interbolt.runtime import guard

        reporter = InMemoryReporter()
        configure(policy=make_policy(), reporter=reporter)

        @guard(tool="my_ns.my_tool")  # type: ignore[untyped-decorator]
        def my_func(x: str) -> str:
            return x

        my_func("hello")
        assert reporter.decisions[0].tool == "my_ns.my_tool"

    def test_module_level_check_raises_before_configure(
        self, reset_runtime: None
    ) -> None:
        import interbolt

        with pytest.raises(InterboltUsageError):
            interbolt.check(tool="default.t", args={}, agent_id="a")

    def test_module_level_check_works_after_configure(
        self,
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        import interbolt
        from interbolt.models.core import Decision

        configure(policy=make_policy())
        decision = interbolt.check(tool="default.t", args={}, agent_id="a")
        assert isinstance(decision, Decision)
