from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable
from typing import TYPE_CHECKING

import pytest

import interbolt.runtime as _rt_module
from interbolt.constants import DEFAULT_AGENT_ID, ENV_AUDIT, ENV_MODE
from interbolt.errors import InterboltConfigError, InterboltUsageError
from interbolt.models.core import Action, Mode
from interbolt.policy import Policy
from interbolt.policy.schema import SinkRule
from interbolt.reporting import InMemoryReporter, NullReporter
from interbolt.runtime import Runtime, _current, agent, configure
from interbolt.runtime.guard import AgentHandle, current_agent_id, current_run_id

if TYPE_CHECKING:
    pass


def _installed_taint_observer() -> object:
    """The current `taint/`-level observer, or `None` if uninstalled.

    Looked up via `sys.modules` rather than `import interbolt.taint as X`:
    `interbolt/__init__.py` does `from interbolt.taint import taint`, which
    overwrites the `taint` attribute on the `interbolt` package with the
    function; `import a.b as x` resolves through that attribute chain, so it
    would silently bind to the function instead of the submodule.
    """
    return getattr(sys.modules["interbolt.taint"], "_taint_observer")  # noqa: B009


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

    def test_logs_summary_info_for_file_loaded_policy(
        self,
        make_policy: Callable[..., Policy],
        caplog: pytest.LogCaptureFixture,
        reset_runtime: None,
    ) -> None:
        policy = make_policy(
            sources=(),
            sinks={"default.t": (SinkRule(name="r", action=Action.ALLOW),)},
        )
        with caplog.at_level("INFO", logger="interbolt.runtime"):
            configure(policy=policy, mode=Mode.MONITOR)
        messages = [r.message for r in caplog.records]
        assert any("mode=monitor" in m and "sinks=1" in m for m in messages)
        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert warnings == []

    def test_logs_summary_info_for_default_policy(
        self,
        caplog: pytest.LogCaptureFixture,
        reset_runtime: None,
    ) -> None:
        # No policy= given: configure() falls back to the built-in default,
        # whose Policy has no file source. The log message says so
        # generically ("programmatic (no file...)") rather than claiming
        # specifically "this is the built-in default" — a caller passing
        # their own programmatically-built Policy hits the same source=None
        # case and deserves the same honest wording, not a false claim that
        # it's the built-in default.
        with caplog.at_level("INFO", logger="interbolt.runtime"):
            configure()
        messages = [r.message for r in caplog.records]
        assert any("programmatic" in m and "no file" in m for m in messages)

    def test_logs_default_policy_warning_when_no_policy_given(
        self,
        caplog: pytest.LogCaptureFixture,
        reset_runtime: None,
    ) -> None:
        with caplog.at_level("WARNING", logger="interbolt.runtime"):
            configure()
        warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
        assert any("interbolt init" in m for m in warnings)

    def test_no_default_policy_warning_when_policy_given(
        self,
        make_policy: Callable[..., Policy],
        caplog: pytest.LogCaptureFixture,
        reset_runtime: None,
    ) -> None:
        with caplog.at_level("WARNING", logger="interbolt.runtime"):
            configure(policy=make_policy())
        warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
        assert not any("interbolt init" in m for m in warnings)

    def test_configure_logs_caller_file_and_line(
        self,
        make_policy: Callable[..., Policy],
        caplog: pytest.LogCaptureFixture,
        reset_runtime: None,
    ) -> None:
        with caplog.at_level("INFO", logger="interbolt.runtime"):
            configure(policy=make_policy())
        messages = [r.message for r in caplog.records]
        assert any("caller=" in m and __file__ in m for m in messages)

    def test_caller_location_falls_back_when_getframe_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Tests _caller_location() directly rather than through configure():
        # sys._getframe is also used internally by the stdlib logging module
        # (findCaller), so patching it globally around a configure() call
        # (which logs) would break logging's own frame introspection too.
        def _raise(_depth: int) -> None:
            raise AttributeError("no _getframe")

        monkeypatch.setattr(sys, "_getframe", _raise)
        assert _rt_module._caller_location() == ("unknown", 0)

    def test_configure_audit_true_installs_taint_observer(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        configure(policy=make_policy(), audit=True)
        assert _installed_taint_observer() is not None

    def test_configure_audit_false_installs_no_observer(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        configure(policy=make_policy(), audit=False)
        assert _installed_taint_observer() is None


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

    def test_current_resolves_correctly_across_threads_after_single_configure(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        from concurrent.futures import ThreadPoolExecutor

        rt = configure(policy=make_policy())
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: _current(), range(64)))
        assert all(r is rt for r in results)


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

    def test_runtime_agent_rebinds_after_reconfigure(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        # Runtime.agent() must not pin to the instance it was called on: a
        # later configure() should redirect the same handle to the new
        # runtime, exactly like bare guard already does.
        reporter_a = InMemoryReporter()
        rt = configure(policy=make_policy(), reporter=reporter_a)
        handle = rt.agent("x")

        @handle.guard
        def send_email(to: str) -> None:
            return None

        send_email(to="a@example.com")
        assert len(reporter_a.decisions) == 1

        reporter_b = InMemoryReporter()
        configure(policy=make_policy(), reporter=reporter_b)
        send_email(to="a@example.com")

        assert len(reporter_a.decisions) == 1  # unchanged
        assert len(reporter_b.decisions) == 1  # the second call landed here

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


class TestAgentContextSync:
    """Mirrors TestRuntime's agent_context tests, but synchronous."""

    def test_agent_context_sync_sets_context_vars(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())
        with rt.agent_context_sync("agent-xyz"):
            assert current_agent_id.get() == "agent-xyz"
            assert current_run_id.get() is not None

    def test_agent_context_sync_resets_context_vars_on_exit(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())
        with rt.agent_context_sync("agent-xyz"):
            pass
        assert current_agent_id.get() is None
        assert current_run_id.get() is None

    def test_agent_context_sync_resets_context_vars_on_exception(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())
        with (
            pytest.raises(ValueError, match="boom"),
            rt.agent_context_sync("agent-xyz"),
        ):
            raise ValueError("boom")
        assert current_agent_id.get() is None
        assert current_run_id.get() is None

    def test_agent_context_sync_clears_audit_registry_on_exit(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        from interbolt.constants import AUDIT_MIN_MATCH_LENGTH
        from interbolt.models.core import TrustLevel
        from interbolt.taint import taint

        rt = configure(policy=make_policy(), audit=True)
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        tainted = taint(secret, source="web")

        with rt.agent_context_sync("agent-xyz"):
            run_id = current_run_id.get()
            assert run_id is not None
            registry = rt._audit_registry
            assert registry is not None
            registry.register_from_args(
                {"x": tainted},
                sources_table={"web": TrustLevel.UNTRUSTED},
                run_id=run_id,
                depth=4,
            )
            assert run_id in registry._by_run

        assert registry is not None
        assert run_id not in registry._by_run

    def test_agent_context_sync_mints_fresh_run_id_per_call(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())
        run_ids = []
        for _ in range(2):
            with rt.agent_context_sync("agent-xyz"):
                run_ids.append(current_run_id.get())
        assert run_ids[0] != run_ids[1]

    def test_agent_context_sync_requires_no_event_loop(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        # A plain sync test with no pytest-asyncio machinery involved proves
        # this doesn't require an event loop to be running.
        from interbolt.runtime import guard

        rt = configure(policy=make_policy(), reporter=InMemoryReporter())

        @guard
        def my_tool(x: str) -> str:
            return x

        with rt.agent_context_sync("agent-xyz"):
            result = my_tool("hello")
        assert result == "hello"


class TestModuleLevelAgent:
    def test_agent_callable_before_configure(self, reset_runtime: None) -> None:
        handle = agent("support-agent")
        assert isinstance(handle, AgentHandle)

    def test_agent_handle_raises_usage_error_before_configure(
        self, reset_runtime: None
    ) -> None:
        handle = agent("support-agent")

        @handle.guard
        def my_func(x: str) -> str:
            return x

        with pytest.raises(InterboltUsageError):
            my_func("value")

    def test_agent_defined_before_configure_binds_at_first_call(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        # The handle is created (e.g. at module import time) before
        # configure() has run anywhere; the first *call* still resolves
        # correctly once configure() has since been called.
        handle = agent("support-agent")

        @handle.guard
        def my_func(x: str) -> str:
            return x

        reporter = InMemoryReporter()
        configure(policy=make_policy(), reporter=reporter)
        my_func("hello")
        assert reporter.decisions[0].agent_id == "support-agent"

    def test_agent_rebinds_after_reconfigure(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        reporter_a = InMemoryReporter()
        configure(policy=make_policy(), reporter=reporter_a)
        handle = agent("support-agent")

        @handle.guard
        def my_func(x: str) -> str:
            return x

        my_func("hello")
        assert len(reporter_a.decisions) == 1

        reporter_b = InMemoryReporter()
        configure(policy=make_policy(), reporter=reporter_b)
        my_func("hello")

        assert len(reporter_a.decisions) == 1
        assert len(reporter_b.decisions) == 1


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
