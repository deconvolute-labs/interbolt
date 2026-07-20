from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from interbolt.errors import (
    ApprovalDenied,
    InterboltConfigError,
    InterboltUsageError,
    PolicyViolation,
)
from interbolt.models.core import Action, Decision
from interbolt.policy import Policy
from interbolt.reporting import InMemoryReporter
from interbolt.runtime import configure
from interbolt.runtime import enforce_decision as _ambient_enforce_decision
from interbolt.runtime import enforce_decision_async as _ambient_enforce_decision_async
from interbolt.runtime.guard import (
    AgentHandle,
    _build_wrapper,
    _qualify_tool_name,
)
from interbolt.taint import Tainted, taint

if TYPE_CHECKING:
    pass


class TestQualifyToolName:
    def test_bare_name_gets_default_namespace(self) -> None:
        assert _qualify_tool_name("foo") == "default.foo"

    def test_explicit_qualified_name_preserved(self) -> None:
        assert _qualify_tool_name("ns.tool") == "ns.tool"

    def test_dotted_namespace_raises(self) -> None:
        # "a.b.c" -> rpartition -> namespace="a.b", tool="c" -> "a.b" has a dot -> error
        with pytest.raises(InterboltConfigError):
            _qualify_tool_name("a.b.c")

    def test_bare_name_with_allowed_chars(self) -> None:
        assert _qualify_tool_name("my_tool") == "default.my_tool"

    def test_qualified_name_with_underscores(self) -> None:
        assert _qualify_tool_name("my_ns.my_tool") == "my_ns.my_tool"


class TestRuntimeEnforceDecision:
    """`Runtime.enforce_decision`/`enforce_decision_async`: the pure enforcement
    core (`enforcement.enforce_decision`) is exercised directly in
    `test_enforcement.py`; these tests confirm the `Runtime` methods thread
    `self.approval_resolver` through correctly.
    """

    def test_allow_returns_without_raise(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = configure(policy=make_policy())
        decision = make_decision(action=Action.ALLOW)
        rt.enforce_decision(decision)  # should not raise

    def test_block_raises_policy_violation(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = configure(policy=make_policy())
        decision = make_decision(action=Action.BLOCK)
        with pytest.raises(PolicyViolation) as exc_info:
            rt.enforce_decision(decision)
        assert exc_info.value.decision is decision

    def test_require_approval_uses_runtimes_resolver(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = configure(policy=make_policy(), approval_resolver=lambda decision: False)
        decision = make_decision(action=Action.REQUIRE_APPROVAL)
        with pytest.raises(ApprovalDenied) as exc_info:
            rt.enforce_decision(decision)
        assert exc_info.value.decision is decision

    async def test_async_uses_runtimes_resolver(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        mock_resolver = AsyncMock(return_value=True)
        rt = configure(policy=make_policy(), approval_resolver=mock_resolver)
        decision = make_decision(action=Action.REQUIRE_APPROVAL)
        await rt.enforce_decision_async(decision)
        mock_resolver.assert_awaited_once()


class TestAmbientEnforceDecision:
    """The module-level `enforce_decision`/`enforce_decision_async`: resolve
    the process-current runtime, same shape as the bare `check()`.
    """

    def test_raises_usage_error_when_unconfigured(
        self, make_decision: Callable[..., Decision], reset_runtime: None
    ) -> None:
        decision = make_decision(action=Action.BLOCK)
        with pytest.raises(InterboltUsageError):
            _ambient_enforce_decision(decision)

    def test_delegates_to_current_runtime_sync(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        configure(policy=make_policy(), approval_resolver=lambda decision: False)
        decision = make_decision(action=Action.REQUIRE_APPROVAL)
        with pytest.raises(ApprovalDenied):
            _ambient_enforce_decision(decision)

    async def test_delegates_to_current_runtime_async(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        mock_resolver = AsyncMock(return_value=True)
        configure(policy=make_policy(), approval_resolver=mock_resolver)
        decision = make_decision(action=Action.REQUIRE_APPROVAL)
        await _ambient_enforce_decision_async(decision)
        mock_resolver.assert_awaited_once()


class TestBuildWrapper:
    def test_sync_fn_produces_sync_wrapper(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())

        def fn(x: str) -> str:
            return x

        wrapper = _build_wrapper(
            fn,
            agent_id_source=lambda: "agent",
            tool="default.fn",
            runtime_resolver=lambda: rt,
        )
        assert not inspect.iscoroutinefunction(wrapper)

    def test_async_fn_produces_async_wrapper(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())

        async def fn(x: str) -> str:
            return x

        wrapper = _build_wrapper(
            fn,
            agent_id_source=lambda: "agent",
            tool="default.fn",
            runtime_resolver=lambda: rt,
        )
        assert inspect.iscoroutinefunction(wrapper)

    def test_functools_wraps_preserves_name(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())

        def my_special_function(x: str) -> str:
            return x

        wrapper = _build_wrapper(
            my_special_function,
            agent_id_source=lambda: "agent",
            tool="default.my_special_function",
            runtime_resolver=lambda: rt,
        )
        assert wrapper.__name__ == "my_special_function"

    def test_sync_wrapper_raises_policy_violation_on_block(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        from interbolt.policy.schema import SinkRule

        policy = make_policy(
            sinks={"default.fn": (SinkRule(name="block_all", action=Action.BLOCK),)}
        )
        rt = configure(policy=policy)

        def fn(x: str) -> str:
            return x

        wrapper = _build_wrapper(
            fn,
            agent_id_source=lambda: "agent",
            tool="default.fn",
            runtime_resolver=lambda: rt,
        )
        with pytest.raises(PolicyViolation):
            wrapper("value")

    async def test_async_wrapper_raises_policy_violation_on_block(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        from interbolt.policy.schema import SinkRule

        policy = make_policy(
            sinks={"default.fn": (SinkRule(name="block_all", action=Action.BLOCK),)}
        )
        rt = configure(policy=policy)

        async def fn(x: str) -> str:
            return x

        wrapper = _build_wrapper(
            fn,
            agent_id_source=lambda: "agent",
            tool="default.fn",
            runtime_resolver=lambda: rt,
        )
        with pytest.raises(PolicyViolation):
            await wrapper("value")

    def test_sync_wrapper_passes_through_return_value(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        rt = configure(policy=make_policy())

        def fn(x: str) -> str:
            return x.upper()

        wrapper = _build_wrapper(
            fn,
            agent_id_source=lambda: "agent",
            tool="default.fn",
            runtime_resolver=lambda: rt,
        )
        assert wrapper("hello") == "HELLO"


class TestAgentHandle:
    def test_agent_handle_guard_uses_agent_id(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        reporter = InMemoryReporter()
        rt = configure(policy=make_policy(), reporter=reporter)
        handle = AgentHandle("my-agent", runtime_resolver=lambda: rt)

        @handle.guard
        def fn(x: str) -> str:
            return x

        fn("value")
        assert reporter.decisions[0].agent_id == "my-agent"

    def test_agent_handle_guard_with_tool_arg_uses_qualified_name(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        reporter = InMemoryReporter()
        rt = configure(policy=make_policy(), reporter=reporter)
        handle = AgentHandle("agent", runtime_resolver=lambda: rt)

        @handle.guard(tool="my_ns.my_tool")
        def fn(x: str) -> str:
            return x

        fn("value")
        assert reporter.decisions[0].tool == "my_ns.my_tool"

    def test_agent_handle_guard_bare_name_gets_default_namespace(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        reporter = InMemoryReporter()
        rt = configure(policy=make_policy(), reporter=reporter)
        handle = AgentHandle("agent", runtime_resolver=lambda: rt)

        @handle.guard(tool="mytool")
        def fn(x: str) -> str:
            return x

        fn("value")
        assert reporter.decisions[0].tool == "default.mytool"

    def test_agent_handle_guard_fn_name_used_as_tool_when_no_tool_arg(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        reporter = InMemoryReporter()
        rt = configure(policy=make_policy(), reporter=reporter)
        handle = AgentHandle("agent", runtime_resolver=lambda: rt)

        @handle.guard
        def my_function(x: str) -> str:
            return x

        my_function("value")
        assert reporter.decisions[0].tool == "default.my_function"


class TestAgentHandleTrackModelCall:
    """Mirrors TestTrackModelCall in test_taint.py, but through a handle."""

    def _handle(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> AgentHandle:
        rt = configure(policy=make_policy())
        return AgentHandle("agent", runtime_resolver=lambda: rt)

    def test_bare_decorator_taints_return_value(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        handle = self._handle(make_policy, reset_runtime)

        @handle.track_model_call
        def call_model(prompt: str) -> str:
            return "summary"

        untrusted = taint("attacker text", source="web_search")
        result = call_model(untrusted)
        assert isinstance(result, Tainted)
        assert result.label.source == "model"
        assert result.label.lineage == ("web_search",)

    def test_parameterized_decorator_uses_custom_source(
        self, make_policy: Callable[..., Policy], reset_runtime: None
    ) -> None:
        handle = self._handle(make_policy, reset_runtime)

        @handle.track_model_call(source="gpt-4")
        def call_model(prompt: str) -> str:
            return "summary"

        untrusted = taint("attacker text", source="web_search")
        result = call_model(untrusted)
        assert isinstance(result, Tainted)
        assert result.label.source == "gpt-4"
