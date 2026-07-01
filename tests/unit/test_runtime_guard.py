from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import TYPE_CHECKING, Any
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
from interbolt.runtime.guard import (
    AgentHandle,
    _bind_args,
    _build_wrapper,
    _enforce_decision_async,
    _enforce_decision_sync,
    _qualify_tool_name,
)

if TYPE_CHECKING:
    pass


class TestQualifyToolName:
    def test_bare_name_gets_default_namespace(self) -> None:
        assert _qualify_tool_name("foo") == "default.foo"

    def test_explicit_qualified_name_preserved(self) -> None:
        assert _qualify_tool_name("ns.tool") == "ns.tool"

    def test_dotted_namespace_raises(self) -> None:
        # "a.b.c" → rpartition → namespace="a.b", tool="c" → "a.b" has a dot → error
        with pytest.raises(InterboltConfigError):
            _qualify_tool_name("a.b.c")

    def test_bare_name_with_allowed_chars(self) -> None:
        assert _qualify_tool_name("my_tool") == "default.my_tool"

    def test_qualified_name_with_underscores(self) -> None:
        assert _qualify_tool_name("my_ns.my_tool") == "my_ns.my_tool"


class TestEnforceDecisionSync:
    def _make_decision(
        self,
        make_decision: Callable[..., Decision],
        action: Action,
        matched_rule: str | None = None,
    ) -> Decision:
        return make_decision(action=action, matched_rule=matched_rule)

    def _runtime(self, make_policy: Callable[..., Policy], reset_runtime: None) -> Any:
        return configure(policy=make_policy())

    def test_allow_returns_without_raise(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = self._runtime(make_policy, reset_runtime)
        decision = self._make_decision(make_decision, Action.ALLOW)
        _enforce_decision_sync(rt, decision)  # should not raise

    def test_block_raises_policy_violation(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = self._runtime(make_policy, reset_runtime)
        decision = self._make_decision(make_decision, Action.BLOCK)
        with pytest.raises(PolicyViolation) as exc_info:
            _enforce_decision_sync(rt, decision)
        assert exc_info.value.decision is decision

    def test_violation_message_contains_rule_name_when_matched(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = self._runtime(make_policy, reset_runtime)
        decision = self._make_decision(
            make_decision, Action.BLOCK, matched_rule="my_rule"
        )
        with pytest.raises(PolicyViolation, match="my_rule"):
            _enforce_decision_sync(rt, decision)

    def test_violation_message_mentions_default_when_no_rule(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = self._runtime(make_policy, reset_runtime)
        decision = self._make_decision(make_decision, Action.BLOCK, matched_rule=None)
        with pytest.raises(PolicyViolation, match="default sink action"):
            _enforce_decision_sync(rt, decision)

    def test_require_approval_resolver_true_no_raise(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = configure(policy=make_policy(), approval_resolver=lambda _: True)
        decision = self._make_decision(make_decision, Action.REQUIRE_APPROVAL)
        _enforce_decision_sync(rt, decision)  # resolver returns True → no raise

    def test_require_approval_resolver_false_raises_approval_denied(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = configure(policy=make_policy(), approval_resolver=lambda _: False)
        decision = self._make_decision(make_decision, Action.REQUIRE_APPROVAL)
        with pytest.raises(ApprovalDenied) as exc_info:
            _enforce_decision_sync(rt, decision)
        assert exc_info.value.decision is decision

    def test_require_approval_async_resolver_raises_usage_error(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        # An awaitable returned at a sync call site must raise InterboltUsageError.
        # Use AsyncMock so the coroutine object is created but never awaited here,
        # which is expected — the code raises before it could be awaited.
        mock_resolver = AsyncMock(return_value=True)
        rt = configure(policy=make_policy(), approval_resolver=mock_resolver)
        decision = self._make_decision(make_decision, Action.REQUIRE_APPROVAL)
        with pytest.raises(InterboltUsageError, match="sync call site"):
            _enforce_decision_sync(rt, decision)


class TestEnforceDecisionAsync:
    async def test_allow_returns_without_raise(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = configure(policy=make_policy())
        decision = make_decision(action=Action.ALLOW)
        await _enforce_decision_async(rt, decision)  # should not raise

    async def test_block_raises_policy_violation(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = configure(policy=make_policy())
        decision = make_decision(action=Action.BLOCK)
        with pytest.raises(PolicyViolation) as exc_info:
            await _enforce_decision_async(rt, decision)
        assert exc_info.value.decision is decision

    async def test_require_approval_sync_resolver_true_no_raise(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = configure(policy=make_policy(), approval_resolver=lambda _: True)
        decision = make_decision(action=Action.REQUIRE_APPROVAL)
        await _enforce_decision_async(rt, decision)

    async def test_require_approval_sync_resolver_false_raises_approval_denied(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        rt = configure(policy=make_policy(), approval_resolver=lambda _: False)
        decision = make_decision(action=Action.REQUIRE_APPROVAL)
        with pytest.raises(ApprovalDenied):
            await _enforce_decision_async(rt, decision)

    async def test_require_approval_async_resolver_is_awaited(
        self,
        make_decision: Callable[..., Decision],
        make_policy: Callable[..., Policy],
        reset_runtime: None,
    ) -> None:
        mock_resolver = AsyncMock(return_value=True)
        rt = configure(policy=make_policy(), approval_resolver=mock_resolver)
        decision = make_decision(action=Action.REQUIRE_APPROVAL)
        await _enforce_decision_async(rt, decision)
        mock_resolver.assert_awaited_once()


class TestBindArgs:
    def test_bind_positional_and_keyword_args(self) -> None:
        def fn(a: str, b: int) -> str:
            return a

        sig = inspect.signature(fn)
        result = _bind_args(sig, ("hello",), {"b": 42})
        assert result == {"a": "hello", "b": 42}

    def test_bind_applies_defaults(self) -> None:
        def fn(a: str, b: int = 99) -> str:
            return a

        sig = inspect.signature(fn)
        result = _bind_args(sig, ("hello",), {})
        assert result == {"a": "hello", "b": 99}

    def test_bind_all_kwargs(self) -> None:
        def fn(x: str, y: str) -> str:
            return x + y

        sig = inspect.signature(fn)
        result = _bind_args(sig, (), {"x": "a", "y": "b"})
        assert result == {"x": "a", "y": "b"}


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
