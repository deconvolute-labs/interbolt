from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from typing import Any

import pytest
from pytest_mock import MockerFixture

from interbolt.constants import AUDIT_MIN_MATCH_LENGTH, EVENT_SCHEMA_VERSION
from interbolt.enforcement import (
    AuditRegistry,
    _compute_trifecta,
    _emit,
    _walk_strings,
    check,
)
from interbolt.models.core import Action, Label, Mode, TrustLevel
from interbolt.models.protocols import Reporter
from interbolt.policy import Policy
from interbolt.policy.engine import resolve_labels
from interbolt.policy.schema import SinkRule, SourceDeclaration
from interbolt.reporting import InMemoryReporter, NullReporter
from interbolt.taint import _fresh_label, taint

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _label(source: str = "src", *, trust: TrustLevel = TrustLevel.UNTRUSTED) -> Label:
    return _fresh_label(source)


def _run_check(
    policy: Policy,
    *,
    tool: str = "default.test_tool",
    args: Mapping[str, Any] | None = None,
    mode: Mode = Mode.ENFORCE,
    reporter: Reporter | None = None,
    agent_id: str = "agent",
    run_id: str | None = "run-1",
) -> object:
    from interbolt.enforcement import check as _check

    return _check(
        tool=tool,
        args=args or {},
        agent_id=agent_id,
        run_id=run_id,
        session_id=None,
        policy=policy,
        reporter=reporter or NullReporter(),
        mode=mode,
    )


# ---------------------------------------------------------------------------
# TestCheckFunction
# ---------------------------------------------------------------------------


class TestCheckFunction:
    def test_allow_action_returned(self, make_policy: Callable[..., Policy]) -> None:
        policy = make_policy(sink_action=Action.ALLOW)
        decision = check(
            tool="default.test_tool",
            args={},
            agent_id="agent",
            run_id="run",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert decision.action is Action.ALLOW

    def test_block_from_rule(self, make_policy: Callable[..., Policy]) -> None:
        policy = make_policy(
            sink_action=Action.ALLOW,
            sinks={
                "default.test_tool": (SinkRule(name="block_all", action=Action.BLOCK),)
            },
        )
        decision = check(
            tool="default.test_tool",
            args={},
            agent_id="agent",
            run_id="run",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert decision.action is Action.BLOCK
        assert decision.matched_rule == "block_all"

    def test_require_approval_from_rule(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy(
            sinks={
                "default.test_tool": (
                    SinkRule(name="need_approval", action=Action.REQUIRE_APPROVAL),
                )
            },
        )
        decision = check(
            tool="default.test_tool",
            args={},
            agent_id="agent",
            run_id="run",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert decision.action is Action.REQUIRE_APPROVAL

    def test_undeclared_sink_uses_default_action(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy(sink_action=Action.BLOCK)
        decision = check(
            tool="default.unknown_tool",
            args={},
            agent_id="agent",
            run_id="run",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert decision.action is Action.BLOCK
        assert decision.matched_rule is None

    def test_emits_event_to_reporter(self, make_policy: Callable[..., Policy]) -> None:
        reporter = InMemoryReporter()
        policy = make_policy()
        check(
            tool="default.test_tool",
            args={},
            agent_id="agent",
            run_id="run",
            session_id=None,
            policy=policy,
            reporter=reporter,
            mode=Mode.ENFORCE,
        )
        assert len(reporter.events) == 1

    def test_event_schema_version_is_constant(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        reporter = InMemoryReporter()
        policy = make_policy()
        check(
            tool="default.test_tool",
            args={},
            agent_id="agent",
            run_id="run",
            session_id=None,
            policy=policy,
            reporter=reporter,
            mode=Mode.ENFORCE,
        )
        assert reporter.events[0].schema_version == EVENT_SCHEMA_VERSION

    def test_decision_id_unique_per_call(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy()
        d1 = check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        d2 = check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert d1.decision_id != d2.decision_id

    def test_run_id_none_generates_uuid(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy()
        decision = check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id=None,
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert len(decision.run_id) == 36

    def test_run_id_provided_is_preserved(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy()
        decision = check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="my-custom-run",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert decision.run_id == "my-custom-run"

    def test_session_id_propagates(self, make_policy: Callable[..., Policy]) -> None:
        policy = make_policy()
        decision = check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="r",
            session_id="sess-xyz",
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert decision.session_id == "sess-xyz"

    def test_cel_error_monitor_mode_returns_allow(
        self, make_policy: Callable[..., Policy], mocker: MockerFixture
    ) -> None:
        from celpy.evaluation import CELEvalError

        policy = make_policy(
            sinks={"default.t": (SinkRule(name="r", when="true", action=Action.BLOCK),)}
        )
        mocker.patch(
            "interbolt.enforcement.evaluate_sink",
            side_effect=CELEvalError("oops"),
        )
        decision = check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.MONITOR,
        )
        assert decision.action is Action.ALLOW

    def test_cel_error_enforce_mode_raises(
        self, make_policy: Callable[..., Policy], mocker: MockerFixture
    ) -> None:
        from celpy.evaluation import CELEvalError

        from interbolt.errors import PolicyEvaluationError

        policy = make_policy(
            sinks={"default.t": (SinkRule(name="r", when="true", action=Action.BLOCK),)}
        )
        mocker.patch(
            "interbolt.enforcement.evaluate_sink",
            side_effect=CELEvalError("oops"),
        )
        with pytest.raises(PolicyEvaluationError) as exc_info:
            check(
                tool="default.t",
                args={},
                agent_id="a",
                run_id="r",
                session_id=None,
                policy=policy,
                reporter=NullReporter(),
                mode=Mode.ENFORCE,
            )
        assert exc_info.value.decision is not None

    def test_cel_error_decision_in_enforce_mode_has_block_action(
        self, make_policy: Callable[..., Policy], mocker: MockerFixture
    ) -> None:
        from celpy.evaluation import CELEvalError

        from interbolt.errors import PolicyEvaluationError

        policy = make_policy(
            sinks={"default.t": (SinkRule(name="r", when="true", action=Action.ALLOW),)}
        )
        mocker.patch(
            "interbolt.enforcement.evaluate_sink",
            side_effect=CELEvalError("oops"),
        )
        with pytest.raises(PolicyEvaluationError) as exc_info:
            check(
                tool="default.t",
                args={},
                agent_id="a",
                run_id="r",
                session_id=None,
                policy=policy,
                reporter=NullReporter(),
                mode=Mode.ENFORCE,
            )
        assert exc_info.value.decision is not None
        assert exc_info.value.decision.action is Action.BLOCK

    def test_cel_unsupported_error_monitor_mode_returns_allow(
        self, make_policy: Callable[..., Policy], mocker: MockerFixture
    ) -> None:
        from celpy.evaluation import CELUnsupportedError

        policy = make_policy(
            sinks={"default.t": (SinkRule(name="r", when="true", action=Action.BLOCK),)}
        )
        mocker.patch(
            "interbolt.enforcement.evaluate_sink",
            side_effect=CELUnsupportedError("oops", 1, 1),
        )
        decision = check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.MONITOR,
        )
        assert decision.action is Action.ALLOW

    def test_cel_unsupported_error_enforce_mode_raises(
        self, make_policy: Callable[..., Policy], mocker: MockerFixture
    ) -> None:
        from celpy.evaluation import CELUnsupportedError

        from interbolt.errors import PolicyEvaluationError

        policy = make_policy(
            sinks={"default.t": (SinkRule(name="r", when="true", action=Action.BLOCK),)}
        )
        mocker.patch(
            "interbolt.enforcement.evaluate_sink",
            side_effect=CELUnsupportedError("oops", 1, 1),
        )
        with pytest.raises(PolicyEvaluationError) as exc_info:
            check(
                tool="default.t",
                args={},
                agent_id="a",
                run_id="r",
                session_id=None,
                policy=policy,
                reporter=NullReporter(),
                mode=Mode.ENFORCE,
            )
        assert exc_info.value.decision is not None
        assert exc_info.value.decision.action is Action.BLOCK

    def test_cel_unsupported_error_still_emits_event(
        self, make_policy: Callable[..., Policy], mocker: MockerFixture
    ) -> None:
        # Before the exception surface was widened, a CELUnsupportedError
        # propagated uncaught, skipping reporter emission entirely.
        from celpy.evaluation import CELUnsupportedError

        policy = make_policy(
            sinks={"default.t": (SinkRule(name="r", when="true", action=Action.BLOCK),)}
        )
        mocker.patch(
            "interbolt.enforcement.evaluate_sink",
            side_effect=CELUnsupportedError("oops", 1, 1),
        )
        reporter = InMemoryReporter()
        check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=reporter,
            mode=Mode.MONITOR,
        )
        assert len(reporter.events) == 1
        assert reporter.events[0].outcome == "evaluation_error"

    def test_dry_run_downgrades_block_to_allow(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        reporter = InMemoryReporter()
        policy = make_policy(
            sinks={"default.t": (SinkRule(name="block_all", action=Action.BLOCK),)}
        )
        decision = check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=reporter,
            mode=Mode.DRY_RUN,
        )
        assert decision.action is Action.ALLOW
        assert reporter.events[0].outcome == "block"
        assert reporter.events[0].matched_rule == "block_all"

    def test_dry_run_downgrades_require_approval_to_allow(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy(
            sinks={"default.t": (SinkRule(name="ra", action=Action.REQUIRE_APPROVAL),)}
        )
        decision = check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.DRY_RUN,
        )
        assert decision.action is Action.ALLOW

    def test_reporter_exception_is_swallowed(
        self, make_policy: Callable[..., Policy], mocker: MockerFixture
    ) -> None:
        bad_reporter = mocker.Mock(spec=Reporter)
        bad_reporter.export.side_effect = RuntimeError("reporter crashed")
        policy = make_policy()
        decision = check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=bad_reporter,
            mode=Mode.ENFORCE,
        )
        assert decision is not None

    def test_trifecta_from_untrusted_when_untrusted_label(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy(
            sources=(SourceDeclaration(name="web", trust=TrustLevel.UNTRUSTED),)
        )
        tainted_arg = taint("value", source="web")
        decision = check(
            tool="default.t",
            args={"x": tainted_arg},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert "from_untrusted" in decision.trifecta

    def test_trifecta_empty_for_all_trusted(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy(
            sources=(SourceDeclaration(name="kb", trust=TrustLevel.TRUSTED),)
        )
        tainted_arg = taint("value", source="kb")
        decision = check(
            tool="default.t",
            args={"x": tainted_arg},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert decision.trifecta == frozenset()

    def test_contributing_labels_populated(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy()
        tainted_arg = taint("hello", source="s")
        decision = check(
            tool="default.t",
            args={"x": tainted_arg},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert len(decision.contributing_labels) == 1

    def test_matched_rule_name_on_decision_and_event(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        reporter = InMemoryReporter()
        policy = make_policy(
            sinks={"default.t": (SinkRule(name="my_rule", action=Action.ALLOW),)}
        )
        decision = check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=reporter,
            mode=Mode.ENFORCE,
        )
        assert decision.matched_rule == "my_rule"
        assert reporter.events[0].matched_rule == "my_rule"

    def test_audit_registry_none_no_findings(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        reporter = InMemoryReporter()
        policy = make_policy()
        check(
            tool="default.t",
            args={},
            agent_id="a",
            run_id="r",
            session_id=None,
            policy=policy,
            reporter=reporter,
            mode=Mode.ENFORCE,
            audit_registry=None,
        )
        assert reporter.findings == []

    def test_audit_registry_detects_laundering(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        registry = AuditRegistry()
        reporter = InMemoryReporter()
        policy = make_policy(
            sources=(SourceDeclaration(name="web", trust=TrustLevel.UNTRUSTED),)
        )
        long_secret = "a" * AUDIT_MIN_MATCH_LENGTH
        tainted_arg = taint(long_secret, source="web")

        # First call: register the untrusted content
        check(
            tool="default.t",
            args={"x": tainted_arg},
            agent_id="a",
            run_id="run-audit",
            session_id=None,
            policy=policy,
            reporter=reporter,
            mode=Mode.ENFORCE,
            audit_registry=registry,
        )
        # Second call: same content now appears unlabeled (laundered)
        check(
            tool="default.sink",
            args={"cmd": long_secret},
            agent_id="a",
            run_id="run-audit",
            session_id=None,
            policy=policy,
            reporter=reporter,
            mode=Mode.ENFORCE,
            audit_registry=registry,
        )
        assert len(reporter.findings) >= 1


# ---------------------------------------------------------------------------
# Change 6: split-then-sink contributing_labels collapses to length 1
# ---------------------------------------------------------------------------


class TestSplitThenSinkContributingLabels:
    def test_split_parts_collapse_to_one_contributing_label(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy(sink_action=Action.ALLOW)
        original = taint("line one\nline two\nline three", source="web_search")
        parts = original.splitlines()
        decision = check(
            tool="default.test_tool",
            args={"lines": parts},
            agent_id="agent",
            run_id="run",
            session_id=None,
            policy=policy,
            reporter=NullReporter(),
            mode=Mode.ENFORCE,
        )
        assert len(decision.contributing_labels) == 1


# ---------------------------------------------------------------------------
# TestComputeTrifecta
# ---------------------------------------------------------------------------


class TestComputeTrifecta:
    def test_empty_labels_empty_trifecta(self) -> None:
        result = _compute_trifecta(resolve_labels((), {}))
        assert result == frozenset()

    def test_untrusted_label_adds_from_untrusted(self) -> None:
        lbl = _label("web")
        result = _compute_trifecta(
            resolve_labels((lbl,), {"web": TrustLevel.UNTRUSTED})
        )
        assert "from_untrusted" in result

    def test_trusted_only_labels_empty_trifecta(self) -> None:
        lbl = _label("kb")
        result = _compute_trifecta(resolve_labels((lbl,), {"kb": TrustLevel.TRUSTED}))
        assert result == frozenset()

    def test_mixed_labels_adds_from_untrusted(self) -> None:
        lbl_trusted = _label("kb")
        lbl_untrusted = _label("web")
        result = _compute_trifecta(
            resolve_labels(
                (lbl_trusted, lbl_untrusted),
                {"kb": TrustLevel.TRUSTED, "web": TrustLevel.UNTRUSTED},
            )
        )
        assert "from_untrusted" in result


# ---------------------------------------------------------------------------
# TestWalkStrings
# ---------------------------------------------------------------------------


class TestWalkStrings:
    def test_plain_str_yields_no_label(self) -> None:
        results = list(_walk_strings("hello", depth=2))
        assert len(results) == 1
        content, label = results[0]
        assert content == "hello"
        assert label is None

    def test_tainted_str_yields_label(self) -> None:
        t = taint("hello", source="s")
        results = list(_walk_strings(t, depth=2))
        assert len(results) == 1
        content, label = results[0]
        assert content == "hello"
        assert label is not None
        assert label.source == "s"

    def test_tainted_bytes_decodes_and_yields_label(self) -> None:
        tb = taint(b"hello", source="s")
        results = list(_walk_strings(tb, depth=2))
        assert len(results) == 1
        content, label = results[0]
        assert "hello" in content
        assert label is not None

    def test_mapping_walks_keys_and_values(self) -> None:
        # Matches taint.collect_labels's traversal: both keys and values are
        # walked, so a tainted key is not invisible to the laundering audit.
        tainted_key = taint("secret_key_data", source="s")
        results = list(_walk_strings({tainted_key: "plain_value"}, depth=2))
        labels = [lbl for _, lbl in results]
        assert any(lbl is None for lbl in labels)  # the plain value
        assert any(lbl is not None for lbl in labels)  # the tainted key

    def test_list_container_recurses(self) -> None:
        results = list(_walk_strings(["a", "b"], depth=2))
        assert len(results) == 2

    def test_depth_zero_stops_recursion(self) -> None:
        results = list(_walk_strings(["a", "b"], depth=0))
        assert results == []


# ---------------------------------------------------------------------------
# TestAuditRegistry
# ---------------------------------------------------------------------------


class TestAuditRegistry:
    def _sources(self) -> dict[str, TrustLevel]:
        return {"web": TrustLevel.UNTRUSTED}

    def test_register_from_args_registers_untrusted_strings(self) -> None:
        registry = AuditRegistry()
        long_val = taint("a" * AUDIT_MIN_MATCH_LENGTH, source="web")
        registry.register_from_args(
            {"x": long_val}, sources_table=self._sources(), run_id="r", depth=4
        )
        assert len(registry._by_run.get("r", [])) == 1

    def test_register_from_args_ignores_short_strings(self) -> None:
        registry = AuditRegistry()
        short_val = taint("a" * (AUDIT_MIN_MATCH_LENGTH - 1), source="web")
        registry.register_from_args(
            {"x": short_val}, sources_table=self._sources(), run_id="r", depth=4
        )
        assert len(registry._by_run.get("r", [])) == 0

    def test_register_from_args_ignores_plain_strings(self) -> None:
        registry = AuditRegistry()
        registry.register_from_args(
            {"x": "plain_string_long_enough"},
            sources_table=self._sources(),
            run_id="r",
            depth=4,
        )
        assert "r" not in registry._by_run

    def test_register_from_args_ignores_trusted_strings(self) -> None:
        registry = AuditRegistry()
        trusted_val = taint("a" * AUDIT_MIN_MATCH_LENGTH, source="kb")
        registry.register_from_args(
            {"x": trusted_val},
            sources_table={"kb": TrustLevel.TRUSTED},
            run_id="r",
            depth=4,
        )
        assert "r" not in registry._by_run

    def test_scan_detects_unlabeled_string_containing_registered_content(
        self,
    ) -> None:
        registry = AuditRegistry()
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        tainted_secret = taint(secret, source="web")
        registry.register_from_args(
            {"x": tainted_secret},
            sources_table=self._sources(),
            run_id="r",
            depth=4,
        )
        findings = registry.scan(
            {"cmd": secret},  # same content, now plain string
            tool="default.tool",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        assert len(findings) >= 1

    def test_scan_does_not_report_labeled_strings(self) -> None:
        registry = AuditRegistry()
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        tainted_secret = taint(secret, source="web")
        registry.register_from_args(
            {"x": tainted_secret},
            sources_table=self._sources(),
            run_id="r",
            depth=4,
        )
        # Same content but still tainted — not a laundering point
        findings = registry.scan(
            {"cmd": tainted_secret},
            tool="default.tool",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        assert findings == []

    def test_scan_no_registered_content_returns_empty(self) -> None:
        registry = AuditRegistry()
        findings = registry.scan(
            {"cmd": "something"},
            tool="default.tool",
            run_id="nonexistent-run",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        assert findings == []

    def test_clear_run_removes_entries(self) -> None:
        registry = AuditRegistry()
        val = taint("a" * AUDIT_MIN_MATCH_LENGTH, source="web")
        registry.register_from_args(
            {"x": val}, sources_table=self._sources(), run_id="r", depth=4
        )
        registry.clear_run("r")
        assert "r" not in registry._by_run

    def test_clear_run_nonexistent_run_no_error(self) -> None:
        AuditRegistry().clear_run("ghost-run")

    def test_findings_property_accumulates_across_scans(self) -> None:
        registry = AuditRegistry()
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        val = taint(secret, source="web")
        registry.register_from_args(
            {"x": val}, sources_table=self._sources(), run_id="r", depth=4
        )
        registry.scan(
            {"cmd": secret},
            tool="default.t1",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        registry.scan(
            {"cmd": secret},
            tool="default.t2",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        assert len(registry.findings) >= 2

    def test_register_from_args_detects_untrusted_content_in_mapping_keys(
        self,
    ) -> None:
        registry = AuditRegistry()
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        tainted_key = taint(secret, source="web")
        registry.register_from_args(
            {"x": {tainted_key: "plain_value"}},
            sources_table=self._sources(),
            run_id="r",
            depth=4,
        )
        assert len(registry._by_run.get("r", [])) == 1
        findings = registry.scan(
            {"cmd": secret},  # same content as the key, now a plain string
            tool="default.tool",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        assert len(findings) >= 1

    def test_findings_capped_at_configured_max(self) -> None:
        registry = AuditRegistry(max_findings=2)
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        val = taint(secret, source="web")
        registry.register_from_args(
            {"x": val}, sources_table=self._sources(), run_id="r", depth=4
        )
        for i in range(3):
            registry.scan(
                {"cmd": secret},
                tool=f"default.t{i}",
                run_id="r",
                agent_id="a",
                session_id=None,
                depth=4,
            )
        assert len(registry.findings) == 2
        # The oldest finding (tool="default.t0") was evicted; the two most
        # recent survive.
        tools = {f.tool for f in registry.findings}
        assert tools == {"default.t1", "default.t2"}

    def test_by_run_bounded_evicts_oldest_run(self) -> None:
        registry = AuditRegistry(max_tracked_runs=2)
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        for run_id in ("r1", "r2", "r3"):
            val = taint(secret, source="web")
            registry.register_from_args(
                {"x": val}, sources_table=self._sources(), run_id=run_id, depth=4
            )
        assert len(registry._by_run) == 2
        assert "r1" not in registry._by_run
        assert "r2" in registry._by_run
        assert "r3" in registry._by_run

    def test_scan_dedupes_identical_finding_within_same_run(self) -> None:
        registry = AuditRegistry()
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        registry.register_from_args(
            {"x": taint(secret, source="web")},
            sources_table=self._sources(),
            run_id="r",
            depth=4,
        )
        first = registry.scan(
            {"cmd": secret},
            tool="default.tool",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        second = registry.scan(
            {"cmd": secret},
            tool="default.tool",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        assert len(first) == 1
        assert second == []
        assert len(registry.findings) == 1

    def test_scan_different_argument_still_reported(self) -> None:
        registry = AuditRegistry()
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        registry.register_from_args(
            {"x": taint(secret, source="web")},
            sources_table=self._sources(),
            run_id="r",
            depth=4,
        )
        registry.scan(
            {"cmd": secret},
            tool="default.tool",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        second = registry.scan(
            {"other_arg": secret},
            tool="default.tool",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        assert len(second) == 1

    def test_scan_different_tool_still_reported(self) -> None:
        registry = AuditRegistry()
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        registry.register_from_args(
            {"x": taint(secret, source="web")},
            sources_table=self._sources(),
            run_id="r",
            depth=4,
        )
        registry.scan(
            {"cmd": secret},
            tool="default.tool_a",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        second = registry.scan(
            {"cmd": secret},
            tool="default.tool_b",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        assert len(second) == 1

    def test_scan_new_run_reports_again(self) -> None:
        registry = AuditRegistry()
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        for run_id in ("r1", "r2"):
            registry.register_from_args(
                {"x": taint(secret, source="web")},
                sources_table=self._sources(),
                run_id=run_id,
                depth=4,
            )
        first = registry.scan(
            {"cmd": secret},
            tool="default.tool",
            run_id="r1",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        second = registry.scan(
            {"cmd": secret},
            tool="default.tool",
            run_id="r2",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        assert len(first) == 1
        assert len(second) == 1

    def test_clear_run_removes_emitted_keys_too(self) -> None:
        registry = AuditRegistry()
        secret = "a" * AUDIT_MIN_MATCH_LENGTH
        registry.register_from_args(
            {"x": taint(secret, source="web")},
            sources_table=self._sources(),
            run_id="r",
            depth=4,
        )
        registry.scan(
            {"cmd": secret},
            tool="default.tool",
            run_id="r",
            agent_id="a",
            session_id=None,
            depth=4,
        )
        registry.clear_run("r")
        assert "r" not in registry._emitted


# ---------------------------------------------------------------------------
# TestEmit
# ---------------------------------------------------------------------------


class TestEmit:
    def test_emit_calls_reporter_export(
        self, mocker: MockerFixture, make_policy: Callable[..., Policy]
    ) -> None:
        from datetime import UTC, datetime

        from interbolt.constants import EVENT_SCHEMA_VERSION
        from interbolt.models.core import Decision, Event, Mode

        mock_reporter = mocker.Mock(spec=Reporter)
        d = Decision(
            action=Action.ALLOW,
            matched_rule=None,
            matched_condition=None,
            tool="default.t",
            contributing_labels=(),
            trifecta=frozenset(),
            untrusted_sources=frozenset(),
            run_tainted=False,
            mode=Mode.ENFORCE,
            decision_id=str(uuid.uuid4()),
            agent_id="a",
            run_id="r",
            session_id=None,
        )
        event = Event(
            schema_version=EVENT_SCHEMA_VERSION,
            decision=d,
            agent_id="a",
            run_id="r",
            session_id=None,
            sources=frozenset(),
            lineage=(),
            matched_rule=None,
            trifecta=frozenset(),
            untrusted_sources=frozenset(),
            run_tainted=False,
            mode=Mode.ENFORCE,
            outcome="allow",
            timestamp=datetime.now(UTC),
        )
        _emit(mock_reporter, event)
        mock_reporter.export.assert_called_once_with(event)

    def test_emit_reporter_exception_is_swallowed(self, mocker: MockerFixture) -> None:
        from datetime import UTC, datetime

        from interbolt.constants import EVENT_SCHEMA_VERSION
        from interbolt.models.core import Decision, Event, Mode

        bad_reporter = mocker.Mock(spec=Reporter)
        bad_reporter.export.side_effect = RuntimeError("crash")
        d = Decision(
            action=Action.ALLOW,
            matched_rule=None,
            matched_condition=None,
            tool="default.t",
            contributing_labels=(),
            trifecta=frozenset(),
            untrusted_sources=frozenset(),
            run_tainted=False,
            mode=Mode.ENFORCE,
            decision_id=str(uuid.uuid4()),
            agent_id="a",
            run_id="r",
            session_id=None,
        )
        event = Event(
            schema_version=EVENT_SCHEMA_VERSION,
            decision=d,
            agent_id="a",
            run_id="r",
            session_id=None,
            sources=frozenset(),
            lineage=(),
            matched_rule=None,
            trifecta=frozenset(),
            untrusted_sources=frozenset(),
            run_tainted=False,
            mode=Mode.ENFORCE,
            outcome="allow",
            timestamp=datetime.now(UTC),
        )
        _emit(bad_reporter, event)  # must not raise
