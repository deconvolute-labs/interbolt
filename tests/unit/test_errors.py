from __future__ import annotations

import uuid

from interbolt.errors import (
    ApprovalDenied,
    InterboltConfigError,
    InterboltError,
    InterboltUsageError,
    PolicyEvaluationError,
    PolicyViolation,
)
from interbolt.models.core import Action, Decision, Mode


def _make_decision() -> Decision:
    return Decision(
        action=Action.ALLOW,
        matched_rule=None,
        tool="default.test",
        contributing_labels=(),
        trifecta=frozenset(),
        untrusted_sources=frozenset(),
        run_tainted=False,
        mode=Mode.ENFORCE,
        decision_id=str(uuid.uuid4()),
        agent_id="agent",
        run_id="run",
        session_id=None,
    )


def test_policy_violation_stores_decision() -> None:
    d = _make_decision()
    exc = PolicyViolation("blocked", decision=d)
    assert exc.decision is d
    assert str(exc) == "blocked"


def test_policy_evaluation_error_with_decision() -> None:
    d = _make_decision()
    exc = PolicyEvaluationError("eval failed", decision=d)
    assert exc.decision is d
    assert str(exc) == "eval failed"


def test_policy_evaluation_error_without_decision() -> None:
    exc = PolicyEvaluationError("load failed")
    assert exc.decision is None


def test_approval_denied_stores_decision() -> None:
    d = _make_decision()
    exc = ApprovalDenied("denied", decision=d)
    assert exc.decision is d
    assert str(exc) == "denied"


def test_interbolt_config_error_is_value_error() -> None:
    exc = InterboltConfigError("bad config")
    assert isinstance(exc, ValueError)


def test_interbolt_config_error_is_interbolt_error() -> None:
    exc = InterboltConfigError("bad config")
    assert isinstance(exc, InterboltError)


def test_interbolt_usage_error_is_runtime_error() -> None:
    exc = InterboltUsageError("bad sequence")
    assert isinstance(exc, RuntimeError)


def test_interbolt_usage_error_is_interbolt_error() -> None:
    exc = InterboltUsageError("bad sequence")
    assert isinstance(exc, InterboltError)


def test_policy_violation_caught_as_interbolt_error() -> None:
    d = _make_decision()
    caught = False
    try:
        raise PolicyViolation("blocked", decision=d)
    except InterboltError:
        caught = True
    assert caught


def test_all_decision_errors_are_interbolt_error() -> None:
    d = _make_decision()
    for exc_type in (PolicyViolation, ApprovalDenied):
        assert issubclass(exc_type, InterboltError)
    assert issubclass(PolicyEvaluationError, InterboltError)

    for exc in (
        PolicyViolation("x", decision=d),
        ApprovalDenied("x", decision=d),
        PolicyEvaluationError("x"),
    ):
        assert isinstance(exc, InterboltError)
