from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from interbolt.constants import EVENT_SCHEMA_VERSION
from interbolt.errors import InterboltConfigError
from interbolt.models.core import (
    Action,
    Decision,
    Event,
    Label,
    Mode,
    QualifiedName,
    TrustLevel,
    validate_qualified_name_part,
)
from interbolt.models.protocols import ApprovalResolver, Reporter, auto_deny
from interbolt.reporting import InMemoryReporter, NullReporter


def _label(source: str = "src") -> Label:
    return Label(source=source, value_id=str(uuid.uuid4()), lineage=(source,))


def _decision(action: Action = Action.ALLOW) -> Decision:
    return Decision(
        action=action,
        matched_rule=None,
        tool="default.tool",
        contributing_labels=(),
        trifecta=frozenset(),
        run_tainted=False,
        mode=Mode.ENFORCE,
        decision_id=str(uuid.uuid4()),
        agent_id="agent",
        run_id="run",
        session_id=None,
    )


def test_validate_qualified_name_part_with_dot_raises() -> None:
    with pytest.raises(InterboltConfigError, match="dot"):
        validate_qualified_name_part("a.b", part="namespace")


def test_validate_qualified_name_part_no_dot_passes() -> None:
    validate_qualified_name_part("valid_name", part="tool")


def test_qualified_name_str_form() -> None:
    qn = QualifiedName(namespace="ns", tool="tool")
    assert str(qn) == "ns.tool"


def test_qualified_name_dotted_namespace_raises() -> None:
    with pytest.raises(ValidationError):
        QualifiedName(namespace="a.b", tool="tool")


def test_qualified_name_dotted_tool_raises() -> None:
    with pytest.raises(ValidationError):
        QualifiedName(namespace="ns", tool="a.b")


def test_label_is_frozen() -> None:
    lbl = _label()
    with pytest.raises((ValidationError, TypeError)):
        lbl.source = "other"


def test_decision_is_frozen() -> None:
    d = _decision()
    with pytest.raises((ValidationError, TypeError)):
        d.action = Action.BLOCK


def test_mode_str_enum_values() -> None:
    assert Mode.ENFORCE.value == "enforce"
    assert Mode.MONITOR.value == "monitor"
    assert Mode.DRY_RUN.value == "dry_run"


def test_action_str_enum_values() -> None:
    assert Action.ALLOW.value == "allow"
    assert Action.BLOCK.value == "block"
    assert Action.REQUIRE_APPROVAL.value == "require_approval"


def test_trust_level_str_enum_values() -> None:
    assert TrustLevel.TRUSTED.value == "trusted"
    assert TrustLevel.UNTRUSTED.value == "untrusted"


def test_auto_deny_always_returns_false() -> None:
    d = _decision()
    assert auto_deny(d) is False


def test_reporter_protocol_satisfied_by_null_reporter() -> None:
    assert isinstance(NullReporter(), Reporter)


def test_reporter_protocol_satisfied_by_in_memory_reporter() -> None:
    assert isinstance(InMemoryReporter(), Reporter)


def test_approval_resolver_protocol_satisfied_by_auto_deny() -> None:
    assert isinstance(auto_deny, ApprovalResolver)


def test_event_carries_schema_version_constant() -> None:
    d = _decision()
    event = Event(
        schema_version=EVENT_SCHEMA_VERSION,
        decision=d,
        agent_id="agent",
        run_id="run",
        session_id=None,
        sources=frozenset(),
        lineage=(),
        matched_rule=None,
        trifecta=frozenset(),
        run_tainted=False,
        mode=Mode.ENFORCE,
        outcome="allow",
        timestamp=datetime.now(UTC),
    )
    assert event.schema_version == EVENT_SCHEMA_VERSION
