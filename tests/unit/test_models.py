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
    Outcome,
    TrustLevel,
)
from interbolt.runtime import auto_deny
from interbolt.utils.names import validate_qualified_name_part


def _label(source: str = "src") -> Label:
    return Label(source=source, value_id=str(uuid.uuid4()), lineage=(source,))


def _decision(action: Action = Action.ALLOW) -> Decision:
    return Decision(
        action=action,
        matched_rule=None,
        matched_condition=None,
        tool="default.tool",
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


def test_validate_qualified_name_part_with_dot_raises() -> None:
    with pytest.raises(InterboltConfigError, match="dot"):
        validate_qualified_name_part("a.b", part="namespace")


def test_validate_qualified_name_part_no_dot_passes() -> None:
    validate_qualified_name_part("valid_name", part="tool")


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


def test_event_carries_schema_version_constant() -> None:
    d = _decision()
    event = Event(
        schema_version=EVENT_SCHEMA_VERSION,
        decision=d,
        sources=frozenset(),
        outcome=Outcome.ALLOW,
        timestamp=datetime.now(UTC),
    )
    assert event.schema_version == EVENT_SCHEMA_VERSION
