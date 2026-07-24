"""The `endorse()` primitive, re-exported from `taint/__init__.py`."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from interbolt.constants import DEFAULT_AGENT_ID, EVENT_SCHEMA_VERSION, RECURSION_DEPTH
from interbolt.models.core import Endorsement, Label
from interbolt.taint.carriers import LabeledValue, Tainted, TaintedBytes, _new_value_id
from interbolt.taint.runstate import get_endorsement_emitter
from interbolt.taint.walk import map_leaves
from interbolt.utils import (
    current_agent_id,
    current_run_id,
    current_trace_context,
    get_logger,
)
from interbolt.utils.names import validate_endorsement_kind

_logger = get_logger("taint.endorse")


def _add_endorsement(label: Label, kind: str) -> Label:
    """Return a copy of `label` with `kind` added to its endorsements.

    De-duplicated, insertion order preserved; lineage and ingested_by are
    unchanged (an endorsement never touches provenance, attribution, or
    trust resolution). Always mints a fresh `value_id`: the endorsement hop
    is itself a derivation.
    """
    if kind in label.endorsements:
        endorsements = label.endorsements
    else:
        endorsements = (*label.endorsements, kind)
    return Label.model_construct(
        source=label.source,
        value_id=_new_value_id(),
        lineage=label.lineage,
        ingested_by=label.ingested_by,
        endorsements=endorsements,
    )


def _record_endorsement(*, kind: str, note: str | None, label: Label) -> None:
    trace_id, span_id = current_trace_context() or (None, None)
    endorsement = Endorsement(
        schema_version=EVENT_SCHEMA_VERSION,
        kind=kind,
        note=note,
        lineage=label.lineage,
        value_id=label.value_id,
        agent_id=current_agent_id.get() or DEFAULT_AGENT_ID,
        run_id=current_run_id.get() or str(uuid.uuid4()),
        session_id=None,
        trace_id=trace_id,
        span_id=span_id,
        timestamp=datetime.now(UTC),
    )
    emitter = get_endorsement_emitter()
    if emitter is None:
        _logger.info(
            "endorse(): kind=%s value_id=%s lineage=%s "
            "(no runtime configured; not emitted through a reporter)",
            kind,
            endorsement.value_id,
            endorsement.lineage,
        )
        return
    emitter(endorsement)


def _endorse_leaf(
    value: Any,  # noqa: ANN401
    *,
    kind: str,
    endorsed_labels: list[Label],
) -> Any:  # noqa: ANN401
    if isinstance(value, Tainted):
        new_label = _add_endorsement(value.label, kind)
        endorsed_labels.append(new_label)
        return Tainted(value, label=new_label)
    if isinstance(value, TaintedBytes):
        new_label = _add_endorsement(value.label, kind)
        endorsed_labels.append(new_label)
        return TaintedBytes(value, label=new_label)
    if isinstance(value, LabeledValue):
        new_label = _add_endorsement(value.label, kind)
        endorsed_labels.append(new_label)
        return LabeledValue(value=value.value, label=new_label)
    return value


def endorse(value: Any, *, kind: str, note: str | None = None) -> Any:  # noqa: ANN401
    """Record that a value passed a named validation step.

    Use this after code has actually checked an untrusted value: parsed a URL,
    matched a recipient against an allowlist, validated a payload against a
    schema. `kind` names the check that ran. A sink whose policy asks for that
    kind will accept the value; every other sink is unaffected.

    The value's sources and its resolved trust do not change. Only a policy
    that names the endorsement sees a difference, so adding `endorse()` calls
    cannot loosen a rule that does not mention them.

    Endorse from deterministic code, immediately after the check it stands
    for. A model's assessment of a value is not a validation step.

    Accepts the same shapes as `taint()`. A value carrying no mark comes back
    unchanged.

    Args:
        value: The value to endorse.
        kind: The name of the validation that ran. Match it in a policy with
            `t.endorsements.any(k, k == "...")` or a rule's
            `require_endorsement`. Letters, digits, `_`, `.`, and `-`.
        note: Free text recorded on the emitted `Endorsement`. It is not
            attached to the value.

    Returns:
        The endorsed value, or `value` unchanged if it carries no mark.

    Raises:
        InterboltConfigError: If `kind` is empty or contains a character
            outside `[A-Za-z0-9_.-]`.
    """
    validate_endorsement_kind(kind)
    endorsed_labels: list[Label] = []
    result = map_leaves(
        value,
        depth=RECURSION_DEPTH,
        fn=lambda leaf: _endorse_leaf(leaf, kind=kind, endorsed_labels=endorsed_labels),
    )
    if not endorsed_labels:
        _logger.debug(
            "endorse(kind=%r): value carries no label; nothing to endorse", kind
        )
        return result
    for label in endorsed_labels:
        _record_endorsement(kind=kind, note=note, label=label)
    return result
