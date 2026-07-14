"""The `endorse()` primitive: the integrity dual of declassification.

`endorse` and `install_endorsement_emitter` are re-exported from
`taint/__init__.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from interbolt.constants import (
    CONTAINER_TYPES,
    DEFAULT_AGENT_ID,
    EVENT_SCHEMA_VERSION,
    RECURSION_DEPTH,
)
from interbolt.models.core import Endorsement, Label
from interbolt.taint.carriers import LabeledValue, Tainted, TaintedBytes, _new_value_id
from interbolt.utils import current_agent_id, current_run_id, get_logger

_logger = get_logger("taint.endorse")

_endorsement_emitter: Callable[[Endorsement], None] | None = None
"""The endorse()-time emitter hook, installed by runtime.configure().

Unlike the taint()-time audit observer (`install_taint_observer`, gated
behind `audit=True`), this hook is installed unconditionally on every
`configure()` call: endorsement auditing is not optional whenever a
runtime (and therefore a reporter, even the default `NullReporter`) exists.
Internal, not part of the public surface.
"""


def install_endorsement_emitter(cb: Callable[[Endorsement], None] | None) -> None:
    """Install, or clear with `None`, the endorse()-time emitter hook.

    Called only from `runtime.configure()`, every call, regardless of the
    `audit` flag.
    """
    global _endorsement_emitter
    _endorsement_emitter = cb


def _add_endorsement(label: Label, kind: str) -> Label:
    """Return a copy of `label` with `kind` added to its endorsements.

    De-duplicated, insertion order preserved; lineage is unchanged (an
    endorsement never touches provenance or trust resolution). Always mints
    a fresh `value_id`: the endorsement hop is itself a derivation.
    """
    if kind in label.endorsements:
        endorsements = label.endorsements
    else:
        endorsements = (*label.endorsements, kind)
    return Label.model_construct(
        source=label.source,
        value_id=_new_value_id(),
        lineage=label.lineage,
        endorsements=endorsements,
    )


def _record_endorsement(*, kind: str, note: str | None, label: Label) -> None:
    endorsement = Endorsement(
        schema_version=EVENT_SCHEMA_VERSION,
        kind=kind,
        note=note,
        lineage=label.lineage,
        value_id=label.value_id,
        agent_id=current_agent_id.get() or DEFAULT_AGENT_ID,
        run_id=current_run_id.get() or str(uuid.uuid4()),
        session_id=None,
        timestamp=datetime.now(UTC),
    )
    emitter = _endorsement_emitter
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


def _endorse_recurse(
    value: Any,  # noqa: ANN401
    *,
    kind: str,
    depth: int,
    endorsed_labels: list[Label],
    rebuild: Callable[[Any, list[Any]], Any],
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
    if depth <= 0:
        return value
    if isinstance(value, Mapping):
        return {
            _endorse_recurse(
                k,
                kind=kind,
                depth=depth - 1,
                endorsed_labels=endorsed_labels,
                rebuild=rebuild,
            ): _endorse_recurse(
                v,
                kind=kind,
                depth=depth - 1,
                endorsed_labels=endorsed_labels,
                rebuild=rebuild,
            )
            for k, v in value.items()
        }
    if isinstance(value, CONTAINER_TYPES):
        items = [
            _endorse_recurse(
                item,
                kind=kind,
                depth=depth - 1,
                endorsed_labels=endorsed_labels,
                rebuild=rebuild,
            )
            for item in value
        ]
        try:
            return rebuild(value, items)
        except Exception:  # noqa: BLE001 -- containment must never crash the caller
            _logger.debug(
                "endorse(): could not reconstruct container type %s; "
                "returning the value unendorsed",
                type(value).__name__,
                exc_info=True,
            )
            return value
    return value


def endorse(value: Any, *, kind: str, note: str | None = None) -> Any:  # noqa: ANN401
    """Reduce a value's restrictiveness after explicit, code-driven validation.

    The integrity dual of declassification: where `taint()` marks a value's
    provenance at ingress, `endorse()` records that a specific validation
    step has vouched for it, without erasing that provenance. `lineage` is
    unchanged and `t.trust` still resolves exactly as before; `kind` is
    added to the label's `endorsements`, a policy-visible fact a sink can
    require (`t.endorsements.exists(k, k == "recipient_allowlisted")`).
    Endorsing with a kind a sink does not check has no effect there, which
    is what keeps one endorsement from silently over-authorizing an
    unrelated sink.

    Accepts the same shapes as `taint()`: a `Tainted`/`TaintedBytes`/
    `LabeledValue` leaf, or a builtin container/mapping (recursing to the
    same bounded depth, endorsing every already-labeled leaf found). A value
    with no label anywhere in it passes through unchanged; there is nothing
    to endorse.

    `kind` is required and machine-matchable on purpose: a blanket boolean
    "endorsed" flag cannot express that a value validated safe for one sink
    (a URL sanitizer) is not thereby safe for another (an email allowlist),
    and a low-friction untainting primitive with no required category is
    exactly the rubber stamp that undermined Perl's taint mode. Call this
    only from deterministic code immediately after a real validation step;
    never call it because a model asked to, or based on model output, since
    the model is the confused deputy this library defends against.

    `run.tainted` is unaffected: run-level gating is coarse and
    laundering-resistant by design, and a value-level endorsement must not
    clear it.

    Args:
        value: The value to endorse.
        kind: The endorsement category, matched against a policy's
            `t.endorsements` in CEL. Required, so every endorsement is
            explicit about what it vouches for.
        note: An optional free-text annotation carried on the emitted
            `Endorsement` record only, never on the value's label.

    Returns:
        The endorsed value, or `value` unchanged if it carries no label.
    """
    # Local import: taint/__init__.py re-exports this module's `endorse`, so
    # a module-level import of `_rebuild_container` back from there would
    # form an import cycle. Same pattern policy/schema.py already uses.
    from interbolt.taint import _rebuild_container

    endorsed_labels: list[Label] = []
    result = _endorse_recurse(
        value,
        kind=kind,
        depth=RECURSION_DEPTH,
        endorsed_labels=endorsed_labels,
        rebuild=_rebuild_container,
    )
    if not endorsed_labels:
        _logger.debug(
            "endorse(kind=%r): value carries no label; nothing to endorse", kind
        )
        return result
    for label in endorsed_labels:
        _record_endorsement(kind=kind, note=note, label=label)
    return result
