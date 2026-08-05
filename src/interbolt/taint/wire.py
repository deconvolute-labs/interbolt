"""pack(), unpack(), pack_into(), unpack_from(): the serialization contract."""

from __future__ import annotations

from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from pydantic import ValidationError

from interbolt.constants import WIRE_ENVELOPE_KEY, WIRE_SCHEMA_VERSION
from interbolt.errors import InterboltConfigError
from interbolt.models.core import Label
from interbolt.taint.runstate import (
    record_capabilities,
    record_ingress,
    run_capabilities,
    run_ingress,
)
from interbolt.taint.wire_rebuild import _rebuild, _replay_audit
from interbolt.taint.wire_schema import (
    LabelEntry,
    PooledLabel,
    RunBlock,
    RunSourceEntry,
    ShapeEntry,
    WireEnvelope,
    compute_mac,
    verify_mac,
)
from interbolt.taint.wire_walk import LabelCarrier, Path, strip_to_json
from interbolt.utils import current_run_id, get_logger

_logger = get_logger("taint.wire")


def _intern_labels(
    raw_labels: list[tuple[Path, LabelCarrier, Label]],
) -> tuple[tuple[PooledLabel, ...], tuple[LabelEntry, ...]]:
    """Deduplicate raw `(path, carrier, label)` entries by `label.value_id`."""
    pool: list[Label] = []
    index_by_value_id: dict[str, int] = {}
    entries: list[LabelEntry] = []
    for path, carrier, label in raw_labels:
        index = index_by_value_id.get(label.value_id)
        if index is None:
            index = len(pool)
            index_by_value_id[label.value_id] = index
            pool.append(label)
        entries.append(LabelEntry(path=path, label=index, carrier=carrier))
    pooled = tuple(
        PooledLabel(
            source=label.source,
            value_id=label.value_id,
            lineage=label.lineage,
            ingested_by=label.ingested_by,
            endorsements=label.endorsements,
        )
        for label in pool
    )
    return pooled, tuple(entries)


@lru_cache(maxsize=1)
def _warn_unauthenticated_once() -> None:
    """Log, once per process, that an unkeyed `unpack()` trusts its channel.

    Guarded by `lru_cache` rather than a mutable flag: the cache slot itself
    is the guard.
    """
    _logger.warning(
        "unpack() called with key=None: this envelope's provenance is "
        "trusted only as far as the medium that carried it. A store or "
        "channel an attacker can write to can assert any source or label "
        "it chooses. Pass key= to verify a producer-attached mac."
    )


def pack(
    value: Any,  # noqa: ANN401 -- accepts any packable shape
    *,
    key: bytes | str | None = None,
    key_id: str | None = None,
    include_run: bool = True,
) -> dict[str, Any]:
    """Capture `value`'s provenance in a plain, JSON-representable envelope.

    Strips every `Tainted`/`TaintedBytes`/`LabeledValue` carrier down to a
    JSON-representable leaf and records what it stripped in a path-keyed
    sidecar, so `unpack` can rebuild the carriers later, possibly in another
    process. The library does not serialize; hand the returned `dict` to
    whatever codec you already use.

    An unauthenticated envelope (no `key`) inherits the trust of whatever
    medium carries it: anyone who can write the store can assert any
    provenance they choose. Pass `key` when the store is not already inside
    your trust boundary.

    Args:
        value: The value to pack. May be a bare tainted leaf or an
            arbitrarily nested container of them.
        key: An HMAC key authenticating the envelope. `None` produces an
            unauthenticated envelope.
        key_id: An opaque identifier for `key`, carried in the envelope and
            covered by the MAC. Reserved for future key rotation; no
            semantics beyond that today.
        include_run: Whether to record the active run's ingested sources and
            their agents, and its accumulated trifecta capability legs, in
            the envelope, sorted for reproducibility, for replay into
            whatever run unpacks it. A capability leg only ever accumulates,
            so replaying one forward into the next turn is intentional: a
            run-scoped Rule-of-Two check that reset at every turn boundary
            would not survive the multi-turn handoff this contract exists
            for.

    Returns:
        A plain, JSON-representable envelope dict.

    Raises:
        InterboltConfigError: `key_id` was given without `key`; `value`
            contains a non-string mapping key; or `value` contains a leaf
            that cannot be represented in the envelope (a `datetime`, a
            Pydantic model, or any other non-JSON-representable object,
            including a `LabeledValue` wrapping one).
    """
    if key_id is not None and key is None:
        raise InterboltConfigError("key_id given without key")

    payload, raw_labels, raw_shapes = strip_to_json(value, depth=None)
    pool, label_entries = _intern_labels(raw_labels)
    shape_entries = tuple(ShapeEntry(path=path, kind=kind) for path, kind in raw_shapes)

    run_block: RunBlock | None = None
    if include_run:
        run_id = current_run_id.get()
        if run_id is not None:
            entries = run_ingress(run_id)
            run_block = RunBlock(
                sources=tuple(
                    RunSourceEntry(name=name, ingested_by=tuple(sorted(entries[name])))
                    for name in sorted(entries)
                ),
                capabilities=tuple(sorted(run_capabilities(run_id))),
            )

    envelope = WireEnvelope(
        version=WIRE_SCHEMA_VERSION,
        payload=payload,
        label_pool=pool,
        labels=label_entries,
        shape=shape_entries,
        run=run_block,
        key_id=key_id,
        mac=None,
    )
    if key is not None:
        envelope = envelope.model_copy(update={"mac": compute_mac(envelope, key=key)})
    return envelope.model_dump(mode="json")


def unpack(
    envelope: Mapping[str, Any],
    *,
    key: bytes | str | None = None,
) -> Any:  # noqa: ANN401 -- returns whatever shape was packed
    """Rehydrate a `pack()`-produced envelope.

    Validates the envelope's shape, verifies the MAC when one is expected,
    rebuilds every carrier at its recorded path, replays the run's ingested
    source names and accumulated trifecta capability legs into the
    currently active run, and replays rehydrated content to the laundering
    audit observer when one is installed. Builds the complete rehydrated
    value before any of these replays run, so a rejection never leaves
    partial state behind. Replayed capability legs only ever accumulate
    into the active run's set; they are never used to reset it.

    Args:
        envelope: The envelope to unpack, typically the direct output of
            `json.loads` on whatever `pack()` produced.
        key: The HMAC key to verify the envelope's `mac` with. Required if
            the envelope carries a `mac`; must be omitted if it does not.

    Returns:
        The rehydrated value, in the same shape it was packed from.

    Raises:
        InterboltConfigError: The envelope's `version` is unrecognized; it
            fails schema validation or carries unknown keys; `key` and the
            envelope's `mac` are inconsistent (one given without the
            other); the `mac` does not verify; a label or shape entry's
            path does not resolve against `payload`, or resolves to a leaf
            whose type contradicts its `carrier`/`kind`; two entries share
            a path; a pooled label fails validation; a `label` index is out
            of range; the entry count exceeds the configured cap; or a
            `set`/`frozenset` shape entry's restored members are unhashable.
    """
    raw_version = envelope.get("version")
    if raw_version != WIRE_SCHEMA_VERSION:
        raise InterboltConfigError(
            f"unknown or missing wire schema version: {raw_version!r}"
        )

    try:
        parsed = WireEnvelope.model_validate(envelope)
    except ValidationError as exc:
        raise InterboltConfigError(f"invalid serialization envelope: {exc}") from exc

    if key is not None and parsed.mac is None:
        raise InterboltConfigError("key supplied but envelope carries no mac")
    if key is None and parsed.mac is not None:
        raise InterboltConfigError("envelope carries a mac but no key was supplied")
    if key is not None:
        if not verify_mac(parsed, key=key):
            raise InterboltConfigError("mac does not verify")
    else:
        _warn_unauthenticated_once()

    pool = tuple(pooled.to_label() for pooled in parsed.label_pool)

    rehydrated, rebuilt_by_path = _rebuild(parsed, pool)

    if parsed.run is not None:
        record_ingress({entry.name: entry.ingested_by for entry in parsed.run.sources})
        if parsed.run.capabilities:
            _replay_capabilities(frozenset(parsed.run.capabilities))
    _replay_audit(parsed, pool, rebuilt_by_path)

    return rehydrated


def _replay_capabilities(capabilities: frozenset[str]) -> None:
    """Replay packed run capabilities into the currently active run, if any."""
    run_id = current_run_id.get()
    if run_id is None:
        _logger.debug(
            "unpack() carried run capabilities %r but no run is active; "
            "this cannot be attributed to a run",
            tuple(sorted(capabilities)),
        )
        return
    record_capabilities(run_id, capabilities)


def pack_into(
    mapping: Mapping[str, Any],
    *,
    key: bytes | str | None = None,
    key_id: str | None = None,
    include_run: bool = True,
) -> dict[str, Any]:
    """Pack a top-level state mapping, keeping its shape.

    Sugar over `pack` for the dominant case: a mapping other code reads by
    key and must keep its shape. Returns a new mapping with every carrier
    stripped and one reserved key, `constants.WIRE_ENVELOPE_KEY`, added to
    hold the sidecar. Every other key is left exactly where it was.

    Args:
        mapping: The state mapping to pack. Must not already contain
            `constants.WIRE_ENVELOPE_KEY`.
        key: An HMAC key authenticating the envelope. `None` produces an
            unauthenticated envelope.
        key_id: An opaque identifier for `key`, carried in the envelope and
            covered by the MAC.
        include_run: Whether to record the active run's ingested source
            names and accumulated trifecta capability legs in the envelope,
            for replay into whatever run unpacks it.

    Returns:
        A new plain mapping: every original key with its carriers stripped,
        plus `constants.WIRE_ENVELOPE_KEY` holding the sidecar.

    Raises:
        InterboltConfigError: `mapping` already contains
            `constants.WIRE_ENVELOPE_KEY`, or for any reason `pack` itself
            would raise.
    """
    if WIRE_ENVELOPE_KEY in mapping:
        raise InterboltConfigError(
            f"mapping already contains the reserved key {WIRE_ENVELOPE_KEY!r}"
        )
    envelope = pack(dict(mapping), key=key, key_id=key_id, include_run=include_run)
    payload = envelope.pop("payload")
    result: dict[str, Any] = dict(payload)
    result[WIRE_ENVELOPE_KEY] = envelope
    return result


def unpack_from(
    mapping: Mapping[str, Any],
    *,
    key: bytes | str | None = None,
) -> dict[str, Any]:
    """Unpack a top-level state mapping produced by `pack_into`.

    Args:
        mapping: The mapping to unpack. Must contain
            `constants.WIRE_ENVELOPE_KEY`.
        key: The HMAC key to verify the envelope's `mac` with. Required if
            the envelope carries a `mac`; must be omitted if it does not.

    Returns:
        A new plain mapping with every carrier rebuilt, the reserved key
        removed.

    Raises:
        InterboltConfigError: `mapping` has no `constants.WIRE_ENVELOPE_KEY`
            sidecar, or for any reason `unpack` itself would raise.
    """
    if WIRE_ENVELOPE_KEY not in mapping:
        raise InterboltConfigError(
            f"mapping has no {WIRE_ENVELOPE_KEY!r} sidecar to unpack"
        )
    sidecar = dict(mapping[WIRE_ENVELOPE_KEY])
    sidecar["payload"] = {k: v for k, v in mapping.items() if k != WIRE_ENVELOPE_KEY}
    rehydrated = unpack(sidecar, key=key)
    return dict(rehydrated)
