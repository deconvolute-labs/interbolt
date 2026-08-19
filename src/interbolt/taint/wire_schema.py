"""Wire-format envelope models, canonicalization, and MAC helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationInfo,
    field_validator,
    model_validator,
)

from interbolt.constants import (
    WIRE_MAX_ENTRIES,
    WIRE_MAX_LIST_LENGTH,
    WIRE_MAX_NAME_LENGTH,
    WIRE_SCHEMA_VERSION,
)
from interbolt.models.core import Capability, Label
from interbolt.taint.wire_walk import LabelCarrier, Path, ShapeKind
from interbolt.utils.names import validate_agent_id, validate_endorsement_kind

_MAC_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_VALID_PATH_TAGS = frozenset({"v", "k", "i"})


def _validate_path(value: Path) -> Path:
    """Reject a path whose segments don't match their addressing mode.

    `"v"`/`"k"` segments must carry a `str` key; `"i"` segments must carry a
    non-`bool` `int` index. A `"k"` segment is valid only as the path's final
    segment.
    """
    for position, (tag, key) in enumerate(value):
        if tag not in _VALID_PATH_TAGS:
            raise ValueError(
                f"path segment tag {tag!r} is not one of {sorted(_VALID_PATH_TAGS)}"
            )
        if tag == "i":
            if not isinstance(key, int) or isinstance(key, bool):
                raise ValueError(
                    f"path segment {(tag, key)!r}: 'i' requires an int index"
                )
        else:
            if not isinstance(key, str):
                raise ValueError(
                    f"path segment {(tag, key)!r}: {tag!r} requires a string key"
                )
            if tag == "k" and position != len(value) - 1:
                raise ValueError(
                    "a 'k' path segment is only valid as the final segment"
                )
    return value


def _validate_name_length(value: str, *, field: str) -> str:
    if len(value) > WIRE_MAX_NAME_LENGTH:
        raise ValueError(f"{field} exceeds {WIRE_MAX_NAME_LENGTH} characters")
    return value


def _validate_list_length(value: tuple[str, ...], *, field: str) -> tuple[str, ...]:
    if len(value) > WIRE_MAX_LIST_LENGTH:
        raise ValueError(f"{field} exceeds {WIRE_MAX_LIST_LENGTH} entries")
    return value


class PooledLabel(BaseModel):
    """The wire form of one interned `Label`, validated against untrusted input."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str
    value_id: str
    lineage: tuple[str, ...]
    ingested_by: tuple[str, ...] = ()
    endorsements: tuple[str, ...] = ()

    @field_validator("source", "value_id")
    @classmethod
    def _validate_short_name(cls, value: str, info: ValidationInfo) -> str:
        return _validate_name_length(value, field=info.field_name or "field")

    @field_validator("lineage")
    @classmethod
    def _validate_lineage(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for name in value:
            _validate_name_length(name, field="lineage entry")
        return _validate_list_length(value, field="lineage")

    @field_validator("ingested_by")
    @classmethod
    def _validate_ingested_by(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for agent_id in value:
            validate_agent_id(agent_id)
            _validate_name_length(agent_id, field="ingested_by entry")
        return _validate_list_length(value, field="ingested_by")

    @field_validator("endorsements")
    @classmethod
    def _validate_endorsements(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for kind in value:
            validate_endorsement_kind(kind)
            _validate_name_length(kind, field="endorsements entry")
        return _validate_list_length(value, field="endorsements")

    def to_label(self) -> Label:
        """Materialize a real, fully-validated `Label` from this pooled entry."""
        return Label(
            source=self.source,
            value_id=self.value_id,
            lineage=self.lineage,
            ingested_by=self.ingested_by,
            endorsements=self.endorsements,
        )


class LabelEntry(BaseModel):
    """Where one pooled label attaches in `payload`, and which carrier to rebuild."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: Path
    label: int
    carrier: LabelCarrier

    @field_validator("path")
    @classmethod
    def _validate_path_shape(cls, value: Path) -> Path:
        return _validate_path(value)


class ShapeEntry(BaseModel):
    """A type restoration JSON cannot express at `path`."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: Path
    kind: ShapeKind

    @field_validator("path")
    @classmethod
    def _validate_path_shape(cls, value: Path) -> Path:
        return _validate_path(value)


class RunSourceEntry(BaseModel):
    """One source active at pack time, with the agent ids that ingested it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    ingested_by: tuple[str, ...]

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _validate_name_length(value, field="run.sources entry")

    @field_validator("ingested_by")
    @classmethod
    def _validate_ingested_by(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for agent_id in value:
            _validate_name_length(agent_id, field="run.sources ingested_by entry")
        return _validate_list_length(value, field="run.sources ingested_by")


class RunBlock(BaseModel):
    """Run-scoped provenance: the sources active at pack time, with their agents.

    Attributes:
        sources: The sources active at pack time, with their agents.
        capabilities: The run-scoped trifecta capability legs accumulated so
            far, so a Rule-of-Two check survives a `pack`/`unpack` round trip
            across a turn boundary.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sources: tuple[RunSourceEntry, ...]
    capabilities: tuple[str, ...] = ()

    @field_validator("sources")
    @classmethod
    def _validate_sources_length(
        cls, value: tuple[RunSourceEntry, ...]
    ) -> tuple[RunSourceEntry, ...]:
        if len(value) > WIRE_MAX_LIST_LENGTH:
            raise ValueError(f"run.sources exceeds {WIRE_MAX_LIST_LENGTH} entries")
        return value

    @field_validator("capabilities")
    @classmethod
    def _validate_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        valid = {member.value for member in Capability}
        for leg in value:
            if leg not in valid:
                raise ValueError(
                    f"unknown capability {leg!r}; expected one of {sorted(valid)}"
                )
        return _validate_list_length(value, field="run.capabilities")


class WireEnvelope(BaseModel):
    """The validated shape of one `pack`/`unpack` envelope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int
    payload: Any  # noqa: ANN401 -- any JSON-representable value, by wire-format design
    label_pool: tuple[PooledLabel, ...]
    labels: tuple[LabelEntry, ...]
    shape: tuple[ShapeEntry, ...]
    run: RunBlock | None
    key_id: str | None
    mac: str | None

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: int) -> int:
        if value != WIRE_SCHEMA_VERSION:
            raise ValueError(f"unknown wire schema version {value!r}")
        return value

    @field_validator("key_id")
    @classmethod
    def _validate_key_id(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_name_length(value, field="key_id")
        return value

    @field_validator("mac")
    @classmethod
    def _validate_mac(cls, value: str | None) -> str | None:
        if value is not None and not _MAC_PATTERN.fullmatch(value):
            raise ValueError("mac must match 'sha256:<64 lowercase hex chars>'")
        return value

    @field_validator("labels")
    @classmethod
    def _validate_unique_label_paths(
        cls, value: tuple[LabelEntry, ...]
    ) -> tuple[LabelEntry, ...]:
        paths = [entry.path for entry in value]
        if len(set(paths)) != len(paths):
            raise ValueError("two label entries share a path")
        return value

    @field_validator("shape")
    @classmethod
    def _validate_unique_shape_paths(
        cls, value: tuple[ShapeEntry, ...]
    ) -> tuple[ShapeEntry, ...]:
        paths = [entry.path for entry in value]
        if len(set(paths)) != len(paths):
            raise ValueError("two shape entries share a path")
        return value

    @field_validator("label_pool")
    @classmethod
    def _validate_unique_value_ids(
        cls, value: tuple[PooledLabel, ...]
    ) -> tuple[PooledLabel, ...]:
        value_ids = [label.value_id for label in value]
        if len(set(value_ids)) != len(value_ids):
            raise ValueError("label_pool contains a duplicate value_id")
        return value

    @model_validator(mode="after")
    def _validate_entry_bounds(self) -> WireEnvelope:
        if len(self.labels) + len(self.shape) > WIRE_MAX_ENTRIES:
            raise ValueError(f"labels + shape entries exceed {WIRE_MAX_ENTRIES}")
        for entry in self.labels:
            if not 0 <= entry.label < len(self.label_pool):
                raise ValueError(
                    f"label index {entry.label} out of range for label_pool"
                )
        return self


def canonical_bytes(envelope: WireEnvelope) -> bytes:
    """Serialize `envelope` in canonical form for MAC computation.

    `mac` is forced to `null` regardless of what `envelope.mac` holds; the
    rest is dumped via `model_dump(mode="json")`, then serialized with
    sorted keys and compact separators, UTF-8 encoded.

    Args:
        envelope: The envelope to canonicalize.

    Returns:
        The canonical UTF-8 encoded bytes.
    """
    data = envelope.model_dump(mode="json")
    data["mac"] = None
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_mac(envelope: WireEnvelope, *, key: bytes | str) -> str:
    """Compute `"sha256:<hex>"`, the HMAC-SHA256 over `envelope`'s canonical form.

    Args:
        envelope: The envelope to authenticate.
        key: The HMAC key. A `str` key is UTF-8 encoded.

    Returns:
        The MAC, prefixed with its algorithm name.
    """
    key_bytes = key if isinstance(key, bytes) else key.encode("utf-8")
    digest = hmac.new(key_bytes, canonical_bytes(envelope), hashlib.sha256).hexdigest()
    return f"sha256:{digest}"


def verify_mac(envelope: WireEnvelope, *, key: bytes | str) -> bool:
    """Whether `envelope.mac` matches the HMAC computed over its canonical form.

    Args:
        envelope: The envelope to verify. Must already carry a `mac`.
        key: The HMAC key. A `str` key is UTF-8 encoded.

    Returns:
        `True` if `envelope.mac` matches, `False` otherwise (including when
        `envelope.mac` is `None`).
    """
    if envelope.mac is None:
        return False
    return hmac.compare_digest(compute_mac(envelope, key=key), envelope.mac)
