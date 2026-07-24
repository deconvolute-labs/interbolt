"""The taint carriers: `Tainted`, `TaintedBytes`, `LabeledValue`, and label merge.

The bulk of this file is mechanically repetitive per-operation dunder
overrides on `Tainted`/`TaintedBytes`, not independent concerns to split
into separate files.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from interbolt.constants import DEFAULT_AGENT_ID
from interbolt.errors import InterboltUsageError
from interbolt.models.core import Label
from interbolt.utils import current_agent_id


def _new_value_id() -> str:
    return str(uuid.uuid4())


def _fresh_label(source: str) -> Label:
    agent = current_agent_id.get() or DEFAULT_AGENT_ID
    return Label(
        source=source, value_id=_new_value_id(), lineage=(source,), ingested_by=(agent,)
    )


def _identity(value: Any) -> Any:  # noqa: ANN401 - pickle reconstruction target
    """Return `value` unchanged; the `__reduce__` target for `LabeledValue`.

    A plain, importable module-level function, since pickle needs a callable
    it can reference by qualified name, and `type(value)` is not always a
    valid single-argument reconstructor (`NoneType()` takes no arguments).
    """
    return value


def _intersect_endorsements(labels: Sequence[Label]) -> tuple[str, ...]:
    """Intersect every label's `endorsements`, order from the first label.

    A merge is conservative: an endorsement kind survives only if every
    contributing label carried it.
    """
    common = set(labels[0].endorsements)
    for label in labels[1:]:
        common &= set(label.endorsements)
    return tuple(kind for kind in labels[0].endorsements if kind in common)


def _merge_labels(*labels: Label) -> Label:
    """Union the lineage of one or more labels and mint a fresh value_id.

    Used both to retag a single-label transformation result and to merge
    two or more differently-sourced operands (lineage and ingested_by
    union, endorsements intersection). This is an operand-level combine,
    not a derivation hop, so it does not add the current agent to
    `ingested_by`, unlike `taint(..., derived_from=...)`. A single label is
    returned unchanged: it is frozen and safe to share, and there is
    nothing to merge, so no new `value_id` is minted for a single-parent
    derivation: the fast path for the common case of transforming one
    already-tainted value.
    """
    if not labels:
        raise InterboltUsageError("_merge_labels requires at least one label")
    if len(labels) == 1:
        return labels[0]
    seen_lineage: dict[str, None] = {}
    seen_agents: dict[str, None] = {}
    for label in labels:
        for name in label.lineage:
            seen_lineage.setdefault(name, None)
        for agent in label.ingested_by:
            seen_agents.setdefault(agent, None)
    return Label.model_construct(
        source=labels[0].source,
        value_id=_new_value_id(),
        lineage=tuple(seen_lineage),
        ingested_by=tuple(seen_agents),
        endorsements=_intersect_endorsements(labels),
    )


def _labels_of(*values: Any) -> list[Label]:  # noqa: ANN401 - operands are arbitrary by nature
    return [v.label for v in values if isinstance(v, (Tainted, TaintedBytes))]


def _wrap(value: str, *labels: Label) -> Tainted:
    return Tainted(value, label=_merge_labels(*labels))


def _wrap_bytes(value: bytes, *labels: Label) -> TaintedBytes:
    return TaintedBytes(value, label=_merge_labels(*labels))


class Tainted(str):
    """A `str` that carries a provenance `Label` through a defined operation subset.

    Operator-style combination (`+`, `%`, `*`, slicing, string methods called
    on a `Tainted` receiver) propagates the label. F-strings with literal
    text, `str.format`/`format_map` on a plain template, and `join` on a
    plain separator produce a fresh, unlabeled string; re-`taint` the
    result in those cases.

    `copy.copy`/`copy.deepcopy` preserve the label: both the string value and
    the label are immutable, so a copy safely returns `self`. Pickling
    (`__reduce__`) instead reduces to the plain underlying `str`, dropping
    the label: pickling crosses the process/storage boundary, and taint
    propagation does not survive that boundary by design, so dropping to
    plain here is intentional, not a gap.
    """

    __slots__ = ("label",)
    label: Label

    def __new__(cls, value: str, *, label: Label) -> Tainted:
        obj = str.__new__(cls, value)
        obj.label = label
        return obj

    def __copy__(self) -> Tainted:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> Tainted:
        return self

    def __reduce__(self) -> tuple[Any, ...]:
        return (str, (str(self),))

    def __add__(self, other: Any) -> Any:  # noqa: ANN401 - binary operand, type-checked at runtime
        if not isinstance(other, str):
            return NotImplemented
        result = str.__add__(self, other)
        return _wrap(result, self.label, *_labels_of(other))

    def __radd__(self, other: Any) -> Any:  # noqa: ANN401
        if not isinstance(other, str):
            return NotImplemented
        result = str.__add__(other, self)
        return _wrap(result, self.label)

    def __mod__(self, other: Any) -> Any:  # noqa: ANN401
        result = str.__mod__(self, other)
        if isinstance(other, Mapping):
            return _wrap(result, self.label, *_labels_of(*other.values()))
        values = other if isinstance(other, tuple) else (other,)
        return _wrap(result, self.label, *_labels_of(*values))

    def __rmod__(self, other: Any) -> Any:  # noqa: ANN401
        if not isinstance(other, str):
            return NotImplemented
        result = str.__mod__(other, self)
        return _wrap(result, self.label)

    def __mul__(self, n: Any) -> Any:  # noqa: ANN401
        result = str.__mul__(self, n)
        if result is NotImplemented:
            return result
        return _wrap(result, self.label)

    def __rmul__(self, n: Any) -> Any:  # noqa: ANN401
        result = str.__mul__(self, n)
        if result is NotImplemented:
            return result
        return _wrap(result, self.label)

    def __getitem__(self, key: Any) -> Any:  # noqa: ANN401
        result = str.__getitem__(self, key)
        return _wrap(result, self.label)

    def __format__(self, format_spec: str) -> str:
        if format_spec == "":
            return self
        return str.__format__(self, format_spec)

    def upper(self) -> Tainted:
        return _wrap(str.upper(self), self.label)

    def lower(self) -> Tainted:
        return _wrap(str.lower(self), self.label)

    def strip(self, chars: str | None = None) -> Tainted:
        return _wrap(str.strip(self, chars), self.label)

    def lstrip(self, chars: str | None = None) -> Tainted:
        return _wrap(str.lstrip(self, chars), self.label)

    def rstrip(self, chars: str | None = None) -> Tainted:
        return _wrap(str.rstrip(self, chars), self.label)

    def replace(self, old: str, new: str, count: int = -1) -> Tainted:  # type: ignore[override]
        # Narrows str's return type to Tainted; a covariant, intentional override.
        result = str.replace(self, old, new, count)
        return _wrap(result, self.label, *_labels_of(new))

    def format(self, *args: Any, **kwargs: Any) -> Tainted:  # noqa: ANN401
        result = str.format(self, *args, **kwargs)
        return _wrap(result, self.label, *_labels_of(*args, *kwargs.values()))

    def split(  # type: ignore[override]
        self, sep: str | None = None, maxsplit: int = -1
    ) -> list[Tainted]:
        # Narrows str's return type to list[Tainted]; a covariant, intentional override.
        return [_wrap(part, self.label) for part in str.split(self, sep, maxsplit)]

    def rsplit(  # type: ignore[override]
        self, sep: str | None = None, maxsplit: int = -1
    ) -> list[Tainted]:
        return [_wrap(part, self.label) for part in str.rsplit(self, sep, maxsplit)]

    def splitlines(self, keepends: bool = False) -> list[Tainted]:  # type: ignore[override]
        return [_wrap(part, self.label) for part in str.splitlines(self, keepends)]

    def partition(self, sep: str) -> tuple[Tainted, Tainted, Tainted]:
        head, sep_part, tail = str.partition(self, sep)
        return (
            _wrap(head, self.label),
            _wrap(sep_part, self.label),
            _wrap(tail, self.label),
        )

    def rpartition(self, sep: str) -> tuple[Tainted, Tainted, Tainted]:
        head, sep_part, tail = str.rpartition(self, sep)
        return (
            _wrap(head, self.label),
            _wrap(sep_part, self.label),
            _wrap(tail, self.label),
        )

    def join(self, iterable: Iterable[Any]) -> Tainted:
        items = list(iterable)
        result = str.join(self, items)
        return _wrap(result, self.label, *_labels_of(*items))

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> TaintedBytes:
        # Narrows str's return type to TaintedBytes; the str-to-bytes I/O boundary.
        return _wrap_bytes(str.encode(self, encoding, errors), self.label)

    def casefold(self) -> Tainted:
        return _wrap(str.casefold(self), self.label)

    def capitalize(self) -> Tainted:
        return _wrap(str.capitalize(self), self.label)

    def title(self) -> Tainted:
        return _wrap(str.title(self), self.label)

    def swapcase(self) -> Tainted:
        return _wrap(str.swapcase(self), self.label)

    def removeprefix(self, prefix: str) -> Tainted:
        return _wrap(str.removeprefix(self, prefix), self.label)

    def removesuffix(self, suffix: str) -> Tainted:
        return _wrap(str.removesuffix(self, suffix), self.label)

    def center(self, width: int, fillchar: str = " ") -> Tainted:  # type: ignore[override]
        # Narrows str's return type to Tainted; a covariant, intentional override.
        return _wrap(str.center(self, width, fillchar), self.label)

    def ljust(self, width: int, fillchar: str = " ") -> Tainted:  # type: ignore[override]
        return _wrap(str.ljust(self, width, fillchar), self.label)

    def rjust(self, width: int, fillchar: str = " ") -> Tainted:  # type: ignore[override]
        return _wrap(str.rjust(self, width, fillchar), self.label)

    def zfill(self, width: int) -> Tainted:  # type: ignore[override]
        return _wrap(str.zfill(self, width), self.label)

    def expandtabs(self, tabsize: int = 8) -> Tainted:  # type: ignore[override]
        return _wrap(str.expandtabs(self, tabsize), self.label)

    def format_map(self, mapping: Mapping[str, Any]) -> Tainted:  # type: ignore[override]
        # Narrows str's return type to Tainted, mirroring format() above.
        result = str.format_map(self, mapping)
        return _wrap(result, self.label, *_labels_of(*mapping.values()))


class TaintedBytes(bytes):
    """The `bytes` counterpart to `Tainted`.

    Covers binary `+`/`__radd__`, `%`-formatting (`__mod__`/`__rmod__`),
    repetition (`__mul__`/`__rmul__`), slicing/indexing, the case/padding
    family (`upper`/`lower`/`capitalize`/`title`/`swapcase`), `strip`/
    `lstrip`/`rstrip`, `removeprefix`/`removesuffix`, `center`/`ljust`/
    `rjust`/`zfill`/`expandtabs`, `replace`, `decode` (the bytes-to-str I/O
    boundary), the part-returning family
    (`split`/`rsplit`/`partition`/`rpartition`/`splitlines`), and `join`, the
    same subset `Tainted` covers minus the string-formatting methods that
    have no `bytes` analog: `bytes` has no `.format()`/`str.format_map`/
    `casefold` equivalent, so there is nothing to override there.

    Stores `label` as a plain attribute rather than via `__slots__`, since
    CPython bytes subclasses can't add nonempty slots.

    `copy.copy`/`copy.deepcopy` preserve the label by returning `self` (both
    the bytes value and the label are immutable). Pickling reduces to the
    plain underlying `bytes`, dropping the label, the same boundary-reset
    behavior `Tainted` documents above.
    """

    label: Label

    def __new__(cls, value: bytes, *, label: Label) -> TaintedBytes:
        obj = bytes.__new__(cls, value)
        obj.label = label
        return obj

    def __copy__(self) -> TaintedBytes:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> TaintedBytes:
        return self

    def __reduce__(self) -> tuple[Any, ...]:
        return (bytes, (bytes(self),))

    def __add__(self, other: Any) -> Any:  # noqa: ANN401
        if not isinstance(other, bytes):
            return NotImplemented
        result = bytes.__add__(self, other)
        return _wrap_bytes(result, self.label, *_labels_of(other))

    def __radd__(self, other: Any) -> Any:  # noqa: ANN401
        if not isinstance(other, bytes):
            return NotImplemented
        result = bytes.__add__(other, self)
        return _wrap_bytes(result, self.label)

    def __mod__(self, other: Any) -> Any:  # noqa: ANN401
        result = bytes.__mod__(self, other)
        if isinstance(other, Mapping):
            return _wrap_bytes(result, self.label, *_labels_of(*other.values()))
        values = other if isinstance(other, tuple) else (other,)
        return _wrap_bytes(result, self.label, *_labels_of(*values))

    def __rmod__(self, other: Any) -> Any:  # noqa: ANN401
        if not isinstance(other, bytes):
            return NotImplemented
        result = bytes.__mod__(other, self)
        return _wrap_bytes(result, self.label)

    def __mul__(self, n: Any) -> Any:  # noqa: ANN401
        result = bytes.__mul__(self, n)
        if result is NotImplemented:
            return result
        return _wrap_bytes(result, self.label)

    def __rmul__(self, n: Any) -> Any:  # noqa: ANN401
        result = bytes.__mul__(self, n)
        if result is NotImplemented:
            return result
        return _wrap_bytes(result, self.label)

    def __getitem__(self, key: Any) -> Any:  # noqa: ANN401
        result = bytes.__getitem__(self, key)
        if isinstance(result, int):
            return result
        return _wrap_bytes(result, self.label)

    def upper(self) -> TaintedBytes:
        return _wrap_bytes(bytes.upper(self), self.label)

    def lower(self) -> TaintedBytes:
        return _wrap_bytes(bytes.lower(self), self.label)

    def strip(self, chars: bytes | None = None) -> TaintedBytes:  # type: ignore[override]
        # Narrows bytes's return type; a covariant, intentional override.
        return _wrap_bytes(bytes.strip(self, chars), self.label)

    def lstrip(self, chars: bytes | None = None) -> TaintedBytes:  # type: ignore[override]
        return _wrap_bytes(bytes.lstrip(self, chars), self.label)

    def rstrip(self, chars: bytes | None = None) -> TaintedBytes:  # type: ignore[override]
        return _wrap_bytes(bytes.rstrip(self, chars), self.label)

    def replace(  # type: ignore[override]
        self, old: bytes, new: bytes, count: int = -1
    ) -> TaintedBytes:
        result = bytes.replace(self, old, new, count)
        return _wrap_bytes(result, self.label, *_labels_of(new))

    def split(  # type: ignore[override]
        self, sep: bytes | None = None, maxsplit: int = -1
    ) -> list[TaintedBytes]:
        return [
            _wrap_bytes(part, self.label) for part in bytes.split(self, sep, maxsplit)
        ]

    def rsplit(  # type: ignore[override]
        self, sep: bytes | None = None, maxsplit: int = -1
    ) -> list[TaintedBytes]:
        return [
            _wrap_bytes(part, self.label) for part in bytes.rsplit(self, sep, maxsplit)
        ]

    def splitlines(self, keepends: bool = False) -> list[TaintedBytes]:  # type: ignore[override]
        return [
            _wrap_bytes(part, self.label) for part in bytes.splitlines(self, keepends)
        ]

    def partition(  # type: ignore[override]
        self, sep: bytes
    ) -> tuple[TaintedBytes, TaintedBytes, TaintedBytes]:
        # Narrows bytes's Buffer-typed argument to bytes; a covariant,
        # intentional override, matching the treatment already applied to
        # strip/replace/split above.
        head, sep_part, tail = bytes.partition(self, sep)
        return (
            _wrap_bytes(head, self.label),
            _wrap_bytes(sep_part, self.label),
            _wrap_bytes(tail, self.label),
        )

    def rpartition(  # type: ignore[override]
        self, sep: bytes
    ) -> tuple[TaintedBytes, TaintedBytes, TaintedBytes]:
        head, sep_part, tail = bytes.rpartition(self, sep)
        return (
            _wrap_bytes(head, self.label),
            _wrap_bytes(sep_part, self.label),
            _wrap_bytes(tail, self.label),
        )

    def join(self, iterable: Iterable[Any]) -> TaintedBytes:
        items = list(iterable)
        result = bytes.join(self, items)
        return _wrap_bytes(result, self.label, *_labels_of(*items))

    def decode(self, encoding: str = "utf-8", errors: str = "strict") -> Tainted:
        # Narrows bytes's return type to Tainted; the bytes-to-str I/O boundary.
        return _wrap(bytes.decode(self, encoding, errors), self.label)

    def capitalize(self) -> TaintedBytes:
        return _wrap_bytes(bytes.capitalize(self), self.label)

    def title(self) -> TaintedBytes:
        return _wrap_bytes(bytes.title(self), self.label)

    def swapcase(self) -> TaintedBytes:
        return _wrap_bytes(bytes.swapcase(self), self.label)

    def removeprefix(self, prefix: bytes) -> TaintedBytes:  # type: ignore[override]
        return _wrap_bytes(bytes.removeprefix(self, prefix), self.label)

    def removesuffix(self, suffix: bytes) -> TaintedBytes:  # type: ignore[override]
        return _wrap_bytes(bytes.removesuffix(self, suffix), self.label)

    def center(  # type: ignore[override]
        self, width: int, fillchar: bytes = b" "
    ) -> TaintedBytes:
        return _wrap_bytes(bytes.center(self, width, fillchar), self.label)

    def ljust(  # type: ignore[override]
        self, width: int, fillchar: bytes = b" "
    ) -> TaintedBytes:
        return _wrap_bytes(bytes.ljust(self, width, fillchar), self.label)

    def rjust(  # type: ignore[override]
        self, width: int, fillchar: bytes = b" "
    ) -> TaintedBytes:
        return _wrap_bytes(bytes.rjust(self, width, fillchar), self.label)

    def zfill(self, width: int) -> TaintedBytes:  # type: ignore[override]
        return _wrap_bytes(bytes.zfill(self, width), self.label)

    def expandtabs(self, tabsize: int = 8) -> TaintedBytes:  # type: ignore[override]
        return _wrap_bytes(bytes.expandtabs(self, tabsize), self.label)


class LabeledValue:
    """A non-string, non-bytes value labeled at ingress.

    Preserves the label on a number, `bool`, or `None` (types that can't be
    subclassed the way `str`/`bytes` are) for direct use as a sink argument.
    Transforming `.value` first produces a plain, unlabeled result.

    `copy.copy` shares `.value`; `copy.deepcopy` deep-copies `.value` and
    shares the label (frozen, safe to share either way). Pickling reduces to
    the plain `.value`, dropping the label, the same boundary-reset behavior
    `Tainted`/`TaintedBytes` document above.
    """

    __slots__ = ("value", "label")

    def __init__(self, *, value: Any, label: Label) -> None:  # noqa: ANN401
        self.value = value
        self.label = label

    def __repr__(self) -> str:
        return f"LabeledValue({self.value!r}, source={self.label.source!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, LabeledValue):
            return bool(self.value == other.value)
        return bool(self.value == other)

    def __hash__(self) -> int:
        return hash(self.value)

    def __bool__(self) -> bool:
        return bool(self.value)

    def __copy__(self) -> LabeledValue:
        return LabeledValue(value=self.value, label=self.label)

    def __deepcopy__(self, memo: dict[int, Any]) -> LabeledValue:
        return LabeledValue(value=copy.deepcopy(self.value, memo), label=self.label)

    def __reduce__(self) -> tuple[Any, ...]:
        return (_identity, (self.value,))
