from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from typing import Any

from interbolt.constants import RECURSION_DEPTH
from interbolt.errors import InterboltUsageError
from interbolt.models.core import Label

_CONTAINER_TYPES = (list, tuple, set, frozenset)


def _new_value_id() -> str:
    return str(uuid.uuid4())


def _fresh_label(source: str) -> Label:
    return Label(source=source, value_id=_new_value_id(), lineage=(source,))


def _merge_labels(*labels: Label) -> Label:
    """Union the lineage of one or more labels and mint a fresh value_id.

    Used both to retag a single-label transformation result (one label in,
    fresh id out) and to merge two differently-sourced operands (lineage union).
    """
    if not labels:
        raise InterboltUsageError("_merge_labels requires at least one label")
    seen: dict[str, None] = {}
    for label in labels:
        for name in label.lineage:
            seen.setdefault(name, None)
    return Label.model_construct(
        source=labels[0].source, value_id=_new_value_id(), lineage=tuple(seen)
    )


def _labels_of(*values: Any) -> list[Label]:  # noqa: ANN401 -- operands are arbitrary by nature
    return [v.label for v in values if isinstance(v, (Tainted, TaintedBytes))]


def _wrap(value: str, *labels: Label) -> Tainted:
    return Tainted(value, label=_merge_labels(*labels))


def _wrap_bytes(value: bytes, *labels: Label) -> TaintedBytes:
    return TaintedBytes(value, label=_merge_labels(*labels))


class Tainted(str):
    """A `str` that carries a provenance `Label` through a defined operation subset.

    See the propagation contract: operator-style combination (`+`, `%`, `*`,
    slicing, string methods called on a `Tainted` receiver) propagates the
    label. f-strings with surrounding literal text, `str.format`/`format_map`
    on a plain template, and `join` on a plain separator do not; re-`taint`
    the result by hand in those cases.
    """

    __slots__ = ("label",)
    label: Label

    def __new__(cls, value: str, *, label: Label) -> Tainted:
        obj = str.__new__(cls, value)
        obj.label = label
        return obj

    def __add__(self, other: Any) -> Any:  # noqa: ANN401 -- binary operand, type-checked at runtime
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

    def __format__(self, format_spec: str) -> Any:
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


class TaintedBytes(bytes):
    """The `bytes` counterpart to `Tainted`, with the same propagation subset.

    Unlike `Tainted`, this cannot use `__slots__`: CPython does not support
    adding nonempty `__slots__` to a `bytes` subclass.
    """

    label: Label

    def __new__(cls, value: bytes, *, label: Label) -> TaintedBytes:
        obj = bytes.__new__(cls, value)
        obj.label = label
        return obj

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

    def replace(  # type: ignore[override]
        self, old: bytes, new: bytes, count: int = -1
    ) -> TaintedBytes:
        result = bytes.replace(self, old, new, count)
        return _wrap_bytes(result, self.label, *_labels_of(new))


class LabeledValue:
    """A non-string, non-bytes value labeled at ingress.

    Numbers, `bool`, and `None` cannot be subclassed, so they cannot carry a
    label transparently the way `Tainted`/`TaintedBytes` do. This wrapper
    preserves the label for direct passing to a sink argument; the label does
    not survive transforming `.value` first, since that was never achievable
    for these types regardless of taint.
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


def taint(value: Any, *, source: str) -> Any:  # noqa: ANN401 -- accepts any ingress shape
    """Mark a value with its provenance at the point it enters the agent.

    For `str`/`bytes` this returns a `Tainted`/`TaintedBytes` carrier that
    propagates over the supported operation subset. For other scalars it
    returns a `LabeledValue` that does not propagate through transformations.
    For builtin containers (`list`, `tuple`, `set`, `frozenset`, `dict` keys
    and values) it recurses and labels string leaves, to the resolved depth
    `constants.RECURSION_DEPTH` (the same constant `check()`/`guard` read, so
    ingress labeling and sink collection are bounded identically).

    Trust is not resolved here. The label only records `source`; trust is
    resolved later, at the sink, from the policy's `sources` table.

    Args:
        value: The value to mark.
        source: The stable name of the source this value came from.

    Returns:
        The labeled value: a `Tainted`/`TaintedBytes` carrier, a recursively
        labeled container, or a `LabeledValue` wrapper.
    """
    return _taint_value(value, source=source, depth=RECURSION_DEPTH)


def _taint_value(value: Any, *, source: str, depth: int) -> Any:  # noqa: ANN401
    if isinstance(value, str):
        return Tainted(value, label=_fresh_label(source))
    if isinstance(value, bytes):
        return TaintedBytes(value, label=_fresh_label(source))
    if depth > 0 and isinstance(value, _CONTAINER_TYPES):
        items = (_taint_value(item, source=source, depth=depth - 1) for item in value)
        return type(value)(items)
    if depth > 0 and isinstance(value, dict):
        return {
            _taint_value(k, source=source, depth=depth - 1): _taint_value(
                v, source=source, depth=depth - 1
            )
            for k, v in value.items()
        }
    return LabeledValue(value=value, label=_fresh_label(source))


def collect_labels(value: Any, *, max_depth: int) -> tuple[Label, ...]:  # noqa: ANN401
    """Recursively collect every label found in `value`, to a bounded depth.

    Walks builtin containers (`list`, `tuple`, `set`, `frozenset`, `Mapping`
    keys and values) looking for `Tainted`, `TaintedBytes`, and `LabeledValue`
    leaves. A label buried below `max_depth` is not found, and the value it
    belongs to is treated as if it were untainted.

    Args:
        value: The value (often a `Mapping` of bound call arguments) to scan.
        max_depth: How many container levels to recurse into.

    Returns:
        Every label found, de-duplicated by `value_id`, in discovery order.
    """
    found: list[Label] = []
    _collect(value, depth=max_depth, found=found)
    seen: dict[str, Label] = {}
    for label in found:
        seen.setdefault(label.value_id, label)
    return tuple(seen.values())


def _collect(value: Any, *, depth: int, found: list[Label]) -> None:  # noqa: ANN401
    if isinstance(value, (Tainted, TaintedBytes, LabeledValue)):
        found.append(value.label)
        return
    if depth <= 0:
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            _collect(k, depth=depth - 1, found=found)
            _collect(v, depth=depth - 1, found=found)
        return
    if isinstance(value, _CONTAINER_TYPES):
        for item in value:
            _collect(item, depth=depth - 1, found=found)


def unwrap(value: Any) -> Any:  # noqa: ANN401 -- accepts and returns any shape
    """Strip taint carriers down to plain values, recursively.

    `Tainted`/`TaintedBytes` are already plain `str`/`bytes` for any caller
    that doesn't need the label, so they pass through unchanged. `LabeledValue`
    unwraps to its `.value`. Containers are rebuilt with unwrapped elements.

    This is the boundary helper other layers (notably `enforcement`) use to
    hand plain values to code that has no business knowing about taint
    carriers, such as the CEL context builder in `policy.engine`.

    Args:
        value: The value to strip.

    Returns:
        The same shape with every label stripped.
    """
    if isinstance(value, LabeledValue):
        return unwrap(value.value)
    if isinstance(value, Mapping):
        return {unwrap(k): unwrap(v) for k, v in value.items()}
    if isinstance(value, _CONTAINER_TYPES):
        return type(value)(unwrap(item) for item in value)
    return value
