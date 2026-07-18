from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from typing import Any

from interbolt.constants import CONTAINER_TYPES
from interbolt.models.core import Label
from interbolt.taint.carriers import LabeledValue, Tainted, TaintedBytes
from interbolt.utils import get_logger

_logger = get_logger("taint.walk")


def is_container(value: Any) -> bool:  # noqa: ANN401
    """Whether `value` is a shape `walk_leaves`/`map_leaves` recurse into.

    The single place that names `Mapping`/`CONTAINER_TYPES` for this
    purpose, so a caller deciding whether to recurse never needs its own
    copy of the check.
    """
    return isinstance(value, (Mapping, *CONTAINER_TYPES))


def _is_namedtuple(value: Any) -> bool:  # noqa: ANN401
    """Duck-type check for a namedtuple: a tuple subclass with `_fields`."""
    return isinstance(value, tuple) and hasattr(value, "_fields")


def _rebuild_container(value: Any, items: list[Any]) -> Any:  # noqa: ANN401
    """Reconstruct a CONTAINER_TYPES instance from `items`, namedtuple-safe.

    A namedtuple subclasses tuple but its constructor takes positional
    fields, not a single iterable, so `type(value)(items)` raises for it;
    detect that shape and unpack instead. Callers wrap this in try/except,
    since an exotic container subclass may still fail to reconstruct either
    way, and the containment layer must never be the thing that crashes a
    guarded call.
    """
    if _is_namedtuple(value):
        return type(value)(*items)
    return type(value)(items)


def walk_leaves(value: Any, *, depth: int | None) -> Iterator[Any]:  # noqa: ANN401
    """Yield every leaf in `value`, to the depth bound.

    A leaf is anything that is not a `Mapping` and not one of
    `CONTAINER_TYPES`; `Tainted`, `TaintedBytes`, and `LabeledValue` are
    therefore always leaves, never introspected. `depth` bounds how many
    more container levels may be entered; `None` means unbounded. Read-only.
    """
    if isinstance(value, Mapping):
        if depth is not None and depth <= 0:
            return
        next_depth = None if depth is None else depth - 1
        for k, v in value.items():
            yield from walk_leaves(k, depth=next_depth)
            yield from walk_leaves(v, depth=next_depth)
        return
    if isinstance(value, CONTAINER_TYPES):
        if depth is not None and depth <= 0:
            return
        next_depth = None if depth is None else depth - 1
        for item in value:
            yield from walk_leaves(item, depth=next_depth)
        return
    yield value


def map_leaves(
    value: Any,  # noqa: ANN401
    *,
    depth: int | None,
    fn: Callable[[Any], Any],
) -> Any:  # noqa: ANN401
    """Rebuild the same shape as `value`, applying `fn` to every leaf.

    A leaf is anything that is not a `Mapping` and not one of
    `CONTAINER_TYPES`. `depth` bounds how many more container levels may be
    entered; `None` means unbounded. At the depth cutoff, or when
    reconstructing a container fails, the sub-value passes through
    unchanged rather than being rebuilt or wrapped.
    """
    if isinstance(value, Mapping):
        if depth is not None and depth <= 0:
            return value
        next_depth = None if depth is None else depth - 1
        return {
            map_leaves(k, depth=next_depth, fn=fn): map_leaves(
                v, depth=next_depth, fn=fn
            )
            for k, v in value.items()
        }
    if isinstance(value, CONTAINER_TYPES):
        if depth is not None and depth <= 0:
            return value
        next_depth = None if depth is None else depth - 1
        items = [map_leaves(item, depth=next_depth, fn=fn) for item in value]
        try:
            return _rebuild_container(value, items)
        except Exception:  # noqa: BLE001 -- containment must never crash the guard
            _logger.debug(
                "map_leaves(): could not reconstruct container type %s; "
                "returning the value unchanged",
                type(value).__name__,
                exc_info=True,
            )
            return value
    return fn(value)


def leaf_text(value: Any) -> str | None:  # noqa: ANN401
    """The plain string content of a str/bytes-shaped leaf, or `None`.

    A `str`/`Tainted` leaf returns its content as a plain `str`; a
    `bytes`/`TaintedBytes` leaf is decoded with `errors="ignore"`. Any
    other leaf returns `None`.
    """
    if isinstance(value, str):
        return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return None


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
    for leaf in walk_leaves(value, depth=max_depth):
        if isinstance(leaf, (Tainted, TaintedBytes, LabeledValue)):
            found.append(leaf.label)
    seen: dict[str, Label] = {}
    for label in found:
        seen.setdefault(label.value_id, label)
    return tuple(seen.values())


def _strip_labeled_value(value: Any) -> Any:  # noqa: ANN401
    return unwrap(value.value) if isinstance(value, LabeledValue) else value


def unwrap(value: Any) -> Any:  # noqa: ANN401 -- accepts and returns any shape
    """Strip taint carriers down to plain values, recursively.

    `Tainted`/`TaintedBytes` pass through unchanged, since they're already
    plain `str`/`bytes`. `LabeledValue` unwraps to its `.value`. Containers
    are rebuilt with unwrapped elements, to unbounded depth.

    Used by `enforcement` to hand plain values to code that doesn't know
    about taint carriers, such as the CEL context builder in `policy.engine`.

    Args:
        value: The value to strip.

    Returns:
        The same shape with every label stripped.
    """
    if isinstance(value, LabeledValue):
        return unwrap(value.value)
    return map_leaves(value, depth=None, fn=_strip_labeled_value)
