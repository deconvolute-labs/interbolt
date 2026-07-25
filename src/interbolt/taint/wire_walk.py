"""Path-keyed container traversal for the serialization contract's wire format.

Complements `taint/walk.py`'s depth-bounded, leaf-oriented traversal (used at
ingress and the sink) with a path-keyed traversal oriented around building
and rebuilding a JSON-representable envelope.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any, Literal

from interbolt.constants import CONTAINER_TYPES
from interbolt.errors import InterboltConfigError
from interbolt.models.core import Label
from interbolt.taint.carriers import LabeledValue, Tainted, TaintedBytes

PathSegment = tuple[str, str | int]
Path = tuple[PathSegment, ...]
LabelCarrier = Literal["str", "bytes", "scalar"]
ShapeKind = Literal["tuple", "set", "frozenset", "bytes"]

_JSON_SCALAR_TYPES = (str, int, float, bool, type(None))


def _strip_leaf(
    node: Any,  # noqa: ANN401
    *,
    path: Path,
    label_entries: list[tuple[Path, LabelCarrier, Label]],
    shape_entries: list[tuple[Path, ShapeKind]],
) -> Any:  # noqa: ANN401
    if isinstance(node, Tainted):
        label_entries.append((path, "str", node.label))
        return str(node)
    if isinstance(node, TaintedBytes):
        label_entries.append((path, "bytes", node.label))
        shape_entries.append((path, "bytes"))
        return base64.b64encode(bytes(node)).decode("ascii")
    if isinstance(node, LabeledValue):
        if not isinstance(node.value, _JSON_SCALAR_TYPES):
            raise InterboltConfigError(
                f"path {path!r}: LabeledValue wraps a non-scalar value"
            )
        label_entries.append((path, "scalar", node.label))
        return node.value
    if isinstance(node, bytes):
        shape_entries.append((path, "bytes"))
        return base64.b64encode(node).decode("ascii")
    if isinstance(node, _JSON_SCALAR_TYPES):
        return node
    raise InterboltConfigError(
        f"path {path!r}: {type(node).__name__} cannot be represented in a "
        "serialization envelope"
    )


def _strip_node(
    node: Any,  # noqa: ANN401
    *,
    path: Path,
    depth: int | None,
    label_entries: list[tuple[Path, LabelCarrier, Label]],
    shape_entries: list[tuple[Path, ShapeKind]],
) -> Any:  # noqa: ANN401
    if isinstance(node, Mapping):
        if depth is not None and depth <= 0:
            raise InterboltConfigError(
                f"path {path!r}: exceeds the traversal depth bound"
            )
        next_depth = None if depth is None else depth - 1
        result: dict[str, Any] = {}
        for key, item in node.items():
            if isinstance(key, Tainted):
                key_str = str(key)
                label_entries.append((path + (("k", key_str),), "str", key.label))
            elif isinstance(key, str):
                key_str = key
            else:
                raise InterboltConfigError(
                    f"path {path!r}: mapping key {key!r} must be str or Tainted"
                )
            result[key_str] = _strip_node(
                item,
                path=(*path, ("v", key_str)),
                depth=next_depth,
                label_entries=label_entries,
                shape_entries=shape_entries,
            )
        return result
    if isinstance(node, CONTAINER_TYPES):
        if depth is not None and depth <= 0:
            raise InterboltConfigError(
                f"path {path!r}: exceeds the traversal depth bound"
            )
        next_depth = None if depth is None else depth - 1
        items = [
            _strip_node(
                item,
                path=(*path, ("i", i)),
                depth=next_depth,
                label_entries=label_entries,
                shape_entries=shape_entries,
            )
            for i, item in enumerate(node)
        ]
        if type(node) is not list:
            kind: ShapeKind
            if isinstance(node, tuple):
                kind = "tuple"
            elif isinstance(node, frozenset):
                kind = "frozenset"
            else:
                kind = "set"
            shape_entries.append((path, kind))
        return items
    return _strip_leaf(
        node, path=path, label_entries=label_entries, shape_entries=shape_entries
    )


def strip_to_json(
    value: Any,  # noqa: ANN401
    *,
    depth: int | None,
) -> tuple[Any, list[tuple[Path, LabelCarrier, Label]], list[tuple[Path, ShapeKind]]]:
    """Recursively rebuild `value` into a JSON-representable payload.

    Every `Mapping` becomes a `dict`; every `CONTAINER_TYPES` instance
    (including a namedtuple) becomes a `list`; every `Tainted`,
    `TaintedBytes`, or `LabeledValue` carrier is stripped to its plain
    JSON-representable leaf; every `bytes` value, tainted or not, is
    base64-encoded. `depth` bounds how many more container levels may be
    entered; `None` means unbounded.

    Args:
        value: The value to flatten.
        depth: How many more container levels may be entered; `None` for
            unbounded.

    Returns:
        A `(payload, label_entries, shape_entries)` triple: `payload` is the
        JSON-representable rebuild of `value`; `label_entries` is
        `(path, carrier, label)` for every `Tainted` (carrier `"str"`),
        `TaintedBytes` (carrier `"bytes"`), or `LabeledValue` (carrier
        `"scalar"`) found; `shape_entries` is `(path, kind)` for every
        `tuple`, `set`, `frozenset` (a namedtuple reported as `"tuple"`), or
        `bytes` value found. A plain `list` produces no shape entry.

    Raises:
        InterboltConfigError: A `Mapping` key is neither `str` nor
            `Tainted`; a `LabeledValue.value` is not a JSON scalar (`str`,
            `int`, `float`, `bool`, or `None`); a leaf is not a recognized
            carrier, a JSON scalar, `bytes`, or a container; or `depth`
            reaches zero while still inside a container.
    """
    label_entries: list[tuple[Path, LabelCarrier, Label]] = []
    shape_entries: list[tuple[Path, ShapeKind]] = []
    payload = _strip_node(
        value,
        path=(),
        depth=depth,
        label_entries=label_entries,
        shape_entries=shape_entries,
    )
    return payload, label_entries, shape_entries


def resolve_path(value: Any, path: Path) -> Any:  # noqa: ANN401
    """Return the object addressed by `path`, walked left to right from `value`.

    A `("v", key)` segment indexes a `Mapping` by key. A `("k", key)`
    segment returns `key` itself, valid only as the path's final segment. An
    `("i", index)` segment indexes a `list`/`tuple` by position. The empty
    path returns `value` itself.

    Args:
        value: The structure to walk.
        path: The path to resolve.

    Returns:
        The object at `path`.

    Raises:
        KeyError: A `"v"`/`"k"` segment against a `Mapping` lacking `key`.
        IndexError: An `"i"` segment out of range.
        TypeError: A segment's addressing mode does not match the value's
            type at that point, or a `"k"` segment appears before the
            path's final position.
    """
    node = value
    for position, (tag, key) in enumerate(path):
        if tag == "i":
            if not isinstance(node, list | tuple):
                raise TypeError(
                    f"'i' segment against non-list/tuple {type(node).__name__}"
                )
            if not isinstance(key, int):
                raise TypeError(f"'i' segment requires an int index, got {key!r}")
            node = node[key]
        elif tag == "v":
            if not isinstance(node, Mapping):
                raise TypeError(
                    f"'v' segment against non-mapping {type(node).__name__}"
                )
            node = node[key]
        elif tag == "k":
            if position != len(path) - 1:
                raise TypeError("a 'k' segment is only valid as the final segment")
            if not isinstance(node, Mapping):
                raise TypeError(
                    f"'k' segment against non-mapping {type(node).__name__}"
                )
            if key not in node:
                raise KeyError(key)
            node = key
        else:
            raise TypeError(f"unknown path segment tag {tag!r}")
    return node


def replace_at_path(value: Any, path: Path, new_leaf: Any) -> Any:  # noqa: ANN401
    """Return a copy of `value` with the object at `path` replaced by `new_leaf`.

    Rebuilds every container from the root down to the replacement point;
    `value` itself is never mutated. `("v", key)` replaces the value stored
    under `key` in a `dict`/`Mapping`. `("k", key)` (valid only as the final
    segment) replaces the mapping key `key` with `new_leaf` itself,
    rebuilding the dict in its original iteration order with that one key
    swapped, rather than replacing the value stored under it. `("i", index)`
    replaces the element of a `list`/`tuple` at `index`, preserving the
    container's concrete type. The empty path returns `new_leaf` directly.

    Args:
        value: The structure to copy-and-replace within.
        path: Where to replace.
        new_leaf: The replacement object.

    Returns:
        A new structure, structurally identical to `value` except at `path`.

    Raises:
        KeyError: A `"v"`/`"k"` segment against a mapping lacking `key`.
        IndexError: An `"i"` segment out of range.
        TypeError: A segment's addressing mode does not match the value's
            type at that point, or a `"k"` segment appears before the final
            position.
    """
    if not path:
        return new_leaf
    (tag, key), *rest = path
    rest_path = tuple(rest)
    if tag == "i":
        if not isinstance(value, list | tuple):
            raise TypeError(
                f"'i' segment against non-list/tuple {type(value).__name__}"
            )
        if not isinstance(key, int):
            raise TypeError(f"'i' segment requires an int index, got {key!r}")
        items = list(value)
        items[key] = replace_at_path(items[key], rest_path, new_leaf)
        return type(value)(items)
    if tag == "v":
        if not isinstance(value, Mapping):
            raise TypeError(f"'v' segment against non-mapping {type(value).__name__}")
        if key not in value:
            raise KeyError(key)
        result = dict(value)
        result[key] = replace_at_path(result[key], rest_path, new_leaf)
        return result
    if tag == "k":
        if rest_path:
            raise TypeError("a 'k' segment is only valid as the final segment")
        if not isinstance(value, Mapping):
            raise TypeError(f"'k' segment against non-mapping {type(value).__name__}")
        if key not in value:
            raise KeyError(key)
        return {(new_leaf if k == key else k): v for k, v in value.items()}
    raise TypeError(f"unknown path segment tag {tag!r}")
