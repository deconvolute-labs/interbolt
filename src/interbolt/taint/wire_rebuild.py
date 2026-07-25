"""unpack()'s entry-driven payload rebuild and audit replay."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from interbolt.errors import InterboltConfigError
from interbolt.models.core import Label
from interbolt.taint.carriers import LabeledValue, Tainted, TaintedBytes
from interbolt.taint.ingress import _observe_ingress
from interbolt.taint.runstate import get_taint_observer
from interbolt.taint.wire_schema import LabelEntry, ShapeEntry, WireEnvelope
from interbolt.taint.wire_walk import Path, replace_at_path, resolve_path
from interbolt.utils import current_run_id

_JSON_SCALAR_TYPES = (str, int, float, bool, type(None))


def _rebuild(
    parsed: WireEnvelope, pool: tuple[Label, ...]
) -> tuple[Any, dict[Path, Any]]:
    """Apply every shape and label entry, deepest path first.

    A child path is always longer than any ancestor path nested within it,
    so processing longest-first guarantees a labeled leaf is wrapped while
    its parent container is still a positionally-addressable list, before
    that parent is itself converted to a `tuple`/`set`/`frozenset`. At a
    path shared by both a shape and a label entry (`TaintedBytes`), the
    shape entry (base64 decode) is applied first, since the label entry
    requires real `bytes` already restored.
    """
    by_path: dict[Path, tuple[ShapeEntry | None, LabelEntry | None]] = {}
    for shape_entry in parsed.shape:
        _, existing_label = by_path.get(shape_entry.path, (None, None))
        by_path[shape_entry.path] = (shape_entry, existing_label)
    for label_entry in parsed.labels:
        existing_shape, _ = by_path.get(label_entry.path, (None, None))
        by_path[label_entry.path] = (existing_shape, label_entry)

    ordered_paths = sorted(by_path, key=len, reverse=True)
    payload: Any = parsed.payload
    rebuilt_by_path: dict[Path, Any] = {}
    for path in ordered_paths:
        shape_at_path, label_at_path = by_path[path]
        if shape_at_path is not None:
            payload = _apply_shape(payload, path, shape_at_path.kind)
        if label_at_path is not None:
            label = pool[label_at_path.label]
            payload, rebuilt = _apply_label(payload, path, label_at_path.carrier, label)
            rebuilt_by_path[path] = rebuilt
    return payload, rebuilt_by_path


def _apply_shape(payload: Any, path: Path, kind: str) -> Any:  # noqa: ANN401
    try:
        raw = resolve_path(payload, path)
    except (KeyError, IndexError, TypeError) as exc:
        raise InterboltConfigError(
            f"path {path!r} does not resolve in payload"
        ) from exc
    new_obj: Any
    if kind == "bytes":
        if not isinstance(raw, str):
            raise InterboltConfigError(
                f"path {path!r}: expected a base64 string for shape 'bytes'"
            )
        try:
            new_obj = base64.b64decode(raw, validate=True)
        except binascii.Error as exc:
            raise InterboltConfigError(f"path {path!r}: invalid base64") from exc
    else:
        if not isinstance(raw, list):
            raise InterboltConfigError(f"path {path!r}: expected a list for {kind!r}")
        if kind == "tuple":
            new_obj = tuple(raw)
        else:
            try:
                new_obj = set(raw) if kind == "set" else frozenset(raw)
            except TypeError as exc:
                raise InterboltConfigError(
                    f"path {path!r}: {kind} member is unhashable"
                ) from exc
    try:
        return replace_at_path(payload, path, new_obj)
    except (KeyError, IndexError, TypeError) as exc:
        raise InterboltConfigError(
            f"path {path!r} does not resolve in payload"
        ) from exc


def _apply_label(
    payload: Any,  # noqa: ANN401
    path: Path,
    carrier: str,
    label: Label,
) -> tuple[Any, Any]:
    try:
        raw = resolve_path(payload, path)
    except (KeyError, IndexError, TypeError) as exc:
        raise InterboltConfigError(
            f"path {path!r} does not resolve in payload"
        ) from exc
    new_obj: Any
    if carrier == "str":
        if not isinstance(raw, str):
            raise InterboltConfigError(
                f"path {path!r}: expected a string for carrier 'str'"
            )
        new_obj = Tainted(raw, label=label)
    elif carrier == "bytes":
        if not isinstance(raw, bytes):
            raise InterboltConfigError(
                f"path {path!r}: carrier 'bytes' requires a companion bytes shape entry"
            )
        new_obj = TaintedBytes(raw, label=label)
    else:  # "scalar"
        if not isinstance(raw, _JSON_SCALAR_TYPES):
            raise InterboltConfigError(
                f"path {path!r}: expected a JSON scalar for carrier 'scalar'"
            )
        new_obj = LabeledValue(value=raw, label=label)
    try:
        return replace_at_path(payload, path, new_obj), new_obj
    except (KeyError, IndexError, TypeError) as exc:
        raise InterboltConfigError(
            f"path {path!r} does not resolve in payload"
        ) from exc


def _replay_audit(
    parsed: WireEnvelope, pool: tuple[Label, ...], rebuilt_by_path: dict[Path, Any]
) -> None:
    """Report every rehydrated str/bytes leaf to the installed taint observer."""
    if get_taint_observer() is None:
        return
    run_id = current_run_id.get()
    if run_id is None:
        return
    for entry in parsed.labels:
        if entry.carrier not in ("str", "bytes"):
            continue
        leaf = rebuilt_by_path[entry.path]
        label = pool[entry.label]
        _observe_ingress(leaf, source=label.source, run_id=run_id, depth=0)
