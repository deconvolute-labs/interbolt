"""taint() and track_model_call(): the ingress-labeling primitives."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Iterable
from typing import Any

from interbolt.constants import DEFAULT_AGENT_ID, RECURSION_DEPTH
from interbolt.models.core import Label
from interbolt.taint.carriers import LabeledValue as LabeledValue
from interbolt.taint.carriers import Tainted as Tainted
from interbolt.taint.carriers import TaintedBytes as TaintedBytes
from interbolt.taint.carriers import _fresh_label, _merge_labels, _new_value_id
from interbolt.taint.runstate import _record_ingress, get_taint_observer
from interbolt.taint.walk import (
    collect_labels,
    is_container,
    leaf_text,
    map_leaves,
    walk_leaves,
)
from interbolt.utils import bind_arguments, current_agent_id, current_run_id


def _observe_ingress(value: Any, *, source: str, run_id: str, depth: int) -> None:  # noqa: ANN401
    """Report every str/bytes leaf in a fresh-ingress `value` to the observer."""
    observer = get_taint_observer()
    if observer is None:
        return
    for leaf in walk_leaves(value, depth=depth):
        text = leaf_text(leaf)
        if text is not None:
            observer(text, source, run_id)


def taint(
    value: Any,  # noqa: ANN401 - accepts any ingress shape
    *,
    source: str,
    derived_from: Iterable[Any] | None = None,
) -> Any:  # noqa: ANN401 - returns whatever shape it labeled
    """Mark a value with the source it came from.

    Call this wherever data enters the agent from outside: a search result, a
    retrieved document, an API response, an email body. The mark travels with
    the value through your code, and `guard`/`check` read it at the tool call
    to decide whether the call is allowed. Whether a source is trusted is
    decided there, from your policy's `sources` table, so this function only
    records the name.

    `str` and `bytes` come back as `Tainted`/`TaintedBytes`, subclasses usable
    anywhere the plain type is. Lists, tuples, sets, and mappings have their
    string leaves marked, to a bounded depth. Any other scalar comes back
    wrapped in a `LabeledValue`.

    Use `derived_from` when a value was computed from other values rather than
    read from a new source. `source` then names the step that produced it, for
    example `"model"` for an LLM call, and the value inherits its inputs'
    sources, so it resolves untrusted if any input was. A value whose inputs
    carry no marks comes back unchanged.

    Args:
        value: The value to mark.
        source: The name of the source this value came from, or of the step
            that produced it when `derived_from` is given. Declare the same
            name in your policy's `sources` table.
        derived_from: The values this one was computed from. Omit for data
            arriving from a new source.

    Returns:
        The marked value, in the same shape it came in.

    Example:
        >>> results = taint(web_search(query), source="web_search")
        >>> send_email(to=addr, body=results)   # policy sees "web_search"
    """
    derived_items = None if derived_from is None else list(derived_from)
    if not derived_items:
        _record_ingress(source)
        observer = get_taint_observer()
        if observer is not None:
            run_id = current_run_id.get()
            if run_id is not None:
                _observe_ingress(
                    value, source=source, run_id=run_id, depth=RECURSION_DEPTH
                )
        return _taint_value(
            value, depth=RECURSION_DEPTH, make_label=lambda: _fresh_label(source)
        )

    labels = collect_labels(derived_items, max_depth=RECURSION_DEPTH)
    if not labels:
        return value

    merged = _merge_labels(*labels)
    current_agent = current_agent_id.get() or DEFAULT_AGENT_ID
    ingested_by = (
        merged.ingested_by
        if current_agent in merged.ingested_by
        else (*merged.ingested_by, current_agent)
    )
    return _taint_value(
        value,
        depth=RECURSION_DEPTH,
        make_label=lambda: Label.model_construct(
            source=source,
            value_id=_new_value_id(),
            lineage=merged.lineage,
            ingested_by=ingested_by,
        ),
    )


def _taint_value(
    value: Any,  # noqa: ANN401
    *,
    depth: int,
    make_label: Callable[[], Label],
) -> Any:  # noqa: ANN401
    """Top-level ingress entry: the only place a `LabeledValue` is produced.

    A `str`/`bytes` top-level value is wrapped directly; a container or
    mapping recurses via `map_leaves`, which labels only string/bytes leaves
    inside it; any other top-level scalar (int, bool, None, ...) becomes a
    `LabeledValue`, since it has no propagating carrier of its own.
    """
    if isinstance(value, str):
        return Tainted(value, label=make_label())
    if isinstance(value, bytes):
        return TaintedBytes(value, label=make_label())
    if is_container(value):
        return map_leaves(
            value, depth=depth, fn=lambda leaf: _wrap_leaf(leaf, make_label)
        )
    return LabeledValue(value=value, label=make_label())


def _wrap_leaf(value: Any, make_label: Callable[[], Label]) -> Any:  # noqa: ANN401
    """One recursive step inside a container: wrap only string/bytes leaves.

    Anything else (a number, bool, None, or other object) passes through
    completely unchanged, never wrapped in a `LabeledValue`, so it remains a
    drop-in substitute for arithmetic and other native operations.
    """
    if isinstance(value, str):
        return Tainted(value, label=make_label())
    if isinstance(value, bytes):
        return TaintedBytes(value, label=make_label())
    return value


def track_model_call[F: Callable[..., Any]](
    fn: F | None = None, *, source: str = "model"
) -> Any:  # noqa: ANN401 - returns a decorator or a wrapped callable
    """Taint a model/LLM call's return value, derived from its arguments.

    Wraps `fn` so its return value is tainted via `taint(result,
    source=source, derived_from=<fn's bound arguments>)`: trusted only if
    every tainted argument was trusted, untrusted if any one of them was.
    Usable bare (`@track_model_call`) or parameterized
    (`@track_model_call(source="gpt-4")`); auto-detects sync vs async.

    This only tracks provenance; it does not evaluate policy. Stack it with
    `@guard`/`@handle.guard` separately if the call into the model should
    also be gated.

    Args:
        fn: The function to wrap, when used as a bare `@track_model_call`.
        source: The name recorded as the derivation hop on the tainted
            return value.

    Returns:
        The wrapped function, or a decorator if called with arguments.
    """

    def decorator(inner: F) -> F:
        return _build_model_call_wrapper(inner, source=source)

    if fn is not None:
        return decorator(fn)
    return decorator


def _build_model_call_wrapper[F: Callable[..., Any]](fn: F, *, source: str) -> F:
    sig = inspect.signature(fn)

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            bound = bind_arguments(sig, args, kwargs)
            result = await fn(*args, **kwargs)
            return taint(result, source=source, derived_from=bound.values())

        return async_wrapper  # type: ignore[return-value]

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        bound = bind_arguments(sig, args, kwargs)
        result = fn(*args, **kwargs)
        return taint(result, source=source, derived_from=bound.values())

    return sync_wrapper  # type: ignore[return-value]
