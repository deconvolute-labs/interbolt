from __future__ import annotations

import functools
import inspect
import threading
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from interbolt.constants import CONTAINER_TYPES, RECURSION_DEPTH
from interbolt.models.core import Label
from interbolt.taint.carriers import LabeledValue as LabeledValue
from interbolt.taint.carriers import Tainted as Tainted
from interbolt.taint.carriers import TaintedBytes as TaintedBytes
from interbolt.taint.carriers import _fresh_label as _fresh_label
from interbolt.taint.carriers import _merge_labels as _merge_labels
from interbolt.taint.carriers import _new_value_id
from interbolt.utils import bind_arguments, current_run_id, get_logger

_logger = get_logger("taint")

_run_ingress_sources: dict[str, set[str]] = {}
_ingress_lock = threading.Lock()


def _record_ingress(source: str) -> None:
    """Record that `source` tainted data during the active run, if any.

    Records the bare source name, keyed by the ambient `current_run_id`, for
    `enforcement.check()` to resolve later against run-level gating
    (`run.tainted`, spec §15.8). Trust itself is resolved at the sink, from
    the policy's `sources` table.
    """
    run_id = current_run_id.get()
    if run_id is None:
        _logger.debug(
            "taint(source=%r) called with no active agent_context; this "
            "ingress cannot be attributed to a run, so run.tainted will not "
            "reflect it for any policy that references it",
            source,
        )
        return
    with _ingress_lock:
        _run_ingress_sources.setdefault(run_id, set()).add(source)


def run_ingress_sources(run_id: str) -> frozenset[str]:
    """Every source name passed to `taint()` while `run_id` was active."""
    with _ingress_lock:
        return frozenset(_run_ingress_sources.get(run_id, ()))


def clear_run_ingress(run_id: str) -> None:
    """Drop the recorded ingress sources for a finished run."""
    with _ingress_lock:
        _run_ingress_sources.pop(run_id, None)


def taint(
    value: Any,  # noqa: ANN401 -- accepts any ingress shape
    *,
    source: str,
    derived_from: Iterable[Any] | None = None,
) -> Any:  # noqa: ANN401 -- returns whatever shape it labeled
    """Mark a value with its provenance at the point it enters the agent.

    For `str`/`bytes` this returns a `Tainted`/`TaintedBytes` carrier that
    propagates over the supported operation subset. For other scalars it
    returns a `LabeledValue` that does not propagate through transformations.
    For builtin containers (`list`, `tuple`, `set`, `frozenset`, `Mapping`
    keys and values) it recurses and labels string leaves, to the resolved
    depth `constants.RECURSION_DEPTH` (the same constant `check()`/`guard`
    read, so ingress labeling and sink collection are bounded identically).

    The label only records `source`. Trust is resolved later, at the sink,
    from the policy's `sources` table.

    Passing `derived_from` marks `value` as derived from other values instead
    of as a raw ingress point: `source` becomes the name of the derivation
    hop (for example `"model"`, an LLM call, or `"agent_a"`, an agent
    handoff), and the label's `lineage` is the union of every label found
    among `derived_from`, so trust resolves at the sink exactly as if the
    original inputs had reached the sink directly: trusted only if every
    contributing input was trusted, untrusted if any one of them was. If no
    label is found among `derived_from` (every input was trusted-by-
    construction), `value` is returned completely unwrapped, since there is
    no provenance to propagate. This does not record a raw ingress event for
    `source`: the derivation hop is not itself a policy-declared source, and
    recording it would make `run.tainted` spuriously true regardless of
    whether the actual inputs were trusted.

    Args:
        value: The value to mark.
        source: The stable name of the source this value came from, or the
            name of the derivation hop when `derived_from` is given.
        derived_from: The input values this one was derived from (for
            example, an LLM call's prompt and retrieved context). When
            omitted or empty, `value` is treated as a fresh ingress point.

    Returns:
        The labeled value: a `Tainted`/`TaintedBytes` carrier, a recursively
        labeled container, a `LabeledValue` wrapper, or, when `derived_from`
        is given and carries no provenance at all, `value` unchanged.
    """
    derived_items = None if derived_from is None else list(derived_from)
    if not derived_items:
        _record_ingress(source)
        return _taint_value(
            value, depth=RECURSION_DEPTH, make_label=lambda: _fresh_label(source)
        )

    labels = collect_labels(derived_items, max_depth=RECURSION_DEPTH)
    if not labels:
        return value

    lineage = _merge_labels(*labels).lineage
    return _taint_value(
        value,
        depth=RECURSION_DEPTH,
        make_label=lambda: Label.model_construct(
            source=source, value_id=_new_value_id(), lineage=lineage
        ),
    )


def _taint_value(
    value: Any,  # noqa: ANN401
    *,
    depth: int,
    make_label: Callable[[], Label],
) -> Any:  # noqa: ANN401
    if isinstance(value, str):
        return Tainted(value, label=make_label())
    if isinstance(value, bytes):
        return TaintedBytes(value, label=make_label())
    if depth > 0 and isinstance(value, CONTAINER_TYPES):
        items = (
            _taint_value(item, depth=depth - 1, make_label=make_label) for item in value
        )
        return type(value)(items)
    if depth > 0 and isinstance(value, Mapping):
        return {
            _taint_value(k, depth=depth - 1, make_label=make_label): _taint_value(
                v, depth=depth - 1, make_label=make_label
            )
            for k, v in value.items()
        }
    return LabeledValue(value=value, label=make_label())


def track_model_call[F: Callable[..., Any]](
    fn: F | None = None, *, source: str = "model"
) -> Any:  # noqa: ANN401 -- returns a decorator or a wrapped callable
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
    if isinstance(value, CONTAINER_TYPES):
        for item in value:
            _collect(item, depth=depth - 1, found=found)


def unwrap(value: Any) -> Any:  # noqa: ANN401 -- accepts and returns any shape
    """Strip taint carriers down to plain values, recursively.

    `Tainted`/`TaintedBytes` pass through unchanged, since they're already
    plain `str`/`bytes`. `LabeledValue` unwraps to its `.value`. Containers
    are rebuilt with unwrapped elements.

    Used by `enforcement` to hand plain values to code that doesn't know
    about taint carriers, such as the CEL context builder in `policy.engine`.

    Args:
        value: The value to strip.

    Returns:
        The same shape with every label stripped.
    """
    if isinstance(value, LabeledValue):
        return unwrap(value.value)
    if isinstance(value, Mapping):
        return {unwrap(k): unwrap(v) for k, v in value.items()}
    if isinstance(value, CONTAINER_TYPES):
        return type(value)(unwrap(item) for item in value)
    return value
