"""Adversarial container-recursion stress tests.

Kept separate from test_taint.py since these are timing-based sanity
checks, not pure correctness tests, and deliberately avoid deep-equality
or repr-based assertions on the fixtures themselves: pytest's own
failure-message formatting could hit a RecursionError trying to pretty
print a very deep structure on an assertion failure, an orthogonal
footgun to the code under test.

Conclusion drawn from these tests: the existing depth bound
(`constants.RECURSION_DEPTH`, hard-capped at `constants.RECURSION_DEPTH_MAX`
= 10, checked before every recursive call) is sufficient to prevent a
`RecursionError`/stack-overflow class of crash regardless of how deeply
nested the input actually is. Container *width* (the number of elements at
a single level) has no such bound today; these tests characterize its
actual behavior rather than assume a fix is needed. Adding a width/item-
count bound is a real, separate follow-up decision (a new env-var-backed
constant, plus a behavior choice for truncate-vs-log-vs-raise on overflow)
that was deliberately not folded into this pass; see the project plan.
"""

from __future__ import annotations

import time

from interbolt.constants import RECURSION_DEPTH
from interbolt.taint import collect_labels, taint

_TIME_BUDGET_SECONDS = 5.0


def _build_nested_list(depth: int, leaf: object) -> object:
    """Build a `depth`-levels-deep nested list iteratively, no recursion."""
    value = leaf
    for _ in range(depth):
        value = [value]
    return value


class TestDeepContainerRecursion:
    def test_taint_on_pathologically_deep_list_does_not_crash(self) -> None:
        # Far deeper than RECURSION_DEPTH (default 4): the depth bound must
        # stop traversal long before this could be slow or hit Python's own
        # recursion limit.
        nested = _build_nested_list(50_000, "leaf")
        start = time.monotonic()
        result = taint(nested, source="s")
        elapsed = time.monotonic() - start
        assert elapsed < _TIME_BUDGET_SECONDS
        assert isinstance(result, list)

    def test_collect_labels_on_pathologically_deep_list_does_not_crash(self) -> None:
        tainted_leaf = taint("leaf", source="s")
        nested = _build_nested_list(50_000, tainted_leaf)
        start = time.monotonic()
        labels = collect_labels(nested, max_depth=RECURSION_DEPTH)
        elapsed = time.monotonic() - start
        assert elapsed < _TIME_BUDGET_SECONDS
        # Buried far below the resolved depth: correctly invisible, not a
        # crash. This is the documented, honest limit (spec Section 6.6),
        # not a bug.
        assert labels == ()


class TestWideContainerRecursion:
    def test_taint_on_very_wide_list_completes_in_bounded_time(self) -> None:
        wide = ["leaf"] * 200_000
        start = time.monotonic()
        result = taint(wide, source="s")
        elapsed = time.monotonic() - start
        assert elapsed < _TIME_BUDGET_SECONDS
        assert len(result) == 200_000

    def test_collect_labels_on_very_wide_list_completes_in_bounded_time(self) -> None:
        wide = [taint("leaf", source="s") for _ in range(200_000)]
        start = time.monotonic()
        labels = collect_labels(wide, max_depth=RECURSION_DEPTH)
        elapsed = time.monotonic() - start
        assert elapsed < _TIME_BUDGET_SECONDS
        assert len(labels) == 200_000
