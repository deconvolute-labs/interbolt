"""Benchmark: check() per-call overhead and the tainted splitlines() fast path.

A plain script, not a pytest-discovered test (spec 9.2/14b.9: "the benchmark
and its result are published," not a CI gate). Run with:

    uv run python dev/bench.py

Measures:
  - check() overhead for a small tainted arg and a 25KB tainted arg, against
    a one-rule sink policy.
  - Tainted.splitlines() on a 5000-line tainted string (the single-label
    fast path in _merge_labels, PR 3 Change 6).
"""

from __future__ import annotations

import logging
import statistics
import time
from collections.abc import Callable

from interbolt import Action, InMemoryReporter, Policy, TrustLevel, configure, taint
from interbolt.policy.engine import compile_policy
from interbolt.policy.schema import (
    Defaults,
    PolicyDocument,
    SinkRule,
    SourceDeclaration,
)


def _make_policy() -> Policy:
    document = PolicyDocument(
        version="1.0",
        defaults=Defaults(),
        sources=(SourceDeclaration(name="web_search", trust=TrustLevel.UNTRUSTED),),
        sinks={
            "default.tool": (
                SinkRule(
                    name="block_untrusted",
                    when='taint.any(t, t.trust == "untrusted")',
                    action=Action.REQUIRE_APPROVAL,
                ),
                SinkRule(name="default", action=Action.ALLOW),
            )
        },
    )
    return Policy(document=document, compiled_sinks=compile_policy(document))


def _time_ms(fn: Callable[[], None], iterations: int) -> list[float]:
    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return samples


def _report(label: str, samples: list[float]) -> None:
    mean = statistics.mean(samples)
    median = statistics.median(samples)
    p95 = sorted(samples)[int(len(samples) * 0.95) - 1]
    print(f"{label}: mean={mean:.4f}ms median={median:.4f}ms p95={p95:.4f}ms")


def bench_check_small_arg() -> None:
    policy = _make_policy()
    runtime = configure(policy=policy, reporter=InMemoryReporter(), mode="enforce")
    arg = taint("attacker@external.com", source="web_search")

    def call() -> None:
        runtime.check(
            tool="default.tool", args={"to": arg}, agent_id="bench", run_id="r"
        )

    # Warm up, then measure.
    for _ in range(50):
        call()
    samples = _time_ms(call, 2000)
    _report("check() small arg (25 bytes)", samples)


def bench_check_large_arg() -> None:
    policy = _make_policy()
    runtime = configure(policy=policy, reporter=InMemoryReporter(), mode="enforce")
    arg = taint("x" * 25_000, source="web_search")

    def call() -> None:
        runtime.check(
            tool="default.tool", args={"to": arg}, agent_id="bench", run_id="r"
        )

    for _ in range(50):
        call()
    samples = _time_ms(call, 2000)
    _report("check() large arg (25 KB)", samples)


def bench_splitlines() -> None:
    text = "\n".join(f"line {i}" for i in range(5000))
    tainted = taint(text, source="web_search")

    def call() -> None:
        tainted.splitlines()

    for _ in range(10):
        call()
    samples = _time_ms(call, 200)
    _report("Tainted.splitlines() on a 5000-line string", samples)


if __name__ == "__main__":
    logging.getLogger("interbolt").setLevel(logging.ERROR)
    bench_check_small_arg()
    bench_check_large_arg()
    bench_splitlines()
