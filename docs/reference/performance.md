# Performance

`check()` sits on every guarded tool call, so it carries a latency budget:
under 1 ms of overhead per call in the common case (see
[the spec's latency budget](../../dev/spec.md)). The benchmark and its
result are published here, not just claimed.

## Benchmark

`dev/bench.py` is a plain script (not a pytest-discovered test — it is not a
CI gate; a script the maintainer runs):

```bash
uv run python dev/bench.py
```

It measures three things: `check()` overhead for a small tainted argument
and a 25 KB tainted argument against a one-rule sink policy, and
`Tainted.splitlines()` on a 5000-line tainted string.

## Results

Measured on the reference development machine (CPython 3.12, macOS):

| Benchmark | Mean | Median | p95 |
| --- | --- | --- | --- |
| `check()`, small arg (25 bytes) | 0.13 ms | 0.13 ms | 0.15 ms |
| `check()`, large arg (25 KB) | 0.13 ms | 0.13 ms | 0.15 ms |
| `Tainted.splitlines()`, 5000-line string | 2.2 ms | 1.8 ms | 2.0 ms |

`check()` overhead is essentially flat between a 25-byte and a 25 KB
argument, comfortably inside the 1 ms budget: argument size does not drive
the cost, label inspection over a small frozen structure and one CEL
evaluation do.

## Before the propagation-path fast path

Before the fixes below landed, `splitlines()` on the same 5000-line string
took **78 ms**, about 35x slower, because every one of the 5000 returned
parts went through `_merge_labels`, minting a fresh `uuid4` and `Label` per
part (about 15 microseconds per operation). That also meant a `Decision`
for a sink call downstream of that split carried 5000 `contributing_labels`
instead of 1, which a `JsonlReporter` then serialized in full per event.

Four changes closed this gap:

1. **Single-label fast path.** A single-parent derivation (a slice, a case
   change, one part of a split) reuses the parent `Label` object outright,
   including its `value_id` — no new label is minted, since there's nothing
   to merge. A fresh `value_id` is now minted only at ingress, at a genuine
   multi-label merge, or at an `endorse()` hop.
2. **`Policy.sources_table` precomputed once**, in `Policy.__init__`,
   instead of rebuilt on every property access (once per `check()` call
   previously).
3. **`build_context` built only when a sink has rules to evaluate.** A tool
   with no matching sink now skips CEL-context construction entirely.
4. **Single-pass trust resolution.** `check()` previously resolved every
   contributing label's trust up to four separate times (once each for the
   CEL `taint` list, `max_trust`, `trifecta`, and `untrusted_sources`); it
   now resolves each label once and derives all four from that.

The result: the same 5000-line `splitlines()` now measures about 2.2 ms
(see the table above), comfortably under a 5 ms threshold, and
`contributing_labels` for a split-then-sink flow collapses from 5000 labels
to 1.

## What this doesn't cover

The laundering audit (`audit=True`) and any future flow-tracking instrument
are explicitly **not** on this budget: they are off by default, and running
either moves a run outside the per-call budget by design. See
[Auditing](../guides/auditing.md).
