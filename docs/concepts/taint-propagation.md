# Taint propagation

This is the most important honesty surface in the library. Read it before
relying on taint propagating through any transformation you write.

## The trust model: a provenance set, not a lattice

A label records *where the data came from*, not a trusted/untrusted bit.
Trust is resolved late, at the sink, by looking each contributing
source up in the policy's `sources` table (see [Policies](policies.md)).
"More restrictive wins" falls out of this for free: if any source
contributing to a value is untrusted, the value resolves untrusted at the
sink, regardless of how many trusted sources also contributed.

`Label` (in `interbolt.models.core`) carries:

- `source`: the originating source name, or the first contributor (in
  insertion order) on a value formed by merging two differently-sourced
  values. Informational; trust resolution uses `lineage` (below), not this
  field alone.
- `value_id`: a unique id minted when the label was created or last
  transformed.
- `lineage`: the de-duplicated set of every source name that contributed to
  this value. Trust resolution checks every name in `lineage`, not just
  `source`, which is what makes "more restrictive wins" hold after a merge.

A plain `str` literal carries no label and contributes no sources; it is
trusted by construction because it has no provenance to resolve as
untrusted.

## `Tainted` and `TaintedBytes`

`taint(value, source=...)` returns a `Tainted` (a `str` subclass) for string
input, or `TaintedBytes` (a `bytes` subclass) for bytes input. Both serialize
transparently to their underlying value, so they pass to model SDKs and tool
functions with no special handling, and expose `.label` for inspection.

## Why propagation is partial: the CPython mechanism

A `str` subclass can intercept an operation only when the `Tainted` instance
is the **receiver**, or the **right operand of a binary operator** (CPython
runs the subclass's reflected dunder, e.g. `__radd__`, before the plain
`str`'s forward dunder). Every other path assembles the result as an exact
`str` in C, with no Python-level hook, and the label is lost. This single
fact determines the entire contract below.

## Propagates (reliable)

- Binary operators where a `Tainted` is the left or right operand: `+`
  (`__add__`/`__radd__`), `%` (`__mod__`/`__rmod__`), `*`
  (`__mul__`/`__rmul__`).
- Slicing and indexing on a `Tainted` receiver (`__getitem__`).
- `str` methods called **on** a `Tainted` receiver that return a new string:
  `upper`, `lower`, `strip`/`lstrip`/`rstrip`, `replace`, and the
  part-returning methods `split`/`rsplit`/`splitlines`/`partition`/
  `rpartition` (every returned part is individually re-wrapped, carrying the
  same label).
- `template.format(*args, **kwargs)` and `template % arg` where the
  **template** (the receiver / left operand) is `Tainted`. Any `Tainted`
  value passed as a substitution argument is also inspected and its label
  merged in, so a tainted argument's provenance is captured too, not only
  the template's. When the substitution argument is a mapping
  (`template % {"k": tainted_value}`), each value in the mapping is
  inspected the same way and merged in; only keys are not, since
  `%`-formatting only ever substitutes values.
- The bare single-field f-string `f"{x}"` (no surrounding literal text)
  preserves taint, because `__format__` is overridden. This case is
  salvageable but narrow; see below.

## Laundering points (re-`taint` required)

- **f-strings with any literal text**, e.g. `f"Summary: {x}"`. These compile
  to a `BUILD_STRING` opcode that produces an exact `str` regardless of its
  parts; there is no hook. Treat f-strings as a laundering point.
- `"{}".format(x)` and `str.format_map(...)` where the template is a
  **plain** `str`. `__format__` runs on the argument, but `str.format`
  assembles an exact `str`.
- `" ".join(chunks)` where the **separator** (the receiver) is a plain
  `str`. The join builds an exact `str`; joining on a `Tainted` separator
  would propagate instead.
- `plain_template % (tainted, ...)`: a plain template with a tuple right
  operand. The operation is `str.__mod__` on the plain template; the right
  operand is a `tuple`, not a `Tainted`, so `Tainted.__rmod__` never fires.
  The single-argument `plain % tainted` and the `Tainted`-template forms
  above do propagate; the plain-template-with-tuple form does not.
- Any path that routes a tainted value through a non-overridden operation:
  `json.loads(tainted)` then dict reconstruction, `int(tainted)` then
  arithmetic, and so on.

## Boundaries that always reset to untrusted ingress

Serialization (JSON encode/decode, pickling), storage round-trips (writing to
and reading from a database or file), and crossing the process boundary all
reset the label. Data that leaves the process and returns is fresh untrusted
ingress, unconnected to any prior label, and must be re-`taint`ed at
re-entry.

A model-mediated agent-to-agent handoff is the same kind of boundary: the
next agent receives the prior agent's output as plain, unlabeled text, even
when it is causally derived from untrusted data. Re-`taint` it at the
boundary:

```python
handoff = taint(agent_a_output, source="agent_a")
```

This is coarse (the whole output is marked, not just the untrusted-derived
parts), but coarse-and-safe is the right default for a containment layer.
See the next section for the trust-aware form of this same re-taint.

## Model calls and derived values

`taint()` accepts an optional `derived_from` argument for exactly this kind
of boundary: instead of marking `value` as a fresh ingress point, it marks
`value` as **derived from** other values, so trust is inherited from them
rather than assumed one way or the other.

```python
def taint(value: Any, *, source: str, derived_from: Iterable[Any] | None = None) -> Any: ...
```

```python
summary = taint(model_output, source="model", derived_from=[prompt, context])
```

Every label found among `derived_from` (recursing into containers, to the
same bounded depth as everything else in this document) is merged: the
returned value's `lineage` is the union of those labels' lineage, so trust
resolves at the sink exactly as if the original inputs had reached it
directly — untrusted if any one of them was, trusted if all were. `source`
becomes the *derivation hop*'s name (`"model"` above), kept on the returned
label for tracing, the same way a merged label's `source` already names the
first contributor (see [the trust model](#the-trust-model-a-provenance-set-not-a-lattice)
above); `lineage` still names the real upstream sources for full
traceability back through the hop. If `derived_from` carries no label at
all (every item was a plain, untainted value), `value` is returned
completely unmarked: there is no provenance among the inputs to propagate,
consistent with a plain `str` literal being trusted by construction.

This does not record `source` as a run-level ingress event the way a plain
`taint(value, source=...)` call does (see
[Policies: run-level gating](policies.md#run-level-gating-run-tainted)):
`"model"` is a derivation marker, not a source declared in your policy's
`sources:` table, and recording it would make `run.tainted` spuriously true
on every model call regardless of whether its actual inputs were trusted.

`track_model_call` is the ergonomic wrapper over this same primitive for the
common shape, "wrap a function so its return value inherits trust from its
arguments":

```python
from interbolt import track_model_call

@track_model_call(source="model")
def summarize(web_result: str, internal_result: str) -> str:
    return llm_client.complete(...)
```

It binds the wrapped function's call arguments (the same way `@guard`
binds them for label collection) and calls `taint(result, source=source,
derived_from=bound_arguments.values())` on the return value. It works on
both sync and async functions, auto-detected the same way `@guard` detects
a coroutine function. It tracks provenance only; it does not evaluate
policy, so stack `@guard` alongside it if the call into the model should
also be gated.

**This closes part of, not all of, the model-mediated-handoff gap above.**
`derived_from` requires the integrator to identify which values a
derivation's trust should come from and either call `taint(..., derived_from=...)`
by hand or wrap the producing function in `@track_model_call`; it is not
automatic, and interbolt never inspects the model's own generated text to
verify a summary is faithful to its untrusted input. It is still the
documented, explicit mechanism (§5.4/§8.3 in `dev/spec.md`), not the
deferred automatic contamination model; see
[Deferred features: agent-boundary provenance](../design/deferred.md#agent-boundary-provenance).

## The honest summary

Taint survives **direct passing** of a tainted value to a tool argument, and
**operator-style combination**. Common string-assembly constructs (f-strings
with text, `str.format`, `join`) produce a fresh, unlabeled string; the
mitigation is an explicit re-`taint` call. The
[laundering audit](../guides/auditing.md) finds the cases where a developer
forgot to.

The audit catches **mechanical** laundering, where the untrusted bytes
survive into the sink argument. It cannot catch **semantic** laundering,
where a model summarizes or paraphrases the untrusted text before it reaches
the sink, because there is no surviving byte sequence to match against. That
limit is fundamental to an in-process string-subclass carrier, not a bug to
be fixed later.

## Non-string values

Non-string scalars (numbers, `bool`, `None`) are wrapped in a `LabeledValue`
rather than a dedicated carrier like `TaintedInt`. `bool` and `NoneType`
can't be subclassed in CPython, and numeric coercion (`int(x)`, comparisons
feeding branches, arithmetic) discards subclass identity immediately, so a
numeric carrier would lose its label on nearly everything except direct
passing.

`taint(value, source=...)` wraps a non-string scalar in a `LabeledValue`,
exposing `.value` and `.label` for direct passing to a sink argument, where
`check()` and the policy see it. Transforming `.value` first produces a
plain, unlabeled result.

## Container recursion

Tool outputs are routinely containers: a search returns a list of records, an
API returns a dict. `taint()` recurses into builtin containers (`list`,
`tuple`, `set`, `frozenset`, `dict` keys and values) and labels string
leaves; `check()`/`guard` recurse the same way when collecting labels from
bound call arguments.

Both read the same bounded depth, `interbolt.constants.RECURSION_DEPTH`
(default 4, overridable by `INTERBOLT_RECURSION_DEPTH` in `[1, 10]`), so
ingress labeling and sink collection are bounded identically. Bounding is a
denial-of-service and latency requirement: container recursion runs on the
guarded-call hot path. The honest edge: a label buried below the resolved
depth is not seen, and the call is evaluated as if that leaf were untainted.
Only builtin containers are traversed; arbitrary objects are not
introspected.

A namedtuple is handled correctly: it is a `tuple` subclass whose
constructor takes positional fields, so both `taint()` and `unwrap()`
reconstruct it by unpacking rather than passing a single iterable. If
reconstructing an exotic container subclass ever fails, `taint()`/`unwrap()`
degrade to passing the value through unlabeled/untraversed rather than
raising, since the containment layer must never be the thing that crashes a
guarded call.

## Merge rule

When two tainted values combine (for example `+`), the merged label's
`lineage` is the de-duplicated union of every contributing source, and a
fresh `value_id` is minted. There is no trusted/untrusted state to merge;
trust resolution happens later, at the sink. Merge is associative and
order-independent, so propagation is predictable regardless of how an
expression is parenthesized.
