# Taint propagation

This is the most important honesty surface in the library. Read it before
relying on taint propagating through any transformation you write.

## The trust model: a provenance set, not a lattice

A label does not record a trusted/untrusted bit. It records *where the data
came from*. Trust is resolved late, at the sink, by looking each contributing
source up in the policy's `sources` table (see [Policies](policies.md)).
"More restrictive wins" falls out of this for free: if any source
contributing to a value is untrusted, the value resolves untrusted at the
sink, regardless of how many trusted sources also contributed.

`Label` (in `interbolt.models.core`) carries:

- `source`: the originating source name, or the first contributor (in
  insertion order) on a value formed by merging two differently-sourced
  values. Informational; trust resolution never uses `source` alone.
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
  the template's.
- The bare single-field f-string `f"{x}"` (no surrounding literal text)
  preserves taint, because `__format__` is overridden. This case is
  salvageable but narrow; see below.

## Does NOT propagate (laundering points; re-`taint` required)

- **f-strings with any literal text**, e.g. `f"Summary: {x}"`. These compile
  to a `BUILD_STRING` opcode that produces an exact `str` regardless of its
  parts; there is no hook. Treat f-strings as a laundering point.
- `"{}".format(x)` and `str.format_map(...)` where the template is a
  **plain** `str`. `__format__` runs on the argument, but `str.format`
  assembles an exact `str`.
- `" ".join(chunks)` where the **separator** (the receiver) is a plain
  `str`. The join builds an exact `str`. Joining on a `Tainted` separator
  would propagate, but that is not how `join` is normally written.
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
ingress and must be re-`taint`ed at re-entry; interbolt does not reconnect
re-entered data to a prior label.

A model-mediated agent-to-agent handoff is the same kind of boundary: the
next agent receives the prior agent's output as plain, unlabeled text, even
when it is causally derived from untrusted data. Re-`taint` it at the
boundary:

```python
handoff = taint(agent_a_output, source="agent_a")
```

This is coarse (the whole output is marked, not just the untrusted-derived
parts), but coarse-and-safe is the right default for a containment layer.

## The honest summary

Taint survives **direct passing** of a tainted value to a tool argument, and
**operator-style combination**. It does **not** survive the common
string-assembly constructs (f-strings with text, `str.format`, `join`). For
those, the mitigation is an explicit re-`taint` call, the documented escape
hatch. The [laundering audit](../guides/auditing.md) exists to find the cases
where a developer forgot to.

The audit catches **mechanical** laundering, where the untrusted bytes
survive into the sink argument. It cannot catch **semantic** laundering,
where a model summarizes or paraphrases the untrusted text before it reaches
the sink, because there is no surviving byte sequence to match against. That
limit is fundamental to an in-process string-subclass carrier, not a bug to
be fixed later.

## Non-string values

There is no numeric or boolean taint carrier (`TaintedInt` and similar), in
this version or planned for a later one. `bool` and `NoneType` cannot be
subclassed in CPython, and numeric coercion (`int(x)`, comparisons feeding
branches, arithmetic) discards subclass identity immediately, so a numeric
carrier would silently lose its label on nearly everything except direct
passing, a worse version of the string problem with less obvious failure.

Instead, `taint(value, source=...)` wraps a non-string scalar in a
`LabeledValue`, which exposes `.value` (the original value) and `.label`. It
does not propagate through transformations, the same limit non-string values
have always had, but a `LabeledValue` passed **directly** to a sink argument
is seen by `check()` and the policy.

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

## Merge rule

When two tainted values combine (for example `+`), the merged label's
`lineage` is the de-duplicated union of every contributing source, and a
fresh `value_id` is minted. There is no trusted/untrusted state to merge;
trust resolution happens later, at the sink. Merge is associative and
order-independent, so propagation is predictable regardless of how an
expression is parenthesized.
