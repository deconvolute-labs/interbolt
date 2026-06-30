# Policies

A policy is YAML for structure, [CEL](https://github.com/google/cel-spec) for
boolean conditions, loaded and compiled once via `Policy.from_file(path)`. The
CEL implementation is [`cel-python`](https://github.com/cloud-custodian/cel-python).

## Structure

```yaml
version: "1.0"

defaults:
  source_trust: untrusted        # any source not listed below is untrusted
  sink_action: require_approval  # a sink with no matching rule falls through to this
  fail_mode: enforce             # enforce | monitor | dry_run

# INGRESS: assign trust to named sources.
sources:
  - name: web_search
    trust: untrusted
  - name: internal_kb
    trust: trusted
  - name: user_input
    trust: trusted

# EGRESS: gate sinks. Keys are dotted qualified names "namespace.tool".
# Within a sink, rules are ordered; first match wins. A trailing rule with
# no `when` is the catch-all.
sinks:
  email.send_email:
    - name: block_untrusted_exfil
      when: taint.any(t, t.trust == "untrusted") && args.to.endsWith("@external.com")
      action: block
    - name: default
      action: require_approval

  default.fs_write:
    - name: approve_untrusted_to_disk
      when: taint.any(t, t.trust == "untrusted")
      action: require_approval
```

A sink key must be a dotted `namespace.tool` name; see
[Namespacing](namespacing.md) for how a bare tool name resolves to one. A
malformed or schema-invalid file raises `PolicyEvaluationError` from
`Policy.from_file`.

## Actions

Exactly three: `allow`, `block`, `require_approval`. There is no `sanitize`
or `rewrite` action: that would invite an unverifiable "we cleaned the
input" claim that an adaptive attacker can defeat.

## The CEL evaluation context

A `when:` expression can reference:

- `tool`: the qualified name of the guarded sink, as a string.
- `args`: the bound call arguments by name, e.g. `args.to`, `args.path`.
  Arguments are exposed **raw**, with taint carriers already stripped to
  their plain `str`/`bytes`/scalar/container form, so write plain predicates
  like `args.to.endsWith(...)`. An argument value with no CEL-representable
  shape (not a JSON-like scalar, string, list, or mapping) is simply omitted
  from the context; referencing it in a `when` then behaves like referencing
  a missing key, which is an evaluation error (see below).
- `taint`: a CEL list of per-label objects, one per label collected from the
  call's arguments. Each entry exposes `t.trust` (resolved at evaluation
  time by checking every name in the label's `lineage` against the policy's
  `sources` table, untrusted-wins) and `t.source` (the label's recorded
  `source` field). Quantify over it with `taint.any(t, <expr>)` or
  `taint.all(t, <expr>)`.
- `sources`: a CEL list, the de-duplicated set of every source name
  contributing to any argument's label across the call.
- `max_trust`: a CEL string, `"untrusted"` if any contributing label
  resolves untrusted, else `"trusted"`. The same "more restrictive wins"
  resolution as `taint.any(t, t.trust == "untrusted")`, exposed as a
  convenience scalar.
- `trifecta`: the lethal-trifecta legs satisfied by this call. See
  [the v1 trifecta limit](#the-v1-trifecta-limit-read-this) below; this is
  load-bearing.

`sources` and `max_trust` are top-level context variables, siblings of
`taint`, not `taint.sources`/`taint.max_trust`. CEL's `exists`/`all` macros
(which `taint.any`/`taint.all` are built on) require their receiver to be a
CEL list; a single context value cannot be both a list and a map at once.

`taint.any(...)` is implemented as a compile-time rewrite to CEL's real
`exists` macro (CEL has no `any` macro). The rewrite operates on the
compiled call node, not on the raw expression text, so a literal `.any(`
appearing inside a quoted string (a path, URL, or regex) in your CEL is
never touched. Write `taint.any(t, ...)` exactly as shown throughout this
page; the rewrite is an internal implementation detail. `taint.all(...)`
already matches CEL's real `all` macro and needs no rewrite.

### Evaluation errors

A missing argument, a `None` value, or a non-marshalable value encountered
during CEL evaluation is an evaluation error, handled per
[mode](#modes-and-fail_mode): fail-closed under `enforce`, log-and-proceed
under `monitor`, downgraded to allow under `dry_run`. The canonical case is
`args.to.endsWith(...)` on an optional argument that was not passed: the
reference raises, and under `enforce` the call is blocked with
`PolicyEvaluationError`. Guard for presence in CEL when writing a predicate
over an optional argument, for example `has(args.to) && args.to.endsWith(...)`.

## Evaluation semantics

- **Default deny.** A source not listed in `sources` is untrusted. A sink
  with no matching rule falls through to `defaults.sink_action`.
- **First match wins** within a sink's ordered rule list.
- **Trust resolution at the sink.** `taint()` records only the source name;
  `t.trust` is resolved during `check()` by looking the source up in the
  policy's `sources` table. The same policy file governs both ingress trust
  and egress gating.
- Policies and CEL expressions are compiled once, at `Policy.from_file(...)`
  (or `configure()`), never per call.

## Modes and `fail_mode`

`mode` governs what happens on an evaluation error, and whether a real
`block` is enforced. It does not change a correctly-computed `block` or
`require_approval` decision except under `dry_run`.

- `enforce` (default): fail-closed. An evaluation error is treated as a
  block and raises `PolicyEvaluationError`.
- `monitor`: fail-open on evaluation error (logged, call proceeds); a
  correct `block` still blocks. An adoption on-ramp.
- `dry_run`: every decision is computed and emitted but downgraded to
  `allow`; nothing is ever blocked. The emitted event's `outcome` field
  still records the real, pre-downgrade action, so a dry run against live
  traffic shows what a real rollout would have done.

Mode has three sources, highest precedence first: the `INTERBOLT_MODE`
environment variable, the policy file's `defaults.fail_mode`, and the
`mode=` argument to `configure()` (the in-code default, lowest precedence).
Each source is parsed strictly; an unrecognized value raises
`InterboltConfigError`. An `INTERBOLT_MODE` override that actually changes
the effective mode logs a warning, so a non-enforcing mode cannot silently
ship to production. This is the one-line CI escape hatch:

```bash
INTERBOLT_MODE=monitor pytest
```

## The v1 trifecta limit (read this)

v1 computes exactly one of the three lethal-trifecta legs: `from_untrusted`,
present if any label contributing to the call resolves untrusted. The other
two legs are not computed:

- `reaches_external` has no computation path in this version. There is no
  policy field to declare it. `trifecta.contains("reaches_external")`
  **always evaluates to `false`**.
- `reads_private` requires a capabilities declaration that does not exist
  yet (see [Deferred features](../design/deferred.md)).

This makes `trifecta.size` **under-count**, which is fail-open, not
conservative. `trifecta.size >= 3` never trips. **Do not rely on
`trifecta.size >= 3`, or on the two-leg
`trifecta.contains("from_untrusted") && trifecta.contains("reaches_external")`
pattern, as a backstop.** The second leg of that pattern is always false, so
the whole expression is always false and a rule built on it never fires,
silently. Write rules directly against `taint`/`args` instead, as in the
worked example at the top of this page.

`interbolt validate` rejects any policy referencing a trifecta leg name
outside the v1-computable set `{from_untrusted}`, converting this silent
fail-open into a loud failure at validation time. See [CI](../guides/ci.md).

## Static validation

`Policy.validate(path)` (and `interbolt validate policy.yaml` on the command
line) performs static analysis only: it never executes an agent and never
observes live taint. It checks the file against the policy schema, compiles
every CEL expression, flags dead rules (more than one unconditional
catch-all within a sink, or any rule placed after one), and rejects
references to trifecta legs outside the v1-computable set. It does not
verify that every source name compared against `t.source` inside a `when`
expression is declared in `sources`; an undeclared source is still handled
safely at evaluation time regardless, since it resolves untrusted by
default-deny. See [CI](../guides/ci.md) for wiring it into a pipeline.
