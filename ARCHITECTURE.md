# Architecture

How Interbolt is put together, and the properties the implementation is
required to hold. Written for someone reading or changing the source. For usage,
see the [documentation](https://docs.deconvolutelabs.com/docs).

Every rule here is a constraint on the code. If the code and this document
disagree, one of them is a bug.

## The decision path

One guarded tool call runs the following sequence. Reading it in order is the
fastest way to orient in the codebase.

1. **Ingress.** `taint(value, source="web_search")` in `taint/ingress.py` wraps
   the value in a carrier from `taint/carriers.py` and attaches a `Label`
   recording the source name. The source is recorded against the active run in
   `taint/runstate.py`. No trust is decided here.
2. **Propagation.** The carrier moves through application code, overriding the
   operations in the propagation contract so the label survives them.
   Everything else produces a plain, unlabeled value.
3. **The boundary.** `@guard` in `runtime/guard.py` binds the call's arguments
   with `inspect.signature`, resolves the acting agent, and calls
   `Runtime.check`.
4. **Collection.** `enforcement/check.py` walks the bound arguments to a bounded
   depth, collecting every label (`taint/walk.py: collect_labels`) and producing
   a carrier-free copy for CEL (`unwrap`).
5. **Resolution.** `policy/evaluate.py: resolve_labels` resolves each label's
   lineage against the policy's `sources` table exactly once. A source absent
   from the table resolves untrusted. The trifecta leg, the untrusted source
   set, and the CEL `taint` list all derive from that single resolution.
6. **Evaluation.** The sink's precompiled CEL rules run in order, first match
   wins. No match falls through to `defaults.sink_action`.
7. **Mode.** `_apply_mode` maps an evaluation error to block under `enforce` and
   to allow under `monitor`, and downgrades everything to allow under `dry_run`.
   `Outcome` records what evaluation computed, before that downgrade;
   `Decision.action` records what was enforced.
8. **Emission.** A `Decision` and an `Event` are handed to the reporter.
   Emission is fire-and-forget and never affects the decision.
9. **Enforcement.** `enforcement/enforce.py` turns the `Decision` into control
   flow: return on allow, raise `PolicyViolation` on block, consult the
   `ApprovalResolver` on require-approval.

Steps 4 through 8 are `check()`. Step 9 is `enforce_decision`. `guard` does both.

## Layers

Imports point inward along this order. Nothing reaches outward.

```
errors.py, constants.py, utils/     leaves
        |
      models/                       Pydantic models and Protocols only
        |
   taint/    policy/                independent of each other
        \      /
       enforcement/                 the decision core
            |
        reporting/
            |
        runtime/                    the composition root
            |
      cli/, integrations/           thin edges
```

`tests/unit/test_architecture_invariants.py` enforces this by parsing every
import in `src/interbolt`. The rules it cannot check:

- Leaves import only the standard library. `constants.py` and `utils/` may
  import `errors.py`. `errors.py` references `Decision` under `TYPE_CHECKING`
  only. `utils/` may resolve `opentelemetry.trace` through a guarded, cached
  `try/except ImportError`, which is never a hard dependency.
- `models/` holds Pydantic models and Protocols. Validation, parsing, and name
  helpers live in `utils/`, not here.
- `taint/` and `policy/` never import each other. This is why
  `policy/evaluate.py` handles only `str`, `bytes`, and containers: it receives
  arguments with carriers already stripped.
- `enforcement/` emits through the `Reporter` protocol in
  `models/protocols.py` and never imports `reporting/`.
- `runtime/` is the composition root. Nothing imports it except the package
  `__init__`.
- `cli/` imports the public surface and never reaches into a package's
  internals. The same rule governs `integrations/`, which is planned and not yet
  present: framework glue lives there behind an optional extra, never in core.
- `from __future__ import annotations` at the top of every module. Cross-layer
  type-only references use `TYPE_CHECKING`-guarded imports.

## Module map

**`taint/`** carries provenance.

| Module | Contents |
| --- | --- |
| `carriers.py` | `Tainted`, `TaintedBytes`, `LabeledValue`, label merge |
| `ingress.py` | `taint()`, `track_model_call` |
| `endorse.py` | `endorse()` and its record emission |
| `walk.py` | depth-bounded leaf traversal, used at ingress and the sink |
| `runstate.py` | run-ingress registry, run-capability registry, and the two extension hooks |
| `wire*.py` | the `pack`/`unpack` serialization contract |

**`policy/`** loads, compiles, evaluates, and statically analyzes policy.

| Module | Contents |
| --- | --- |
| `schema.py` | the Pydantic policy document, validation, fingerprinting |
| `cel.py` | CEL parsing and compilation helpers |
| `compile.py` | one-time compilation of every sink's rule list |
| `evaluate.py` | per-call trust resolution, CEL context, sink evaluation |
| `policy.py` | the `Policy` class and the built-in default |
| `identity_ast.py`, `shadowing.py`, `partial_eval.py`, `explain.py` | static analysis behind `interbolt explain` and the unreachable-rule check |

**`enforcement/`** is the decision core: `check.py` (the pipeline), `signals.py`
(trust signals derived once per call), `enforce.py` (decision to control flow),
`audit.py` (the laundering audit registry).

**`runtime/`** composes everything: `config.py` (`configure()`), `runtime.py`
(the `Runtime` class), `current.py` (the process-current runtime), `guard.py`
(`@guard`, `check`, `agent`, agent-id validation), `observers.py` (the hooks
`configure()` installs).

**`reporting/`** holds the shipped `Reporter` implementations, the `describe_*`
formatters, and the optional OpenTelemetry reporter.

## Invariants

- `taint()` records only the source name. Trust resolves at the sink from the
  policy's `sources` table. A resolved `TrustLevel` is never stored on a `Label`.
- `check()` is the single decision entrypoint. `guard` is sugar over it.
- Mode governs only behavior on evaluation error and whether blocks are real. A
  correct block or require-approval always acts, except under `dry_run`.
- The default posture is deny. An undeclared source is untrusted. A sink with no
  matching rule falls through to `defaults.sink_action`.
- Rule evaluation is first-match-wins within a sink's ordered list. Rules are
  never reordered at load time.
- Policies and CEL expressions compile once at load. Nothing compiles inside
  `check()`.
- Tool identity is the structured `(namespace, tool)` pair internally; the
  dotted form is surface only. A namespace or tool containing a dot is rejected.
- Every `Decision` carries `agent_id`, `run_id`, and optional `session_id`. A
  durable `agent_id` is never fabricated.
- A `Decision` carries the run's ingested sources (`run_ingress`, one entry
  per source with its resolved trust and ingesting agents) alongside the
  `run_tainted` boolean derived from the same entries.
- `agent_id` is never accepted from a taint carrier. It is an authorization
  input once a policy reads `agent.id`, so it comes from deterministic dispatch
  rather than model output. Charset, carrier rejection, and rejection of the
  reserved `"default"` apply where identity is bound; charset and carrier
  rejection alone apply inside `Runtime.check`, the chokepoint every path
  funnels through.
- An approval authorizes exactly one call. It is never cached, persisted, or
  reused, not across runs and not for the next call in the same run.
- There is no principal-level elevation primitive. Group membership is fixed on
  a live runtime and changes only by a new `configure()` call.
- Effective mode comes from the first of `INTERBOLT_MODE`, the policy's
  `defaults.fail_mode`, then `configure(mode=)`. Every override logs a warning.
- `Event` embeds its `Decision` and duplicates nothing from it. Changing a
  record shape means bumping `constants.EVENT_SCHEMA_VERSION`; changing the
  `pack` envelope means bumping `WIRE_SCHEMA_VERSION`.
- `configure()` has no import-time side effects, and is the only function that
  installs process-global state.
- Reporter emission is fire-and-forget. A reporter failure never affects,
  delays, or fails a decision.
- The core makes no network calls under any default configuration.
- All exceptions come from `errors.py` under `InterboltError`, in two branches:
  decision outcomes (`PolicyViolation`, `PolicyEvaluationError`,
  `ApprovalDenied`) and misuse (`InterboltConfigError`, `InterboltUsageError`).
  The misuse pair also inherits the fitting builtin. The library never raises a
  bare `Exception`, `ValueError`, or `RuntimeError`.

## Two rules that are easy to violate by accident

**Container traversal exists in exactly two places.** `taint/walk.py` is
depth-bounded and leaf-oriented, used at ingress and the sink.
`taint/wire_walk.py` is path-keyed, used by the serialization contract.
`wire.py` and `wire_rebuild.py` build entirely on `wire_walk.py`'s primitives
and descend nothing themselves. Do not add a third.

**Mutable module-level state exists in exactly two modules.**
`taint/runstate.py` holds the run-ingress registry, the run-capability
registry, and the two hooks; `runtime/current.py` holds the process-current
runtime. Both hooks exist so
`runtime/` can wire behavior into `taint/` without `taint/` importing upward.
Read a global through its owning module's getter, never with
`from x import _the_variable`, which binds a stale snapshot. Do not add a third
module holding state.

Identity binding uses `ContextVar`s in `utils/context.py`, which do not cross a
thread boundary. A guarded call on a thread pool needs `agent(...)`, and a
`taint()` call on an offloaded thread is invisible to that run's `run.tainted`.

## Where the rest lives

- **The propagation contract**, stating exactly what survives which operation:
  [taint propagation](https://docs.deconvolutelabs.com/docs/concepts/taint-propagation).
  Summary: labels survive direct passing and operator-style combination, and are
  lost to f-strings with literal text, `str.format` on a plain template, and
  `join` on a plain separator.
- **Design limits and what is not a vulnerability**: [SECURITY.md](SECURITY.md).
  The one worth knowing before writing a policy is that `reads_private` and
  `reaches_external` are computed only for a tool whose `sinks:` entry
  declares `capabilities:`; an undeclared tool contributes neither leg, and
  `interbolt validate` warns about any sink missing the key once at least one
  other sink declares it.
- **Record schemas and the OTel mapping**:
  [events](https://docs.deconvolutelabs.com/docs/reference/events).
- **Policy internals**, including the CEL context shape and what `validate`
  does and does not catch:
  [policy internals](https://docs.deconvolutelabs.com/docs/reference/policy-internals).
- **Style, testing, and the local check loop**: [CONTRIBUTING.md](CONTRIBUTING.md).

## Adding code

- A package `__init__.py` holds the package docstring and re-exports only.
- Split a module past roughly 300 lines, along the conceptual seam rather than
  at the line count. `taint/carriers.py` is a standing exemption: its
  `Tainted`/`TaintedBytes` symmetry is deliberate, because the propagation
  contract is the security surface and a reader auditing whether `.replace()`
  propagates should find a method rather than a metaclass.
- Constants live in `constants.py` if global, or in the owning layer.
- No agent framework imports in the core.
- Type hints on every signature. `Any` needs an inline comment explaining why.
