# Claude Code Instructions

## Primary references

This file is the authoritative, self-contained rule set for working in this
repo. If a file `dev/spec.md` exists in your working tree, read it in full
before writing any code and treat it as governing wherever it overlaps with
this file. If it does not exist, this file stands alone; do not ask for it,
reference it, or block on it.

---

## Non-negotiable rules

### Architecture

- The layered dependency direction must never be violated. Imports point inward along the flow (leaves, then `models`, then `taint`/`policy`, then `enforcement`, then `runtime`); nothing reaches outward.
- `models/` contains pure Pydantic models and Protocols only. It imports only stdlib, Pydantic, and the leaf modules (`errors`, `constants`). Nothing else. Helper functions (validation, parsing, name handling) never live here.
- `errors.py`, `constants.py`, and everything in `utils/` import only Python stdlib. The one exception among themselves: `constants.py` and `utils/` may import `errors.py`, also a leaf, for `InterboltConfigError`. One sanctioned soft-import: `utils` may resolve `opentelemetry.trace` via a guarded, cached `try/except ImportError` for trace-context reads; it is never a hard dependency. These are the leaves.
- `taint/` and `policy/` import only `models/` and the leaves. They never import each other, `enforcement/`, `reporting/`, `runtime/`, `integrations/`, or `cli/`.
- `enforcement/` imports `taint/`, `policy/`, and `models/`. It never imports `reporting/` (it emits through the `Reporter` protocol from `models/`), `runtime/`, `integrations/`, or `cli/`.
- `reporting/` imports only `models/` and the leaves. It never imports `enforcement/` or `runtime/`.
- `runtime/` is the composition root. It may import any flow layer. Nothing imports `runtime/` except the package `__init__`.
- `integrations/` and `cli/` are thin edges. They import only the public surface (the package `__init__`) and never reach into `taint/`, `policy/`, `enforcement/`, `reporting/`, or `runtime/` internals.
- `enforcement/` and `taint/` depend on the `Reporter` and `ApprovalResolver` protocols defined in `models/protocols.py`, never on concrete implementations. The concrete reporter and resolver are injected by `runtime/` at composition time.
- Process-global mutable state is confined to two modules: `taint/runstate.py` (the run-ingress registry, the taint observer hook, the endorsement emitter hook) and `runtime/current.py` (the process-current runtime). `runtime/config.py:configure()` is the only function that installs any of it. Never add a mutable module-level global anywhere else. Read a mutable global only through its owning module's getter function; never `from x import _the_variable`, which binds a stale snapshot. Pure functions may be from-imported freely.
- Container traversal (recursion into builtin containers and mappings, depth bounding, reconstruction with its fail-safe) is implemented exactly once, in `taint/walk.py`. Never write another recursive container walk; use `walk_leaves`/`map_leaves`/`leaf_text`.
- No circular imports anywhere. The structure makes them impossible when the rules above are followed; no import-linting tool is used.
- `from __future__ import annotations` at the top of every module. Cross-layer type-only references use `TYPE_CHECKING`-guarded imports, never runtime imports.

### Core invariants

- `taint()` records only the source name on the `Label`. Trust is never resolved at marking time; it is resolved at the sink during `check()` from the policy's `sources` table. Never store a resolved `TrustLevel` on a `Label`.
- `check()` is the single decision entrypoint. `guard` is sugar over `check()`. Never duplicate the decision sequence (context build, evaluate, assemble `Decision`, emit) anywhere else.
- Mode (`enforce`, `monitor`, `dry_run`) governs only behavior on evaluation error and whether blocks are real. A correct `block` or `require_approval` always acts, except under `dry_run` where it is downgraded to allow. Never let mode change a correct decision otherwise.
- Default posture is deny: an undeclared source is untrusted; a sink with no matching rule falls through to `defaults.sink_action`. Never default to allow.
- Policy evaluation is first-match-wins within a sink's ordered rule list. Never reorder rules at load or evaluate out of order.
- Policies and CEL expressions are compiled once at load, never per call. Never compile inside `check()`.
- Tool identity is always the structured `(namespace, tool)` pair internally; the dotted `namespace.tool` form is surface only. The default namespace is `default`. Reject qualified names where the namespace or tool contains a dot.
- Every `Decision` carries the identity triple: `agent_id` (durable, integrator-supplied), `run_id` (minted per run by the runtime), `session_id` (optional, integrator-supplied). Never omit `agent_id` or `run_id`; never fabricate a durable `agent_id`.
- `Event` embeds its `Decision` and duplicates nothing from it. Identity, matched-rule, trifecta, and mode facts are read via `event.decision`; `Event` itself carries only `schema_version`, `decision`, `sources`, `outcome`, `trace_id`, `span_id`, and `timestamp`. Never re-flatten a `Decision` field onto `Event`.
- `outcome` is the `Outcome` StrEnum (`allow`, `block`, `require_approval`, `evaluation_error`), never a raw string. It records what policy evaluation actually computed, before any mode-based downgrade; `Decision.action` records the enforced action.
- The `Event`/`Finding`/`Endorsement` schemas are versioned via `constants.EVENT_SCHEMA_VERSION`. Never change any record shape without bumping the version.

### Taint propagation invariants

- Propagation is in-process only, following the `SafeString` model. When tainted and untainted values combine, the result is tainted. When two tainted values combine, labels merge (union of lineage, intersection of endorsements, fresh `value_id`). A single-parent derivation (slice, case change, one part of a split) reuses the parent `Label` and `value_id`; a fresh `value_id` is minted only at ingress, at a genuine multi-label merge, and at an `endorse()` hop. Never let a combining operation produce an untainted result from a tainted input.
- Propagation does not survive serialization, storage round-trips, or the process boundary. Data re-entering the process is fresh untrusted ingress and must be re-`taint`ed. Never attempt to reconnect re-entered data to a prior label in v1.
- The propagation contract is deliberately honest about its limits: f-strings with literal text, plain-template `str.format`, plain-separator `join`, and plain-template `%` with a tuple operand all launder the label, and this is documented, never papered over. Never weaken or overstate the contract in code, docstrings, or docs. Direct passing and operator-style combination propagate; common string assembly does not; the laundering audit exists to catch mechanical laundering and cannot catch model paraphrase.
- Container recursion at ingress and at the sink is bounded by `constants.RECURSION_DEPTH`; a label below the bound is not seen. `unwrap()` is the one deliberately unbounded traversal (`depth=None`); never introduce a bound there, and never remove the bound elsewhere.
- Inside a container, only `str`/`bytes` leaves are ever wrapped; a non-string leaf passes through unchanged. `LabeledValue` is produced only for a top-level non-string scalar passed directly to `taint()`. At the depth cutoff, a sub-container passes through unchanged, never wrapped.
- `endorse()` preserves provenance and never changes trust resolution: it adds a named kind to `endorsements`, and only a policy that explicitly references `t.endorsements` (or `require_endorsement`) is affected. Endorsement is issued only by deterministic validation code, never conditioned on model output. Every `endorse()` call emits an `Endorsement` record.

### Specific invariants

- All exceptions come from `errors.py`, under one base, `InterboltError`. Two branches: decision outcomes (`PolicyViolation`, `PolicyEvaluationError`, `ApprovalDenied`) and misuse (`InterboltConfigError(InterboltError, ValueError)`, `InterboltUsageError(InterboltError, RuntimeError)`). The misuse pair multiply-inherits the fitting builtin so `except InterboltError` and `except ValueError`/`except RuntimeError` both catch correctly. Never raise a generic `Exception`, a bare `ValueError`, or a bare `RuntimeError` anywhere in the library; a config mistake raises `InterboltConfigError`, a bad call sequence raises `InterboltUsageError`. Never add a sixth error class without removing the temptation to over-specialize.
- All constants live in `constants.py` (global) or the owning layer (layer-specific). Never hardcode a magic value at a call site.
- `configure()` has no import-time side effects. Importing a module that uses `@guard` must not require `configure()` to have run. Policy compilation happens in `configure()`, never at import.
- Reporter emission is fire-and-forget and non-blocking. A reporter failure must never affect, delay, or fail a decision. Never `await` or block on the reporter in the decision path.
- The core makes no network calls under any default configuration. The default reporter is `NullReporter`. Any transmission is a non-default reporter the integrator opts into. Never add a phone-home to the core path.
- All async methods are `async def`. The decision core is pure and synchronous; only the reporter and approval resolver are colored. `asyncio.run()` is never called inside the library. Never block the event loop.
- The library logger never configures the root logger and never emits at import. `DEBUG` is extensive; `INFO` is the verbose default. Never call logging configuration from library code.
- Google-style docstrings on all public functions, methods, and classes (the set re-exported from the package `__init__`). Internal docstrings are optional but recommended and kept short (one-line summary preferred).
- Docstrings and comments never justify themselves. Never reference an internal design document (by name, section number, or "the spec"), a PR/fix/ticket number, a line-count or file-size threshold, or any other internal project-management artifact, in a docstring or a comment. Never explain why something is *not* done, why an alternative was rejected, or otherwise narrate a design discussion. State what the code does and, where it genuinely helps a reader, why it does it that way, in a way that stands on its own with no external document to point to. Docstrings are for the library's user; comments are for a developer working on the library and may carry more internal reasoning, but are held to the same two rules: no internal-document references, no justifications. This applies to every module, including a module whose existence follows from an internal engineering rule (for example the file-split threshold below) — the resulting module's docstring describes what it contains, never why it was split out.
- Type hints on every function and method signature including return types. No `Any` without an inline comment explaining why it is intentional.
- No agent framework imports in the core (LangChain, LangGraph, CrewAI, etc.). Framework glue lives only in `integrations/`, behind optional extras. Core is plain Python.
- A package `__init__.py` contains only the package docstring and re-exports; implementation lives in named modules within the package. Split an implementation module when it exceeds 300 lines, or when a separate file is required to break a dependency cycle. Split along the most natural conceptual seam, not arbitrarily at the line count. Do not pre-split by sub-feature. One standing exemption: `taint/carriers.py` (mechanically repetitive per-operation dunder overrides, not independent concerns).
- Always ensure `uv run ruff check .`, `uv run ruff format --check .`, and `uv run mypy .` pass after making changes.

---

## Testing

Use `pytest` with `pytest-asyncio` and `pytest-mock`. The colored edges
(`Reporter`, `ApprovalResolver`) are mocked with the `mocker` fixture or
`AsyncMock`; `InMemoryReporter` is the assertion surface for decisions. Do not
build a bespoke test harness. Do not implement tests unless explicitly
instructed.

When moving a function between modules, repoint every `mocker.patch` target to
the module where the name is now looked up, not where it is defined. Test
fixtures that reset process-global state write through the owning module
object (`interbolt.runtime.current`, `interbolt.taint.runstate`), never
through a stale imported name.

The wall-clock-bounded stress tests are sensitive to coverage instrumentation
and machine load; if one fails in a full run but passes in isolation, treat it
as a timing flake, not a regression, and do not "fix" it by changing library
code.

---

## Style

- American English only, never British English.
- Never use the em dash or a double dash.
- No `print()` calls anywhere. CLI output goes through `rich.console.Console`. Log output goes through stdlib `logging` via the library logger.
- No inline comments that restate what the code does. Comments explain why, not what.
