# Claude Code Instructions

## Primary references

Before writing any code, read `dev/spec.md` in full. All implementation decisions
must be consistent with the module structure, dependency rules, naming conventions,
and component contracts defined there. Where this file and the spec overlap, the
spec governs; this file is the short enforcement checklist.

---

## Non-negotiable rules

### Architecture

- The layered dependency direction must never be violated. See `dev/spec.md` §3. Imports point inward along the flow; nothing reaches outward.
- `models/` contains pure Pydantic models and Protocols only. It imports only stdlib, Pydantic, and the leaf modules (`errors`, `constants`). Nothing else.
- `errors.py`, `constants.py`, and everything in `utils/` import only Python stdlib. The one exception: `constants.py` may import `errors.py`, also a leaf, for `InterboltConfigError`. These are the leaves.
- `taint/` and `policy/` import only `models/` and the leaves. They never import each other, `enforcement/`, `reporting/`, `runtime/`, `integrations/`, or `cli/`.
- `enforcement/` imports `taint/`, `policy/`, and `models/`. It never imports `reporting/` (it emits through the `Reporter` protocol from `models/`), `runtime/`, `integrations/`, or `cli/`.
- `reporting/` imports only `models/` and the leaves. It never imports `enforcement/` or `runtime/`.
- `runtime/` is the composition root. It may import any flow layer. Nothing imports `runtime/` except the package `__init__`.
- `integrations/` and `cli/` are thin edges. They import only the public surface (the package `__init__`) and never reach into `taint/`, `policy/`, `enforcement/`, `reporting/`, or `runtime/` internals.
- `enforcement/` and `taint/` depend on the `Reporter` and `ApprovalResolver` protocols defined in `models/protocols.py`, never on concrete implementations. The concrete reporter and resolver are injected by `runtime/` at composition time.
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
- Every `Decision` and `Event` carries the identity triple: `agent_id` (durable, integrator-supplied), `run_id` (minted per run by the runtime), `session_id` (optional, integrator-supplied). Never omit `agent_id` or `run_id`; never fabricate a durable `agent_id`.
- The `Event` schema is versioned via `constants.EVENT_SCHEMA_VERSION`. Never change the event shape without bumping the version.

### Taint propagation invariants

- Propagation is in-process only, following the `SafeString` model. When tainted and untainted values combine, the result is tainted. When two tainted values combine, labels merge (union of lineage, fresh `value_id`, tainted). Never let a combining operation produce an untainted result from a tainted input.
- Propagation does not survive serialization, storage round-trips, or the process boundary. Data re-entering the process is fresh untrusted ingress and must be re-`taint`ed. Never attempt to reconnect re-entered data to a prior label in v1.
- The propagation contract in `dev/spec.md` §6.3 is authoritative and is documented honestly, including its limits. Never weaken or overstate it in code, docstrings, or docs.

### Specific invariants

- All exceptions come from `errors.py`, under one base, `InterboltError`. Two branches: decision outcomes (`PolicyViolation`, `PolicyEvaluationError`, `ApprovalDenied`) and misuse (`InterboltConfigError(InterboltError, ValueError)`, `InterboltUsageError(InterboltError, RuntimeError)`). The misuse pair multiply-inherits the fitting builtin so `except InterboltError` and `except ValueError`/`except RuntimeError` both catch correctly. Never raise a generic `Exception`, a bare `ValueError`, or a bare `RuntimeError` anywhere in the library; a config mistake raises `InterboltConfigError`, a bad call sequence raises `InterboltUsageError`. Never add a sixth error class without removing the temptation to over-specialize.
- All constants live in `constants.py` (global) or the owning layer (layer-specific). Never hardcode a magic value at a call site.
- `configure()` has no import-time side effects. Importing a module that uses `@guard` must not require `configure()` to have run. Policy compilation happens in `configure()`, never at import.
- Reporter emission is fire-and-forget and non-blocking. A reporter failure must never affect, delay, or fail a decision. Never `await` or block on the reporter in the decision path.
- The core makes no network calls under any default configuration. The default reporter is `NullReporter`. Any transmission is a non-default reporter the integrator opts into. Never add a phone-home to the core path.
- All async methods are `async def`. The decision core is pure and synchronous; only the reporter and approval resolver are colored. `asyncio.run()` is never called inside the library. Never block the event loop.
- The library logger never configures the root logger and never emits at import. `DEBUG` is extensive; `INFO` is the verbose default. Never call logging configuration from library code.
- Google-style docstrings on all public functions, methods, and classes (the set re-exported from the package `__init__`). Internal docstrings are optional but recommended and kept short (one-line summary preferred).
- In docstrings, never reference the spec. Also do not explain what something is not doing. Keep the docstrings concise.
- Type hints on every function and method signature including return types. No `Any` without an inline comment explaining why it is intentional.
- No agent framework imports in the core (LangChain, LangGraph, CrewAI, etc.). Framework glue lives only in `integrations/`, behind optional extras. Core is plain Python.
- Split a module into multiple files only when it exceeds 500 lines, or when a separate file is required to break a dependency cycle. Do not pre-split by sub-feature.
- Always ensure `uv run ruff check .`, `uv run ruff format --check .`, and `uv run mypy .` pass after making changes.

---

## Testing

Use `pytest` with `pytest-asyncio` and `pytest-mock`. The colored edges
(`Reporter`, `ApprovalResolver`) are mocked with the `mocker` fixture or
`AsyncMock`; `InMemoryReporter` is the assertion surface for decisions. Do not
build a bespoke test harness. Do not implement tests unless explicitly instructed.

---

## Style

- American English only, never British English.
- Never use the em dash or a double dash.
- No `print()` calls anywhere. CLI output goes through `rich.console.Console`. Log output goes through stdlib `logging` via the library logger.
- No inline comments that restate what the code does. Comments explain why, not what.
