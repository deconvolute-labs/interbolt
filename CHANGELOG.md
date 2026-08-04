## [Unreleased]

### ⚠️ Breaking Changes

- **`Decision` gains a required `run_ingress` field, bumping
  `EVENT_SCHEMA_VERSION` from 9 to 10.** A schema-version-9 JSONL log no
  longer parses: `interbolt inspect` skips each such line with a warning and
  reads on, rather than failing the whole file. Migrate an existing log by
  inserting an empty list, which reads as "this run's ingress was never
  recorded":

  ```
  jq -c 'if .record_type == "event" then .decision.run_ingress = [] else . end' old.jsonl > new.jsonl
  ```

- **The `pack`/`unpack` wire envelope's `run` block now carries per-source
  agent attribution, bumping `WIRE_SCHEMA_VERSION` from 1 to 2.** A
  version-1 envelope is rejected outright; there is no compatibility path.

### 🚀 Features

- **`Decision.run_ingress`**, naming every source that entered the active run
  before a call, the trust each resolved to, and the agent ids that ingested
  it. This is what explains a `run.tainted`-driven decision after the fact
  when a model-mediated handoff leaves `contributing_labels`,
  `sources`, and `untrusted_sources` empty on the record; previously only the
  boolean `run_tainted` survived onto the record, with the resolved sources
  discarded.
- **Three new CEL fields on `run`**: `run.sources`, `run.untrusted_sources`,
  and `run.ingested_by`, alongside the existing `run.tainted`. `interbolt
  validate` widens its `run.<field>` check accordingly and adds a
  warning-level lint for `run.sources.all(...)`/`run.untrusted_sources.all(...)`/
  `run.ingested_by.all(...)` inside an `allow` rule, which folds to `true` on
  a run with no recorded ingress; use `.exists(...)` instead.
- `describe_event`/`describe_decision` append a `run_untrusted={...}` segment
  when `run_tainted` is true, and `OTelReporter` exports
  `interbolt.run_ingested_sources`, `interbolt.run_untrusted_sources`, and
  `interbolt.run_ingested_by` as sorted string lists (the source-to-agent
  pairing itself is not exported to OpenTelemetry).

## [0.2.0] - 2026-07-26

### ⚠️ Breaking Changes

- **Policy conditions are plain CEL; the `.any(` alias is removed.** Change
  `.any(` to `.exists(` in every `when:` expression. A policy still using it
  now fails at load with `InterboltConfigError` and at `interbolt validate`
  with a message naming the fix, rather than failing at evaluation time.
- **`Event` no longer duplicates fields from its embedded `Decision`.**
  `agent_id`, `run_id`, `session_id`, `matched_rule`, `mode`, `run_tainted`,
  `trifecta`, and `untrusted_sources` are gone from `Event`; read them via
  `event.decision.<field>`. `Event.lineage` is also removed, having been
  redundant with `Event.sources`.
- **`Event.outcome` is now the `Outcome` enum** rather than a raw string. It
  is a `StrEnum`, so `event.outcome == "block"` still works.
- **`defaults.source_trust` is removed from the policy schema.** No code path
  ever read it; undeclared sources have always resolved untrusted. Because
  `Defaults` now forbids unknown keys, a policy still carrying it fails to
  load instead of loading and silently doing nothing. Delete the line.
- **`EVENT_SCHEMA_VERSION` moves from 6 to 9.** Anything parsing a
  `JsonlReporter` log should read it and fail loudly on an unrecognized value.

### 🔒 Security

- **Fixed a silent fail-open in bare `check()`.** Because the run-ingress
  registry keys on `run_id` and `check()` minted a fresh one whenever the
  caller passed `None`, a `check()` call made inside an active `agent_context`
  reported `run.tainted` as false even when the run had ingested untrusted
  data. Any `run.tainted`-gated rule silently permitted the call. `check()`
  now resolves `run_id` from the ambient context, minting one only when no run
  is active. Custom dispatch loops using `check()` directly were affected but
  `@guard` was not.
- **Fixed string-literal false positives and false negatives in
  `interbolt validate`.** Text-level lints treated the contents of CEL string
  literals as code, so a valid condition such as
  `args.path == "/etc/agent.conf"` failed validation with an error about a
  field the author never wrote, while a literal containing the word `sources`
  suppressed the identity-only-allow safety warning. The reference checks now
  run on the parsed CEL AST.

### 🚀 Features

- **Cross-boundary provenance.** `pack`, `unpack`, `pack_into`, and
  `unpack_from` carry a value's labels and run-scoped ingress across a
  serialization or process boundary in a versioned, optionally
  MAC-authenticated envelope, at `WIRE_SCHEMA_VERSION` 1. Every other channel
  still resets to fresh untrusted ingress.
- **`interbolt explain`.** Answers what a given agent, group, or tool can
  actually reach, resolving each sink's rules against one identity and
  reporting unreachable rules. Backed by `explain_for_agent`,
  `explain_for_group`, and `explain_for_tool` on the public surface.
- **Agent identity in policy.** `agent.id` and `agent.groups` are available in
  CEL conditions, with group membership declared in a new optional `agents:`
  policy section, so a per-agent carve-out can live in one policy file.
- **`enforce_decision` and `enforce_decision_sync`.** Turn a `Decision` into
  control flow at a call site `@guard` cannot decorate, such as a
  framework-owned tool executor or an MCP proxy.
- **`Label.ingested_by`**, recording which agents ingested or derived a value,
  readable in CEL as `t.ingested_by`.
- **`policy_fingerprint` on every emitted record**, a stable hash of the
  policy in force, so a stored record stays attributable after the policy
  changes.

### 📚 Documentation

- Added `ARCHITECTURE.md`.
- Rewrote the README against the code, with an explicit pre-1.0 stability
  statement: the public API may change in any `0.x` minor.
- Add Interbolt-for-OTel-users guide and record integration wrapper decision

### 🧪 Testing

- Enforce the layering rule mechanically

### ⚙️ Miscellaneous Tasks

- Improve docstrings and comments
- Update release workflow and tooling

## [0.1.1] - 2026-07-15

### 🚀 Features

- Add unit tests
- Add init policy handling
- Add new guard api
- Add taint for run-level
- Add better logging
- Add graph tool
- Add improved reporters
- Add extensible reporters via add_reporter and get_runtime
- Fix taint-tracking correctness and propagation path efficiency
- OpenTelemetry integration via OTelReporter and trace-context join keys

### 🐛 Bug Fixes

- Correctness fixes for CEL rewrite, audit registration, and container traversal

### 📚 Documentation

- Add first draft

### ⚙️ Miscellaneous Tasks

- Clean up code
- Improve model
- Update docstrings

## [0.1.0] - 2026-06-30

### 🚀 Features

- Init commit

### ⚙️ Miscellaneous Tasks

- Prepare v0.1.0
