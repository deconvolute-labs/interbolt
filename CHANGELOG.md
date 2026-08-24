## [0.4.0] - 2026-08-24

### ⚠️ Breaking Changes

- **The CLI is regrouped by object: `interbolt policy init|validate|explain`
  and `interbolt run inspect`.**
  Exit codes are now a fixed 0/1/2/3 contract (clean, failed check, usage
  error, internal error); several outcomes that previously returned `1` now
  return `2` or `3`, see the [command line reference](https://docs.deconvolutelabs.com/docs/reference/cli).
  `init`'s default write path changes from `policy.example.yaml` to
  `policy.yaml`, matching `validate`/`explain`'s default read path. All four
  commands gain `--format text|json`, `--quiet`, and `--no-color`.

- **A propagating string/bytes operation on an endorsed value now clears its
  `endorsements` instead of carrying them through unchanged.** Only
  `copy`/`deepcopy` and the `pack`/`unpack` round trip keep them, since only
  those preserve the value's content; every operation that changes the
  value now requires re-`endorse()`, the same as at ingress. A policy
  relying on an endorsement surviving a transformation (`.upper()`,
  `.replace()`, combining two endorsed values, and so on) needs the
  transformed value re-endorsed after the change.

### 🔒 Security

- **`SinkRule`, `PolicyDocument`, and `SourceDeclaration` now reject unknown
  keys at load**, matching the existing treatment on `Defaults` and an
  `agents:` entry.

- **`check()` now treats any exception raised during rule evaluation as an
  evaluation error.** `unwrap` is now bounded by `RECURSION_DEPTH`, matching
  every other container traversal, closing an unbounded-recursion path reachable
  from a self-referential or deeply nested argument.

- **The run-capability registry now logs at `WARNING` when it evicts a run
  past `RUN_CAPABILITY_MAX_TRACKED_RUNS`, and exposes `run.capability_evicted`
  in the CEL context.** A policy can now fail closed on a run whose `run.trifecta`
  may be under-counted, instead of the degraded state passing silently.

- **`check()` now qualifies a bare `tool` name the same way `@guard` already
  does.** One behavior change: a `tool` with more than one dot, previously
  passed through unchanged, now raises `InterboltConfigError`, matching
  `@guard`'s existing rejection of an ambiguous dotted name.This matters for
  an MCP router or tool registry that passes an external tool name straight
  through.

- **`check()` now logs a `WARNING` when a call's qualified `tool` matches no
  declared sink, while at least one sink is declared.** Catches a typo on
  either the `check()` or `@guard` path that previously fell through to
  `defaults.sink_action` with no signal at all.

### 🚀 Features

- **`interbolt scan`.** Statically inventories the tools in a Python
  repository without importing or executing scanned code. Writes a versioned
  JSON artifact (`.interbolt/scan.json`, `SCAN_SCHEMA_VERSION`) carrying per-tool
  evidence, coverage against a policy, and a first-class list of undetected/unreadable
  surface.
- **`interbolt policy init --from-scan PATH`.** Wizard mode walks a scan
  artifact's undeclared sources and tools and writes capability declarations,
  plus derived provenance rules, into the policy. `--non-interactive` writes
  conservative defaults instead of prompting.
- **A bare `<tool>:` key in a policy's `sinks:` mapping is now valid**,
  coercing to an empty `SinkDeclaration`, matching the form the wizard writes
  for an undeclared sink.

### 🔒 Security

- **The packaged policy starter (`policy.example.yaml`) no longer ships live
  example declarations.** It now ships empty `sources: []` and `sinks: {}` instead.

## [0.3.0] - 2026-08-05

### ⚠️ Breaking Changes

- **Policy documents are version `2.0`, and a `sinks:` entry is now a mapping
  rather than a bare rule list.** Each entry takes two optional keys:
  `capabilities:` says what the tool does, and `rules:` gates calls to it. An
  entry with no rules falls through to `defaults.sink_action`, exactly as a
  tool with no entry at all does. Nothing inside a rule changed, so no `when:`
  expression needs editing. A `1.0` document fails at load with a message
  naming both edits.

- **`Decision` gains two required fields, `run_ingress` and `run_trifecta`,
  bumping `EVENT_SCHEMA_VERSION` from 9 to 11.** Code constructing a
  `Decision` directly, including test fixtures, must supply both. A
  schema-version-9 or -10 JSONL log no longer parses; `interbolt inspect`
  skips each such line with a warning and reads on.

- **The `pack`/`unpack` wire envelope's `run` block now carries per-source
  agent attribution and the run's accumulated trifecta capability legs,
  bumping `WIRE_SCHEMA_VERSION` from 1 to 3.** Version-1 and version-2
  envelopes are rejected outright; there is no compatibility path.

- **`Policy.fingerprint` changes for every policy**, since the document shape
  changed. Records emitted before and after this release do not join on
  `policy_fingerprint` even where the policy is semantically identical.

### 🚀 Features

- **All three lethal-trifecta legs are computable.** `reads_private` and
  `reaches_external` are declared per tool with the `capabilities:` key on a
  sink entry, alongside `from_untrusted` derived from a call's own labels. A
  tool that only reads data is declared with capabilities and no rules, which
  is what lets a run reach three legs. `Capability` joins the public surface,
  and `Policy.tool_capabilities` reads the declarations back.

- **`run.trifecta`**, a CEL list of every leg satisfied anywhere in the active
  run, making `size(run.trifecta) >= 3` the Rule-of-Two check. Run-scoped
  rather than value-scoped, so it holds across a model-mediated handoff that
  launders taint off the outgoing argument. A call's own capabilities are
  recorded before its rules are evaluated, so a rule on an external-reaching
  call sees its own leg. Empty outside any `agent_context`, like
  `run.tainted`.

- **`Decision.run_ingress`**, naming every source that entered the active run
  before a call, the trust each resolved to, and the agent ids that ingested
  it. With `Decision.run_trifecta`, this is what explains a run-scoped
  decision on a call whose own arguments carry no labels.

- **Three new CEL fields on `run`**: `run.sources`, `run.untrusted_sources`,
  and `run.ingested_by`, alongside `run.tainted`.

- **`interbolt validate` gains four checks.** It rejects a `1.0` document or a
  bare-list sink entry with a migration message. It checks every trifecta leg
  literal, erroring when no sink declares any capability and warning when no
  sink declares that leg. It warns about a sink entry with no `capabilities:`
  key once at least one entry carries one, where `capabilities: []` records a
  deliberate assessment. It covers the new `run.<field>` names, warning on
  `.all(...)` over any of them inside an `allow` rule, since that folds to
  `true` on a run with no recorded ingress; use `.exists(...)`.

- **`interbolt explain --tool`** leads with the tool's declared capabilities,
  or states that none are declared.

- `describe_event`/`describe_decision` append a `run_untrusted={...}` segment
  when `run_tainted` is true and a `run_trifecta={...}` segment when a
  capability leg is present. `OTelReporter` exports
  `interbolt.run_ingested_sources`, `interbolt.run_untrusted_sources`,
  `interbolt.run_ingested_by`, and `interbolt.run_trifecta` as sorted string
  lists; the source-to-agent pairing is not exported.

### 📚 Documentation

- Rewrote every policy example against the `2.0` document shape, and added the
  trifecta derivation, the capabilities declaration, and the Rule-of-Two
  pattern to the concepts, guide, and reference pages.
- Add agentdojo benchmark reference.

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
