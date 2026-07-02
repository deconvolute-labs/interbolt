# Interbolt documentation

Interbolt marks untrusted data where it enters an agent, propagates that mark
through your code, and evaluates a YAML+CEL policy at each guarded tool call.
The decision (allow, block, require approval) is deterministic and computed
in-process: no model, no network calls.

See the [design lineage](#design-lineage) below for how the three pieces fit
together, or jump straight to the [quickstart](quickstart.md).

## Start here

- [Quickstart](quickstart.md): install, write a policy, taint a value, guard a tool.

## Concepts

- [Taint propagation](concepts/taint-propagation.md): what `taint()` marks
  and what survives a transformation.
- [Policies](concepts/policies.md): the YAML+CEL policy format, evaluation
  semantics, and the CEL context available to a `when` expression.
- [Identity](concepts/identity.md): the `agent_id` / `run_id` / `session_id`
  triple, per-agent handles, and `agent_context`.
- [Namespacing](concepts/namespacing.md): the `(namespace, tool)` identity pair
  and the dotted `namespace.tool` policy-key surface.

## Reference

- [API reference](reference/api.md): every name re-exported from `interbolt`.
- [Reporters](reference/reporters.md): the `Reporter` protocol and the three
  shipped implementations.

## Guides

- [Testing](guides/testing.md): how to assert on policy decisions with
  `InMemoryReporter` and a fake approval resolver.
- [Auditing](guides/auditing.md): finding the places a transformation
  laundered a taint label that should have been re-tainted.
- [CI](guides/ci.md): checking a policy file with `interbolt validate` in CI
  or pre-commit.
- [MCP](guides/mcp.md): the planned MCP client-session integration and its
  current status.

## Design

- [Deferred features](design/deferred.md): what's out of scope for v1, and
  the seams left to add each later.

## Design lineage

The architecture assembles three proven patterns rather than inventing new
mechanisms:

- **Enforcement core, modeled on [Casbin](https://casbin.org/).** A pure
  `check()` entrypoint, analogous to Casbin's `enforce()`: given a request
  (tool, args, taint), evaluate a policy and return a decision.
- **Reporting, modeled on [OpenTelemetry](https://opentelemetry.io/).** A
  stable public surface that is inert by default, with swappable reporter
  implementations behind a protocol and an in-memory reporter for tests. The
  difference: interbolt is an enforcement authority, not just observability.
  Reporting is an output, never the engine.
- **Taint carrier, modeled on Django's `SafeString` / MarkupSafe.** A
  `str`/`bytes` subclass that overrides dunder methods so taint propagates
  through a defined subset of string operations. The divergence: interbolt
  carries a **provenance set** and resolves trust late, at the sink, rather
  than a two-state lattice that degrades on contact.

The full design rationale lives in [`dev/spec.md`](../dev/spec.md), which is
the authoritative specification this documentation summarizes for users.
