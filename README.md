# Interbolt

**Provenance-gated tool calls for AI agents.**

[![PyPI version](https://img.shields.io/pypi/v/interbolt.svg)](https://pypi.org/project/interbolt/)
[![Python versions](https://img.shields.io/pypi/pyversions/interbolt.svg)](https://pypi.org/project/interbolt/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/deconvolute-labs/interbolt/ci.yml?branch=main)](https://github.com/deconvolute-labs/interbolt/actions)

> **Status: pre-1.0.** The public API can change in any `0.x` minor release.
> Pin an exact version if you depend on it. Breaking changes bump the minor
> (`0.2.0`); additive changes and fixes bump the patch (`0.2.1`). The emitted
> record schema is versioned separately via `EVENT_SCHEMA_VERSION` and has its
> own [history](https://docs.deconvolutelabs.com/docs/reference/events). See
> [stability](#stability) for what has to be true before 1.0.

Mark untrusted data where it enters an agent. Interbolt propagates that mark
through your code and evaluates a YAML+CEL policy at each guarded tool call,
returning allow, block, or require-approval based on the provenance of the
call's arguments rather than on their content. Decisions are deterministic and
in-process, with no model and no network call involved. The
[benchmark](https://docs.deconvolutelabs.com/docs/reference/performance) publishes
`check()` overhead and the machine it was measured on.

When code has actually validated untrusted data, `endorse()` lets it say so
without erasing the taint: provenance-preserving, policy-visible, and never
model-triggered. See
[auditing](https://docs.deconvolutelabs.com/docs/guides/auditing).

See how it [performs on the AgentDojo Benchmark](https://deconvoluteai.com/blog/prompt-injection-defense-provenance-agentdojo-benchmark).

## Install

```bash
pip install interbolt
```

Requires Python 3.12 or newer. The `[otel]` extra adds `OTelReporter`.

## Quick start

```python
import asyncio

from interbolt import Policy, PolicyViolation, Tainted, configure, guard, taint

runtime = configure(policy=Policy.from_file("policy.yaml"))

@guard
def send_email(to: str, body: str) -> None:
    ...

# taint() on a str returns a Tainted, which is a str subclass, so it is
# accepted anywhere a str is expected with no change to send_email's signature.
summary: Tainted = taint(web_search("..."), source="web_search")

async def main() -> None:
    # agent_context binds the acting agent's identity for guarded calls
    # made inside the block.
    async with runtime.agent_context("support-agent"):
        try:
            send_email(to="attacker@external.com", body=summary)
        except PolicyViolation as e:
            print(e.decision.matched_rule)   # "block_untrusted_exfil"

asyncio.run(main())
```

Generate a starter policy with `interbolt policy init`, then check it in CI with
`interbolt policy validate policy.yaml`. Calling `configure()` without a policy
uses a built-in default-deny posture (no sources, no sinks, every call requires
approval) and logs a warning pointing to `interbolt policy init`.

## Getting the decision

`check()` and `guard` always compute a `Decision`. On `allow` it is the return
value of `check()`; on `block` and `require_approval` it is attached to the
raised exception:

```python
from interbolt import ApprovalDenied, PolicyEvaluationError, PolicyViolation

try:
    send_email(to="attacker@external.com", body=summary)
except (PolicyViolation, ApprovalDenied, PolicyEvaluationError) as e:
    decision = e.decision              # every decision-outcome error carries one
    decision.action                    # Action.BLOCK
    decision.matched_rule              # rule name, or None for the sink default
    decision.matched_condition         # the rule's CEL text, or None
    decision.untrusted_sources         # frozenset({"web_search"})
```

`describe_decision(decision)` returns a ready-made one-line summary as a
rich-markup string, meant to be printed through a `rich.console.Console`.
Calling `check()` directly rather than through `@guard` returns the `Decision`
for every outcome including allow, so you can log it unconditionally instead of
only on the exception path. Full reference:
[API](https://docs.deconvolutelabs.com/docs/reference/api).

## Propagation

Provenance is a set of source names attached to a value. Trust is resolved at
the sink by looking each source up in your policy, so one file governs both
ingress trust and egress gating.

The label survives direct passing of a value to a tool argument and
operator-style combination (`+`, `%`, slicing, and string methods called on a
tainted value). Common string assembly produces a fresh, unlabeled string:
f-strings with surrounding literal text, `str.format` on a plain template, and
`" ".join(...)` on a plain separator. Re-`taint` the result in those cases. The
same applies across a model-mediated agent-to-agent handoff, where one agent's
generated output reaches the next as plain text.

This is an inherent limit of an in-process string-subclass carrier, and the
[propagation contract](https://docs.deconvolutelabs.com/docs/concepts/taint-propagation)
states every case exactly. Run the audit to find a transformation that should
have been re-tainted.

Provenance also does not survive an ordinary serialization or storage round
trip. A checkpoint write, a queue hop, or a process boundary makes re-entering
data fresh untrusted ingress. The one explicit exception is `pack`/`unpack`,
which carries labels and run-scoped provenance across that boundary in a
versioned, optionally MAC-authenticated envelope. See
[serialization](https://docs.deconvolutelabs.com/docs/guides/serialization).

## The model as a new source

A call into an LLM is exactly this kind of boundary: whatever the model emits
carries no label, even when its prompt was tainted.
`taint(..., derived_from=...)` marks a value as derived from other values, so
trust is inherited rather than assumed, and `track_model_call` applies that to a
function's return value automatically:

```python
from interbolt import taint, track_model_call

@track_model_call(source="model")
def summarize(web_result: str, internal_result: str) -> str:
    return llm_client.complete(f"Summarize: {web_result}\n{internal_result}")

summary = summarize(
    taint(web_search("..."), source="web_search"),      # untrusted
    taint(read_kb("..."), source="internal_kb"),        # trusted
)
summary.label.source    # "model" - the derivation hop, for tracing
summary.label.lineage   # ("web_search", "internal_kb") - the upstream sources
```

Passing `summary` to a guarded sink resolves trust from `lineage` exactly as if
the original inputs had reached that sink directly, so untrusted here. The
model's own text is never inspected or paraphrase-detected.

## Modes and the audit

`configure(mode=...)` sets enforcement behavior:

- `enforce` (default): fails closed. An evaluation error is treated as a block.
- `monitor`: fails open on evaluation error and logs it. Real blocks still
  block. An adoption on-ramp.
- `dry_run`: computes and emits every decision but blocks nothing.

`configure(audit=True)` turns on the laundering audit, an opt-in in-process
instrument orthogonal to the mode. It watches a real run and reports where
untrusted content reached a sink without a label, which is how you catch a
forgotten re-`taint`. It catches mechanical laundering and cannot catch a model
paraphrasing the text first. Findings come out through the reporter, so you can
assert on them in a test with `InMemoryReporter`. Running it takes that run
outside the per-call latency budget.

## Reporting

`Reporter` is the seam for decision output. `NullReporter` (default),
`InMemoryReporter`, `LoggingReporter`, `JsonlReporter`, and `CompositeReporter`
ship out of the box, and `describe_decision`/`describe_event`/`describe_finding`/
`describe_endorsement` format a record for a human. `pip install
"interbolt[otel]"` adds `OTelReporter`, which drops decisions into your existing
OpenTelemetry traces. Reporter emission is fire-and-forget: a reporter that
blocks in `export` delays the decision that triggered it. See
[reporters](https://docs.deconvolutelabs.com/docs/reference/reporters).

## Command line

```bash
interbolt policy init [path]              # write a starter policy; refuses to overwrite
interbolt policy validate policy.yaml     # schema and CEL checks only, safe for CI
interbolt policy explain policy.yaml --agent support-agent
interbolt run inspect provenance.jsonl    # render a JsonlReporter log as a tree
interbolt scan                            # inventory every tool, with evidence
interbolt policy init --from-scan .interbolt/scan.json   # declare capabilities from a scan
```

Every command takes `--format text|json`, `--quiet`, and `--no-color`. Exit codes
are 0 for clean, 1 for a failed check, 2 for a usage error, and 3 for an internal
error. See the [command line reference](https://docs.deconvolutelabs.com/docs/reference/cli).

`explain` answers "what can this agent actually do" by resolving each sink's
rules against one agent, group, or tool, including which rules are unreachable.
See [explain](https://docs.deconvolutelabs.com/docs/guides/explain).

## MCP

An `interbolt[mcp]` extra is planned to adapt an MCP client session directly.
Until it ships, gate an MCP router by calling `check()` before each tool
dispatch and `taint()`-ing tool results as they come back, which
[MCP](https://docs.deconvolutelabs.com/docs/guides/mcp) shows in full.

## Design lineage

The architecture assembles proven patterns rather than inventing new
mechanisms: the pure `check()` entrypoint follows [Casbin](https://casbin.org/)'s
`enforce()`, the inert-by-default reporter surface follows
[OpenTelemetry](https://opentelemetry.io/), the `str`/`bytes` carrier follows
Django's `SafeString` and MarkupSafe, and `endorse()` follows Resin (Yip et al.,
SOSP 2009). The full comparison, including where Interbolt diverges from each,
is in [design lineage](https://docs.deconvolutelabs.com/docs/reference/lineage).

## Stability

Interbolt is pre-1.0 and the API is still moving. What that means concretely:

- Any `0.x` minor may rename, change, or remove public API. Migration notes for
  each one are in [CHANGELOG.md](CHANGELOG.md).
- `EVENT_SCHEMA_VERSION` versions the emitted `Event`/`Finding`/`Endorsement`
  shape independently of the library version. Anything parsing a
  `JsonlReporter` log should read it and fail loudly on an unrecognized value.
- Before 1.0 the following need to hold: the public surface stable across two
  consecutive minors, the record schema stable, the MCP integration shipped,
  and a deprecation policy in force (one minor of warning before removal).

## Documentation

The full documentation is at
[docs.deconvolutelabs.com](https://docs.deconvolutelabs.com/docs), covering the
[threat model](https://docs.deconvolutelabs.com/docs/concepts/threat-model),
[policies](https://docs.deconvolutelabs.com/docs/concepts/policies),
[identity](https://docs.deconvolutelabs.com/docs/concepts/identity),
[testing](https://docs.deconvolutelabs.com/docs/guides/testing), and the
[API reference](https://docs.deconvolutelabs.com/docs/reference/api). Read the
threat model before adopting it: Interbolt is not a prompt-injection
classifier, a content filter, or a sandbox, and that page lists exactly what it
does and does not cover.

Contributors should start with [ARCHITECTURE.md](ARCHITECTURE.md). To report a vulnerability, see
[SECURITY.md](SECURITY.md).

## License

Apache-2.0. Built by [Deconvolute Labs](https://deconvolutelabs.com).
