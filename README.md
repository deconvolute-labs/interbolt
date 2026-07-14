# Interbolt

**Provenance-gated tool calls for AI agents.**

[![PyPI version](https://img.shields.io/pypi/v/interbolt.svg)](https://pypi.org/project/interbolt/)
[![Python versions](https://img.shields.io/pypi/pyversions/interbolt.svg)](https://pypi.org/project/interbolt/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/deconvolute-labs/interbolt/ci.yml?branch=main)](https://github.com/deconvolute-labs/interbolt/actions)

Mark untrusted data where it enters an agent. Interbolt propagates that mark through your code and evaluates a YAML+CEL policy at each guarded tool call, returning allow, block, or require-approval based on the provenance of the call's arguments. Decisions are deterministic and in-process: no model, no network calls, and `check()` overhead measures about 0.13 ms per call (see [performance](docs/reference/performance.md)).

When code has actually validated untrusted data, `endorse()` lets it say so without erasing the taint: provenance-preserving, policy-visible, and never model-triggered (see [auditing](docs/guides/auditing.md#endorsement)).

## Design lineage

The architecture assembles proven patterns rather than inventing new mechanisms:

- **Enforcement core**, modeled on [Casbin](https://casbin.org/): a pure `check()` entrypoint, analogous to Casbin's `enforce()`.
- **Reporting**, modeled on [OpenTelemetry](https://opentelemetry.io/): an inert-by-default public surface with swappable reporter implementations behind a protocol.
- **Taint carrier**, modeled on Django's `SafeString` / MarkupSafe: a `str`/`bytes` subclass that propagates a **provenance set**, resolving trust late at the sink, rather than a two-state lattice that degrades on contact.
- **Endorsement**, modeled on Resin (Yip et al., SOSP 2009): an explicit, auditable primitive that reduces a value's restrictiveness under a named policy, distinct from the tracking mechanism itself.

See [the docs](docs/index.md#design-lineage) for the full comparison.

## Quick start

```bash
pip install interbolt
```

```python
from interbolt import configure, guard, taint, Policy, PolicyViolation, Tainted
import asyncio

runtime = configure(policy=Policy.from_file("policy.yaml"))

@guard
def send_email(to: str, body: str) -> None:
    ...

# web_search returns a plain str. taint() on a str returns a Tainted, which
# is a str subclass, so it is accepted anywhere a str is expected with no
# change to send_email's signature.
summary: Tainted = taint(web_search("..."), source="web_search")

# body: str accepts the Tainted str; the policy still sees the provenance label
# at the call boundary. agent_context binds the acting agent's identity for
# guarded calls made inside the block.
async def main() -> None:
    async with runtime.agent_context("support-agent"):
        try:
            send_email(to="attacker@external.com", body=summary)
        except PolicyViolation as e:
            print(e.decision.matched_rule)   # "block_untrusted_exfil"

asyncio.run(main())
```

Generate a starter policy with `interbolt init`, then check it in CI with `interbolt validate policy.yaml`. If you call `configure()` without a policy, interbolt uses a built-in default-deny posture (no sources, no sinks, every call requires approval) and logs a warning pointing to `interbolt init`.

## Getting the evaluation result

`check()`/`guard` always compute a `Decision`, whether the call is allowed, blocked, or needs approval. On `allow` it's just the return value of `check()`; on `block`/`require_approval` it's attached to the raised exception:

```python
from interbolt import ApprovalDenied, PolicyEvaluationError, PolicyViolation

try:
    send_email(to="attacker@external.com", body=summary)
except (PolicyViolation, ApprovalDenied, PolicyEvaluationError) as e:
    decision = e.decision              # every decision-outcome error carries one
    decision.action                    # Action.BLOCK
    decision.matched_rule              # "block_untrusted_exfil", or None for the sink's default action
    decision.matched_condition         # the rule's actual CEL text, or None for the catch-all/no-match
    decision.untrusted_sources         # frozenset({"web_search"}) - exactly which source(s) caused this
```

For a ready-made human summary instead of assembling one from those fields by hand, use `describe_decision`. Like `describe_event`/`describe_finding` (below), it returns a rich-markup-tagged string, meant to be printed through a `rich.console.Console`, not a bare `print()`:

```python
from rich.console import Console
from interbolt import describe_decision

console = Console()
console.print(describe_decision(decision))
# one line (wrapped here for width):
# default.send_email  block  rule=block_untrusted_exfil
#   when='taint.any(t, t.trust == "untrusted") && args.to.endsWith("@external.com")'
#   mode=enforce  untrusted_sources={web_search}
```

`describe_decision` is the fastest way to log or display *why* a call was gated: which rule matched, the condition it evaluated, and which contributing source(s) resolved untrusted. Calling `check()` directly (rather than through `@guard`) returns the `Decision` for every outcome, including `allow`, so you can inspect or log it unconditionally instead of only on the exception path.

## Propagation

Provenance is a set of source names attached to a value. Trust is resolved at the sink by looking each source up in your policy, so the same file governs both ingress trust and egress gating.

The label survives **direct passing** of a value to a tool argument and **operator-style combination** (`+`, `%`, slicing, and string methods called on a tainted value). Common string-assembly constructs (f-strings with surrounding text, `str.format`, `" ".join(...)` on a plain separator) produce a fresh, unlabeled string; re-`taint` the result by hand in those cases. The same applies across a model-mediated agent-to-agent handoff: one agent's generated output reaches the next as plain, unlabeled text, so re-`taint` it at the boundary.

This is an inherent limit of an in-process string-subclass carrier; see the full [propagation contract](docs/concepts/taint-propagation.md). Run the audit (below) to find a transformation that should have been re-tainted.

## The model as a new source

A call into an LLM is exactly this kind of boundary: whatever the model emits carries no label, even when its prompt or context was tainted. `taint(..., derived_from=...)` marks a value as derived from other values instead of as a fresh ingress point, so trust is inherited rather than assumed:

```python
from interbolt import taint, track_model_call

# The model call's return value is automatically tainted, derived from its
# bound arguments: trusted only if every tainted argument was, untrusted if
# any one of them was. An argument that was never tainted (a plain str) is
# trusted by construction, same as everywhere else in interbolt.
@track_model_call(source="model")
def summarize(web_result: str, internal_result: str) -> str:
    return llm_client.complete(f"Summarize: {web_result}\n{internal_result}")

summary = summarize(
    taint(web_search("..."), source="web_search"),      # untrusted
    taint(read_kb("..."), source="internal_kb"),        # trusted
)
summary.label.source    # "model" - the derivation hop, for tracing
summary.label.lineage   # ("web_search", "internal_kb") - the real upstream sources
```

Passing `summary` on to a guarded sink resolves trust from `lineage` exactly as if the original inputs had reached that sink directly: untrusted here, since `web_search` was. The same primitive is the trust-aware upgrade to the manual agent-handoff pattern above: `taint(agent_a_output, source="agent_a", derived_from=[agent_a_inputs...])`. Neither is automatic (the model's own text is never inspected or paraphrase-detected); both are the explicit, low-effort way to keep provenance flowing across a boundary that would otherwise launder it. See [taint propagation](docs/concepts/taint-propagation.md) for the full contract.

## Modes and the audit

`configure(mode=...)` sets enforcement behavior:

- `enforce` (default): fails closed. An evaluation error is treated as a block.
- `monitor`: fails open on evaluation error and logs it; real blocks still block. An adoption on-ramp.
- `dry_run`: computes and emits every decision but blocks nothing. Test a new policy against live traffic.

`configure(audit=True)` turns on the laundering audit, an in-process instrument orthogonal to the mode. It watches a real run and reports where untrusted content reached a sink without a label, which is how you catch a forgotten re-`taint`. It catches mechanical laundering, not a model paraphrasing the text first; see the [propagation contract](docs/concepts/taint-propagation.md) for the full picture. Findings come out through the reporter, so you assert on them in a test with `InMemoryReporter`.

`interbolt validate policy.yaml` performs schema and CEL checks only, so it's safe for CI and pre-commit without running your agent. See [policies](docs/concepts/policies.md) for the full list of checks.

`interbolt init` writes an editable starter policy to the current directory (or a path you supply). It refuses to overwrite an existing file.

## Reporting

`Reporter` is the seam for decision output: blocked, approval required, allowed, and why (`Decision.untrusted_sources` names the specific source that drove a block). `NullReporter` (default), `InMemoryReporter`, `LoggingReporter`, `JsonlReporter`, and `CompositeReporter` (fan-out to more than one) ship out of the box; `describe_event`/`describe_finding`/`describe_decision` format a record for a human. See [reporters](docs/reference/reporters.md) for the full reference, including a recipe for a quiet-by-default console reporter for your own CLI.

## MCP

An `interbolt[mcp]` extra is planned to adapt an MCP client session directly. Until it ships, gate an MCP router today by calling `check()` (or `runtime.check()`) before each tool dispatch and `taint()`-ing tool results as they come back. See [MCP](docs/guides/mcp.md) for the pattern and the intended design.

## Documentation

See [`docs/`](docs/index.md) for [policies](docs/concepts/policies.md), the [propagation contract](docs/concepts/taint-propagation.md), [identity and namespacing](docs/concepts/identity.md), [testing](docs/guides/testing.md), [auditing](docs/guides/auditing.md), [reporters](docs/reference/reporters.md), and the [API reference](docs/reference/api.md).

## License

Apache-2.0. Built by [Deconvolute Labs](https://deconvoluteai.com).
