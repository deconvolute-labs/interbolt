# Interbolt

**Provenance-gated tool calls for AI agents.**

[![PyPI version](https://img.shields.io/pypi/v/interbolt.svg)](https://pypi.org/project/interbolt/)
[![Python versions](https://img.shields.io/pypi/pyversions/interbolt.svg)](https://pypi.org/project/interbolt/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/deconvolute-labs/interbolt/ci.yml?branch=main)](https://github.com/deconvolute-labs/interbolt/actions)

Mark untrusted data where it enters an agent. Interbolt propagates that mark through your code and evaluates a YAML+CEL policy at each guarded tool call, returning allow, block, or require-approval based on the provenance of the call's arguments. Decisions are deterministic and in-process: no model, no network calls.

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

## Propagation

Provenance is a set of source names attached to a value. Trust is resolved at the sink by looking each source up in your policy, so the same file governs both ingress trust and egress gating.

The label survives **direct passing** of a value to a tool argument and **operator-style combination** (`+`, `%`, slicing, and string methods called on a tainted value). Common string-assembly constructs (f-strings with surrounding text, `str.format`, `" ".join(...)` on a plain separator) produce a fresh, unlabeled string; re-`taint` the result by hand in those cases. The same applies across a model-mediated agent-to-agent handoff: one agent's generated output reaches the next as plain, unlabeled text, so re-`taint` it at the boundary.

This is an inherent limit of an in-process string-subclass carrier; see the full [propagation contract](docs/concepts/taint-propagation.md). Run the audit (below) to find a transformation that should have been re-tainted.

## Modes and the audit

`configure(mode=...)` sets enforcement behavior:

- `enforce` (default): fails closed. An evaluation error is treated as a block.
- `monitor`: fails open on evaluation error and logs it; real blocks still block. An adoption on-ramp.
- `dry_run`: computes and emits every decision but blocks nothing. Test a new policy against live traffic.

`configure(audit=True)` turns on the laundering audit, an in-process instrument orthogonal to the mode. It watches a real run and reports where untrusted content reached a sink without a label, which is how you catch a forgotten re-`taint`. It catches mechanical laundering, not a model paraphrasing the text first; see the [propagation contract](docs/concepts/taint-propagation.md) for the full picture. Findings come out through the reporter, so you assert on them in a test with `InMemoryReporter`.

`interbolt validate policy.yaml` performs schema and CEL checks only, so it's safe for CI and pre-commit without running your agent. See [policies](docs/concepts/policies.md) for the full list of checks.

`interbolt init` writes an editable starter policy to the current directory (or a path you supply). It refuses to overwrite an existing file.

## Reporting

`Reporter` is the seam for decision output: blocked, approval required, allowed, and why (`Decision.untrusted_sources` names the specific source that drove a block). `NullReporter` (default), `InMemoryReporter`, `LoggingReporter`, `JsonlReporter`, and `CompositeReporter` (fan-out to more than one) ship out of the box; `describe_event`/`describe_finding` format a record for a human. See [reporters](docs/reference/reporters.md) for the full reference, including a recipe for a quiet-by-default console reporter for your own CLI.

## MCP

An `interbolt[mcp]` extra is planned to adapt an MCP client session directly. Until it ships, gate an MCP router today by calling `check()` (or `runtime.check()`) before each tool dispatch and `taint()`-ing tool results as they come back. See [MCP](docs/guides/mcp.md) for the pattern and the intended design.

## Documentation

See [`docs/`](docs/index.md) for [policies](docs/concepts/policies.md), the [propagation contract](docs/concepts/taint-propagation.md), [identity and namespacing](docs/concepts/identity.md), [testing](docs/guides/testing.md), [auditing](docs/guides/auditing.md), [reporters](docs/reference/reporters.md), and the [API reference](docs/reference/api.md).

## License

Apache-2.0. Built by [Deconvolute Labs](https://deconvoluteai.com).
