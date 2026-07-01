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
from interbolt import configure, taint, Policy, PolicyViolation, Tainted

runtime = configure(policy=Policy.from_file("policy.yaml"))
agent = runtime.agent("support-agent")

@agent.guard
def send_email(to: str, body: str) -> None:
    ...

# web_search returns a plain str. taint() on a str returns a Tainted, which
# is a str subclass, so it is accepted anywhere a str is expected with no
# change to send_email's signature.
summary: Tainted = taint(web_search("..."), source="web_search")

# body: str accepts the Tainted str; the policy still sees the provenance label
# at the call boundary.
try:
    send_email(to="attacker@external.com", body=summary)
except PolicyViolation as e:
    print(e.decision.matched_rule)   # "block_untrusted_exfil"
```

Generate a starter policy with `interbolt init`, then check it in CI with `interbolt validate policy.yaml`. If you call `configure()` without a policy, interbolt uses a built-in default-deny posture (no sources, no sinks, every call requires approval) and logs a warning pointing to `interbolt init`.

## What propagates, and what does not

Provenance is a set of source names attached to a value. Trust is resolved at the sink by looking each source up in your policy, so the same file governs both ingress trust and egress gating.

The label survives **direct passing** of a value to a tool argument and **operator-style combination** (`+`, `%`, slicing, and string methods called on a tainted value). It does **not** survive the common string-assembly constructs: f-strings with surrounding text, `str.format`, and `" ".join(...)` on a plain separator all produce a fresh string with no label. For those, re-`taint` the result by hand, which is the documented escape hatch. The same applies across a model-mediated agent-to-agent handoff: one agent's generated output reaches the next as plain, unlabeled text, so re-`taint` it at the boundary.

This is a deliberate, honest limit of an in-process string-subclass carrier, stated in full in the [propagation contract](docs/concepts/taint-propagation.md). To find the places where a transformation laundered a label that should have been re-tainted, run the audit (below).

## Modes and the audit

`configure(mode=...)` sets enforcement behavior:

- `enforce` (default): fails closed. An evaluation error is treated as a block.
- `monitor`: fails open on evaluation error and logs it; real blocks still block. An adoption on-ramp.
- `dry_run`: computes and emits every decision but blocks nothing. Test a new policy against live traffic.

`configure(audit=True)` turns on the laundering audit, an in-process instrument orthogonal to the mode. It watches a real run and reports where untrusted content reached a sink without a label, which is how you catch a forgotten re-`taint`. It catches mechanical laundering (the bytes survive into the argument); it cannot catch a model summarizing or paraphrasing the untrusted text first. Findings come out through the reporter, so you assert on them in a test with `InMemoryReporter`.

`interbolt validate policy.yaml` is static analysis only: it checks the schema, compiles every CEL expression, and rejects ambiguous dotted names, dead rules, and references to trifecta legs this version cannot compute. It never runs your agent, so it fits CI and pre-commit.

`interbolt init` writes an editable starter policy to the current directory (or a path you supply). It refuses to overwrite an existing file.

## MCP

`interbolt[mcp]` provides `wrap_session`, which adapts an MCP client session: the namespace becomes the server name, tool outputs are tainted as untrusted by default, and calls route through the policy. No core dependency, no rewrite of your tool logic.

## Documentation

See [`docs/`](docs/index.md) for [policies](docs/concepts/policies.md), the [propagation contract](docs/concepts/taint-propagation.md), [identity and namespacing](docs/concepts/identity.md), [testing](docs/guides/testing.md), [auditing](docs/guides/auditing.md), and the [API reference](docs/reference/api.md).

## License

Apache-2.0. Built by [Deconvolute Labs](https://deconvoluteai.com).
