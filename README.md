# Interlock

**Provenance-gated tool calls for AI agents.**

[![PyPI version](https://img.shields.io/pypi/v/interlock.svg)](https://pypi.org/project/interlock/)
[![Python versions](https://img.shields.io/pypi/pyversions/interlock.svg)](https://pypi.org/project/interlock/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/deconvolute-labs/interlock/ci.yml?branch=main)](https://github.com/deconvolute-labs/interlock/actions)

Mark untrusted data where it enters an agent. interlock records its provenance, carries that provenance through your code, and evaluates a YAML+CEL policy at the tool-call boundary to allow, block, or require approval. Decisions are deterministic and local: no model in the loop, no network calls.

Interlock does not try to detect prompt injection. It gates where untrusted data is allowed to go, so the gate holds even when an upstream detector is bypassed. The decision is on data provenance and the sink, not on recognizing the attack.

## Quick start

```bash
pip install interlock
```

```python
from interlock import configure, taint, Policy, PolicyViolation, Tainted

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

A starter `policy.example.yaml` ships with the repo. Check policies in CI with `interlock validate policy.yaml`.

## What propagates, and what does not

Provenance is a set of source names attached to a value. Trust is resolved at the sink by looking each source up in your policy, so the same file governs both ingress trust and egress gating.

The label survives **direct passing** of a value to a tool argument and **operator-style combination** (`+`, `%`, slicing, and string methods called on a tainted value). It does **not** survive the common string-assembly constructs: f-strings with surrounding text, `str.format`, and `" ".join(...)` on a plain separator all produce a fresh string with no label. For those, re-`taint` the result by hand, which is the documented escape hatch.

This is a deliberate, honest limit of an in-process string-subclass carrier, stated in full in the [propagation contract](docs/concepts/taint-propagation.md). To find the places where a transformation laundered a label that should have been re-tainted, run the audit (below).

## Modes and the audit

`configure(mode=...)` sets enforcement behavior:

- `enforce` (default): fails closed. An evaluation error is treated as a block.
- `monitor`: fails open on evaluation error and logs it; real blocks still block. An adoption on-ramp.
- `dry_run`: computes and emits every decision but blocks nothing. Test a new policy against live traffic.

`configure(audit=True)` turns on the laundering audit, an in-process instrument orthogonal to the mode. It watches a real run and reports where untrusted content reached a sink without a label, which is how you catch a forgotten re-`taint`. It catches mechanical laundering (the bytes survive into the argument); it cannot catch a model summarizing or paraphrasing the untrusted text first. Findings come out through the reporter, so you assert on them in a test with `InMemoryReporter`.

`interlock validate policy.yaml` is static analysis only: schema, CEL compilation, source resolution, name ambiguity. It never runs your agent, so it fits CI and pre-commit.

## MCP

`interlock[mcp]` provides `wrap_session`, which adapts an MCP client session: the namespace becomes the server name, tool outputs are tainted as untrusted by default, and calls route through the policy. No core dependency, no rewrite of your tool logic.

## Documentation

See [`docs/`](docs/index.md) for [policies](docs/concepts/policies.md), the [propagation contract](docs/concepts/taint-propagation.md), [identity and namespacing](docs/concepts/identity.md), [testing](docs/guides/testing.md), [auditing](docs/guides/auditing.md), and the [API reference](docs/reference/api.md).

## License

Apache-2.0. Built by [Deconvolute Labs](https://deconvoluteai.com).
