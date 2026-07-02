# Auditing

The audit is the in-process answer to the propagation gap described in
[Taint propagation](../concepts/taint-propagation.md): it finds the places
where a transformation (an f-string, a `.format()` call, a `join`) laundered
a label that you forgot to re-`taint`.

## Wiring it in

```python
from interbolt import configure, Policy

runtime = configure(
    policy=Policy.from_file("policy.yaml"),
    mode="dry_run",
    audit=True,
)

# Drive your own agent through your own workload: a test, a recorded
# scenario, a staging run. Interbolt instruments the run; you drive it.
await run_my_agent(test_inputs)

findings = runtime.audit_findings()
```

Or assert on findings through `InMemoryReporter`, the same as for decisions
(see [Testing](testing.md)):

```python
reporter = InMemoryReporter()
runtime = configure(policy=..., reporter=reporter, audit=True)
...
assert reporter.findings == []
```

`INTERBOLT_AUDIT=1` (or `true`/`yes`/`on`) overrides the `audit=` argument
to `configure()`, as an environment escape hatch.

## Mechanism

When `audit` is enabled, the runtime keeps a per-run registry of the string
content of values that passed through `taint()` and resolve to an untrusted
source. At each guarded sink, every argument that arrives as a **plain
`str`** (recursing into containers, to the same bounded depth as label
collection) is scanned for substrings matching content in that run's
registry, above a minimum length
(`interbolt.constants.AUDIT_MIN_MATCH_LENGTH`, 12 characters by default). A
match means untrusted content reached the sink with no label: a laundering
point. The registry is cleared when the owning `agent_context` exits.

Each `Finding` names the source that leaked and the argument it leaked
into:

```python
class Finding(BaseModel, frozen=True):
    schema_version: int
    source: str       # the source whose content leaked
    tool: str          # the qualified sink it leaked into
    argument: str       # the argument name it leaked into
    agent_id: str
    run_id: str
    session_id: str | None
    timestamp: datetime
```

## Properties

- **Advisory only.** Findings are emitted, not enforced.
- **Orthogonal to mode.** Audit can run under `enforce`, `monitor`, or
  `dry_run`. The natural pairing is `dry_run`: compute decisions, block
  nothing, surface leaks. A staging environment may run `enforce` with
  audit on and accept the extra cost.
- **Off by default, real cost when on.** The registry and rescan cost real
  memory and CPU, outside the sub-millisecond enforcement budget `check()`
  otherwise targets. Enabling it in production is fine if you accept that
  overhead.
- **Emitted through the existing `Reporter` seam.** No separate delivery
  mechanism, no separate CLI command. Assert on findings in a test with
  `InMemoryReporter`; route them to logs with `LoggingReporter`.

## What it catches

The audit catches **mechanical** laundering (untrusted bytes that
literally survive into a sink argument: an f-string, `format`, `join`,
slice-then-reassemble), not **semantic** laundering, where a model
paraphrases the text first. See
[Taint propagation](../concepts/taint-propagation.md#the-honest-summary)
for why that limit is structural, not a bug to fix.

The audit raises the floor on developer-introduced leaks. For
model-mediated laundering, the mitigation is re-`taint`ing at every
agent-to-agent or model-generation boundary (see
[Identity: multi-agent and handoffs](../concepts/identity.md#multi-agent-and-handoffs)).
