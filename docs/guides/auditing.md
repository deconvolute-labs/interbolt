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

When `audit` is enabled, `configure()` installs an observer on `taint()`
itself, so content is registered the moment a value is tainted and resolves
to an untrusted source, attributed to the run active at that moment, not
only when a labeled value later reaches a sink. This is what catches the
common case where an f-string or `.format()` call launders the label away
before the value ever reaches a guarded call in labeled form. Sink-side
registration (from labeled arguments actually reaching a guard) still
happens too, as a complementary path, covering content whose label was
attached via a `derived_from` merge at the sink rather than at raw ingress.

At each guarded sink, every argument that arrives as a **plain `str`**
(recursing into containers, to the same bounded depth as label collection)
is scanned for substrings matching content in that run's registry, above a
minimum length (`interbolt.constants.AUDIT_MIN_MATCH_LENGTH`, 12 characters
by default). A match means untrusted content reached the sink with no
label: a laundering point. The registry is cleared when the owning
`agent_context` exits.

**A `taint()` call made with no active `agent_context` cannot be attributed
to a run and is invisible to the audit**, the same limitation `run.tainted`
has (see
[Policies: run-level gating](../concepts/policies.md#run-level-gating-run-tainted)).

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
- **Deduplicated per run.** At most one `Finding` is emitted per
  `(source, tool, argument)` combination per run; repeated identical calls
  in the same run do not produce repeated findings.

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

## Endorsement

Re-`taint`ing at every laundering point isn't the only way a developer
interacts with a tainted value: sometimes they've genuinely *validated* it —
checked a recipient against an allowlist, parsed and confirmed a URL — and
leaving the taint on just means every downstream sink blocks a value that's
already been vetted. Laundering it through an f-string "fixes" this, but at
the cost of making a deliberate validation indistinguishable from an
accidental leak: the audit above would flag it as a finding, and there'd be
no record that anyone looked at it.

`endorse()` is the sanctioned alternative:

```python
from interbolt import endorse, taint

recipient = taint(user_supplied_email, source="web_search")
if is_on_allowlist(recipient):
    recipient = endorse(recipient, kind="recipient_allowlisted",
                         note="checked against CRM export 2026-07-01")
send_email(to=recipient, body=...)
```

It is:

- **Provenance-preserving.** `lineage` is unchanged; `t.trust` still
  resolves exactly as it did before. Endorsement adds a fact, it doesn't
  erase one.
- **Sink-specific, by a required `kind`.** There's no bare "endorsed"
  boolean: a value confirmed to be a well-formed URL is not thereby
  confirmed to be a safe email recipient, and a policy names the exact kind
  a sink accepts (see
  [Policies: endorsement-aware rules](../concepts/policies.md#endorsement-aware-rules-tendorsements-require_endorsement)).
  An endorsement for the wrong kind still blocks — the sanitizer-mismatch
  case a boolean can't express.
- **Audited.** Every `endorse()` call emits an `Endorsement` record (`kind`,
  an optional free-text `note`, the identity triple, a timestamp) through
  the same reporter seam as `Event`/`Finding`, whenever a runtime is
  configured — unlike the laundering audit above, this isn't opt-in.
- **Never model-triggered.** Call `endorse()` only from deterministic code,
  immediately after a real validation step. Never call it because a model
  asked to, or based on model output: the model is the confused deputy this
  library defends against in the first place, and letting it also decide
  when its own restrictions lift would defeat the containment property from
  the inside.

`run.tainted` (above) is unaffected by endorsement: it's a coarse,
run-scoped signal by design, and a value-level fact must not clear it.
