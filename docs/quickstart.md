# Quickstart

## Install

```bash
pip install interbolt
```

## Write a policy

Generate the starter policy with `interbolt init`, or write your own:

```bash
interbolt init                   # writes policy.example.yaml to the current directory
interbolt init my-policy.yaml    # or choose a path
```

A policy declares the trust level of every ingress source, and the rules each
guarded sink evaluates:

```yaml
version: "1.0"

defaults:
  source_trust: untrusted
  sink_action: require_approval
  fail_mode: enforce

sources:
  - name: web_search
    trust: untrusted
  - name: internal_kb
    trust: trusted

sinks:
  default.send_email:
    - name: block_untrusted_exfil
      when: taint.any(t, t.trust == "untrusted") && args.to.endsWith("@external.com")
      action: block
    - name: default
      action: require_approval
```

See [Policies](concepts/policies.md) for the full format and the CEL context
available inside `when`.

## Configure the runtime

```python
from interbolt import configure, Policy

runtime = configure(policy=Policy.from_file("policy.yaml"))
```

`configure()` compiles the policy and installs the result as the
process-current runtime. It has no import-time side effects: a module
decorated with `@guard` can be imported before `configure()` runs; only
calling the guarded function requires it. See [Identity](concepts/identity.md)
for the full binding model.

If you omit `policy`, interbolt loads the built-in default: no sources
declared, every guarded call falls through to `require_approval`. A warning is
logged naming the built-in default and pointing to `interbolt init`. This is
useful for trying the library before writing a real policy.

## Mark untrusted data at ingress

```python
from interbolt import taint, Tainted

def web_search(query: str) -> str:
    ...  # calls an external search API

summary: Tainted = taint(web_search("..."), source="web_search")
```

`taint()` returns a `Tainted`, a `str` subclass, so it is accepted anywhere a
plain `str` is expected with no change to a tool's signature. See
[Taint propagation](concepts/taint-propagation.md) for what survives a
transformation.

## Guard a tool call

Define tools with a bare `@guard`, no agent reference: this is the primary
pattern. Tools can live in their own module, decorated where they're
defined:

```python
# tools.py
from interbolt import guard

@guard
def send_email(to: str, body: str) -> None:
    ...
```

Bind the acting agent's identity separately, at the call site, with
`runtime.agent_context(...)`:

```python
# main.py
from interbolt import PolicyViolation
from tools import send_email

async def handle_request(agent_id: str) -> None:
    async with runtime.agent_context(agent_id):
        try:
            send_email(to="attacker@external.com", body=summary)
        except PolicyViolation as e:
            print(e.decision.matched_rule)   # "block_untrusted_exfil"
            print(e.decision.action)         # Action.BLOCK
```

`@guard` inspects the bound call arguments, collects every taint label
found (recursing into containers), and calls `check()` before the wrapped
function runs:

- `allow`: the call proceeds.
- `block`: raises `PolicyViolation`, carrying the `Decision` on `.decision`.
- `require_approval`: invokes the configured `ApprovalResolver`; if it
  returns `False` (or denies), raises `ApprovalDenied`.

`agent_context` binds `agent_id` in a `contextvars.ContextVar` for the
duration of the `async with` block, and mints one `run_id` shared by every
guarded call inside it. Because `ContextVar` state is isolated per `asyncio`
task, two agents running concurrently, each in its own `agent_context`
block, keep separate identities automatically, with no locking required. A
guarded call made outside any `agent_context` falls back to `"default"`
(`constants.DEFAULT_AGENT_ID`). For a synchronous call site, use
`runtime.agent_context_sync(...)` instead: identical binding and cleanup,
no `async with` required.

### Durable per-agent handles, across modules

For a function that always belongs to one fixed agent, or for guarded calls
**offloaded to a thread pool** (where `agent_context` can't reach the call),
bind the agent at decoration time instead, with `agent(...)`:

```python
# agents.py
from interbolt import agent

support = agent("support-agent")
billing = agent("billing-agent")
```

```python
# tools.py
from agents import support

@support.guard
def send_email(to: str, body: str) -> None:
    ...

send_email(to="attacker@external.com", body=summary)
```

`agent(...)` captures the `agent_id` eagerly (just a string) and resolves
the current runtime lazily at call time, the same way bare `@guard` does:
`agents.py` can be imported, and its handles decorated onto tools in other
modules, before `configure()` has run anywhere in the process. This is the
recommended pattern for a codebase with agents and tools spread across
several files: define the handles once, in one module, and import them
wherever a tool needs one. `runtime.agent(...)` (a method on the object
`configure()` returns) is equivalent, kept for discoverability.

`@support.guard` behaves identically to `@guard` (same taint collection, same
`check()` call, same `allow`/`block`/`require_approval` handling); the only
difference is where `agent_id` comes from. The two patterns compose in the
same codebase. See [Identity](concepts/identity.md) for the full binding
model, including the thread-offload limit.

## Track data into and out of a model call

An LLM call is the same kind of boundary as an agent handoff: whatever the
model emits carries no label, even when its prompt or retrieved context was
tainted. `track_model_call` closes that gap by tainting a function's return
value as derived from its own bound arguments:

```python
from interbolt import taint, track_model_call

@track_model_call(source="model")
def summarize(web_result: str, internal_result: str) -> str:
    return llm_client.complete(f"Summarize: {web_result}\n{internal_result}")

summary = summarize(
    taint(web_search("..."), source="web_search"),   # untrusted
    taint(read_kb("..."), source="internal_kb"),      # trusted
)
```

`summary` is trusted only if every tainted argument passed to `summarize`
was trusted, and untrusted if any one of them was; an argument that was
never tainted at all is trusted by construction, the same rule that applies
everywhere else in interbolt. `summary.label.source` names the derivation
hop (`"model"`), for tracing; `summary.label.lineage` still names the real
upstream sources (`("web_search", "internal_kb")`), so trust resolves at a
downstream sink exactly as if those sources had reached it directly.

This only tracks provenance; it does not evaluate policy. Stack `@guard`
alongside it if the call into the model itself should also be gated:

```python
@support.guard(tool="llm.summarize")
@track_model_call(source="model")
def summarize(web_result: str, internal_result: str) -> str:
    ...
```

The underlying primitive is `taint(value, source=..., derived_from=[...])`;
`track_model_call` is the ergonomic wrapper for the common "wrap a function
call" case. Calling `taint` directly with `derived_from` is also the
trust-aware upgrade to the manual multi-agent handoff pattern (see
[Identity: multi-agent and handoffs](concepts/identity.md#multi-agent-and-handoffs)).
See [Taint propagation](concepts/taint-propagation.md#model-calls-and-derived-values)
for the full contract.

## Get the decision, and why

`check()`/`guard` always compute a `Decision`. `check()` (and `Runtime.check`)
return it directly, for every outcome including `allow`; `@guard` attaches
it to the exception it raises on `block`/`require_approval`/an evaluation
failure:

```python
from interbolt import ApprovalDenied, PolicyEvaluationError, PolicyViolation

try:
    send_email(to="attacker@external.com", body=summary)
except (PolicyViolation, ApprovalDenied, PolicyEvaluationError) as e:
    decision = e.decision
    decision.action              # Action.BLOCK
    decision.matched_rule         # "block_untrusted_exfil", or None for the sink's default action
    decision.matched_condition    # the rule's actual CEL text, or None for the catch-all/no-match
    decision.untrusted_sources    # frozenset({"web_search"}) - exactly which source(s) caused this
```

For a ready-made human summary instead of assembling one from those fields,
use `describe_decision`. Like `describe_event`/`describe_finding`, it
returns a rich-markup-tagged string, meant for a `rich.console.Console`,
not a bare `print()`:

```python
from rich.console import Console
from interbolt import describe_decision

Console().print(describe_decision(decision))
# one line (wrapped here for width):
# default.send_email  block  rule=block_untrusted_exfil
#   when='taint.any(t, t.trust == "untrusted") && args.to.endsWith("@external.com")'
#   mode=enforce  untrusted_sources={web_search}
```

## Next steps

- [Policies](concepts/policies.md): rule structure, evaluation order, the CEL
  context.
- [Testing](guides/testing.md): assert on decisions with `InMemoryReporter`.
- [Auditing](guides/auditing.md): find forgotten re-`taint` calls.
- [API reference](reference/api.md): every public name.
