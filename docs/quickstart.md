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
(`constants.DEFAULT_AGENT_ID`).

### Durable per-agent handles

For a function that always belongs to one fixed agent, or for guarded calls
**offloaded to a thread pool** (where `agent_context` can't reach the call),
bind the agent at decoration time instead, with `runtime.agent(...)`:

```python
agent = runtime.agent("support-agent")

@agent.guard
def send_email(to: str, body: str) -> None:
    ...

send_email(to="attacker@external.com", body=summary)
```

`@agent.guard` behaves identically to `@guard` (same taint collection, same
`check()` call, same `allow`/`block`/`require_approval` handling); the only
difference is where `agent_id` comes from. The two patterns compose in the
same codebase. See [Identity](concepts/identity.md) for the full binding
model, including the thread-offload limit.

## Next steps

- [Policies](concepts/policies.md): rule structure, evaluation order, the CEL
  context.
- [Testing](guides/testing.md): assert on decisions with `InMemoryReporter`.
- [Auditing](guides/auditing.md): find forgotten re-`taint` calls.
- [API reference](reference/api.md): every public name.
