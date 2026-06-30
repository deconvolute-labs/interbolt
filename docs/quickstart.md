# Quickstart

## Install

```bash
pip install interbolt
```

## Write a policy

Copy the starter [`policy.example.yaml`](../policy.example.yaml) shipped with
the repo, or write your own. A policy declares the trust level of every
ingress source, and the rules each guarded sink evaluates:

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
process-current runtime. It has no import-time side effects, so decorating a
module with `@guard` never requires `configure()` to have run first; only
calling the guarded function does. See [Identity](concepts/identity.md) for
the full binding model.

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
transformation and what does not.

## Guard a tool call

```python
from interbolt import PolicyViolation

agent = runtime.agent("support-agent")

@agent.guard
def send_email(to: str, body: str) -> None:
    ...

try:
    send_email(to="attacker@external.com", body=summary)
except PolicyViolation as e:
    print(e.decision.matched_rule)   # "block_untrusted_exfil"
    print(e.decision.action)         # Action.BLOCK
```

`@agent.guard` inspects the bound call arguments, collects every taint label
found (recursing into containers), and calls `check()` before the wrapped
function runs:

- `allow`: the call proceeds.
- `block`: raises `PolicyViolation`, carrying the `Decision` on `.decision`.
- `require_approval`: invokes the configured `ApprovalResolver`; if it
  returns `False` (or denies), raises `ApprovalDenied`.

The bare `@guard` decorator works the same way but picks up the agent
identity from an active `agent_context` (or `"default"` if none is active)
instead of a durable `AgentHandle`. See [Identity](concepts/identity.md).

## Next steps

- [Policies](concepts/policies.md): rule structure, evaluation order, the CEL
  context.
- [Testing](guides/testing.md): assert on decisions with `InMemoryReporter`.
- [Auditing](guides/auditing.md): find forgotten re-`taint` calls.
- [API reference](reference/api.md): every public name.
