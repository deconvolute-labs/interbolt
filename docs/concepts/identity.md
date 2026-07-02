# Identity

Every `Decision` and every emitted `Event` carries an identity triple:

- `agent_id`: durable, integrator-supplied, stable across runs. Required.
- `run_id`: ephemeral, minted by the runtime. Bound once per run at
  `agent_context` entry, not per guarded call, so a run is a single unit in
  the audit trail. A guarded call made outside any `agent_context` gets a
  fresh `run_id` of its own.
- `session_id`: optional, integrator-supplied, spans multiple runs in a
  multi-turn conversation.

This covers single-agent, multi-agent, and multi-turn deployments without
rework: a multi-agent run shares one `run_id`, each agent stamps its own
`agent_id` as it acts, and `session_id` spans the whole conversation.

## Two ways to bind agent identity

```python
runtime = configure(policy=..., reporter=..., mode="enforce")

# Explicit per-agent handle (identity known at decoration time).
support = runtime.agent("support-agent")
billing = runtime.agent("billing-agent")

@support.guard
async def send_email(to: str, body: str) -> None: ...

@billing.guard
def issue_refund(amount: float) -> None: ...

# Context-bound identity (identity known only at call time).
async with runtime.agent_context("support-agent"):
    await run_turn(...)   # guarded calls inside pick up "support-agent"
```

The two compose: `runtime.agent(...)` returns an `AgentHandle` carrying the
durable `agent_id`; `runtime.agent_context(...)` binds the current agent via
a `contextvars.ContextVar` for the duration of an `async with` block, and
mints that block's `run_id`.

A guarded call made through the bare `@guard` decorator (not bound to a
specific `AgentHandle`) reads `agent_id` from the active `agent_context`,
falling back to `interbolt.constants.DEFAULT_AGENT_ID` (`"default"`) when no
`agent_context` is active. A call through `@handle.guard` always uses that
handle's `agent_id`, regardless of any active `agent_context`.

**`run_id` binding is broader than agent-identity binding.** Any guarded
call made during an active `agent_context`, whether through the bare
`@guard` or an explicit `@handle.guard`, picks up that block's `run_id`.
Only the *agent_id* differs between the bare and explicit forms, since a
single run may span multiple agents.

## Binding model: nothing captures the runtime at decoration time

`configure(...)` builds a `Runtime` and stores it as the process-current
runtime; there is one runtime per process. The bare `guard` and `check`
resolve the current runtime **lazily, at call time**, not at decoration
time. `runtime.agent("id")` captures the `agent_id` string eagerly (safe at
import) but also resolves the runtime lazily through the same mechanism.

A module decorated with `@handle.guard` can be imported before `configure()`
has run; only the first *call* needs a configured runtime. Calling a guarded
function before any `configure()` call raises `InterboltUsageError`.
Re-`configure()` (the standard test recipe; see
[Testing](../guides/testing.md)) rebinds the process-current runtime
cleanly, with no stale capture, because every lazily-resolving decorator
picks up whichever runtime is current on its next call.

`taint()` needs no `Runtime` instance at all and works before `configure()`
has run: it takes no `agent_id`, and reads container-recursion depth from
the shared `interbolt.constants.RECURSION_DEPTH` module constant. It does
conditionally read one ambient `ContextVar`, the same one `agent_context`
binds, to attribute ingress to the active run for run-level gating (see
[Policies: run-level gating](policies.md#run-level-gating-run-tainted)). If
none is active (always true before `configure()` runs, since
`agent_context` is a `Runtime` method), the read is a no-op plus a DEBUG
log, with no change to `taint()`'s core behavior.

## Thread offload limit

`agent_context` is built on `contextvars.ContextVar`, which stays on the
calling task's context and doesn't reach a thread pool. Guarded tool calls
dispatched to a thread pool lose the context-bound agent and run identity
inside those threads; bare `@guard` calls there fall back to
`DEFAULT_AGENT_ID` with a fresh `run_id` each. The eager `runtime.agent("id")`
handle carries `agent_id` explicitly instead of reading the contextvar, so
it works across threads and is the recommended form for offloaded tool
calls. It carries only `agent_id`, though, not `run_id`: a `taint()` call
inside an offloaded thread still finds no active run, so that ingress stays
invisible to `run.tainted` for the run it should have contributed to (see
[Policies: run-level gating](policies.md#run-level-gating-run-tainted)).

## `check()` and the contextvar

The framework-agnostic `check()` function (and `Runtime.check()`) takes
`agent_id` as a required keyword argument and `run_id` as an optional one,
always explicitly rather than from the `agent_context` contextvar. `guard`
is sugar over `check()` that reads the contextvar instead. A custom dispatch
loop that
calls `check()` directly inside an active `agent_context` should thread the
bound `run_id` through explicitly, or correlation will fragment one run into
many separate `run_id`s.

The same fragmentation risk applies to `run.tainted`. `taint()`'s run-ingress
recording always reads the ambient `agent_context` contextvar, not an
explicitly-threaded `run_id`. A dispatch loop that enters `agent_context`
but then calls `check()` with some *other* explicit `run_id` (rather than
the one `agent_context` minted) will see `run.tainted` permanently `false`:
`taint()` recorded ingress under the contextvar's run id, but `check()`
resolved it against a different one. To keep `run.tainted` working under a
custom dispatch loop, thread the contextvar's own value through explicitly
(`current_run_id.get()`, exposed via `interbolt.runtime.guard`), the same
value bare `guard` already reads automatically.

## Multi-agent and handoffs

Identity and attribution span agents today, through the mechanism above: a
shared `run_id`, per-agent `agent_id` stamps, and a spanning `session_id`.

Value-level taint is the exception: it doesn't span agents automatically. A
model-generated handoff between agents launders the label the same way any
model generation does (see
[Taint propagation](taint-propagation.md#boundaries-that-always-reset-to-untrusted-ingress)).
Re-`taint` an agent's output at the handoff boundary as a deliberate,
confused-deputy-safe default:

```python
handoff = taint(agent_a_output, source="agent_a")
```
