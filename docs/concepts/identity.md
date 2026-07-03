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
from interbolt import agent, configure

runtime = configure(policy=..., reporter=..., mode="enforce")

# Explicit per-agent handle (identity known at decoration time).
support = agent("support-agent")
billing = agent("billing-agent")

@support.guard
async def send_email(to: str, body: str) -> None: ...

@billing.guard
def issue_refund(amount: float) -> None: ...

# Context-bound identity (identity known only at call time).
async with runtime.agent_context("support-agent"):
    await run_turn(...)   # guarded calls inside pick up "support-agent"
```

The two compose: `agent(...)` returns an `AgentHandle` carrying the durable
`agent_id`; `runtime.agent_context(...)` binds the current agent via a
`contextvars.ContextVar` for the duration of an `async with` block, and
mints that block's `run_id`. A synchronous counterpart,
`runtime.agent_context_sync(...)`, binds and cleans up identically for a
call site that cannot use `async with`.

`agent(...)` is a module-level function, not a method: it needs no
`Runtime` instance, so it is the natural way to define a codebase's agent
identities in one module (`agents.py`) and import them into whichever
module defines the tools each agent owns (`tools.py`), regardless of import
order relative to `configure()`. `runtime.agent(...)` (a method on the
object `configure()` returns) delegates to the exact same lazily-resolving
implementation; it is kept only for discoverability when a `Runtime`
instance is already in hand.

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
time. `agent("id")` (and `runtime.agent("id")`, equivalent) captures the
`agent_id` string eagerly (safe at import, needing no `Runtime` instance)
but also resolves the runtime lazily through the same mechanism.

A module decorated with `@handle.guard` can be imported before `configure()`
has run; only the first *call* needs a configured runtime. Calling a guarded
function before any `configure()` call raises `InterboltUsageError`.
Re-`configure()` (the standard test recipe; see
[Testing](../guides/testing.md)) rebinds the process-current runtime
cleanly, with no stale capture, because every lazily-resolving decorator,
including a handle obtained from `agent(...)` before that `configure()`
call, picks up whichever runtime is current on its next call.

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

`agent_context`/`agent_context_sync` are built on `contextvars.ContextVar`,
which stays on the calling task's context and doesn't reach a thread pool.
Guarded tool calls dispatched to a thread pool lose the context-bound agent
and run identity inside those threads; bare `@guard` calls there fall back
to `DEFAULT_AGENT_ID` with a fresh `run_id` each. The eager `agent("id")`
handle carries `agent_id` explicitly instead of reading the contextvar, so
it works across threads and is the recommended form for offloaded tool
calls. It carries only `agent_id`, though, not `run_id`: a `taint()` call
inside an offloaded thread still finds no active run, so that ingress stays
invisible to `run.tainted` for the run it should have contributed to (see
[Policies: run-level gating](policies.md#run-level-gating-run-tainted)). If
each thread enters its **own** `agent_context_sync` block at the start of
its own work, this is not a problem: a spawned OS thread gets its own,
independent `contextvars.Context`, so identity set inside that thread's own
block is isolated from every other thread's, the same isolation
`agent_context` already gives concurrent `asyncio` tasks. The limit above
applies specifically to identity bound in the *dispatching* thread before
handing work to the pool, which a spawned thread never sees.

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
handoff = taint(agent_a_output, source="agent_a", derived_from=[agent_a_inputs...])
```

Passing `derived_from` makes the re-taint trust-aware instead of
unconditional: `handoff` resolves untrusted only if one of agent A's own
inputs did, rather than being marked untrusted regardless. Omitting
`derived_from` (`taint(agent_a_output, source="agent_a")`) still works and is
the coarser, always-safe form: the whole output is marked as agent A's own
fresh source, unconditionally, useful when the input labels aren't
conveniently in scope at the handoff point. Either way this is still the
manual, value-level mechanism; it is not automatic (interbolt never inspects
or paraphrase-detects the model's own text), and it is not the deferred
agent-boundary contamination model (see
[Deferred features](../design/deferred.md#agent-boundary-provenance)). See
[Taint propagation](taint-propagation.md#model-calls-and-derived-values) for
the underlying mechanism, and the quickstart's
[model tracking section](../quickstart.md#track-data-into-and-out-of-a-model-call)
for the equivalent, more ergonomic `track_model_call` decorator for the
common "wrap a model/LLM call" shape of this same pattern.
