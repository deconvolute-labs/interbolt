# For Phoenix / OpenTelemetry users

Interbolt borrows the OpenTelemetry provider shape on purpose: a setup call
that returns a provider, a factory method that hands back a per-caller
handle, a decorator family, and an extension point for attaching output
processors after the fact. If you have already instrumented an agent with
Phoenix or plain OpenTelemetry, the setup, factory, and decorator patterns
below are the ones you already know. What differs is what the primitives
do once you call them: OpenTelemetry observes execution and records what
happened; Interbolt gates execution and decides, before the call runs,
whether it is allowed to happen at all.

## The mapping

| Phoenix / OpenTelemetry | Interbolt |
| --- | --- |
| `register(...)` returns a tracer provider | `configure(...)` returns a `Runtime`, not named `register` because it configures an enforcement authority with a policy, not an attachment to a collector |
| `provider.get_tracer(name)` | `agent(agent_id)` or `runtime.agent(agent_id)`, returning a durable per-agent handle bound to an identity rather than a tracer bound to a module name |
| `provider.add_span_processor(...)` | `runtime.add_reporter(...)` |
| `trace.get_tracer_provider()` | `get_runtime()` |
| `@tracer.tool`, `@tracer.llm` decorators | `@handle.guard`, `@handle.track_model_call`; `@handle.guard` runs before the call and can raise, unlike any OTel decorator (see "Where Interbolt intentionally differs" below) |
| `using_session(...)` context manager | `agent_context(...)` / `agent_context_sync(...)`, which binds an identity that changes enforcement outcomes for the run, not just an attribute attached to spans |
| `OTEL_*` / `PHOENIX_*` env vars | `INTERBOLT_*` env vars (`INTERBOLT_MODE`, `INTERBOLT_AUDIT`, `INTERBOLT_RECURSION_DEPTH`) |
| In-memory exporter for tests | `InMemoryReporter` |
| Spans in your collector | `OTelReporter` (span events inside your existing traces; `interbolt[otel]` extra) |

## Side by side

A tool instrumented with Phoenix, the way you would already write it:

```python
from phoenix.otel import register

tracer_provider = register(project_name="support-agent")
tracer = tracer_provider.get_tracer(__name__)


@tracer.tool
def send_email(to: str, body: str) -> None:
    ...


send_email(to="user@example.com", body=summary)
```

The same tool, with Interbolt's gate added on top of the existing Phoenix
instrumentation, using the packaged starter policy:

```python
from interbolt import OTelReporter, Policy, configure

runtime = configure(policy=Policy.from_file("policy.yaml"))
runtime.add_reporter(OTelReporter())
support = runtime.agent("support-agent")


@tracer.tool
@support.guard
def send_email(to: str, body: str) -> None:
    ...


send_email(to="user@example.com", body=summary)
```

`@tracer.tool` stays outermost, so its span is already open and recording
by the time `@support.guard` calls `check()`. `OTelReporter` then attaches
the resulting decision as an event on that same span, so the Phoenix trace
and the Interbolt decision live in one place with no separate exporter to
configure. See [What appears in the trace](otel.md#what-appears-in-the-trace)
for the exact event shape.

## Where Interbolt intentionally differs

- **`@guard` is a gate, not an observer.** It evaluates policy before the
  wrapped call executes and raises `PolicyViolation` on block. No OTel
  decorator alters control flow; this one exists to.
- **No `uninstrument()`, no reporter removal, no mutable policy or mode on
  a live runtime.** Detaching an observability instrument is harmless;
  silently detaching a security gate is an attack primitive. Enforcement
  inputs change only through a new `configure()` call.
- **Fail-closed by default.** Under `Mode.ENFORCE`, an evaluation error
  blocks rather than proceeds. Observability tooling fails open by design;
  an enforcement layer must not.

## Next

See [OpenTelemetry](otel.md) for the full reporter wiring detail, including
what happens with no recording span active or no provider configured at
all, and [Events](../reference/events.md) for the versioned record schema
and the complete OpenTelemetry attribute mapping.
