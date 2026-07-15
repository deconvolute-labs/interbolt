# OpenTelemetry

Already instrumenting your agent with OpenTelemetry? Add `OTelReporter` next
to your existing instrumentation and Interbolt's decisions show up as span
events inside the traces you already have:

```python
from interbolt import OTelReporter, Policy, configure

runtime = configure(policy=Policy.from_file("policy.yaml"))
runtime.add_reporter(OTelReporter())

# elsewhere, inside a span your own instrumentation already opened:
with tracer.start_as_current_span("handle_request"):
    send_email(to=..., body=...)  # a guarded call inside the span
```

## What appears in the trace

When a guarded call happens inside a **recording span** (the common case —
your framework or app already wraps the request, turn, or tool dispatch),
the decision, finding, or endorsement is added to that span as an event
named `interbolt.decision`, `interbolt.finding`, or `interbolt.endorsement`,
carrying `interbolt.*`-namespaced attributes (tool, action, matched rule,
mode, sources; see the [full mapping table](../reference/events.md#opentelemetry-attribute-mapping)).
No new span is created; the decision rides inside the span your own code
already started.

## No span active, or no provider configured

With no recording span active, `OTelReporter` opens and immediately closes a
small span of its own (named the same way), so the decision is still
exported as a span, not silently dropped. If no `TracerProvider` is
configured at all, this is a no-op by OpenTelemetry's own design — nothing
is exported, and no error is raised. Either way, `OTelReporter` never blocks
or delays a decision: attaching a span event is an in-memory operation, not
I/O.

`interbolt[otel]` depends only on `opentelemetry-api`; wiring an actual
exporter (OTLP, console, or otherwise) is your own OpenTelemetry SDK setup,
unrelated to Interbolt.
