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

A reporter failure must never affect, delay, or block a decision. The
engine wraps every call to `export` and logs a warning on failure rather
than propagating the exception. This is a property of the engine's call
site; the **non-blocking** part of the contract is owned by the reporter
itself. The three shipped reporters below are non-blocking by construction.
A custom reporter that performs blocking I/O inside `export` blocks the
decision that triggered it, and that is the reporter author's
responsibility, not a guarantee the engine provides.

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
library logger does not configure the root logger and does not emit at
import; attach a handler to `"interbolt"` (or call
`interbolt.utils.get_logger()`) to see output.

## Writing a custom reporter

Any object with a matching `export(self, event: Event | Finding) -> None`
method satisfies the protocol; no base class is required
(`Reporter` is `@runtime_checkable`). For a reporter that does real I/O
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
