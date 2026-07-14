# API reference

Everything re-exported from `interbolt` (the package `__init__.py`). This is
the public surface; anything not listed here is internal and may change
without notice.

```
taint, guard, check, configure, default_policy, agent, get_runtime, AgentHandle,
track_model_call, Runtime, Policy,
Decision, Event, Finding, Action, Mode, Label, TrustLevel,
Reporter, ApprovalResolver,
NullReporter, InMemoryReporter, LoggingReporter, JsonlReporter, CompositeReporter,
describe_decision, describe_event, describe_finding,
RECORD_TYPE_EVENT, RECORD_TYPE_FINDING,
InterboltError, PolicyViolation, PolicyEvaluationError, ApprovalDenied,
InterboltConfigError, InterboltUsageError,
Tainted, LabeledValue, TaintedBytes,
__version__
```

## `taint`

```python
def taint(value: Any, *, source: str, derived_from: Iterable[Any] | None = None) -> Any: ...
```

Marks `value` with a `Label` recording `source`. For `str` returns a
`Tainted`; for `bytes` returns a `TaintedBytes`; for a builtin container
(`list`, `tuple`, `set`, `frozenset`, a `Mapping`'s keys and values) recurses
and labels string leaves to the bounded recursion depth; for any other
scalar returns a `LabeledValue`. The label only records the source name;
trust is resolved later, at the sink. Needs no configured runtime. See
[Taint propagation](../concepts/taint-propagation.md).

`derived_from`, if given a non-empty iterable, marks `value` as **derived
from** those values instead of as a fresh ingress point: `source` becomes
the name of the derivation hop (for example `"model"`), and the returned
label's `lineage` is the union of every label found among `derived_from`,
so trust resolves at the sink exactly as if those original inputs had
reached it directly. If no label is found among `derived_from` at all,
`value` is returned completely unmarked. Does not record a run-level
ingress event for `source` in this case. See
[Taint propagation: model calls and derived values](../concepts/taint-propagation.md#model-calls-and-derived-values).

## `track_model_call`

```python
@track_model_call                      # source defaults to "model"
def summarize(prompt: str) -> str: ...

@track_model_call(source="gpt-4")      # explicit derivation-hop name
async def summarize(prompt: str) -> str: ...
```

Wraps a function so its return value is tainted via `taint(result,
source=source, derived_from=<the function's bound call arguments>)`.
Auto-detects sync vs async the same way `guard` does. Tracks provenance
only; does not evaluate policy, so stack `@guard`/`@handle.guard` alongside
it if the call into the model should also be gated. Needs no configured
runtime, the same as `taint()` itself. See
[Taint propagation: model calls and derived values](../concepts/taint-propagation.md#model-calls-and-derived-values).

## `guard`

```python
@guard                      # tool name defaults to the function name
def send_email(...): ...

@guard(tool="fs.write")     # explicit qualified or bare tool name
def write_file(...): ...
```

Decorates a function or coroutine function so every call is checked against
the current policy before it runs. Agent identity comes from the active
`agent_context`, falling back to `"default"`. Auto-detects whether it wraps
a coroutine function and returns the matching sync or async wrapper. On
`block` raises `PolicyViolation`; on `require_approval` invokes the
configured `ApprovalResolver`; on `allow` calls through. See
[Identity](../concepts/identity.md).

## `check`

```python
def check(
    *,
    tool: str,
    args: Mapping[str, Any],
    agent_id: str,
    run_id: str | None = None,
    session_id: str | None = None,
) -> Decision: ...
```

The framework-agnostic decision core; `guard` is sugar over this. Collects
labels from `args` (recursing into containers), evaluates the policy,
returns a `Decision`, and emits the corresponding `Event` through the
configured reporter. Both `agent_id` and `run_id` are explicit here, not
read from the `agent_context` contextvar. Requires `configure()` to have
run; raises `InterboltUsageError` otherwise. Use this directly for custom
dispatch loops or existing tool registries, instead of `guard`.

Policy testing is just `check()` invoked with synthetic args and taint,
asserted against the returned `Decision`; there's no separate `simulate`
function. See [Testing](../guides/testing.md).

## `configure`

```python
def configure(
    *,
    policy: Policy | None = None,
    reporter: Reporter | None = None,
    approval_resolver: ApprovalResolver = auto_deny,
    mode: Mode | str = Mode.ENFORCE,
    audit: bool = False,
) -> Runtime: ...
```

Builds a `Runtime`, installs it as the process-current runtime, and returns
it. Has no import-time side effects: a module decorated with `@guard` can
be imported before `configure()` has run. `policy` defaults to `None`,
which loads the built-in default policy (`default_policy()`, below):
no sources, no sinks, every guarded call falls through to
`require_approval`. `reporter` defaults to a fresh `NullReporter()`.
`approval_resolver` defaults to `auto_deny` (denies every approval
request). The effective `mode` is resolved from three sources, highest
precedence first: the `INTERBOLT_MODE` environment variable, the policy
file's `defaults.fail_mode`, then this `mode=` argument. `INTERBOLT_AUDIT`
overrides `audit`. Raises `InterboltConfigError` if the effective mode is
not a valid `Mode` value. Every call logs one WARNING-level summary line
(effective mode, policy source, source/sink counts, caller file:line),
independent of any configured `Reporter`. See
[Policies](../concepts/policies.md#modes-and-fail_mode).

## `default_policy`

```python
def default_policy() -> Policy: ...
```

Returns the built-in default policy for programmatic use and testing: the
same posture `configure(policy=None)` uses, exposed directly rather than
only implicitly.

## `agent`

```python
def agent(agent_id: str) -> AgentHandle: ...
```

Returns a durable per-agent handle whose `.guard` decorates with this
`agent_id`, resolved lazily at call time. Captures `agent_id` eagerly (a
plain string, safe to call at import time, before `configure()` has run)
and needs no `Runtime` instance, which is what makes it the natural way to
define a codebase's agent identities in one module and import the handles
into whichever module defines each agent's tools. Rebinds automatically
after a later `configure()` call, the same way bare `guard` does.
`runtime.agent(agent_id)` (a method on the object `configure()` returns) is
equivalent, kept for discoverability. See [Identity](../concepts/identity.md).

## `get_runtime`

```python
def get_runtime() -> Runtime: ...
```

Returns the process-current runtime, the `get_tracer_provider()` analog: for
code that didn't keep `configure()`'s return value (a different module, or
reaching for `Runtime.add_reporter` later). Raises `InterboltUsageError` if
`configure()` hasn't run yet.

## `AgentHandle`

The type returned by `agent(...)`/`runtime.agent(...)`. Exposes `.guard`,
usable bare (`@handle.guard`) or parameterized (`@handle.guard(tool=...)`),
behaving identically to the module-level `guard` except that `agent_id`
comes from the handle instead of the active `agent_context`. Also exposes
`.track_model_call`, equivalent to the module-level `track_model_call`
(above), provided for per-handle symmetry: `@support.guard` and
`@support.track_model_call` are both reachable from one handle. The
handle's agent identity plays no role in `.track_model_call`, since taint
derivation is identity-free.

## `Runtime`

The composition root returned by `configure()`. One per process.

- `runtime.agent(agent_id: str) -> AgentHandle`: equivalent to the
  module-level `agent(...)`, above.
- `runtime.agent_context(agent_id: str)`: an async context manager that
  binds `agent_id` and mints a `run_id` for the duration of the block. See
  [Identity](../concepts/identity.md).
- `runtime.agent_context_sync(agent_id: str)`: the synchronous counterpart;
  identical binding and cleanup, for a call site that cannot use
  `async with`.
- `runtime.check(*, tool, args, agent_id, run_id=None, session_id=None) -> Decision`:
  the same decision core as the module-level `check`, against this runtime
  explicitly.
- `runtime.reporter -> Reporter`: the `CompositeReporter` every decision and
  finding is emitted through (read-only; every `Runtime` holds one
  internally, even for a single `reporter=` passed to `configure()`). See
  [Reporters](reporters.md).
- `runtime.add_reporter(reporter: Reporter) -> None`: attaches an
  additional reporter to this live runtime without reconfiguring, modeled
  on OpenTelemetry's `add_span_processor`. The same non-blocking contract
  as any other reporter applies; there is no removal, only reconfiguring.
  See [Reporters](reporters.md).
- `runtime.audit_findings() -> list[Finding]`: the laundering-audit
  findings recorded so far (bounded; oldest evicted first once the cap is
  reached), or `[]` if `audit` was not enabled. See
  [Auditing](../guides/auditing.md).

## `Policy`

```python
Policy.from_file(path: str) -> Policy
Policy.validate(path: str) -> list[str]
```

`from_file` loads, validates, and compiles a policy YAML file in one call;
raises `PolicyEvaluationError` if the file is missing, malformed, or fails
schema or CEL compilation. `validate` performs schema and CEL checks only,
without executing an agent, and returns a list of human-readable problem
descriptions, empty if the policy is valid, capturing every error there
instead of raising. `policy.sources_table` exposes the declared
source-to-trust mapping. See [Policies](../concepts/policies.md) and
[CI](../guides/ci.md).

## `Decision`

```python
class Decision(BaseModel, frozen=True):
    action: Action                       # ALLOW | BLOCK | REQUIRE_APPROVAL
    matched_rule: str | None             # name of the first matching rule
    matched_condition: str | None        # the matched rule's original CEL `when` text
    tool: str                            # qualified name
    contributing_labels: tuple[Label, ...]
    trifecta: frozenset[str]             # v1: at most {"from_untrusted"}
    untrusted_sources: frozenset[str]    # which contributing source names resolved untrusted
    run_tainted: bool                    # run-level gating; see policies.md
    mode: Mode
    decision_id: str
    agent_id: str
    run_id: str
    session_id: str | None
```

Returned by `check`/`guard`, attached to `PolicyViolation`/`ApprovalDenied`
on `.decision`, and emitted (alongside timing and outcome) as an `Event`.
`matched_condition` is `None` for the sink's catch-all/default rule or when
nothing matched; otherwise it is the exact `when:` text as written in the
policy YAML, not the internal `.any(` to `.exists(` rewritten form, since
it's meant for a human to read (see `describe_decision`, below), not for
re-evaluation.

## `Event`, `Finding`

```python
class Event(BaseModel, frozen=True):
    schema_version: int
    decision: Decision
    agent_id: str
    run_id: str
    session_id: str | None
    sources: frozenset[str]      # every source contributing to the call, trusted or not
    lineage: tuple[str, ...]
    matched_rule: str | None
    trifecta: frozenset[str]
    untrusted_sources: frozenset[str]
    run_tainted: bool
    mode: Mode
    outcome: str                 # the real, pre-dry_run-downgrade action
    timestamp: datetime
```

The versioned, emitted record of a `Decision`, carrying the identity triple
and timing alongside it. `Finding` is the parallel record for a laundering-
audit hit; see [Auditing](../guides/auditing.md). Both travel through the
`Reporter` seam (below); `EVENT_SCHEMA_VERSION` (in `interbolt.constants`)
versions both.

## `Action`, `Mode`, `TrustLevel`

All `enum.StrEnum`, so the same value round-trips a policy YAML string, an
environment variable string, and serialized output with no conversion code.

- `Action`: `ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`.
- `Mode`: `ENFORCE`, `MONITOR`, `DRY_RUN`. See
  [Policies](../concepts/policies.md#modes-and-fail_mode).
- `TrustLevel`: `TRUSTED`, `UNTRUSTED`. The *result* of resolving a source
  name against the policy at the sink; never stored on a `Label`.

## `Label`

```python
class Label(BaseModel, frozen=True):
    source: str
    value_id: str
    lineage: tuple[str, ...]
```

See [Taint propagation](../concepts/taint-propagation.md#the-trust-model-a-provenance-set-not-a-lattice).

## `Tainted`, `TaintedBytes`, `LabeledValue`

`Tainted` (a `str` subclass) and `TaintedBytes` (a `bytes` subclass) carry a
`.label: Label` and propagate it through the operation subset described in
[Taint propagation](../concepts/taint-propagation.md). `LabeledValue` wraps
a non-string scalar, exposing `.value` and `.label`; transforming `.value`
first produces a plain, unlabeled result.

## `Reporter`, `ApprovalResolver`

Protocols in `interbolt.models.protocols`. See
[Reporters](reporters.md) for `Reporter` and its five implementations
(`NullReporter`, `InMemoryReporter`, `LoggingReporter`, `JsonlReporter`,
`CompositeReporter`). `ApprovalResolver` is `Callable[[Decision], bool |
Awaitable[bool]]`: invoked synchronously at a sync call site, awaited at an
async call site. A sync call site needs a resolver that returns a plain
`bool`; one that returns an awaitable raises `InterboltUsageError`. The
default, `auto_deny`, denies every request.

## `describe_decision`, `describe_event`, `describe_finding`

```python
def describe_decision(decision: Decision) -> str: ...
def describe_event(event: Event) -> str: ...
def describe_finding(finding: Finding) -> str: ...
```

Each turns its record into a one-line, rich-markup-tagged human summary,
meant for a `rich.console.Console`, not a bare `print()` (the raw
`[tag]...[/tag]` markup otherwise prints literally). `describe_decision`
is the one to reach for right where a `Decision` is already in hand
(a caught `PolicyViolation`/`ApprovalDenied`, or `check()`'s direct return
value): it shows the tool, action, matched rule, matched condition (if any),
mode, and `untrusted_sources` without a trip through the reporter stream.
`describe_event`/`describe_finding` cover the same ground for the emitted,
versioned `Event`/`Finding` records, and are what `interbolt inspect` uses
internally. See [Reporters](reporters.md).

## `RECORD_TYPE_EVENT`, `RECORD_TYPE_FINDING`

The `"record_type"` string values `JsonlReporter` tags each line with, and
`interbolt inspect` reads back to recover which model (`Event` or `Finding`)
a line deserializes to. In `interbolt.constants`, re-exported at the top
level for a consumer parsing a `JsonlReporter` log directly.

## Errors

```
InterboltError                                          (base)
├── decision outcomes
│   ├── PolicyViolation        # a real block; carries .decision
│   ├── PolicyEvaluationError  # evaluation failed; fail-closed under enforce
│   └── ApprovalDenied         # resolver returned False
└── misuse (also subclasses the matching builtin)
    ├── InterboltConfigError(InterboltError, ValueError)    # bad config value
    └── InterboltUsageError(InterboltError, RuntimeError)   # API used out of sequence
```

`except InterboltError` catches every exception the library raises. Because
the misuse classes multiply-inherit the matching builtin, `except
ValueError` and `except RuntimeError` also catch them by their builtin
semantics. `taint()` needs no configured runtime and works before
`configure()` has run, so it never raises a usage error.

## `__version__`

The single source of truth for the package version; `pyproject.toml` reads
it dynamically from `src/interbolt/__init__.py`.
