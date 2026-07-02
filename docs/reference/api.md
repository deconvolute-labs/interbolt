# API reference

Everything re-exported from `interbolt` (the package `__init__.py`). This is
the public surface; anything not listed here is internal and may change
without notice.

```
taint, guard, check, configure, Runtime, Policy,
Decision, Action, Mode, Label, TrustLevel,
Reporter, ApprovalResolver,
NullReporter, InMemoryReporter, LoggingReporter,
InterboltError, PolicyViolation, PolicyEvaluationError, ApprovalDenied,
InterboltConfigError, InterboltUsageError,
Tainted, LabeledValue, TaintedBytes,
__version__
```

## `taint`

```python
def taint(value: Any, *, source: str) -> Any: ...
```

Marks `value` with a `Label` recording `source`. For `str` returns a
`Tainted`; for `bytes` returns a `TaintedBytes`; for a builtin container
(`list`, `tuple`, `set`, `frozenset`, `dict`) recurses and labels string
leaves to the bounded recursion depth; for any other scalar returns a
`LabeledValue`. Trust is **not** resolved here; the label only records the
source name. Needs no configured runtime. See
[Taint propagation](../concepts/taint-propagation.md).

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
configured reporter. Does not read the `agent_context` contextvar for
either `agent_id` or `run_id`; both are explicit. Requires `configure()` to
have run; raises `InterboltUsageError` otherwise. Use this directly for
custom dispatch loops or existing tool registries, instead of `guard`.

There is no separate `simulate` function: policy testing is `check()`
invoked with synthetic args and taint, asserted against the returned
`Decision`. See [Testing](../guides/testing.md).

## `configure`

```python
def configure(
    *,
    policy: Policy,
    reporter: Reporter | None = None,
    approval_resolver: ApprovalResolver = auto_deny,
    mode: Mode | str = Mode.ENFORCE,
    audit: bool = False,
) -> Runtime: ...
```

Builds a `Runtime`, installs it as the process-current runtime, and returns
it. Has no import-time side effects: importing a module decorated with
`@guard` does not require `configure()` to have run. `reporter` defaults to
a fresh `NullReporter()`. `approval_resolver` defaults to `auto_deny`
(denies every approval request). The effective `mode` is resolved from
three sources, highest precedence first: the `INTERBOLT_MODE` environment
variable, the policy file's `defaults.fail_mode`, then this `mode=`
argument. `INTERBOLT_AUDIT` overrides `audit`. Raises
`InterboltConfigError` if the effective mode is not a valid `Mode` value.
See [Policies](../concepts/policies.md#modes-and-fail_mode).

## `Runtime`

The composition root returned by `configure()`. One per process.

- `runtime.agent(agent_id: str) -> AgentHandle`: a handle whose `.guard`
  decorates with a durable `agent_id`, resolved lazily at call time.
- `runtime.agent_context(agent_id: str)`: an async context manager that
  binds `agent_id` and mints a `run_id` for the duration of the block. See
  [Identity](../concepts/identity.md).
- `runtime.check(*, tool, args, agent_id, run_id=None, session_id=None) -> Decision`:
  the same decision core as the module-level `check`, against this runtime
  explicitly.
- `runtime.audit_findings() -> list[Finding]`: every laundering-audit
  finding recorded so far, or `[]` if `audit` was not enabled. See
  [Auditing](../guides/auditing.md).

## `Policy`

```python
Policy.from_file(path: str) -> Policy
Policy.validate(path: str) -> list[str]
```

`from_file` loads, validates, and compiles a policy YAML file in one call;
raises `PolicyEvaluationError` if the file is missing, malformed, or fails
schema or CEL compilation. `validate` performs static analysis only (never
executes an agent, never raises) and returns a list of human-readable
problem descriptions, empty if the policy is valid. `policy.sources_table`
exposes the declared source-to-trust mapping. See
[Policies](../concepts/policies.md) and [CI](../guides/ci.md).

## `Decision`

```python
class Decision(BaseModel, frozen=True):
    action: Action                       # ALLOW | BLOCK | REQUIRE_APPROVAL
    matched_rule: str | None             # name of the first matching rule
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
a non-string scalar, exposing `.value` and `.label`; it does not propagate
through transformations of `.value`.

## `Reporter`, `ApprovalResolver`

Protocols in `interbolt.models.protocols`. See
[Reporters](reporters.md) for `Reporter` and its three implementations.
`ApprovalResolver` is `Callable[[Decision], bool | Awaitable[bool]]`: invoked
synchronously at a sync call site, awaited at an async call site. A sync
call site cannot use a resolver that returns an awaitable (raises
`InterboltUsageError`). The default, `auto_deny`, denies every request.

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

`except InterboltError` catches every exception the library raises, with no
exceptions. Because the misuse classes multiply-inherit the matching
builtin, `except ValueError` and `except RuntimeError` also catch them by
their builtin semantics. `taint()` never raises a usage error: it needs no
configured runtime and works before `configure()` has run.

## `__version__`

The single source of truth for the package version; `pyproject.toml` reads
it dynamically from `src/interbolt/__init__.py`.
