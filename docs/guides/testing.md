# Testing

Interbolt is built so a consumer's existing tests of their own tool
functions keep working unchanged after adding the library, and so testing
policy behavior itself needs no bespoke harness.

## Why this works

- `@guard` does nothing heavy at import or decoration time; the
  [binding model](../concepts/identity.md#binding-model-nothing-captures-the-runtime-at-decoration-time)
  guarantees decoration captures no runtime. A test that calls a guarded
  function still calls the real function, after a decision is computed.
- The two colored edges, `Reporter` and `ApprovalResolver`, are injectable
  with inert defaults, so they are mocked with stock
  `unittest.mock.Mock`/`AsyncMock` (or `pytest-mock`'s `mocker` fixture),
  with no monkeypatching of internals required.
- Policy testing is `check()` (or `runtime.check()`) called with synthetic
  args and taint, asserted against the returned `Decision`. There is no
  separate `simulate` function.
- `InMemoryReporter` is the assertion surface for "what decisions were
  made" and "what audit findings were found."

## A minimal recipe

```python
from interbolt import (
    Action, InMemoryReporter, Policy, configure, taint,
)

def test_untrusted_email_is_blocked():
    reporter = InMemoryReporter()
    runtime = configure(
        policy=Policy.from_file("policy.yaml"),
        reporter=reporter,
        mode="enforce",
    )
    decision = runtime.check(
        tool="email.send_email",
        args={
            "to": taint("attacker@external.com", source="web_search"),
            "body": "...",
        },
        agent_id="test-agent",
    )
    assert decision.action is Action.BLOCK
    assert decision.matched_rule == "block_untrusted_exfil"
    assert reporter.decisions[-1].decision_id == decision.decision_id
```

## Testing through `@guard`

```python
import pytest
from interbolt import ApprovalDenied, PolicyViolation, configure, taint

def test_guarded_call_is_blocked(runtime):  # see fixtures below
    agent = runtime.agent("research-agent")

    @agent.guard(tool="send_email")
    def send_email(to: str, body: str) -> None:
        ...  # never reached when blocked

    with pytest.raises(PolicyViolation) as exc_info:
        send_email(
            to=taint("attacker@external.com", source="web_search"),
            body="...",
        )

    assert exc_info.value.decision.matched_rule == "block_untrusted_exfil"
```

A `require_approval` decision invokes the configured `ApprovalResolver`. Use
a fake resolver to control the outcome deterministically in tests, rather
than the default `auto_deny`:

```python
def test_approval_denied_then_granted(mocker):
    resolver = mocker.Mock(return_value=False)
    runtime = configure(policy=..., approval_resolver=resolver)
    agent = runtime.agent("research-agent")

    @agent.guard(tool="fs_write")
    def write_file(path: str, content: str) -> None: ...

    with pytest.raises(ApprovalDenied):
        write_file(path="/data/out.txt", content="...")

    resolver.return_value = True
    write_file(path="/data/out.txt", content="...")  # now allowed
```

For an `async def` guarded function, use an `AsyncMock` resolver instead; a
sync call site cannot use a resolver that returns an awaitable, and a guard
wrapping a coroutine function awaits the resolver automatically.

## Recommended fixtures

```python
# conftest.py
from pathlib import Path
from unittest.mock import Mock
import pytest
from pytest_mock import MockerFixture
from interbolt import InMemoryReporter, Policy, Runtime, configure

@pytest.fixture
def in_memory_reporter() -> InMemoryReporter:
    return InMemoryReporter()

@pytest.fixture
def fake_resolver(mocker: MockerFixture) -> Mock:
    return mocker.Mock(return_value=False)

@pytest.fixture
def runtime(in_memory_reporter: InMemoryReporter, fake_resolver: Mock) -> Runtime:
    policy = Policy.from_file("tests/policies/test_policy.yaml")
    return configure(
        policy=policy,
        reporter=in_memory_reporter,
        approval_resolver=fake_resolver,
        mode="enforce",
    )
```

Each test that calls `configure()` (directly, or through a fixture)
rebinds the process-current runtime; the lazily-resolving `guard`/`check`
pick up whichever runtime is current on their next call, so tests do not
leak state into each other through stale captured runtimes.

## `dry_run` against live traffic

To test a new policy without blocking anything, configure `mode="dry_run"`
and drive your agent through real traffic, then inspect
`reporter.events[i].outcome` (the real, pre-downgrade action) rather than
`reporter.decisions[i].action` (always `allow` under `dry_run`). See
[Policies](../concepts/policies.md#modes-and-fail_mode).
