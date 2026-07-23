"""Thread-safety stress tests for the shared mutable registries.

The docs explicitly recommend dispatching guarded calls to a thread pool via
the durable `AgentHandle` pattern, precisely because `ContextVar`s (agent
identity, run identity) don't cross into a spawned thread. That means
concurrent threads legitimately hit the shared module-level registries
(`taint`'s run-ingress registry, `runtime`'s process-current runtime,
`AuditRegistry`'s per-run/finding state) at the same time. These tests
exercise that under real `ThreadPoolExecutor` dispatch, not just asyncio
concurrency (which is single-threaded and safe by construction).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from interbolt import InMemoryReporter, Policy, configure, taint
from interbolt.constants import AUDIT_MIN_MATCH_LENGTH
from interbolt.errors import PolicyViolation
from interbolt.models.core import Action
from interbolt.policy.compile import compile_policy
from interbolt.policy.schema import Defaults, PolicyDocument, SinkRule
from interbolt.runtime import guard

POLICY_PATH = Path(__file__).parent.parent / "policies" / "agent_loop.yaml"


def test_thread_pool_dispatch_via_durable_handle_loses_no_decisions() -> None:
    reporter = InMemoryReporter()
    rt = configure(
        policy=Policy.from_file(str(POLICY_PATH)), reporter=reporter, mode="enforce"
    )
    handle = rt.agent("worker-agent")

    @handle.guard(tool="fs_write")
    def write_file(path: str, content: str) -> None:
        pass

    def call(i: int) -> None:
        # All-trusted content: falls through to the sink's default "allow",
        # so no approval resolver is needed for this stress test.
        write_file(path=f"/data/{i}.txt", content="trusted content only")

    call_count = 200
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(call, i) for i in range(call_count)]
        for future in futures:
            future.result()  # re-raises on any worker exception

    assert len(reporter.decisions) == call_count
    assert len({d.decision_id for d in reporter.decisions}) == call_count
    assert all(d.agent_id == "worker-agent" for d in reporter.decisions)


def test_thread_pool_each_worker_isolates_its_own_agent_context_sync() -> None:
    reporter = InMemoryReporter()
    rt = configure(
        policy=Policy.from_file(str(POLICY_PATH)), reporter=reporter, mode="enforce"
    )

    @guard(tool="run_shell")  # type: ignore[untyped-decorator]
    def run_shell(command: str) -> None:
        pass

    def worker(i: int) -> None:
        with rt.agent_context_sync(f"worker-{i}"):
            # Untrusted ingress recorded against *this thread's own* run,
            # via taint's lock-protected ingress registry.
            taint("a" * AUDIT_MIN_MATCH_LENGTH, source="web_search")
            # This call's own argument carries no label at all (plain str),
            # so it is allowed outright by the policy's default action;
            # run_tainted must still reflect the untrusted taint() call
            # above, which is the whole point of the run-level signal.
            run_shell(command="trusted-only command --dry-run")

    worker_count = 20
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker, i) for i in range(worker_count)]
        for future in futures:
            future.result()

    assert len(reporter.decisions) == worker_count
    run_ids = {d.run_id for d in reporter.decisions}
    assert len(run_ids) == worker_count  # no two threads shared a run_id
    agent_ids = {d.agent_id for d in reporter.decisions}
    assert agent_ids == {f"worker-{i}" for i in range(worker_count)}
    assert all(d.run_tainted for d in reporter.decisions)


def test_thread_pool_agent_id_resolves_correctly_in_cel_context() -> None:
    # Confirms agent.id in the CEL context, not just Decision.agent_id, sees
    # each AgentHandle's validated identity correctly across the thread
    # boundary: only "billing-agent" is allowed, every other worker blocks.
    document = PolicyDocument(
        version="1.0",
        defaults=Defaults(sink_action=Action.BLOCK),
        sources=(),
        sinks={
            "default.pay": (
                SinkRule(
                    name="billing_only",
                    when='agent.id == "billing-agent"',
                    action=Action.ALLOW,
                ),
                SinkRule(name="default", action=Action.BLOCK),
            )
        },
    )
    policy = Policy(document=document, compiled_sinks=compile_policy(document))
    reporter = InMemoryReporter()
    rt = configure(policy=policy, reporter=reporter, mode="enforce")

    billing = rt.agent("billing-agent")
    support = rt.agent("support-agent")

    @billing.guard(tool="pay")
    def pay(amount: float) -> None:
        pass

    @support.guard(tool="pay")
    def pay_as_support(amount: float) -> None:
        pass

    def call(i: int) -> None:
        if i % 2 == 0:
            pay(amount=1.0)
        else:
            try:
                pay_as_support(amount=1.0)
            except PolicyViolation:
                pass

    call_count = 100
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(call, i) for i in range(call_count)]
        for future in futures:
            future.result()

    assert len(reporter.decisions) == call_count
    by_agent: dict[str, set[Action]] = {}
    for d in reporter.decisions:
        by_agent.setdefault(d.agent_id, set()).add(d.action)
    assert by_agent["billing-agent"] == {Action.ALLOW}
    assert by_agent["support-agent"] == {Action.BLOCK}
