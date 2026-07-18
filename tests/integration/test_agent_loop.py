from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from interbolt import (
    Action,
    ApprovalDenied,
    InMemoryReporter,
    Mode,
    Policy,
    PolicyViolation,
    configure,
    taint,
)
from interbolt.constants import ENV_MODE, EVENT_SCHEMA_VERSION

if TYPE_CHECKING:
    from unittest.mock import Mock

    from pytest_mock import MockerFixture

    from interbolt import Runtime

POLICY_PATH = Path(__file__).parent.parent / "policies" / "agent_loop.yaml"


def search_web(query: str) -> str:
    """Simulates an untrusted external retrieval tool."""
    return cast(str, taint(f"contact-{query}@external.com", source="web_search"))


def read_internal_kb(doc_id: str) -> str:
    """Simulates a trusted internal data source."""
    return cast(
        str, taint(f"internal doc {doc_id}: approved for release", source="internal_kb")
    )


def test_untrusted_web_result_blocked_on_email_exfil_to_external(
    runtime: Runtime, in_memory_reporter: InMemoryReporter
) -> None:
    agent = runtime.agent("research-agent")

    @agent.guard(tool="send_email")
    def send_email(to: str, body: str) -> None:
        pass

    with pytest.raises(PolicyViolation) as exc_info:
        send_email(to=search_web("acme-pricing"), body="summary of findings")

    decision = exc_info.value.decision
    assert decision.action is Action.BLOCK
    assert decision.matched_rule == "block_untrusted_exfil"
    assert in_memory_reporter.decisions[-1].decision_id == decision.decision_id


def test_send_email_require_approval_denied_then_granted(
    runtime: Runtime, fake_resolver: Mock
) -> None:
    agent = runtime.agent("research-agent")

    @agent.guard(tool="send_email")
    def send_email(to: str, body: str) -> None:
        pass

    with pytest.raises(ApprovalDenied) as exc_info:
        send_email(to="partner@external.com", body=read_internal_kb("readme"))

    assert exc_info.value.decision.matched_rule == "default"
    fake_resolver.assert_called_once()

    fake_resolver.return_value = True
    send_email(to="partner@external.com", body=read_internal_kb("readme"))


def test_fs_write_require_approval_denied_then_granted(
    runtime: Runtime, fake_resolver: Mock
) -> None:
    agent = runtime.agent("research-agent")

    @agent.guard(tool="fs_write")
    def write_file(path: str, content: str) -> None:
        pass

    with pytest.raises(ApprovalDenied) as exc_info:
        write_file(path="/data/out.txt", content=search_web("acme-pricing"))

    assert exc_info.value.decision.matched_rule == "approve_untrusted_to_disk"

    fake_resolver.return_value = True
    write_file(path="/data/out.txt", content=search_web("acme-pricing"))


def test_fs_write_trusted_only_is_allowed_without_approval_call(
    runtime: Runtime, fake_resolver: Mock
) -> None:
    agent = runtime.agent("research-agent")

    @agent.guard(tool="fs_write")
    def write_file(path: str, content: str) -> None:
        pass

    write_file(path="/data/notes.txt", content=read_internal_kb("readme"))

    fake_resolver.assert_not_called()


def test_guarded_call_with_namedtuple_argument_completes(runtime: Runtime) -> None:
    """A namedtuple anywhere in a guarded call's arguments must not crash."""
    from collections import namedtuple

    Point = namedtuple("Point", "x y")
    agent = runtime.agent("research-agent")

    @agent.guard(tool="fs_write")
    def write_file(path: str, content: object) -> None:
        pass

    write_file(path="/data/out.txt", content=Point("a", "b"))


def test_run_shell_blocked_when_untrusted_data_is_merged_into_command(
    runtime: Runtime,
) -> None:
    agent = runtime.agent("research-agent")

    @agent.guard(tool="run_shell")
    def run_shell(command: str) -> None:
        pass

    trusted_part = read_internal_kb("readme")
    untrusted_part = search_web("payload")
    command = trusted_part + " && " + untrusted_part

    with pytest.raises(PolicyViolation) as exc_info:
        run_shell(command=command)

    decision = exc_info.value.decision
    assert decision.action is Action.BLOCK
    assert decision.matched_rule == "block_any_untrusted"
    assert decision.trifecta == frozenset({"from_untrusted"})


def test_run_shell_allowed_with_trusted_only_input(runtime: Runtime) -> None:
    agent = runtime.agent("research-agent")

    @agent.guard(tool="run_shell")
    def run_shell(command: str) -> None:
        pass

    command = read_internal_kb("readme") + " --dry-run"

    run_shell(command=command)


def test_dry_run_mode_downgrades_block_but_records_real_outcome(
    monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
) -> None:
    monkeypatch.setenv(ENV_MODE, "dry_run")
    reporter = InMemoryReporter()
    rt = configure(
        policy=Policy.from_file(str(POLICY_PATH)),
        reporter=reporter,
        approval_resolver=mocker.Mock(return_value=False),
        mode="enforce",
    )
    agent = rt.agent("research-agent")

    @agent.guard(tool="send_email")
    def send_email(to: str, body: str) -> None:
        pass

    send_email(to=search_web("acme-pricing"), body="quarterly summary")

    decision = reporter.decisions[-1]
    assert decision.action is Action.ALLOW
    assert decision.mode is Mode.DRY_RUN

    event = reporter.events[-1]
    assert event.outcome == "block"
    assert event.decision.matched_rule == "block_untrusted_exfil"


async def test_async_guarded_sink_uses_async_approval_resolver(
    mocker: MockerFixture,
) -> None:
    reporter = InMemoryReporter()
    async_resolver = mocker.AsyncMock(return_value=True)
    rt = configure(
        policy=Policy.from_file(str(POLICY_PATH)),
        reporter=reporter,
        approval_resolver=async_resolver,
        mode="enforce",
    )
    agent = rt.agent("research-agent")

    @agent.guard(tool="fs_write")
    async def write_file(path: str, content: str) -> None:
        pass

    await write_file(path="/data/out.txt", content=search_web("acme-pricing"))

    async_resolver.assert_awaited_once()
    decision = reporter.decisions[-1]
    assert decision.action is Action.REQUIRE_APPROVAL
    assert decision.matched_rule == "approve_untrusted_to_disk"


def test_reporter_records_full_decision_history_across_multiple_calls(
    runtime: Runtime, in_memory_reporter: InMemoryReporter
) -> None:
    agent = runtime.agent("research-agent")

    @agent.guard(tool="send_email")
    def send_email(to: str, body: str) -> None:
        pass

    @agent.guard(tool="fs_write")
    def write_file(path: str, content: str) -> None:
        pass

    with pytest.raises(PolicyViolation):
        send_email(to=search_web("acme-pricing"), body="summary")

    write_file(path="/data/notes.txt", content=read_internal_kb("readme"))

    assert len(in_memory_reporter.decisions) == 2
    assert in_memory_reporter.decisions[0].action is Action.BLOCK
    assert in_memory_reporter.decisions[1].action is Action.ALLOW

    decision_ids = {d.decision_id for d in in_memory_reporter.decisions}
    assert len(decision_ids) == 2

    for event in in_memory_reporter.events:
        assert event.schema_version == EVENT_SCHEMA_VERSION
