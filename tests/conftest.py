from __future__ import annotations

import uuid
from collections.abc import Callable, Generator
from pathlib import Path
from typing import TYPE_CHECKING, cast
from unittest.mock import Mock

import pytest
from pytest_mock import MockerFixture

import interbolt.runtime.current as _current_module
from interbolt import InMemoryReporter, Policy, Runtime, configure
from interbolt.models.core import Action, Decision, Label, Mode
from interbolt.policy import Policy as _Policy
from interbolt.policy.compile import compile_policy
from interbolt.policy.schema import (
    Defaults,
    PolicyDocument,
    SinkRule,
    SourceDeclaration,
)
from interbolt.taint import install_endorsement_emitter, install_taint_observer

if TYPE_CHECKING:
    pass

POLICIES_DIR = Path(__file__).parent / "policies"


@pytest.fixture
def in_memory_reporter() -> InMemoryReporter:
    return InMemoryReporter()


@pytest.fixture
def fake_resolver(mocker: MockerFixture) -> Mock:
    return cast(Mock, mocker.Mock(return_value=False))


@pytest.fixture
def runtime(in_memory_reporter: InMemoryReporter, fake_resolver: Mock) -> Runtime:
    policy = Policy.from_file(str(POLICIES_DIR / "agent_loop.yaml"))
    return configure(
        policy=policy,
        reporter=in_memory_reporter,
        approval_resolver=fake_resolver,
        mode="enforce",
    )


# ---------------------------------------------------------------------------
# Unit-test helpers — pure construction, no file I/O
# ---------------------------------------------------------------------------


@pytest.fixture
def make_label() -> Callable[..., Label]:
    """Return a factory that builds a fresh Label with a UUID value_id."""

    def _factory(source: str = "src", ingested_by: tuple[str, ...] = ()) -> Label:
        return Label(
            source=source,
            value_id=str(uuid.uuid4()),
            lineage=(source,),
            ingested_by=ingested_by,
        )

    return _factory


@pytest.fixture
def make_decision() -> Callable[..., Decision]:
    """Return a factory that builds a minimal frozen Decision."""

    def _factory(
        action: Action = Action.ALLOW,
        matched_rule: str | None = None,
        matched_condition: str | None = None,
        tool: str = "default.test_tool",
        contributing_labels: tuple[Label, ...] = (),
        trifecta: frozenset[str] = frozenset(),
        untrusted_sources: frozenset[str] = frozenset(),
        run_tainted: bool = False,
        mode: Mode = Mode.ENFORCE,
        agent_id: str = "test-agent",
        run_id: str = "test-run",
        session_id: str | None = None,
    ) -> Decision:
        return Decision(
            action=action,
            matched_rule=matched_rule,
            matched_condition=matched_condition,
            tool=tool,
            contributing_labels=contributing_labels,
            trifecta=trifecta,
            untrusted_sources=untrusted_sources,
            run_tainted=run_tainted,
            mode=mode,
            decision_id=str(uuid.uuid4()),
            agent_id=agent_id,
            run_id=run_id,
            session_id=session_id,
        )

    return _factory


@pytest.fixture
def make_policy() -> Callable[..., _Policy]:
    """Return a factory that builds a Policy without any file I/O."""

    def _factory(
        fail_mode: Mode | None = None,
        sink_action: Action = Action.ALLOW,
        sources: tuple[SourceDeclaration, ...] = (),
        sinks: dict[str, tuple[SinkRule, ...]] | None = None,
    ) -> _Policy:
        document = PolicyDocument(
            version="1.0",
            defaults=Defaults(
                sink_action=sink_action,
                fail_mode=fail_mode,
            ),
            sources=sources,
            sinks=sinks or {},
        )
        return _Policy(document=document, compiled_sinks=compile_policy(document))

    return _factory


@pytest.fixture
def reset_runtime() -> Generator[None, None, None]:
    """Set _current_runtime to None before and after the test."""
    _current_module._current_runtime = None
    yield
    _current_module._current_runtime = None


@pytest.fixture(autouse=True)
def reset_taint_observer() -> Generator[None, None, None]:
    """Set the taint()-time audit observer to None before and after each test.

    Without this, one test's configure(audit=True) could leave an installed
    observer that leaks into an unrelated test in the same pytest session.
    """
    install_taint_observer(None)
    yield
    install_taint_observer(None)


@pytest.fixture(autouse=True)
def reset_endorsement_emitter() -> Generator[None, None, None]:
    """Set the endorse()-time emitter to None before and after each test.

    Without this, one test's configure() could leave an emitter installed
    that leaks into an unrelated test calling endorse() directly.
    """
    install_endorsement_emitter(None)
    yield
    install_endorsement_emitter(None)
