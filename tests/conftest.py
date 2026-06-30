from __future__ import annotations

from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest
from pytest_mock import MockerFixture

from interlock import InMemoryReporter, Policy, Runtime, configure

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
