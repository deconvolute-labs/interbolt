"""A genuinely multi-file, multi-agent scenario.

Unlike test_agent_loop.py (one agent, everything defined inline in one
file), this exercises the actual "agents and tools defined in different
modules" story: fixtures/agents.py, fixtures/tools.py, fixtures/sources.py,
and fixtures/model.py are separate modules, imported here at collection
time, before any configure() call in this test session. It also exercises
the "model as a new source" feature end to end: a model call combining
trusted and untrusted context is automatically tainted as derived from
both, and that taint correctly reaches a downstream guarded sink.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from fixtures.model import summarize
from fixtures.sources import fetch_internal, fetch_web
from fixtures.tools import run_shell, send_email, write_file

from interbolt import PolicyViolation

if TYPE_CHECKING:
    from unittest.mock import Mock

    from interbolt import InMemoryReporter, Runtime


def test_model_output_derived_from_untrusted_input_is_blocked(
    runtime: Runtime,
) -> None:
    web_result = fetch_web("acme-pricing")
    internal_result = fetch_internal("readme")

    summary = summarize(web_result, internal_result)

    # Passed directly, not embedded in an f-string: an f-string with literal
    # text is a known laundering point (propagation contract, taint-
    # propagation.md) and would strip the label before it ever reached the
    # sink, defeating the point of this test.
    with pytest.raises(PolicyViolation) as exc_info:
        run_shell(command=summary)

    decision = exc_info.value.decision
    assert decision.action.value == "block"
    assert decision.matched_rule == "block_any_untrusted"
    assert "web_search" in decision.untrusted_sources


def test_model_output_derived_from_all_trusted_input_is_allowed(
    runtime: Runtime,
) -> None:
    internal_a = fetch_internal("readme")
    internal_b = fetch_internal("changelog")

    summary = summarize(internal_a, internal_b)

    # No PolicyViolation: an all-trusted-derived summary sails through.
    run_shell(command=summary)


def test_model_output_carries_model_as_the_derivation_hop(
    runtime: Runtime,
) -> None:
    web_result = fetch_web("acme-pricing")
    internal_result = fetch_internal("readme")

    summary = summarize(web_result, internal_result)

    # Traceability: the immediate hop is "model", the full lineage still
    # names the true upstream sources, so a sink can trace back through both.
    assert summary.label.source == "model"
    assert set(summary.label.lineage) == {"web_search", "internal_kb"}


def test_two_agents_across_modules_attributed_correctly(
    runtime: Runtime, in_memory_reporter: InMemoryReporter, fake_resolver: Mock
) -> None:
    fake_resolver.return_value = True

    send_email(to="partner@external.com", body=fetch_internal("readme"))
    write_file(path="/data/notes.txt", content=fetch_internal("readme"))

    by_agent = {d.agent_id: d for d in in_memory_reporter.decisions}
    assert set(by_agent) == {"research-agent", "writer-agent"}


def test_bare_guard_tool_in_separate_module_uses_default_agent_id(
    runtime: Runtime, in_memory_reporter: InMemoryReporter
) -> None:
    run_shell(command="echo hello")
    assert in_memory_reporter.decisions[-1].agent_id == "default"
