"""Coverage: joining discovered tools against a policy's declarations."""

from __future__ import annotations

from collections.abc import Collection

from interbolt.constants import TRIFECTA_LEGS
from interbolt.models.core import Capability
from interbolt.policy import Policy
from interbolt.scan.artifact import ScanSource, ScanTool, ScanUnmatchedSink, Verdict


def join_declared_sources(
    sources: Collection[ScanSource], policy: Policy
) -> tuple[ScanSource, ...]:
    """Set `declared` on every discovered source from a policy's `sources:` table.

    Args:
        sources: Every source discovered from a literal `taint(source=...)`
            call site.
        policy: The policy to join against.

    Returns:
        `sources`, in the same order, with `declared` populated.
    """
    return tuple(
        source.model_copy(update={"declared": source.name in policy.sources_table})
        for source in sources
    )


def join_declared_capabilities(
    tools: Collection[ScanTool], policy: Policy
) -> tuple[ScanTool, ...]:
    """Set `declared`, `capabilities`, and `policy_rules` from a policy.

    Args:
        tools: Every discovered tool, including ones resolved by policy-name
            grounding.
        policy: The policy to join against.

    Returns:
        `tools`, in the same order, with the three fields populated.
    """
    joined = []
    for tool in tools:
        capabilities = policy.tool_capabilities.get(tool.qualified_name)
        sink = policy.document.sinks.get(tool.qualified_name)
        rules = tuple(rule.name for rule in sink.rules) if sink is not None else ()
        joined.append(
            tool.model_copy(
                update={
                    "declared": capabilities is not None,
                    "capabilities": tuple(sorted(capabilities or ())),
                    "policy_rules": rules,
                }
            )
        )
    return tuple(joined)


def compute_coverage(
    tools: Collection[ScanTool], *, policy_supplied: bool
) -> tuple[Verdict, tuple[Capability, ...], int]:
    """Roll up an agent's bound tools into a verdict and capability set.

    Args:
        tools: Every tool bound to the agent.
        policy_supplied: Whether a policy was joined against `tools`. When
            `False`, every tool is undeclared by construction and the
            verdict is always `Verdict.NO_POLICY`.

    Returns:
        `(verdict, capabilities, undeclared_tool_count)`.
    """
    if not policy_supplied:
        return Verdict.NO_POLICY, (), len(tools)

    undeclared_count = sum(1 for tool in tools if not tool.declared)
    rolled: set[Capability] = set()
    for tool in tools:
        rolled.update(tool.capabilities)
    capabilities = tuple(sorted(rolled))

    if undeclared_count:
        return Verdict.INCOMPLETE, capabilities, undeclared_count
    if set(capabilities) >= TRIFECTA_LEGS:
        return Verdict.TRIFECTA, capabilities, 0
    return Verdict.CLEAR, capabilities, 0


def build_unmatched_sinks(
    policy: Policy, matched_names: Collection[str]
) -> tuple[ScanUnmatchedSink, ...]:
    """Sink keys the policy declares that no tool entry matched.

    Args:
        policy: The policy whose `sinks:` keys are checked.
        matched_names: Every `qualified_name` present in the scan's tool
            list, including tools resolved by policy-name grounding.

    Returns:
        Sorted by `sink_key`.
    """
    matched = set(matched_names)
    unmatched = [
        ScanUnmatchedSink(
            sink_key=sink_key,
            detail=(
                "no scanned tool matches this sink key; the tool may have "
                "been removed, the scanner may not have been able to read "
                "it, or the policy may cover a different repository"
            ),
        )
        for sink_key in policy.document.sinks
        if sink_key not in matched
    ]
    unmatched.sort(key=lambda entry: entry.sink_key)
    return tuple(unmatched)
