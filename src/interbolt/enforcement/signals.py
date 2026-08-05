"""Trust signals derived once per call from resolved labels."""

from __future__ import annotations

from collections.abc import Mapping

from interbolt.constants import TRIFECTA_FROM_UNTRUSTED
from interbolt.models.core import Capability, RunIngressEntry, TrustLevel
from interbolt.policy import ResolvedLabel
from interbolt.policy.evaluate import resolve_source_trust
from interbolt.taint import run_ingress


def _compute_trifecta(
    resolved_labels: tuple[ResolvedLabel, ...],
    call_capabilities: frozenset[Capability],
) -> frozenset[str]:
    """Compute the lethal-trifecta legs satisfied by this call.

    `from_untrusted` when any resolved label is untrusted, unioned with the
    called tool's declared capabilities.
    """
    legs: set[str] = {capability.value for capability in call_capabilities}
    if any(resolved.trust is TrustLevel.UNTRUSTED for resolved in resolved_labels):
        legs.add(TRIFECTA_FROM_UNTRUSTED)
    return frozenset(legs)


def _compute_untrusted_sources(
    resolved_labels: tuple[ResolvedLabel, ...],
) -> frozenset[str]:
    """Resolve which of this call's contributing labels' source names are untrusted.

    Answers "which source caused this" so the reporter doesn't need its own
    sources table to re-derive it. Derived from `resolved_labels` (resolved
    once in `check()`), not re-resolved here.
    """
    return frozenset(
        name for resolved in resolved_labels for name in resolved.untrusted_lineage
    )


def _resolve_run_ingress(
    run_id: str, sources_table: Mapping[str, TrustLevel]
) -> tuple[RunIngressEntry, ...]:
    """Resolve the active run's ingested sources against the policy's trust table.

    Reads the run's recorded ingress (`taint.run_ingress`, independent of
    this call's own arguments) and resolves each source name the same way
    `resolve_label_trust` resolves a label's lineage, pairing it with the
    agent ids that ingested it.
    """
    return tuple(
        RunIngressEntry(
            source=name,
            trust=resolve_source_trust(name, sources_table),
            ingested_by=agent_ids,
        )
        for name, agent_ids in run_ingress(run_id).items()
    )


def _run_tainted(entries: tuple[RunIngressEntry, ...]) -> bool:
    """Whether any resolved run-ingress entry is untrusted."""
    return any(entry.trust is TrustLevel.UNTRUSTED for entry in entries)


def _compute_run_trifecta(
    run_ingress: tuple[RunIngressEntry, ...],
    run_capabilities: frozenset[str],
) -> frozenset[str]:
    """Compute the lethal-trifecta legs satisfied anywhere in the active run.

    `from_untrusted` when `_run_tainted(run_ingress)` is true, unioned with
    `run_capabilities`. Derived from the same `run_ingress` tuple
    `_run_tainted` uses, so the two can never disagree.
    """
    legs = set(run_capabilities)
    if _run_tainted(run_ingress):
        legs.add(TRIFECTA_FROM_UNTRUSTED)
    return frozenset(legs)
