"""Trust signals derived once per call from resolved labels."""

from __future__ import annotations

from collections.abc import Mapping

from interbolt.constants import TRIFECTA_FROM_UNTRUSTED
from interbolt.models.core import TrustLevel
from interbolt.policy.engine import ResolvedLabel, resolve_source_trust
from interbolt.taint import run_ingress_sources


def _compute_trifecta(resolved_labels: tuple[ResolvedLabel, ...]) -> frozenset[str]:
    """Compute the lethal-trifecta legs satisfied by this call.

    v1 computes only the `from_untrusted` leg; `reaches_external` and
    `reads_private` need a capabilities declaration this version does not
    yet have. `trifecta.contains("reaches_external")` always evaluates false, so a
    rule relying on trifecta size as a backstop fails open. Derived from
    `resolved_labels` (resolved once in `check()`), not re-resolved here.
    """
    if any(resolved.trust is TrustLevel.UNTRUSTED for resolved in resolved_labels):
        return frozenset({TRIFECTA_FROM_UNTRUSTED})
    return frozenset()


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


def _compute_run_tainted(run_id: str, sources_table: Mapping[str, TrustLevel]) -> bool:
    """Resolve whether the active run has ingested untrusted data via `taint()`.

    Reads the run's recorded ingress source names (`taint.run_ingress_sources`,
    independent of this call's own arguments) and resolves each the same way
    `resolve_label_trust` resolves a label's lineage. This lets `run.tainted`
    catch a model-mediated handoff that launders value-level taint away.
    """
    return any(
        resolve_source_trust(name, sources_table) is TrustLevel.UNTRUSTED
        for name in run_ingress_sources(run_id)
    )
