"""The dependency-inversion observer/emitter factories `configure()` installs.

These two factories are a self-contained wiring concern, distinct from the
`Runtime` composition root and the module-level `configure`/`agent`/`guard`/
`check` surface.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from interbolt.enforcement import AuditRegistry
from interbolt.models.core import Endorsement, TrustLevel
from interbolt.policy import Policy
from interbolt.policy.engine import resolve_source_trust
from interbolt.utils import get_logger

if TYPE_CHECKING:
    from interbolt.runtime import Runtime

_logger = get_logger("runtime")


def make_audit_observer(
    policy: Policy, audit_registry: AuditRegistry
) -> Callable[[str, str, str], None]:
    """Build the taint()-time observer configure(audit=True) installs.

    Resolves the source name against `policy`'s sources table (unknown
    resolves untrusted) and registers only
    untrusted-resolving content, since the audit exists to catch untrusted
    data laundering, not trusted data moving around.
    """
    sources_table = policy.sources_table

    def _observer(content: str, source: str, run_id: str) -> None:
        if resolve_source_trust(source, sources_table) is not TrustLevel.UNTRUSTED:
            return
        audit_registry.register_content(content, source, run_id)

    return _observer


def make_endorsement_emitter(runtime: Runtime) -> Callable[[Endorsement], None]:
    """Build the endorse()-time emitter every `configure()` call installs.

    Unlike the audit observer above, this is installed unconditionally: an
    `Endorsement` is a fire-and-forget export through whatever reporter is
    configured (even the default `NullReporter`), not an opt-in instrument.
    """

    def _emitter(endorsement: Endorsement) -> None:
        try:
            runtime.reporter.export(endorsement)
        except Exception:  # noqa: BLE001 -- a reporter failure must never propagate
            _logger.warning("reporter failed to export endorsement %r", endorsement)

    return _emitter
