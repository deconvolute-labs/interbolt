from __future__ import annotations

import uuid
from collections.abc import Generator, Mapping
from datetime import UTC, datetime
from typing import Any

from celpy.evaluation import CELEvalError

from interbolt.constants import (
    AUDIT_MIN_MATCH_LENGTH,
    EVENT_SCHEMA_VERSION,
    RECURSION_DEPTH,
    TRIFECTA_FROM_UNTRUSTED,
)
from interbolt.errors import PolicyEvaluationError
from interbolt.models.core import (
    Action,
    Decision,
    Event,
    Finding,
    Label,
    Mode,
    TrustLevel,
)
from interbolt.models.protocols import Reporter
from interbolt.policy import Policy
from interbolt.policy.engine import (
    build_context,
    evaluate_sink,
    resolve_label_trust,
    resolve_source_trust,
)
from interbolt.taint import (
    Tainted,
    TaintedBytes,
    collect_labels,
    run_ingress_sources,
    unwrap,
)
from interbolt.utils import get_logger

_logger = get_logger("enforcement")
_CONTAINER_TYPES = (list, tuple, set, frozenset)


def check(
    *,
    tool: str,
    args: Mapping[str, Any],
    agent_id: str,
    run_id: str | None,
    session_id: str | None,
    policy: Policy,
    reporter: Reporter,
    mode: Mode,
    audit_registry: AuditRegistry | None = None,
) -> Decision:
    """Evaluate policy for one guarded call. The single decision entrypoint.

    Pure with respect to the decision itself; the only side effects are the
    fire-and-forget reporter emission and, when an audit registry is given,
    the laundering scan. `guard` is sugar over this function and never
    duplicates this sequence.

    Note: this function never raises `PolicyViolation` or `ApprovalDenied`
    for a normally-computed `block`/`require_approval` decision; it returns
    the `Decision` and leaves enforcing it (raising, invoking the approval
    resolver) to the caller, exactly as `guard` does. It only raises
    directly for a genuine policy *evaluation* failure under `enforce` mode.

    Args:
        tool: The dotted qualified tool name.
        args: The call's bound arguments.
        agent_id: The durable agent identity.
        run_id: The per-run identity, or `None` to mint a fresh one.
        session_id: The optional session identity.
        policy: The compiled policy to evaluate against.
        reporter: Where to emit the resulting `Event`.
        mode: The enforcement mode in effect.
        audit_registry: The laundering-audit registry, or `None` if the
            audit instrument is disabled.

    Returns:
        The computed `Decision`.

    Raises:
        PolicyEvaluationError: Under `enforce` mode, if policy evaluation
            itself fails (a missing argument, a `None` value, or another CEL
            evaluation error).
    """
    labels = collect_labels(args, max_depth=RECURSION_DEPTH)
    plain_args = unwrap(args)
    sources_table = policy.sources_table
    trifecta = _compute_trifecta(labels, sources_table)
    untrusted_sources = _compute_untrusted_sources(labels, sources_table)
    compiled_sink = policy.compiled_sinks.get(tool)
    resolved_run_id = run_id or str(uuid.uuid4())
    run_tainted = _compute_run_tainted(resolved_run_id, sources_table)

    matched_rule: str | None = None
    action: Action = policy.document.defaults.sink_action
    evaluation_error: CELEvalError | None = None
    try:
        context = build_context(
            tool=tool,
            args=plain_args,
            labels=labels,
            trifecta=trifecta,
            sources_table=sources_table,
            run_tainted=run_tainted,
        )
        if compiled_sink is not None:
            matched_rule, action = evaluate_sink(
                compiled_sink,
                context,
                default_action=policy.document.defaults.sink_action,
            )
    except CELEvalError as exc:
        evaluation_error = exc

    raw_action = action
    outcome = action.value
    if evaluation_error is not None:
        outcome = "evaluation_error"
        matched_rule = None
        raw_action = Action.BLOCK if mode == Mode.ENFORCE else Action.ALLOW

    final_action = Action.ALLOW if mode == Mode.DRY_RUN else raw_action

    if outcome != Action.ALLOW.value:
        _logger.warning(
            "check(): tool=%s outcome=%s matched_rule=%s mode=%s",
            tool,
            outcome,
            matched_rule,
            mode,
        )

    decision = Decision(
        action=final_action,
        matched_rule=matched_rule,
        tool=tool,
        contributing_labels=labels,
        trifecta=trifecta,
        untrusted_sources=untrusted_sources,
        run_tainted=run_tainted,
        mode=mode,
        decision_id=str(uuid.uuid4()),
        agent_id=agent_id,
        run_id=resolved_run_id,
        session_id=session_id,
    )

    all_sources = frozenset(name for label in labels for name in label.lineage)
    event = Event(
        schema_version=EVENT_SCHEMA_VERSION,
        decision=decision,
        agent_id=agent_id,
        run_id=resolved_run_id,
        session_id=session_id,
        sources=all_sources,
        lineage=tuple(sorted(all_sources)),
        matched_rule=matched_rule,
        trifecta=trifecta,
        untrusted_sources=untrusted_sources,
        run_tainted=run_tainted,
        mode=mode,
        outcome=outcome,
        timestamp=datetime.now(UTC),
    )
    _emit(reporter, event)

    if audit_registry is not None:
        audit_registry.register_from_args(
            args,
            sources_table=sources_table,
            run_id=resolved_run_id,
            depth=RECURSION_DEPTH,
        )
        findings = audit_registry.scan(
            args,
            tool=tool,
            run_id=resolved_run_id,
            agent_id=agent_id,
            session_id=session_id,
            depth=RECURSION_DEPTH,
        )
        for finding in findings:
            _emit(reporter, finding)

    if evaluation_error is not None and mode == Mode.ENFORCE:
        raise PolicyEvaluationError(str(evaluation_error), decision=decision)

    return decision


def _emit(reporter: Reporter, event: Event | Finding) -> None:
    try:
        reporter.export(event)
    except Exception:  # noqa: BLE001 -- a reporter failure must never affect a decision
        _logger.warning(
            "reporter %r failed to export %r", reporter, type(event).__name__
        )


def _compute_trifecta(
    labels: tuple[Label, ...], sources_table: Mapping[str, TrustLevel]
) -> frozenset[str]:
    """Compute the lethal-trifecta legs satisfied by this call.

    v1 computes `from_untrusted` only. The `reaches_external` and
    `reads_private` legs are not computed in v1 (the latter requires the
    deferred capabilities declaration); `trifecta.contains("reaches_external")`
    always evaluates false. Do not rely on a v1 trifecta size as a backstop.
    """
    if any(
        resolve_label_trust(label, sources_table) is TrustLevel.UNTRUSTED
        for label in labels
    ):
        return frozenset({TRIFECTA_FROM_UNTRUSTED})
    return frozenset()


def _compute_untrusted_sources(
    labels: tuple[Label, ...], sources_table: Mapping[str, TrustLevel]
) -> frozenset[str]:
    """Resolve which of this call's contributing labels' source names are untrusted.

    Answers "why was this blocked, which source" without the reporter having
    to re-derive trust against a sources table it may not have: reuses the
    same per-name resolution `_compute_trifecta` already performs, but keeps
    the names instead of collapsing them to a boolean.
    """
    return frozenset(
        name
        for label in labels
        for name in label.lineage
        if resolve_source_trust(name, sources_table) is TrustLevel.UNTRUSTED
    )


def _compute_run_tainted(run_id: str, sources_table: Mapping[str, TrustLevel]) -> bool:
    """Resolve whether the active run has ingested untrusted data via `taint()`.

    Reads the run's recorded ingress source names (`taint.run_ingress_sources`,
    populated at `taint()` call time, independent of this call's own
    arguments) and resolves each against the policy's `sources` table, the
    same way `resolve_label_trust` resolves a label's lineage. This is what
    lets `run.tainted` survive a model-mediated handoff that launders
    value-level taint away (`dev/spec.md` §8.3, §15.8).
    """
    return any(
        resolve_source_trust(name, sources_table) is TrustLevel.UNTRUSTED
        for name in run_ingress_sources(run_id)
    )


def _walk_strings(
    value: Any,
    *,
    depth: int,  # noqa: ANN401 -- arbitrary bound-argument value
) -> Generator[tuple[str, Label | None], None, None]:
    """Yield every string leaf in `value`: `(content, label)`.

    `label` is `None` for a plain `str` (a potential laundering point) and
    set for a `Tainted`/`TaintedBytes` leaf (already labeled, not a
    laundering point). Recurses into builtin containers to `depth`.
    """
    if isinstance(value, (Tainted, TaintedBytes)):
        content = (
            value if isinstance(value, str) else value.decode("utf-8", errors="ignore")
        )
        yield str(content), value.label
        return
    if isinstance(value, str):
        yield value, None
        return
    if depth <= 0:
        return
    if isinstance(value, Mapping):
        for v in value.values():
            yield from _walk_strings(v, depth=depth - 1)
        return
    if isinstance(value, _CONTAINER_TYPES):
        for item in value:
            yield from _walk_strings(item, depth=depth - 1)


class AuditRegistry:
    """The laundering audit's per-run registry of untrusted-resolving content.

    Advisory only: findings never change a decision. Off the latency budget;
    only ever invoked when audit is enabled. Catches mechanical laundering
    (the bytes survive into a sink argument unlabeled); cannot catch semantic
    laundering (a model paraphrasing the untrusted text first).
    """

    def __init__(self, *, min_match_length: int = AUDIT_MIN_MATCH_LENGTH) -> None:
        self._min_match_length = min_match_length
        self._by_run: dict[str, list[tuple[str, str]]] = {}
        self._findings: list[Finding] = []

    def register_from_args(
        self,
        args: Mapping[str, Any],
        *,
        sources_table: Mapping[str, TrustLevel],
        run_id: str,
        depth: int,
    ) -> None:
        """Register every untrusted-resolving string found in `args` for this run."""
        for value in args.values():
            for content, label in _walk_strings(value, depth=depth):
                if label is None or len(content) < self._min_match_length:
                    continue
                if resolve_label_trust(label, sources_table) is TrustLevel.UNTRUSTED:
                    self._by_run.setdefault(run_id, []).append((content, label.source))

    def scan(
        self,
        args: Mapping[str, Any],
        *,
        tool: str,
        run_id: str,
        agent_id: str,
        session_id: str | None,
        depth: int,
    ) -> list[Finding]:
        """Scan `args` for previously-registered untrusted content with no label."""
        registered = self._by_run.get(run_id, [])
        if not registered:
            return []
        findings: list[Finding] = []
        for argument, value in args.items():
            for content, label in _walk_strings(value, depth=depth):
                if label is not None:
                    continue
                for registered_content, source in registered:
                    if registered_content in content:
                        findings.append(
                            Finding(
                                schema_version=EVENT_SCHEMA_VERSION,
                                source=source,
                                tool=tool,
                                argument=argument,
                                agent_id=agent_id,
                                run_id=run_id,
                                session_id=session_id,
                                timestamp=datetime.now(UTC),
                            )
                        )
        self._findings.extend(findings)
        return findings

    def clear_run(self, run_id: str) -> None:
        """Drop the registered content for a finished run."""
        self._by_run.pop(run_id, None)

    @property
    def findings(self) -> list[Finding]:
        """Every finding recorded so far, across all runs."""
        return list(self._findings)
