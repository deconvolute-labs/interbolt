"""check(): the decision pipeline, decomposed into one function per phase."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from celpy.evaluation import CELEvalError, CELUnsupportedError

from interbolt.constants import EVENT_SCHEMA_VERSION, RECURSION_DEPTH
from interbolt.enforcement.audit import AuditRegistry
from interbolt.enforcement.signals import (
    _compute_run_tainted,
    _compute_trifecta,
    _compute_untrusted_sources,
)
from interbolt.errors import PolicyEvaluationError
from interbolt.models.core import (
    Action,
    Decision,
    Event,
    Finding,
    Label,
    Mode,
    Outcome,
    TrustLevel,
)
from interbolt.models.protocols import Reporter
from interbolt.policy import Policy, ResolvedLabel
from interbolt.policy.evaluate import (
    build_context,
    evaluate_sink,
    resolve_agent_groups,
    resolve_labels,
)
from interbolt.taint import collect_labels, unwrap
from interbolt.utils import current_trace_context, get_logger

_logger = get_logger("enforcement")


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
    """Evaluate policy for one tool call and return the decision.

    Computes the decision and emits it to the reporter. It does not act on
    the decision: pass the result to `enforce_decision` or
    `enforce_decision_sync` to raise on a block or route an approval. `guard`
    does both steps for you.

    Args:
        tool: The qualified tool name, as `namespace.tool`.
        args: The call's arguments, by name.
        agent_id: The acting agent.
        run_id: The run this call belongs to, or `None` to mint a fresh one.
        session_id: An optional session identifier, carried onto the record.
        policy: The compiled policy.
        reporter: Where the resulting `Event` goes.
        mode: The enforcement mode.
        audit_registry: The audit registry, or `None` when auditing is off.

    Returns:
        The `Decision`, for every outcome including allow.

    Raises:
        PolicyEvaluationError: Under `enforce` mode, when a rule's condition
            fails to evaluate, for example because it reads an argument the
            call did not pass.
    """
    labels = collect_labels(args, max_depth=RECURSION_DEPTH)
    plain_args = unwrap(args)
    sources_table = policy.sources_table
    resolved_labels = resolve_labels(labels, sources_table)
    trifecta = _compute_trifecta(resolved_labels)
    untrusted_sources = _compute_untrusted_sources(resolved_labels)
    resolved_run_id = run_id if run_id is not None else str(uuid.uuid4())
    run_tainted = _compute_run_tainted(resolved_run_id, sources_table)

    action, matched_rule, matched_condition, evaluation_error = _evaluate(
        tool=tool,
        plain_args=plain_args,
        resolved_labels=resolved_labels,
        trifecta=trifecta,
        run_tainted=run_tainted,
        agent_id=agent_id,
        policy=policy,
    )
    final_action, outcome = _apply_mode(action, evaluation_error, mode)
    if evaluation_error is not None:
        matched_rule = None
        matched_condition = None
    if outcome != Outcome.ALLOW:
        _logger.warning(
            "check(): tool=%s outcome=%s matched_rule=%s mode=%s",
            tool,
            outcome,
            matched_rule,
            mode,
        )

    decision, event = _build_records(
        tool=tool,
        labels=labels,
        trifecta=trifecta,
        untrusted_sources=untrusted_sources,
        run_tainted=run_tainted,
        mode=mode,
        final_action=final_action,
        matched_rule=matched_rule,
        matched_condition=matched_condition,
        agent_id=agent_id,
        resolved_run_id=resolved_run_id,
        session_id=session_id,
        outcome=outcome,
        policy_fingerprint=policy.fingerprint,
    )
    _emit(reporter, event)

    if audit_registry is not None:
        _run_audit(
            audit_registry,
            args=args,
            tool=tool,
            sources_table=sources_table,
            run_id=resolved_run_id,
            agent_id=agent_id,
            session_id=session_id,
            reporter=reporter,
            policy_fingerprint=policy.fingerprint,
        )

    if evaluation_error is not None and mode == Mode.ENFORCE:
        raise PolicyEvaluationError(str(evaluation_error), decision=decision)

    return decision


def _evaluate(
    *,
    tool: str,
    plain_args: Mapping[str, Any],
    resolved_labels: tuple[ResolvedLabel, ...],
    trifecta: frozenset[str],
    run_tainted: bool,
    agent_id: str,
    policy: Policy,
) -> tuple[Action, str | None, str | None, CELEvalError | CELUnsupportedError | None]:
    """Sink lookup, CEL context build, and rule evaluation. Pure."""
    compiled_sink = policy.compiled_sinks.get(tool)
    matched_rule: str | None = None
    matched_condition: str | None = None
    action: Action = policy.document.defaults.sink_action
    evaluation_error: CELEvalError | CELUnsupportedError | None = None
    try:
        if compiled_sink is not None:
            groups = resolve_agent_groups(agent_id, policy.id_to_groups)
            context = build_context(
                tool=tool,
                args=plain_args,
                resolved_labels=resolved_labels,
                trifecta=trifecta,
                run_tainted=run_tainted,
                agent_id=agent_id,
                groups=groups,
            )
            matched_rule, action, matched_condition = evaluate_sink(
                compiled_sink,
                context,
                default_action=policy.document.defaults.sink_action,
            )
    except (CELEvalError, CELUnsupportedError) as exc:
        evaluation_error = exc
    return action, matched_rule, matched_condition, evaluation_error


def _apply_mode(
    raw_action: Action,
    evaluation_error: CELEvalError | CELUnsupportedError | None,
    mode: Mode,
) -> tuple[Action, Outcome]:
    """Map the raw action through the error-to-mode rule and the dry-run downgrade.

    Returns the enforced action and the `Outcome`.
    """
    outcome = Outcome(raw_action.value)
    corrected_action = raw_action
    if evaluation_error is not None:
        outcome = Outcome.EVALUATION_ERROR
        corrected_action = Action.BLOCK if mode == Mode.ENFORCE else Action.ALLOW
    final_action = Action.ALLOW if mode == Mode.DRY_RUN else corrected_action
    return final_action, outcome


def _build_records(
    *,
    tool: str,
    labels: tuple[Label, ...],
    trifecta: frozenset[str],
    untrusted_sources: frozenset[str],
    run_tainted: bool,
    mode: Mode,
    final_action: Action,
    matched_rule: str | None,
    matched_condition: str | None,
    agent_id: str,
    resolved_run_id: str,
    session_id: str | None,
    outcome: Outcome,
    policy_fingerprint: str,
) -> tuple[Decision, Event]:
    """Assemble the `Decision` and `Event` records. Assembly only."""
    decision = Decision(
        action=final_action,
        matched_rule=matched_rule,
        matched_condition=matched_condition,
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
    trace_id, span_id = current_trace_context() or (None, None)
    all_sources = frozenset(name for label in labels for name in label.lineage)
    event = Event(
        schema_version=EVENT_SCHEMA_VERSION,
        decision=decision,
        sources=all_sources,
        outcome=outcome,
        trace_id=trace_id,
        span_id=span_id,
        policy_fingerprint=policy_fingerprint,
        timestamp=datetime.now(UTC),
    )
    return decision, event


def _run_audit(
    audit_registry: AuditRegistry,
    *,
    args: Mapping[str, Any],
    tool: str,
    sources_table: Mapping[str, TrustLevel],
    run_id: str,
    agent_id: str,
    session_id: str | None,
    reporter: Reporter,
    policy_fingerprint: str,
) -> None:
    """Register this call's args, scan for laundered content, emit any findings."""
    audit_registry.register_from_args(
        args,
        sources_table=sources_table,
        run_id=run_id,
        depth=RECURSION_DEPTH,
    )
    findings = audit_registry.scan(
        args,
        tool=tool,
        run_id=run_id,
        agent_id=agent_id,
        session_id=session_id,
        depth=RECURSION_DEPTH,
        policy_fingerprint=policy_fingerprint,
    )
    for finding in findings:
        _emit(reporter, finding)


def _emit(reporter: Reporter, event: Event | Finding) -> None:
    try:
        reporter.export(event)
    except Exception:  # noqa: BLE001 - a reporter failure must never affect a decision
        _logger.warning(
            "reporter %r failed to export %r", reporter, type(event).__name__
        )
