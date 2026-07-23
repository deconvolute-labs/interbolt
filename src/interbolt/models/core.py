from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class Mode(StrEnum):
    """The enforcement mode: governs behavior on evaluation error.

    A correct `block`/`require_approval` decision always holds, except under
    `DRY_RUN`, which downgrades every decision to allow.
    """

    ENFORCE = "enforce"
    MONITOR = "monitor"
    DRY_RUN = "dry_run"


class TrustLevel(StrEnum):
    """The result of resolving a source name against a policy's sources table."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Label(BaseModel):
    """Provenance attached to a value: where it came from. Trust is resolved
    later, at the sink, not stored here.

    Attributes:
        source: The originating source name. For a merged value, the first
            contributing source (lineage carries the full set).
        value_id: A unique id minted when this label was created or last
            transformed, for the flow graph and audit trail.
        lineage: The de-duplicated set of source names that contributed to this
            value, in first-contributed order.
        endorsements: The de-duplicated set of endorsement kinds this value
            carries, in the order they were applied. Provenance-preserving
            and trust-neutral: `endorse()` never changes `lineage` or how
            `trust` resolves, it only adds a policy-visible fact a sink can
            require. A merged label's endorsements are the intersection of
            its contributors' (an endorsement survives a merge only if every
            contributor carried it).
    """

    model_config = ConfigDict(frozen=True)

    source: str
    value_id: str
    lineage: tuple[str, ...]
    endorsements: tuple[str, ...] = ()


class Action(StrEnum):
    """The three possible policy decisions."""

    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


class Outcome(StrEnum):
    """What `check()` actually computed, before any mode-based downgrade."""

    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    EVALUATION_ERROR = "evaluation_error"


class Decision(BaseModel):
    """The outcome of evaluating a policy against a guarded call.

    Attributes:
        action: The decision taken.
        matched_rule: The name of the first matching rule, or `None` if the
            sink's default action was used.
        matched_condition: The matched rule's original CEL `when` text, or
            `None` for the catch-all rule or when no rule matched. Lets a
            caller see exactly which policy condition fired, not just its name.
        tool: The qualified tool name the decision was made for.
        contributing_labels: Every label collected from the call's arguments.
        trifecta: The lethal-trifecta legs satisfied by this call. In v1 this
            only ever contains `"from_untrusted"` or is empty; the
            `reaches_external` and `reads_private` legs are not computed.
        untrusted_sources: The subset of contributing labels' lineage names
            that resolved untrusted against the policy's sources table at
            decision time. Answers "which source caused this" directly, so
            the reporter doesn't need its own sources table to re-derive it.
        run_tainted: Whether the active run has ingested untrusted data via
            `taint()` at any point before this call, regardless of whether
            this call's own arguments carry a label (run-level gating).
            Catches a model-mediated handoff that launders value-level
            taint away.
        mode: The enforcement mode in effect when this decision was made.
        decision_id: A unique id for this decision, for the audit trail.
        agent_id: The durable, integrator-supplied agent identity.
        run_id: The per-run identity.
        session_id: The optional, integrator-supplied session identity.
    """

    model_config = ConfigDict(frozen=True)

    action: Action
    matched_rule: str | None
    matched_condition: str | None
    tool: str
    contributing_labels: tuple[Label, ...]
    trifecta: frozenset[str]
    untrusted_sources: frozenset[str]
    run_tainted: bool
    mode: Mode
    decision_id: str
    agent_id: str
    run_id: str
    session_id: str | None


class RecordBase(BaseModel):
    """The shared base for every emitted provenance record.

    Attributes:
        schema_version: The event schema version this record was emitted under.
        trace_id: The active OpenTelemetry trace id (W3C hex), or `None` if
            OpenTelemetry is absent or no span was active at construction.
        span_id: The active OpenTelemetry span id (W3C hex), or `None` under
            the same conditions as `trace_id`.
        policy_fingerprint: A stable hash of the policy in force when this
            record was produced (`Policy.fingerprint`), so a record can be
            joined against a retained copy of that policy even after it has
            since changed. `None` only when no policy was reachable at all,
            for example an `Endorsement` emitted before `configure()` has run.
        timestamp: When the record was constructed.
    """

    model_config = ConfigDict(frozen=True)

    schema_version: int
    trace_id: str | None = None
    span_id: str | None = None
    policy_fingerprint: str | None = None
    timestamp: datetime


class IdentifiedRecordBase(RecordBase):
    """Adds the durable identity triple, for a record that carries it directly
    rather than through an embedded `Decision`.

    Attributes:
        agent_id: The durable, integrator-supplied agent identity.
        run_id: The per-run identity.
        session_id: The optional, integrator-supplied session identity.
    """

    agent_id: str
    run_id: str
    session_id: str | None


class Event(RecordBase):
    """The versioned, emitted record of a `Decision`.

    Identity, matched-rule, trifecta, and mode fields are not duplicated
    here: reach them via `decision`, the single source of truth for what was
    decided.
    """

    decision: Decision
    sources: frozenset[str]
    outcome: Outcome


class Finding(IdentifiedRecordBase):
    """A laundering-audit record: untrusted content reached a sink without a label."""

    source: str
    tool: str
    argument: str


class Endorsement(IdentifiedRecordBase):
    """A record of one `endorse()` call: a value's restrictiveness was
    reduced by explicit, code-driven validation, not by laundering it.

    Attributes:
        kind: The machine-matchable endorsement category (for example
            `"schema_validated"`, `"recipient_allowlisted"`).
        note: An optional free-text audit annotation. Carried only on this
            record, never on the endorsed value's label.
        lineage: The endorsed label's source lineage, for traceability.
        value_id: The endorsed value's fresh label id, minted for this
            endorsement hop.
    """

    kind: str
    note: str | None
    lineage: tuple[str, ...]
    value_id: str
