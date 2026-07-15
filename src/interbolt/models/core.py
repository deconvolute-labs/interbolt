from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from interbolt.errors import InterboltConfigError


def validate_qualified_name_part(value: str, *, part: str) -> None:
    """Reject a namespace or tool name that contains a dot.

    A dot in either half would make the dotted `namespace.tool` surface
    ambiguous to parse back apart.

    Args:
        value: The candidate namespace or tool name.
        part: Which part this is, for the error message ("namespace" or "tool").

    Raises:
        InterboltConfigError: If `value` contains a dot.
    """
    if "." in value:
        raise InterboltConfigError(f"{part} {value!r} may not contain a dot")


def split_qualified_name(value: str) -> tuple[str, str] | None:
    """Split a dotted `namespace.tool` name into its validated halves.

    Args:
        value: The candidate qualified name.

    Returns:
        The `(namespace, tool)` pair, or `None` if `value` has no dot.

    Raises:
        InterboltConfigError: If the namespace or tool half itself contains a dot.
    """
    namespace, separator, tool = value.rpartition(".")
    if not separator:
        return None
    validate_qualified_name_part(namespace, part="namespace")
    validate_qualified_name_part(tool, part="tool")
    return namespace, tool


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


class Event(BaseModel):
    """The versioned, emitted record of a `Decision`.

    `trace_id`/`span_id` are the active OpenTelemetry span's W3C hex
    identifiers at construction time, or `None` if OpenTelemetry is absent
    or no span was active.
    """

    model_config = ConfigDict(frozen=True)

    schema_version: int
    decision: Decision
    agent_id: str
    run_id: str
    session_id: str | None
    sources: frozenset[str]
    lineage: tuple[str, ...]
    matched_rule: str | None
    trifecta: frozenset[str]
    untrusted_sources: frozenset[str]
    run_tainted: bool
    mode: Mode
    outcome: str
    trace_id: str | None = None
    span_id: str | None = None
    timestamp: datetime


class Finding(BaseModel):
    """A laundering-audit record: untrusted content reached a sink without a label.

    `trace_id`/`span_id` are captured the same way as on `Event`.
    """

    model_config = ConfigDict(frozen=True)

    schema_version: int
    source: str
    tool: str
    argument: str
    agent_id: str
    run_id: str
    session_id: str | None
    trace_id: str | None = None
    span_id: str | None = None
    timestamp: datetime


class Endorsement(BaseModel):
    """A record of one `endorse()` call: a value's restrictiveness was
    reduced by explicit, code-driven validation, not by laundering it.

    Attributes:
        schema_version: The event schema version this record was emitted under.
        kind: The machine-matchable endorsement category (for example
            `"schema_validated"`, `"recipient_allowlisted"`).
        note: An optional free-text audit annotation. Carried only on this
            record, never on the endorsed value's label.
        lineage: The endorsed label's source lineage, for traceability.
        value_id: The endorsed value's fresh label id, minted for this
            endorsement hop.
        agent_id: The durable, integrator-supplied agent identity, or
            `constants.DEFAULT_AGENT_ID` if no `agent_context` is active.
        run_id: The active run's identity, or a freshly minted one if no
            `agent_context` is active.
        session_id: Always `None` in v1: there is no session-identity
            context variable for `endorse()` to read, unlike `agent_id`/
            `run_id`.
        trace_id: The active OpenTelemetry trace id (W3C hex), or `None` if
            OpenTelemetry is absent or no span was active at construction.
        span_id: The active OpenTelemetry span id (W3C hex), or `None` under
            the same conditions as `trace_id`.
        timestamp: When the endorsement was recorded.
    """

    model_config = ConfigDict(frozen=True)

    schema_version: int
    kind: str
    note: str | None
    lineage: tuple[str, ...]
    value_id: str
    agent_id: str
    run_id: str
    session_id: str | None
    trace_id: str | None = None
    span_id: str | None = None
    timestamp: datetime
