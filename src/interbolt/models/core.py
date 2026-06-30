from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from interbolt.errors import InterboltConfigError


def validate_qualified_name_part(value: str, *, part: str) -> None:
    """Reject a namespace or tool name that contains a dot.

    The dotted `namespace.tool` form is the policy-key surface, so neither half
    may itself contain a dot or the two forms become ambiguous to parse back apart.

    Args:
        value: The candidate namespace or tool name.
        part: Which part this is, for the error message ("namespace" or "tool").

    Raises:
        InterboltConfigError: If `value` contains a dot.
    """
    if "." in value:
        raise InterboltConfigError(f"{part} {value!r} may not contain a dot")


class Mode(StrEnum):
    """The enforcement mode: governs behavior on evaluation error.

    Does not change a correct `block`/`require_approval` decision, except
    under `DRY_RUN` where every decision is downgraded to allow.
    """

    ENFORCE = "enforce"
    MONITOR = "monitor"
    DRY_RUN = "dry_run"


class TrustLevel(StrEnum):
    """The result of resolving a source name against a policy's sources table."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Label(BaseModel):
    """Provenance attached to a value: where it came from, never a resolved trust bit.

    Attributes:
        source: The originating source name. For a merged value, the first
            contributing source (lineage carries the full set).
        value_id: A unique id minted when this label was created or last
            transformed, for the flow graph and audit trail.
        lineage: The de-duplicated set of source names that contributed to this
            value, in first-contributed order.
    """

    model_config = ConfigDict(frozen=True)

    source: str
    value_id: str
    lineage: tuple[str, ...]


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
        tool: The qualified tool name the decision was made for.
        contributing_labels: Every label collected from the call's arguments.
        trifecta: The lethal-trifecta legs satisfied by this call. In v1 this
            only ever contains `"from_untrusted"` or is empty; the
            `reaches_external` and `reads_private` legs are not computed.
        mode: The enforcement mode in effect when this decision was made.
        decision_id: A unique id for this decision, for the audit trail.
        agent_id: The durable, integrator-supplied agent identity.
        run_id: The per-run identity.
        session_id: The optional, integrator-supplied session identity.
    """

    model_config = ConfigDict(frozen=True)

    action: Action
    matched_rule: str | None
    tool: str
    contributing_labels: tuple[Label, ...]
    trifecta: frozenset[str]
    mode: Mode
    decision_id: str
    agent_id: str
    run_id: str
    session_id: str | None


class QualifiedName(BaseModel):
    """A structured `(namespace, tool)` pair; `namespace.tool` is the surface form."""

    model_config = ConfigDict(frozen=True)

    namespace: str
    tool: str

    @field_validator("namespace")
    @classmethod
    def _validate_namespace(cls, value: str) -> str:
        validate_qualified_name_part(value, part="namespace")
        return value

    @field_validator("tool")
    @classmethod
    def _validate_tool(cls, value: str) -> str:
        validate_qualified_name_part(value, part="tool")
        return value

    def __str__(self) -> str:
        return f"{self.namespace}.{self.tool}"


class Event(BaseModel):
    """The versioned, emitted record of a `Decision`."""

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
    mode: Mode
    outcome: str
    timestamp: datetime


class Finding(BaseModel):
    """A laundering-audit record: untrusted content reached a sink without a label."""

    model_config = ConfigDict(frozen=True)

    schema_version: int
    source: str
    tool: str
    argument: str
    agent_id: str
    run_id: str
    session_id: str | None
    timestamp: datetime
