"""Provenance-gated tool calls for AI agents.

Mark untrusted data where it enters an agent. interbolt records its provenance,
carries that provenance through your code, and evaluates a YAML+CEL policy at
the tool-call boundary to allow, block, or require approval. Decisions are
deterministic and local: no model in the loop, no network calls.
"""

from __future__ import annotations

from typing import Any

__version__ = "0.2.0"

from interbolt.constants import (
    RECORD_TYPE_ENDORSEMENT,
    RECORD_TYPE_EVENT,
    RECORD_TYPE_FINDING,
)
from interbolt.errors import (
    ApprovalDenied,
    InterboltConfigError,
    InterboltError,
    InterboltUsageError,
    PolicyEvaluationError,
    PolicyViolation,
)
from interbolt.models.core import (
    Action,
    Decision,
    Endorsement,
    Event,
    Finding,
    Label,
    Mode,
    TrustLevel,
)
from interbolt.models.protocols import ApprovalResolver, Reporter
from interbolt.policy import Policy, default_policy
from interbolt.reporting import (
    CompositeReporter,
    InMemoryReporter,
    JsonlReporter,
    LoggingReporter,
    NullReporter,
    describe_decision,
    describe_endorsement,
    describe_event,
    describe_finding,
)
from interbolt.runtime import (
    Runtime,
    agent,
    check,
    configure,
    enforce_decision,
    enforce_decision_async,
    get_runtime,
    guard,
)
from interbolt.runtime.guard import AgentHandle
from interbolt.taint import (
    LabeledValue,
    Tainted,
    TaintedBytes,
    endorse,
    taint,
    track_model_call,
)

__all__ = [
    "taint",
    "endorse",
    "guard",
    "check",
    "enforce_decision",
    "enforce_decision_async",
    "configure",
    "default_policy",
    "agent",
    "get_runtime",
    "AgentHandle",
    "track_model_call",
    "Runtime",
    "Policy",
    "Decision",
    "Event",
    "Finding",
    "Endorsement",
    "Action",
    "Mode",
    "Label",
    "TrustLevel",
    "Reporter",
    "ApprovalResolver",
    "NullReporter",
    "InMemoryReporter",
    "LoggingReporter",
    "JsonlReporter",
    "CompositeReporter",
    "describe_decision",
    "describe_event",
    "describe_finding",
    "describe_endorsement",
    "RECORD_TYPE_EVENT",
    "RECORD_TYPE_FINDING",
    "RECORD_TYPE_ENDORSEMENT",
    "InterboltError",
    "PolicyViolation",
    "PolicyEvaluationError",
    "ApprovalDenied",
    "InterboltConfigError",
    "InterboltUsageError",
    "Tainted",
    "LabeledValue",
    "TaintedBytes",
    "OTelReporter",
    "__version__",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401 -- PEP 562 lazy export
    """Lazily import `OTelReporter` on first access (PEP 562).

    Keeps `opentelemetry` out of `import interbolt`'s dependency graph: the
    `[otel]` extra is only ever imported when a caller actually reaches for
    `OTelReporter`.
    """
    if name == "OTelReporter":
        from interbolt.reporting.otel import OTelReporter

        return OTelReporter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
