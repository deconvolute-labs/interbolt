"""Provenance-gated tool calls for AI agents.

Mark untrusted data where it enters an agent. interbolt records its provenance,
carries that provenance through your code, and evaluates a YAML+CEL policy at
the tool-call boundary to allow, block, or require approval. Decisions are
deterministic and local: no model in the loop, no network calls.
"""

from __future__ import annotations

__version__ = "0.1.0"

from interbolt.errors import (
    ApprovalDenied,
    InterboltConfigError,
    InterboltError,
    InterboltUsageError,
    PolicyEvaluationError,
    PolicyViolation,
)
from interbolt.models.core import Action, Decision, Label, Mode, TrustLevel
from interbolt.models.protocols import ApprovalResolver, Reporter
from interbolt.policy import Policy
from interbolt.reporting import InMemoryReporter, LoggingReporter, NullReporter
from interbolt.runtime import Runtime, check, configure, guard
from interbolt.taint import LabeledValue, Tainted, TaintedBytes, taint

__all__ = [
    "taint",
    "guard",
    "check",
    "configure",
    "Runtime",
    "Policy",
    "Decision",
    "Action",
    "Mode",
    "Label",
    "TrustLevel",
    "Reporter",
    "ApprovalResolver",
    "NullReporter",
    "InMemoryReporter",
    "LoggingReporter",
    "InterboltError",
    "PolicyViolation",
    "PolicyEvaluationError",
    "ApprovalDenied",
    "InterboltConfigError",
    "InterboltUsageError",
    "Tainted",
    "LabeledValue",
    "TaintedBytes",
    "__version__",
]
