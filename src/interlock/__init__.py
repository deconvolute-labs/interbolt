"""Provenance-gated tool calls for AI agents.

Mark untrusted data where it enters an agent. interlock records its provenance,
carries that provenance through your code, and evaluates a YAML+CEL policy at
the tool-call boundary to allow, block, or require approval. Decisions are
deterministic and local: no model in the loop, no network calls.
"""

from __future__ import annotations

__version__ = "0.1.0"

from interlock.errors import (
    ApprovalDenied,
    InterlockConfigError,
    InterlockError,
    InterlockUsageError,
    PolicyEvaluationError,
    PolicyViolation,
)
from interlock.models.core import Action, Decision, Label, Mode, TrustLevel
from interlock.models.protocols import ApprovalResolver, Reporter
from interlock.policy import Policy
from interlock.reporting import InMemoryReporter, LoggingReporter, NullReporter
from interlock.runtime import Runtime, check, configure, guard
from interlock.taint import LabeledValue, Tainted, TaintedBytes, taint

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
    "InterlockError",
    "PolicyViolation",
    "PolicyEvaluationError",
    "ApprovalDenied",
    "InterlockConfigError",
    "InterlockUsageError",
    "Tainted",
    "LabeledValue",
    "TaintedBytes",
    "__version__",
]
