"""Static analysis of a Python repository's tool surface. See `scan_repository`."""

from __future__ import annotations

from interbolt.scan.artifact import (
    Discovery,
    ScanAgent,
    ScanAgentIdentity,
    ScanArtifact,
    ScanCollision,
    ScanDefinition,
    ScanEvidence,
    ScanPolicyRef,
    ScanRepository,
    ScanScannerInfo,
    ScanTool,
    ScanUndetected,
    ScanUnmatchedSink,
    UndetectedKind,
    Verdict,
)
from interbolt.scan.scanner import scan_repository

__all__ = [
    "scan_repository",
    "ScanArtifact",
    "ScanAgent",
    "ScanAgentIdentity",
    "ScanTool",
    "ScanEvidence",
    "ScanUndetected",
    "ScanRepository",
    "ScanPolicyRef",
    "ScanCollision",
    "ScanDefinition",
    "ScanScannerInfo",
    "ScanUnmatchedSink",
    "Verdict",
    "Discovery",
    "UndetectedKind",
]
